'use strict';
// Key changes, email codes for known browsers, deleting a key-only project.
//   node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const core = require('../api/_lib/core');
const accounts = require('../api/_lib/accounts');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
let ipn = 1;
const nextIp = () => '192.0.2.' + (ipn++);
const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp(), ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const newProject = (name) => core.createProject({ name, origins: ['https://game.example'] }, nextIp());

test('1. a rotation by the old key holder can\'t cross a claim', async () => {
  const p = await newProject('race');
  // Run the old holder's rotation in the middle of the claim, right after ownership is taken.
  const orig = kv.cmd; let holder = null, holderErr = null;
  kv.cmd = async (...a) => {
    const r = await orig(...a);
    if (a[0] === 'HSETNX' && a[2] === 'owner' && holder === null && holderErr === null) {
      try { holder = await core.rotateSecret(await core.loadProject(p.pid), p.secretKey); } catch (e) { holderErr = e; }
    }
    return r;
  };
  let site;
  try { site = await accounts.claimSite('u_claim1', p.secretKey, {}); } finally { kv.cmd = orig; }
  assert.equal(holderErr && holderErr.status, 409, 'the holder\'s rotation waits for the claim');
  assert.equal(holder, null);
  assert.ok(site.secretKey, 'the claim issued a new key');
  assert.equal(await core.projectBySecretKey(p.secretKey), null, 'the old key is dead');
  assert.equal((await core.projectBySecretKey(site.secretKey)).owner, 'u_claim1');
});

test('1b. a claim while a rotation is running changes nothing', async () => {
  const p = await newProject('busy');
  await kv.cmd('SET', 'ps:rot:' + p.pid, 'someone', 'NX', 'EX', 10);
  await assert.rejects(accounts.claimSite('u_claim2', p.secretKey, {}), (e) => e.status === 409 && e.code === 'rotate_in_progress');
  const after = await core.loadProject(p.pid);
  assert.equal(after.owner, null, 'not taken');
  assert.equal(Number(await kv.cmd('ZCARD', 'ps:us:u_claim2')), 0, 'not in the account');
  await kv.cmd('DEL', 'ps:rot:' + p.pid);
  const site = await accounts.claimSite('u_claim2', p.secretKey, {});
  assert.ok(site.secretKey, 'and works once the rotation is done');
});

test('1c. a claim with a key rotated just before is refused, not half done', async () => {
  const p = await newProject('stale');
  const fresh = await core.rotateSecret(await core.loadProject(p.pid), p.secretKey);
  await assert.rejects(accounts.claimSite('u_claim3', p.secretKey, {}), (e) => e.status === 404);
  assert.equal((await core.loadProject(p.pid)).owner, null);
  assert.ok(await core.projectBySecretKey(fresh));
});

test('2. past the daily cap for existing accounts, a browser that signed in before still gets its code', async () => {
  process.env.RESEND_API_KEY = 'test-resend';
  const email = 'known13@example.com';
  const mails = []; const mailer = async (m) => { mails.push(m); };
  const rid = C.randomId(16);
  await accounts.emailStart({ email }, '203.0.113.50', mailer, { rid });
  const code = /code is (\d{6})/.exec(mails[0].text)[1];
  const r = await accounts.emailVerify({ email, code }, '203.0.113.50', { rid });
  const dev = decodeURIComponent(r.setCookies.find((c) => c.startsWith('__Host-pyrmi_dev=')).split(';')[0].split('=')[1]);
  process.env.PYRMI_EMAIL_KNOWN_PER_DAY = '1';
  try {
    // The day's one code for existing accounts goes out; after it, a stranger's browser is refused...
    await accounts.emailStart({ email }, '203.0.113.51', mailer, { rid: C.randomId(16) });
    await assert.rejects(accounts.emailStart({ email }, '203.0.113.51', mailer, { rid: C.randomId(16) }), (e) => e.status === 429);
    // ...the owner's own browser isn't.
    const before = mails.length;
    assert.deepEqual(await accounts.emailStart({ email }, '203.0.113.52', mailer, { rid: C.randomId(16), device: dev }), { sent: true });
    assert.equal(mails.length, before + 1);
  } finally { delete process.env.PYRMI_EMAIL_KNOWN_PER_DAY; }
});

test('3. a key-only project can be deleted with its own key, and gives its slot back', async () => {
  const p = await newProject('gone');
  const anon0 = Number(await kv.cmd('GET', 'ps:projects:anon'));
  const d = await call('DELETE', '/api/v1/project', undefined, { Authorization: 'Bearer ' + p.secretKey });
  assert.equal(d.status, 200, JSON.stringify(d.body));
  assert.equal(await core.loadProject(p.pid), null);
  assert.equal(await core.projectBySecretKey(p.secretKey), null);
  assert.equal(Number(await kv.cmd('GET', 'ps:projects:anon')), anon0 - 1);
  assert.equal((await call('DELETE', '/api/v1/project', undefined, { Authorization: 'Bearer ' + p.secretKey })).status, 401);
});

test('3b. a project in an account can\'t be deleted with the key alone', async () => {
  const p = await newProject('owned');
  const site = await accounts.claimSite('u_owner13', p.secretKey, {});
  const d = await call('DELETE', '/api/v1/project', undefined, { Authorization: 'Bearer ' + site.secretKey });
  assert.equal(d.status, 403);
  assert.equal(d.body.error, 'owned');
  assert.ok(await core.loadProject(p.pid));
});
