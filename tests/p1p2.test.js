'use strict';
// Follow-up hardening from the tester's P1/P2 list, against the in-memory store:
//   node --test tests/*.test.js
// Each test failed on main before this change.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const accounts = require('../api/_lib/accounts');
const { clientIp } = require('../api/_lib/http');
const { serve } = require('../scripts/dev.js');
const { signals, order } = require('./_browser');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

let ipn = 10;
const nextIp = () => '203.0.113.' + (ipn++);
const UA = 'p1p2-ua', ORIGIN = 'https://p1p2.example';
async function freshProject(settings) {
  const ip = nextIp();
  const p = await core.createProject({ name: 'P1P2', origins: [ORIGIN] }, ip, 'owner-p1p2');
  const project = settings ? await core.updateSettings(await core.loadProject(p.pid), settings) : await core.loadProject(p.pid);
  return { ...p, project, ip };
}
const page = (ip) => ({ ip, ua: UA, origin: ORIGIN, sfs: 'same-site' });

test('rate-limit windows always get their expiry, in the same request as the count', async () => {
  // INCR and then a separate EXPIRE: if the second call was lost, the key had no TTL and that limit stuck forever.
  // Simulate the lost call: a window must still expire.
  const ip = nextIp(), realCmd = kv.cmd;
  kv.cmd = async (...a) => (String(a[0]).toUpperCase() === 'EXPIRE' ? 0 : realCmd(...a));
  try { await core.limitIp(ip, 'p1p2', 60, 'PYRMI_UNSET_FOR_TEST', 5); } finally { kv.cmd = realCmd; }
  const ipf = await C.fingerprint('ip', ip);
  const ttl = Number(await kv.cmd('TTL', 'ps:rl:p1p2:' + ipf));
  assert.ok(ttl > 0 && ttl <= 60, 'ttl ' + ttl);
});

test('an expired token is marked used too, so replaying it is reported as a replay', async () => {
  const { project, ip } = await freshProject({ sessionTtlSec: 60 });
  const s = await core.startSession(project, page(ip), { pt: 0 });
  const realNow = Date.now, later = Date.now() + 120e3;
  Date.now = () => later;
  try {
    const first = await core.verify(project, { token: s.token, player: 'late' }, { ip });
    assert.ok(first.reasons.some((r) => r.code === 'expired'));
    assert.ok(!first.reasons.some((r) => r.code === 'token_reused'));
    const again = await core.verify(project, { token: s.token, player: 'late' }, { ip });
    assert.ok(again.reasons.some((r) => r.code === 'token_reused'), JSON.stringify(again.reasons));
  } finally { Date.now = realNow; }
});

test('/verify is limited per network the session started from, not per single-use token', async () => {
  const saved = process.env.PYRMI_VERIFIES_PER_MIN;
  process.env.PYRMI_VERIFIES_PER_MIN = '3';
  try {
    const { project, ip } = await freshProject();
    const out = [];
    for (let i = 0; i < 4; i++) {
      const s = await core.startSession(project, page(ip), { pt: 0 });
      out.push(await core.verify(project, { token: s.token, player: 'p' + i }, { ip: '192.0.2.1' }));
    }
    assert.ok(!out[2].reasons.some((r) => r.code === 'rate_limited'));
    assert.ok(out[3].reasons.some((r) => r.code === 'rate_limited'), JSON.stringify(out[3].reasons));
    // another network is not affected
    const s = await core.startSession(project, page(nextIp()), { pt: 0 });
    const other = await core.verify(project, { token: s.token, player: 'other' }, { ip: '192.0.2.1' });
    assert.ok(!other.reasons.some((r) => r.code === 'rate_limited'));
  } finally { if (saved === undefined) delete process.env.PYRMI_VERIFIES_PER_MIN; else process.env.PYRMI_VERIFIES_PER_MIN = saved; }
});

test('a beacon whose token and session disagree on the project is refused', async () => {
  const a = await freshProject(), b = await freshProject();
  const s = await core.startSession(a.project, page(a.ip), { pt: 0 });
  const t = await C.readToken(s.token);
  const forged = await C.signToken({ ...t, p: b.project.pid }); // needs the secret; this is the defence in depth
  await assert.rejects(core.recordSignals({ token: forged, ...order(s), signals: signals() }, page(a.ip)), (e) => e.status === 409);
});

test('a beacon from another page is refused and leaves the session alone', async () => {
  const { project, ip } = await freshProject();
  const s = await core.startSession(project, page(ip), { pt: 0 });
  await assert.rejects(
    core.recordSignals({ token: s.token, ...order(s), signals: signals({ wd: true }) }, { ...page(ip), origin: 'https://evil.example' }),
    (e) => e.status === 409 && e.code === 'wrong_origin');
  await assert.rejects(
    core.recordSignals({ token: s.token, ...order(s), signals: signals({ wd: true }) }, { ...page(ip), origin: '' }),
    (e) => e.status === 409 && e.code === 'wrong_origin');
  const sess = kv.pairs(await kv.cmd('HGETALL', 'ps:s:' + s.session));
  assert.equal(Number(sess.b || 0), 0);
  assert.equal(sess.sig, undefined);
});

test('a second rotation with an already rotated key gets a 409', async () => {
  const { project, secretKey } = await freshProject();
  const sk1 = await core.rotateSecret(project, secretKey);
  await assert.rejects(core.rotateSecret(project, secretKey), (e) => e.status === 409 && e.code === 'key_changed');
  assert.equal((await core.projectBySecretKey(sk1)).pid, project.pid);
  // a rotation already under way blocks a second one
  await kv.cmd('SET', 'ps:rot:' + project.pid, 'someone-else', 'EX', 10);
  await assert.rejects(core.rotateSecret(project, sk1), (e) => e.status === 409 && e.code === 'rotate_in_progress');
  await kv.cmd('DEL', 'ps:rot:' + project.pid);
});

test('a signed-in session that was never in the per-user index stops working', async () => {
  // Sessions from before the index existed couldn't be ended by revoke-all.
  const uid = 'u_legacy' + C.randomId(4), sid = C.randomId(32);
  await kv.cmd('HSET', 'ps:u:' + uid, 'email', 'legacy@example.com', 'name', 'Legacy');
  await kv.cmd('SET', 'ps:auth:' + C.sha256(sid), uid, 'EX', 3600);
  const req = { headers: { cookie: accounts.SESSION_COOKIE + '=' + sid } };
  assert.equal(await accounts.currentUser(req), null);
  // the same session in the index works, and revoke-all ends it
  await kv.cmd('ZADD', 'ps:usess:' + uid, Date.now(), C.sha256(sid));
  assert.equal((await accounts.currentUser(req)).uid, uid);
  await accounts.revokeAllSessions(uid);
  assert.equal(await accounts.currentUser(req), null);
});

test('CSRF check: Origin null and a different scheme or port are refused', () => {
  const req = (origin, host) => ({ method: 'POST', headers: { 'x-pyrmi-csrf': '1', host: host || 'pyrmi.com', ...(origin === undefined ? {} : { origin }) } });
  const refused = (r) => assert.throws(() => accounts.checkCsrf(r), (e) => e.status === 403 && e.code === 'csrf');
  refused(req('null'));
  refused(req('http://pyrmi.com'));
  refused(req('https://pyrmi.com:8443'));
  refused(req('https://evil.example'));
  refused(req('not a url'));
  accounts.checkCsrf(req('https://pyrmi.com'));
  accounts.checkCsrf(req(undefined)); // no Origin at all: the custom header and Sec-Fetch-Site still apply
  accounts.checkCsrf(req('http://127.0.0.1:3000', '127.0.0.1:3000')); // local development
  refused(req('http://pyrmi.com', 'pyrmi.com'));
});

test('client address: the first X-Forwarded-For entry on Vercel, counted from the right behind your own proxies', () => {
  const req = { headers: { 'x-forwarded-for': '6.6.6.6, 198.51.100.4' }, socket: {} };
  assert.equal(clientIp(req), '6.6.6.6');
  process.env.PYRMI_PROXY_HOPS = '1';
  try { assert.equal(clientIp(req), '198.51.100.4'); } finally { delete process.env.PYRMI_PROXY_HOPS; }
});

test('an account sees all of its sites when the per-account cap is raised', async () => {
  const saved = process.env.PYRMI_SITES_PER_USER;
  process.env.PYRMI_SITES_PER_USER = '30';
  try {
    const uid = 'u_many' + C.randomId(4);
    for (let i = 0; i < 25; i++) {
      const p = await core.createProject({ name: 'S' + i, origins: ['https://t.example'] }, '10.9.' + Math.floor(i / 3) + '.' + i, uid);
      await kv.cmd('ZADD', 'ps:us:' + uid, Date.now() + i, p.pid);
    }
    assert.equal((await accounts.listSites(uid)).length, 25);
  } finally { if (saved === undefined) delete process.env.PYRMI_SITES_PER_USER; else process.env.PYRMI_SITES_PER_USER = saved; }
});

test('the public demo dashboards show no session ids', async () => {
  const project = await core.loadProject(core.DEMO.pid);
  const s = await core.startSession(project, page(nextIp()), { pt: 0 });
  await core.verify(project, { token: s.token, player: 'visitor-abcd' }, { ip: '192.0.2.9' });
  const d = await core.dashboard(project);
  assert.ok(d.events.length > 0);
  assert.ok(d.events.every((e) => !('sid' in e)), JSON.stringify(d.events[0]));
  // a project's own dashboard keeps them
  const own = await freshProject();
  const t = await core.startSession(own.project, page(own.ip), { pt: 0 });
  await core.verify(own.project, { token: t.token, player: 'x' }, { ip: own.ip });
  assert.ok((await core.dashboard(own.project)).events.every((e) => typeof e.sid === 'string'));
});

test('405 responses say which methods are allowed', async () => {
  for (const [p, method, allow] of [['/api/v1/verify', 'GET', 'POST'], ['/api/v1/dashboard', 'POST', 'GET'], ['/api/v1/session', 'GET', 'POST, OPTIONS']]) {
    const r = await fetch(base + p, { method });
    assert.equal(r.status, 405, p);
    assert.equal(r.headers.get('allow'), allow, p);
  }
});

test('the home page and the docs get a content security policy and can\'t be framed', () => {
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
  for (const src of ['/', '/docs/(.*)']) {
    const rule = v.headers.find((h) => h.source === src);
    assert.ok(rule, src);
    const csp = rule.headers.find((h) => h.key === 'Content-Security-Policy').value;
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp.match(/script-src [^;]*/)[0], /unsafe-inline|unsafe-eval/);
    assert.equal(rule.headers.find((h) => h.key === 'X-Frame-Options').value, 'DENY');
  }
  // the policy only works if the pages have no inline scripts or handlers
  for (const f of ['index.html', 'docs/index.html']) {
    const html = fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, f + ' has an inline script');
    assert.doesNotMatch(html, /\son[a-z]+\s*=/i, f + ' has an inline event handler');
  }
});
