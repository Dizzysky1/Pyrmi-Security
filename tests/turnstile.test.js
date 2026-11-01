'use strict';
// Cloudflare Turnstile on pyrmi.com's own forms and in pyrmi-server, against a fake siteverify endpoint:
//   node --test tests/*.test.js
// Off until TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are set; then sign-in codes, new projects and sites, claiming,
// rotating and deleting each need a fresh token for that form, and a missing, reused or failed one is refused.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
process.env.PYRMI_SITE_GUARD = 'off'; // the Pyrmi self-check has its own tests; this file is about Turnstile
process.env.RESEND_API_KEY = 'test-resend';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const auth = require('../api/v1/auth/[provider].js');
const turnstile = require('../api/_lib/turnstile');
const { Pyrmi, trusted } = require('../packages/pyrmi-server');

const SECRET = 'test-ts-secret';
let base, server, cf, cfUrl;
const seen = []; // what the fake Cloudflare was asked
const used = new Set();
// Fake siteverify: "ok:<action>:<n>" passes once for that action, solved on 127.0.0.1 ("...@host" names another page
// host); "again:<action>:<n>" passes every time it is sent, as if Cloudflare stopped refusing duplicates;
// "noaction:<n>" passes with no action; anything else fails, and the wrong secret fails too.
function siteverify(req, res) {
  let body = '';
  req.on('data', (c) => { body += c; });
  req.on('end', () => {
    const f = new URLSearchParams(body), token = f.get('response') || '';
    seen.push({ secret: f.get('secret'), token, remoteip: f.get('remoteip') });
    let out;
    if (f.get('secret') !== SECRET) out = { success: false, 'error-codes': ['invalid-input-secret'] };
    else if (used.has(token)) out = { success: false, 'error-codes': ['timeout-or-duplicate'] };
    else if (/^(ok|again|noaction):/.test(token)) {
      const [t, host] = token.split('@'), [kind, action] = t.split(':');
      if (kind !== 'again') used.add(token);
      out = { success: true, hostname: host || '127.0.0.1', ...(kind === 'noaction' ? {} : { action }) };
    }
    else out = { success: false, 'error-codes': ['invalid-input-response'] };
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(out));
  });
}
test.before(async () => {
  server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port;
  cf = http.createServer(siteverify); await new Promise((r) => cf.listen(0, r)); cfUrl = 'http://127.0.0.1:' + cf.address().port + '/siteverify';
  turnstile.endpoint = cfUrl;
});
test.after(() => { server.close(); cf.close(); });

let n = 0;
const tok = (action) => 'ok:' + action + ':' + (++n); // a fresh, valid token for one form
const on = () => { process.env.TURNSTILE_SITE_KEY = '0x-test-site-key'; process.env.TURNSTILE_SECRET_KEY = SECRET; };
const off = () => { delete process.env.TURNSTILE_SITE_KEY; delete process.env.TURNSTILE_SECRET_KEY; };
let ipn = 1;
const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', 'X-Forwarded-For': headers && headers.ip || '203.0.113.' + (ipn++ % 250), ...(headers || {}) }, body: body === undefined ? undefined : JSON.stringify(body) });
  let json = null; try { json = await r.json(); } catch (_) { /* none */ }
  return { status: r.status, body: json, headers: r.headers };
};
const mail = [];
auth.mailer = async (m) => { mail.push(m); };
const codeFor = (email) => { const m = mail.filter((x) => x.to === email).pop(); return m && (m.subject.match(/(\d{6})/) || [])[1]; };
const start = (email, turnstileToken, extra) => call('POST', '/api/v1/auth/email?action=start', { email, turnstileToken }, { 'X-Pyrmi-CSRF': '1', ...(extra || {}) });

test('off by default: no site key is handed out and nothing asks for a token', async () => {
  off();
  const me = await call('GET', '/api/v1/me');
  assert.equal(me.status, 401);
  assert.equal(me.body.turnstile, null);
  const r = await start('off@example.com');
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.equal(seen.length, 0, 'Cloudflare is never called while Turnstile is off');
});

test('sign-in codes need a fresh token made for the sign-in form', async () => {
  on();
  try {
    assert.equal((await call('GET', '/api/v1/me')).body.turnstile, '0x-test-site-key');
    const none = await start('a@example.com');
    assert.equal(none.status, 403); assert.equal(none.body.error, 'turnstile_required');
    const bad = await start('a@example.com', 'forged');
    assert.equal(bad.status, 403); assert.equal(bad.body.error, 'turnstile_failed');
    const other = await start('a@example.com', tok('new-site'));
    assert.equal(other.status, 403, 'a token made for another form'); assert.equal(other.body.error, 'turnstile_failed');
    const t = tok('signin');
    const before = mail.length;
    const good = await start('a@example.com', t, { ip: '198.51.100.7' });
    assert.equal(good.status, 200, JSON.stringify(good.body));
    assert.equal(mail.length, before + 1);
    const asked = seen.find((x) => x.token === t);
    assert.equal(asked.secret, SECRET); assert.equal(asked.remoteip, '198.51.100.7');
    const again = await start('a@example.com', t);
    assert.equal(again.status, 403, 'a token works once'); assert.equal(again.body.error, 'turnstile_failed');
    assert.equal(mail.length, before + 1, 'no code was sent for a refused request');
  } finally { off(); }
});

test('fails closed: if Cloudflare can\'t be reached, the request is refused, not waved through', async () => {
  on();
  turnstile.endpoint = 'http://127.0.0.1:9/siteverify';
  try {
    const r = await start('b@example.com', tok('signin'));
    assert.equal(r.status, 503); assert.equal(r.body.error, 'turnstile_unavailable');
  } finally { turnstile.endpoint = cfUrl; off(); }
});

test('the answer must carry this form\'s action and this site\'s hostname, and a token is used once here too', async () => {
  on();
  try {
    const noAction = await start('c@example.com', 'noaction:' + (++n));
    assert.equal(noAction.status, 403, 'Cloudflare\'s answer with no action'); assert.equal(noAction.body.error, 'turnstile_failed');
    const elsewhere = await start('c@example.com', tok('signin') + '@evil.example');
    assert.equal(elsewhere.status, 403, 'solved on another site'); assert.equal(elsewhere.body.error, 'turnstile_failed');
    process.env.TURNSTILE_HOSTNAMES = 'pyrmi.com, www.pyrmi.com';
    try {
      assert.equal((await start('c@example.com', tok('signin'))).status, 403, 'TURNSTILE_HOSTNAMES replaces the request host');
      assert.equal((await start('c@example.com', tok('signin') + '@www.pyrmi.com')).status, 200);
    } finally { delete process.env.TURNSTILE_HOSTNAMES; }
    const t = 'again:signin:' + (++n);
    assert.equal((await start('d@example.com', t)).status, 200);
    const replay = await start('d@example.com', t);
    assert.equal(replay.status, 403, 'refused here even if Cloudflare passes it again'); assert.equal(replay.body.error, 'turnstile_failed');
  } finally { off(); }
});

test('a key-only project needs a token for the new-project form', async () => {
  on();
  try {
    const no = await call('POST', '/api/v1/project', { name: 'x', origins: ['https://t.example'] });
    assert.equal(no.status, 403); assert.equal(no.body.error, 'turnstile_required');
    const yes = await call('POST', '/api/v1/project', { name: 'x', origins: ['https://t.example'], turnstileToken: tok('new-project') });
    assert.equal(yes.status, 201, JSON.stringify(yes.body));
  } finally { off(); }
});

test('signed in: adding, claiming, rotating and deleting each need their own token', async () => {
  on();
  try {
    const email = 'owner@example.com';
    const st = await start(email, tok('signin'));
    assert.equal(st.status, 200);
    const ec = st.headers.getSetCookie().find((c) => c.startsWith('__Host-pyrmi_ec=')).split(';')[0]; // the code is this browser's (round 12)
    const v = await call('POST', '/api/v1/auth/email?action=verify', { email, code: codeFor(email) }, { 'X-Pyrmi-CSRF': '1', Cookie: ec });
    assert.equal(v.status, 200, JSON.stringify(v.body));
    const cookie = v.headers.getSetCookie().find((c) => c.startsWith('__Host-pyrmi_session=')).split(';')[0];
    const as = { Cookie: cookie, 'X-Pyrmi-CSRF': '1', ip: '192.0.2.50' };
    assert.equal((await call('GET', '/api/v1/me', undefined, as)).body.turnstile, '0x-test-site-key');

    const add0 = await call('POST', '/api/v1/sites', { name: 'mine', origins: ['https://t.example'] }, as);
    assert.equal(add0.status, 403); assert.equal(add0.body.error, 'turnstile_required');
    const add = await call('POST', '/api/v1/sites', { name: 'mine', origins: ['https://t.example'], turnstileToken: tok('new-site') }, as);
    assert.equal(add.status, 201, JSON.stringify(add.body));
    const pid = add.body.project.pid;

    const rot0 = await call('POST', '/api/v1/sites?pid=' + pid + '&action=rotate', {}, as);
    assert.equal(rot0.status, 403);
    const rot = await call('POST', '/api/v1/sites?pid=' + pid + '&action=rotate', { turnstileToken: tok('rotate') }, as);
    assert.equal(rot.status, 200); assert.match(rot.body.secretKey, /^sk_/);

    const loose = await call('POST', '/api/v1/project', { name: 'loose', origins: ['https://t.example'], turnstileToken: tok('new-project') });
    const claim0 = await call('POST', '/api/v1/sites?action=claim', { secretKey: loose.body.project.secretKey }, as);
    assert.equal(claim0.status, 403);
    const claim = await call('POST', '/api/v1/sites?action=claim', { secretKey: loose.body.project.secretKey, turnstileToken: tok('claim') }, as);
    assert.equal(claim.status, 200, JSON.stringify(claim.body));

    const del0 = await call('DELETE', '/api/v1/sites?pid=' + pid, {}, as);
    assert.equal(del0.status, 403);
    assert.equal((await call('DELETE', '/api/v1/sites?pid=' + pid, { turnstileToken: tok('rotate') }, as)).status, 403, 'a token for another form');
    const del = await call('DELETE', '/api/v1/sites?pid=' + pid, { turnstileToken: tok('delete') }, as);
    assert.equal(del.status, 200);
  } finally { off(); }
});

test('pyrmi-server: verifyTurnstile fails closed, and trusted(v, t) needs both a corroborated accept and a pass', async () => {
  const p = new Pyrmi({ secretKey: 'sk_test', turnstileSecret: SECRET, turnstileEndpoint: cfUrl });
  const good = await p.verifyTurnstile(tok('payout') + '@pyrmi.com', { action: 'payout', hostname: 'pyrmi.com', remoteip: '192.0.2.9' });
  assert.equal(good.success, true);
  assert.equal(seen[seen.length - 1].remoteip, '192.0.2.9');
  assert.deepEqual((await p.verifyTurnstile(tok('signup'), { action: 'payout' })).errorCodes, ['action-mismatch']);
  assert.deepEqual((await p.verifyTurnstile(tok('payout'), { hostname: 'evil.example' })).errorCodes, ['hostname-mismatch']);
  assert.equal((await p.verifyTurnstile('nope')).success, false);
  assert.deepEqual((await p.verifyTurnstile('')).errorCodes, ['missing-input-response']);
  const t = tok('payout');
  assert.equal((await p.verifyTurnstile(t)).success, true);
  assert.deepEqual((await p.verifyTurnstile(t)).errorCodes, ['timeout-or-duplicate']);
  const down = new Pyrmi({ secretKey: 'sk_test', turnstileSecret: SECRET, turnstileEndpoint: 'http://127.0.0.1:9/x' });
  assert.deepEqual((await down.verifyTurnstile(tok('payout'))).errorCodes, ['turnstile-unreachable']);
  const saved = process.env.TURNSTILE_SECRET_KEY; delete process.env.TURNSTILE_SECRET_KEY;
  assert.deepEqual((await new Pyrmi({ secretKey: 'sk_test' }).verifyTurnstile('ok:x')).errorCodes, ['missing-input-secret']);
  if (saved !== undefined) process.env.TURNSTILE_SECRET_KEY = saved;

  const v = { ok: true, verdict: 'accept', client: 'corroborated', trusted: true, reasons: [] };
  assert.equal(trusted(v), true);
  assert.equal(trusted(v, good), true);
  assert.equal(trusted(v, { success: false, errorCodes: ['x'] }), false);
  assert.equal(trusted(v, null), false, 'asking for Turnstile and passing nothing is a no');
  assert.equal(trusted({ ...v, client: 'unverified' }, good), false);
  assert.equal(trusted({ ...v, verdict: 'review' }, good), false);
});
