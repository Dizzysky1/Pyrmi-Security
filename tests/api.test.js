'use strict';
// End-to-end tests for the API with the in-memory store:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const kv = require('../api/_lib/kv');
const core = require('../api/_lib/core');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
// What the browser script sends: plain-JSON signals under `signals`. They're advisory (the server treats them as
// hints, never proof), so there's nothing to encode and no per-session key.
const beacon = (s, signals) => call('POST', '/api/v1/signal', JSON.stringify({ token: s.token, signals: { pt: 1000, k: 5, p: 3, au: [], tp: [], ...signals } }), { 'Content-Type': 'text/plain' });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
// pyrmi.com's own new-project form is protected by Pyrmi: get a token the way the dashboard page does.
async function siteToken() {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_pyrmi_site' })).body;
  await beacon(s, {});
  await wait(1300);
  return s.token;
}

let pk, sk;

test('create project returns keys once', async () => {
  const r = await call('POST', '/api/v1/project', { name: 'Test Game', origins: ['https://game.example'], pyrmiToken: await siteToken() });
  assert.equal(r.status, 201);
  ({ publicKey: pk, secretKey: sk } = r.body.project);
  assert.match(pk, /^pk_/); assert.match(sk, /^sk_/);
  const g = await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + sk });
  assert.equal(g.body.project.name, 'Test Game');
  assert.equal(g.body.project.secretKey, undefined);
});

test('origins are enforced on session start', async () => {
  const bad = await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://evil.example' });
  assert.equal(bad.status, 403);
  const ok = await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' });
  assert.equal(ok.status, 200);
  assert.equal(typeof ok.body.seed, 'number');
});

test('clean run is accepted, replayed token is rejected', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  await beacon(s, {});
  const v = await call('POST', '/api/v1/verify', { token: s.token, score: 10, durationMs: 0, player: 'alice' }, { Authorization: 'Bearer ' + sk });
  assert.equal(v.body.verdict, 'accept', JSON.stringify(v.body));
  const again = await call('POST', '/api/v1/verify', { token: s.token, score: 10, player: 'alice' }, { Authorization: 'Bearer ' + sk });
  assert.equal(again.body.verdict, 'reject');
  assert.ok(again.body.reasons.some((r) => r.code === 'token_reused'));
});

test('forged token, impossible time and no page all get caught', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  const forged = s.token.slice(0, -3) + 'abc';
  const f = await call('POST', '/api/v1/verify', { token: forged, score: 1 }, { Authorization: 'Bearer ' + sk });
  assert.ok(f.body.reasons.some((r) => r.code === 'invalid_token'));
  const t = await call('POST', '/api/v1/verify', { token: s.token, score: 999, durationMs: 600000, player: 'bob' }, { Authorization: 'Bearer ' + sk });
  assert.equal(t.body.verdict, 'reject');
  assert.ok(t.body.reasons.some((r) => r.code === 'impossible_time'));
  assert.ok(t.body.reasons.some((r) => r.code === 'no_client'));
});

test('bot signals raise risk to reject', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  await beacon(s, { wd: true, ut: 12 });
  const v = await call('POST', '/api/v1/verify', { token: s.token, score: 5, player: 'botty' }, { Authorization: 'Bearer ' + sk });
  assert.equal(v.body.verdict, 'reject');
  assert.ok(v.body.risk >= 70);
});

test('verify refuses secret keys sent from a browser', async () => {
  const v = await call('POST', '/api/v1/verify', { token: 'x', score: 1 }, { Authorization: 'Bearer ' + sk, 'Sec-Fetch-Site': 'cross-site', Origin: 'https://game.example' });
  assert.equal(v.status, 400);
  assert.equal(v.body.error, 'secret_key_in_browser');
});

test('dashboard shows verdicts and flagged players', async () => {
  const d = await call('GET', '/api/v1/dashboard', undefined, { Authorization: 'Bearer ' + sk });
  assert.equal(d.status, 200);
  const today = d.body.days[d.body.days.length - 1];
  assert.ok(today.accept >= 1 && today.reject >= 3);
  assert.ok(d.body.players.find((p) => p.player === 'botty').reject === 1);
  assert.ok(d.body.events.length >= 4);
  const bad = await call('GET', '/api/v1/dashboard', undefined, { Authorization: 'Bearer sk_wrongwrongwrongwrongwrong' });
  assert.equal(bad.status, 401);
});

test('settings update and secret rotation', async () => {
  const u = await call('PATCH', '/api/v1/project', { settings: { maxScore: 100, reviewAt: 30 } }, { Authorization: 'Bearer ' + sk });
  assert.equal(u.body.project.settings.maxScore, 100);
  const bad = await call('PATCH', '/api/v1/project', { settings: { reviewAt: 90, rejectAt: 50 } }, { Authorization: 'Bearer ' + sk });
  assert.equal(bad.status, 400);
  const r = await call('POST', '/api/v1/project?action=rotate', {}, { Authorization: 'Bearer ' + sk });
  const old = await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + sk });
  assert.equal(old.status, 401);
  sk = r.body.secretKey;
  assert.equal((await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + sk })).status, 200);
});

test('the value is optional and user works as an alias for player', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  await beacon(s, {});
  const v = await call('POST', '/api/v1/verify', { token: s.token, user: 'carol@example.com' }, { Authorization: 'Bearer ' + sk });
  assert.equal(v.body.verdict, 'accept', JSON.stringify(v.body));
  assert.equal(v.body.player, 'carol@example.com');
  assert.equal(v.body.score, null);
});

// ---- the homepage sandbox ----

test('sandbox: a normal request is accepted, a replay of it is rejected', async () => {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_demo_sandbox' })).body;
  await beacon(s, {});
  await wait(1600);
  const v = await call('POST', '/api/v1/demo', { token: s.token, value: 42, visitor: 'visitor-abc123' });
  assert.equal(v.body.verdict, 'accept', JSON.stringify(v.body.reasons));
  assert.equal(v.body.player, 'visitor-abc123');
  const again = await call('POST', '/api/v1/demo', { token: s.token, value: 42, visitor: 'visitor-abc123' });
  assert.equal(again.body.verdict, 'reject');
  assert.ok(again.body.reasons.some((r) => r.code === 'token_reused'));
});

test('sandbox: direct API calls, huge values and edited tokens are rejected', async () => {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_demo_sandbox' })).body;
  const direct = await call('POST', '/api/v1/demo', { token: s.token, value: 42, visitor: '<b>me</b>' });
  assert.equal(direct.body.verdict, 'reject');
  assert.ok(direct.body.reasons.some((r) => r.code === 'too_short'));
  assert.ok(direct.body.reasons.some((r) => r.code === 'no_client'));
  assert.equal(direct.body.player, 'visitor');
  const s2 = (await call('POST', '/api/v1/session', { site: 'pk_demo_sandbox' })).body;
  await beacon(s2, {});
  await wait(1600);
  const big = await call('POST', '/api/v1/demo', { token: s2.token, value: 999999 });
  assert.ok(big.body.reasons.some((r) => r.code === 'score_over_max'));
  const [body, mac] = s2.token.split('.');
  const t = JSON.parse(Buffer.from(body, 'base64url').toString()); t.i -= 3600000;
  const edited = await call('POST', '/api/v1/demo', { token: Buffer.from(JSON.stringify(t)).toString('base64url') + '.' + mac });
  assert.ok(edited.body.reasons.some((r) => r.code === 'invalid_token'));
});

test('sandbox: public demo dashboard is readable without a key, and its settings are locked', async () => {
  const d = await call('GET', '/api/v1/dashboard?demo=1');
  assert.equal(d.status, 200);
  assert.equal(d.body.project.demo, true);
  assert.ok(d.body.events.length >= 3);
  assert.equal((await fetch(base + '/api/v1/vessel')).status, 404);
});

test('pyrmi-server SDK verifies through the API, including a simulate hook', async () => {
  const { Pyrmi } = require('../packages/pyrmi-server');
  const pyrmi = new Pyrmi({ secretKey: sk, endpoint: base + '/api/v1' });
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  await beacon(s, {});
  const lied = await pyrmi.verify({ token: s.token, score: 50, player: 'sdk', replay: [1, 2, 3], simulate: () => ({ score: 20 }) });
  assert.equal(lied.verdict, 'reject');
  assert.ok(lied.reasons.some((r) => r.code === 'replay_mismatch'));
  const down = new Pyrmi({ secretKey: sk, endpoint: 'http://127.0.0.1:9/api/v1', timeoutMs: 500 });
  assert.equal((await down.verify({ token: 'x', score: 1 })).verdict, 'reject');
});

// ---- pyrmi.com protecting itself ----
test('site: creating a project without a clean Pyrmi token is refused', async () => {
  const none = await call('POST', '/api/v1/project', { name: 'Bot' });
  assert.equal(none.status, 403);
  assert.equal(none.body.error, 'blocked_by_pyrmi');
  assert.ok(none.body.reasons.includes('invalid_token'));
  const s = (await call('POST', '/api/v1/session', { site: 'pk_pyrmi_site' })).body;
  const rushed = await call('POST', '/api/v1/project', { name: 'Bot', pyrmiToken: s.token });
  assert.equal(rushed.status, 403);
  assert.ok(rushed.body.reasons.includes('too_short') && rushed.body.reasons.includes('no_client'));
  const s2 = (await call('POST', '/api/v1/session', { site: 'pk_pyrmi_site' })).body;
  await beacon(s2, { wd: true });
  await wait(1300);
  const bot = await call('POST', '/api/v1/project', { name: 'Bot', pyrmiToken: s2.token });
  assert.equal(bot.status, 403);
  assert.ok(bot.body.reasons.includes('automation'));
  const d = await call('GET', '/api/v1/dashboard?demo=site');
  assert.equal(d.status, 200);
  assert.ok(d.body.days[d.body.days.length - 1].reject >= 3);
});

test('a session is not shipped a telemetry key, and a malformed beacon does not poison it', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  // The per-session shape key used to ship to the client (and so protected nothing); it is gone now.
  assert.equal(s.x, undefined);
  // Garbage telemetry is dropped with a 400...
  const garbage = await call('POST', '/api/v1/signal', JSON.stringify({ token: s.token, signals: 'not-an-object' }), { 'Content-Type': 'text/plain' });
  assert.equal(garbage.status, 400);
  // ...but it must NOT permanently flag the session (was F-10: one bad beacon tainted the whole session).
  await beacon(s, {});
  const v = await call('POST', '/api/v1/verify', { token: s.token, player: 'copycat' }, { Authorization: 'Bearer ' + sk });
  assert.ok(!v.body.reasons.some((r) => r.code === 'tampered_runtime'), JSON.stringify(v.body.reasons));
});

test('site: an edited copy of the browser script is flagged', async () => {
  const s = (await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://game.example' })).body;
  await beacon(s, { sh: 'deadbeef' });
  const v = await call('POST', '/api/v1/verify', { token: s.token, player: 'editor' }, { Authorization: 'Bearer ' + sk });
  assert.ok(v.body.reasons.some((r) => r.code === 'tampered_runtime' && /pyrmi\.js/.test(r.detail)));
});

test('site: wrong secret keys from one network are capped', async () => {
  const h = { Authorization: 'Bearer sk_wrongwrongwrongwrongwrong', 'X-Forwarded-For': '203.0.113.9' };
  let last;
  for (let i = 0; i < 21; i++) last = await call('GET', '/api/v1/project', undefined, h);
  assert.equal(last.status, 429);
});

test('the built browser script is current and works end to end', async () => {
  const { execFileSync } = require('child_process');
  execFileSync(process.execPath, [require('path').join(__dirname, '../scripts/build-sdk.js'), '--check']);
  const vm = require('vm');
  const src = require('fs').readFileSync(require('path').join(__dirname, '../sdk/pyrmi.js'), 'utf8');
  const noop = () => {};
  const win = {
    navigator: { userAgent: 'Mozilla/5.0 Chrome/120', languages: ['en'] }, performance: { now: () => Date.now() % 1e6 },
    addEventListener: noop, location: { href: base + '/', origin: base }, outerWidth: 0, innerWidth: 0,
    fetch: (u, o) => fetch(u, { ...o, headers: { ...(o && o.headers), 'User-Agent': 'test-ua' } }),
    Date, Math, JSON, String, Promise, Blob, URL, Error, Function, RegExp, EventTarget, setTimeout, setInterval, clearTimeout, clearInterval, isFinite,
    atob, btoa, XMLHttpRequest: function () {},
  };
  win.XMLHttpRequest.prototype.send = noop;
  const doc = { currentScript: { getAttribute: (n) => (n === 'data-site' ? 'pk_demo_sandbox' : null), src: base + '/sdk/pyrmi.js' },
    addEventListener: noop, documentElement: { getAttribute: () => null }, hidden: false };
  const ctx = vm.createContext({ ...win, window: win, document: doc });
  vm.runInContext(src, ctx);
  const Pyrmi = win.Pyrmi;
  assert.equal(Pyrmi.version, require('../api/_lib/sdk-build.json').version);
  const s = await Pyrmi.start();
  await wait(1600);
  await Pyrmi.flush();
  Pyrmi.stop();
  const v = await call('POST', '/api/v1/demo', { token: s.token, value: 5, visitor: 'visitor-feed01' });
  assert.ok(!v.body.reasons.some((r) => r.code === 'no_client'), JSON.stringify(v.body.reasons));
  assert.ok(!v.body.reasons.some((r) => /pyrmi\.js|telemetry/.test(r.detail || '')), JSON.stringify(v.body.reasons));
});

// A2-06: /demo wrote a 30-day per-visitor record on every call under a caller-chosen label, even for a forged token,
// so anyone could grow the store without bound. The record is now written only when a genuine session backs it.
test('a forged demo call writes no per-visitor record (A2-06)', async () => {
  const label = 'visitor-deadbeef'; // matches the allowed visitor pattern
  const v = await call('POST', '/api/v1/demo', { token: 'not-a-real-token', value: 1, visitor: label });
  assert.ok(v.body.reasons.some((r) => r.code === 'invalid_token'));
  assert.equal(Number(await kv.cmd('EXISTS', 'ps:pl:' + core.DEMO.pid + ':' + label)), 0, 'no per-visitor record for a forged call');
});

// F-17 / F-18: the sandbox must use the shared (TTL-correct) limiter and pass IP context to verify, not hand-roll an
// INCR+EXPIRE limiter or land every tokenless call in one shared verify bucket.
test('the sandbox endpoint uses the shared limiter and passes IP context to verify (F-17/F-18)', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '../api/v1/demo.js'), 'utf8');
  assert.ok(/core\.limitIp\(/.test(src), 'demo should rate-limit via the shared core.limitIp (F-17)');
  assert.ok(!/\bEXPIRE\b/.test(src), 'demo should not hand-roll an INCR+EXPIRE limiter (F-17)');
  assert.ok(/,\s*\{\s*ip\s*\}\)/.test(src), 'demo should pass { ip } ctx to verify (F-18)');
});

// F-21: HSTS includeSubDomains hard-fails any subdomain without a *.pyrmi.com cert (mail./autodiscover. serve a
// Private Email cert), with no click-through once seen — and autodiscover is fetched over HTTPS by mail clients.
// Keep max-age on apex+www but drop includeSubDomains (and keep preload off).
test('HSTS keeps max-age but drops includeSubDomains so non-TLS-clean subdomains stay reachable (F-21)', () => {
  const vj = JSON.parse(require('fs').readFileSync(require('path').join(__dirname, '../vercel.json'), 'utf8'));
  const hsts = vj.headers.flatMap((h) => h.headers).find((h) => h.key === 'Strict-Transport-Security');
  assert.ok(hsts, 'an HSTS header is configured');
  assert.ok(/max-age=\d+/.test(hsts.value), 'HSTS keeps a max-age');
  assert.ok(!/includeSubDomains/i.test(hsts.value), 'HSTS must not include subdomains (F-21)');
  assert.ok(!/preload/i.test(hsts.value), 'HSTS preload stays off');
});

// F-23: a rate-limited response should tell the caller when to retry, and the site should publish a security.txt.
test('a 429 carries a Retry-After header (F-23)', async () => {
  const ip = '203.0.113.231'; // own limiter bucket, so other tests don't change the count
  let status = 0, retry = null;
  for (let i = 0; i < 40 && status !== 429; i++) {
    const r = await fetch(base + '/api/v1/demo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: JSON.stringify({ token: 'x', visitor: 'visitor-ret01' }) });
    status = r.status; retry = r.headers.get('retry-after');
  }
  assert.equal(status, 429, 'the demo limiter should eventually 429');
  assert.ok(retry && Number(retry) > 0, 'a 429 must carry a positive Retry-After, got ' + retry);
});

test('a security.txt is published with a contact and an expiry (F-23)', () => {
  const txt = require('fs').readFileSync(require('path').join(__dirname, '../.well-known/security.txt'), 'utf8');
  assert.ok(/^Contact:\s*\S+/mi.test(txt), 'security.txt names a Contact');
  assert.ok(/^Expires:\s*\S+/mi.test(txt), 'security.txt has an Expires field (RFC 9116)');
});

// M9: verify() used to measure elapsed time from the token's own self-reported start `i`, not the server-created
// session record, and never compared the two. A forged token (precondition: a leaked signing secret) carrying a
// genuine session id but a backdated `i` could therefore fake elapsed time and slip past minDurationMs / dilute
// maxScorePerSec — the only durable server-side anti-bot floor. Elapsed now comes from the stored session start, and
// a token whose `i` doesn't match the session is rejected.
test('a forged backdated-start token cannot fake elapsed time (M9)', async () => {
  const C = require('../api/_lib/crypto');
  const created = await call('POST', '/api/v1/project', { name: 'M9 game', origins: ['https://m9.example'], pyrmiToken: await siteToken() });
  const { publicKey: pk9, secretKey: sk9, pid: pid9 } = created.body.project;
  await call('PATCH', '/api/v1/project', { settings: { minDurationMs: 1500, maxScorePerSec: 10 } }, { Authorization: 'Bearer ' + sk9 });
  const s = (await call('POST', '/api/v1/session', { site: pk9 }, { Origin: 'https://m9.example' })).body;
  await beacon(s, {}); // a real session record, so no_client won't fire and only the timing path is under test
  const genuine = await C.readToken(s.token);
  const now = Date.now();
  // same (genuine) session id, but the start is backdated 5s and the expiry pushed out — exactly the attacker's forge
  const forged = await C.signToken({ v: 1, p: pid9, s: genuine.s, i: now - 5000, e: now + 3600000, seed: genuine.seed, ih: genuine.ih, uh: genuine.uh });
  const v = await call('POST', '/api/v1/verify', { token: forged, score: 50, player: 'm9' }, { Authorization: 'Bearer ' + sk9 });
  assert.equal(v.body.verdict, 'reject', 'a backdated-start token must not be accepted: ' + JSON.stringify(v.body));
  assert.ok(v.body.reasons.some((r) => r.code === 'invalid_token' || r.code === 'too_short'),
    'rejected for the backdated/mismatched start, got ' + JSON.stringify(v.body.reasons));
});
