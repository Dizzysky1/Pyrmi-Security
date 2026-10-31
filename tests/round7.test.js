'use strict';
// Round 7: hand-written telemetry. Proof-of-concept tests for the reports, against the in-memory store:
//   node --test tests/*.test.js
// Each test sends what an attacker's script would, straight to the API, and failed on main before this round.
// The first is the report itself: ~15 lines of made-up JSON earned the sandbox's 999 at risk 0.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');
const SDK = require('../api/_lib/sdk-build.json');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let ipn = 1;
// Each test gets its own network, so per-network limits from other tests don't interfere.
const post = async (p, body, headers) => {
  const r = await fetch(base + '/api/v1' + p, { method: 'POST', headers: { 'Content-Type': 'text/plain', 'User-Agent': 'node', ...(headers || {}) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const PAGE = { Origin: 'https://pyrmi.com', 'Sec-Fetch-Site': 'same-origin' };
const verdict = async (token, ip, value) => (await post('/demo', { token, value: value === undefined ? 999 : value, visitor: 'visitor-7e57' }, { 'X-Forwarded-For': ip })).body;
const codes = (v) => v.reasons.map((r) => r.code);
const detail = (v, code) => (v.reasons.find((r) => r.code === code) || {}).detail || '';

test('the reported forge: made-up signals from a script no longer earn a clean 999', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox' }, h)).body;
  await post('/signal', { token: s.token, signals: { wd: false, hl: false, au: [], tp: [], wr: [], dt: 0, ut: 0, ih: 0, k: 4, p: 6, h: 0, pt: 1600, gt: null } }, h);
  await wait(1600);
  const v = await verdict(s.token, ip);
  assert.notEqual(v.verdict, 'accept', JSON.stringify(v));
  assert.ok(codes(v).includes('unverified_client') && codes(v).includes('tampered_runtime'), JSON.stringify(codes(v)));
  assert.match(detail(v, 'unverified_client'), /page/);
  assert.equal(v.client, 'unverified');
});

test('leaving the fields out (signals: {}) counts as a tampered script, not a clean one', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  await post('/signal', { token: s.token, signals: {} }, h);
  await wait(1600);
  const v = await verdict(s.token, ip);
  assert.match(detail(v, 'tampered_runtime'), /pyrmi\.js:missing/, JSON.stringify(v.reasons));
  assert.match(detail(v, 'unverified_client'), /shape/);
  assert.equal(v.verdict, 'reject');
});

test('old build fingerprints stop being a free pass after their grace period; the readable source is not one in production', async () => {
  const old = SDK.previous[SDK.previous.length - 1];
  const saved = { ...(SDK.retired || {}) };
  SDK.retired = { ...saved, [old]: Date.now() - 30 * 86400e3 }; // replaced a month ago
  try {
    const ip = '192.0.2.' + ipn++;
    const h = { ...PAGE, 'X-Forwarded-For': ip };
    const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
    await post('/signal', { token: s.token, signals: B.signals({ sh: old }) }, h);
    await wait(1600);
    const v = await verdict(s.token, ip, 5);
    assert.match(detail(v, 'tampered_runtime'), /pyrmi\.js:outdated/, JSON.stringify(v.reasons));
  } finally { SDK.retired = saved; }
  const env = process.env.VERCEL_ENV;
  process.env.VERCEL_ENV = 'production';
  try {
    const ip = '192.0.2.' + ipn++;
    const h = { ...PAGE, 'X-Forwarded-For': ip };
    const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
    await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ sh: SDK.sourceHash }) }, h);
    await wait(1600);
    const v = await verdict(s.token, ip, 5);
    assert.ok(/pyrmi\.js/.test(detail(v, 'tampered_runtime')), JSON.stringify(v.reasons));
  } finally { if (env === undefined) delete process.env.VERCEL_ENV; else process.env.VERCEL_ENV = env; }
});

test('a clean beacon captured from one session and re-posted under a fresh token is refused', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const a = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  const captured = { bn: a.bn, n: 1, signals: B.signals() };
  assert.equal((await post('/signal', { token: a.token, ...captured }, h)).status, 200);
  // the same body with a fresh session's token: refused outright, and that session is marked
  const b = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  const r = await post('/signal', { token: b.token, ...captured }, h);
  assert.equal(r.status, 409);
  await wait(1600);
  const v = await verdict(b.token, ip, 5);
  assert.ok(codes(v).includes('unverified_client') || codes(v).includes('no_client'), JSON.stringify(v.reasons));
  assert.notEqual(v.verdict, 'accept');
  // without the nonce (the tester's version: same signals, fresh token): still not a clean pass
  const c = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  await wait(1600);
  await post('/signal', { token: c.token, signals: captured.signals }, h);
  const w = await verdict(c.token, ip, 5);
  assert.match(detail(w, 'unverified_client'), /nonce/, JSON.stringify(w.reasons));
  assert.notEqual(w.verdict, 'accept');
});

test('a beacon replayed into its own session is dropped, and counters that go backwards are caught', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ k: 9, p: 12 }) }, h);
  const again = await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ k: 0, p: 0, wd: false }) }, h);
  assert.equal(again.body.dropped, 'stale');
  await post('/signal', { token: s.token, bn: s.bn, n: 2, signals: B.signals({ k: 1, p: 1, pt: 1200 }) }, h);
  await wait(1600);
  const v = await verdict(s.token, ip, 5);
  assert.match(detail(v, 'unverified_client'), /counters/, JSON.stringify(v.reasons));
});

test('the page clock has to keep pace with the server\'s, and beacons have to come from the page that started the session', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 500 }, h)).body;
  await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 500 + 60000 }) }, h); // a minute "passed" in 0 s
  await wait(1600);
  assert.match(detail(await verdict(s.token, ip, 5), 'unverified_client'), /clock/);
  // A beacon from another page is refused outright and changes nothing (it used to mark the session, which let any
  // page holding the token sabotage the real player's session).
  const t = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  const evil = await post('/signal', { token: t.token, bn: t.bn, n: 1, signals: B.signals({ wd: true }) }, { ...h, Origin: 'https://evil.example' });
  assert.equal(evil.status, 409);
  assert.equal(evil.body.error, 'wrong_origin');
  await post('/signal', { token: t.token, bn: t.bn, n: 1, signals: B.signals() }, h);
  await wait(1600);
  const tv = await verdict(t.token, ip, 5);
  assert.ok(!codes(tv).includes('automation') && !codes(tv).includes('unverified_client'), JSON.stringify(tv.reasons));
  // a script that claims to be Chrome but sends none of the fetch metadata Chrome always sends
  const chrome = { 'User-Agent': 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/156.0 Safari/537.36' };
  const u = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, { ...h, ...chrome })).body;
  await post('/signal', { token: u.token, bn: u.bn, n: 1, signals: B.signals() }, { 'X-Forwarded-For': ip, Origin: 'https://pyrmi.com', ...chrome });
  await wait(1600);
  assert.match(detail(await verdict(u.token, ip, 5), 'unverified_client'), /transport/);
});

test('lots of counted input on a page the browser never saw activated is made up', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 0 }, h)).body;
  await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ ac: false, k: 6, p: 9 }) }, h);
  await wait(1600);
  assert.match(detail(await verdict(s.token, ip, 5), 'unverified_client'), /activation/);
});

test('what the real script sends from a real page is still a clean, corroborated accept', async () => {
  const ip = '192.0.2.' + ipn++;
  const h = { ...PAGE, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 1234 }, h)).body;
  await wait(800);
  await post('/signal', { token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 1234 + 800 }) }, h);
  await wait(800);
  // the 10 s timer and flush() can race: an out-of-order beacon is dropped, not held against the page
  await post('/signal', { token: s.token, bn: s.bn, n: 3, signals: B.signals({ pt: 1234 + 1600, k: 6 }) }, h);
  assert.equal((await post('/signal', { token: s.token, bn: s.bn, n: 2, signals: B.signals({ pt: 1234 + 1590 }) }, h)).body.dropped, 'stale');
  const v = await verdict(s.token, ip, 999);
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.risk, 0);
  assert.equal(v.client, 'corroborated');
});
