'use strict';
// Round 8: the re-test of round 7. A script that sent the full field set still came back accept, risk 0,
// client "corroborated", three ways. These send what that script sent, straight to the API, against the in-memory
// store, and each failed on main before this round:
//   node --test tests/*.test.js
// What still passes, by design, is a script that copies everything the real one sends with a real page clock (and a
// real browser running an edited copy). Client telemetry can't rule that out; README "Threat model" says so.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');
const SDK = require('../api/_lib/sdk-build.json');
const { trusted } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let ipn = 1;
const CHROME = 'Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0 Safari/537.36';
const OLD_SAFARI = 'Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15';
const post = async (p, body, headers) => {
  const r = await fetch(base + '/api/v1' + p, { method: 'POST', headers: { 'Content-Type': 'text/plain', ...(headers || {}) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const codes = (v) => v.reasons.map((r) => r.code);
const detail = (v, code) => (v.reasons.find((r) => r.code === code) || {}).detail || '';

// One sandbox session the way the re-test's script ran it: page headers, a page clock at start, one beacon, then the
// sandbox's verify. `beacon(s)` returns the /signal body to send.
async function run(beacon, opts) {
  const o = opts || {};
  const ip = '198.51.100.' + ipn++;
  const h = { Origin: 'https://pyrmi.com', 'Sec-Fetch-Site': 'same-origin', 'User-Agent': o.ua || CHROME, 'X-Forwarded-For': ip };
  const s = (await post('/session', { site: 'pk_demo_sandbox', ...(o.noPt ? {} : { pt: 1000 }) }, h)).body;
  await wait(1600);
  const r = await post('/signal', { token: s.token, ...beacon(s) }, h);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return (await post('/demo', { token: s.token, value: 999, visitor: 'visitor-8e57' }, h)).body;
}
const full = (extra) => B.signals({ pt: 2600, ...(extra || {}) });

test('B: the current fingerprint with pt: null no longer skips the clock check', async () => {
  const v = await run((s) => ({ bn: s.bn, n: 1, signals: full({ pt: null }) }));
  assert.notEqual(v.verdict, 'accept', JSON.stringify(v));
  assert.equal(v.client, 'unverified');
  assert.match(detail(v, 'unverified_client'), /shape|clock/);
});

test('C: a previous build fingerprint is never "corroborated", even inside its grace period', async () => {
  const prev = SDK.previous[SDK.previous.length - 1];
  const saved = { ...(SDK.retired || {}) };
  SDK.retired = { ...saved, [prev]: Date.now() - 3600e3 }; // replaced an hour ago: still in its grace period
  try {
    const v = await run(() => ({ signals: full({ sh: prev, pt: null, ac: undefined }) }), { noPt: true });
    assert.notEqual(v.verdict, 'accept', JSON.stringify(v));
    assert.equal(v.client, 'unverified');
    assert.match(detail(v, 'unverified_client'), /sdk_version/);
    assert.ok(!codes(v).includes('tampered_runtime'), 'a cached copy in its grace period is not called tampered: ' + JSON.stringify(v.reasons));
  } finally { SDK.retired = saved; }
});

test('the grace period for an old build is one day by default, then it counts as tampered too (reject)', async () => {
  const prev = SDK.previous[SDK.previous.length - 1];
  const saved = { ...(SDK.retired || {}) };
  SDK.retired = { ...saved, [prev]: Date.now() - 2 * 86400e3 }; // replaced two days ago
  try {
    const v = await run(() => ({ signals: full({ sh: prev }) }));
    assert.match(detail(v, 'tampered_runtime'), /pyrmi\.js:outdated/, JSON.stringify(v.reasons));
    assert.match(detail(v, 'unverified_client'), /sdk_version/);
    assert.equal(v.verdict, 'reject', JSON.stringify(v));
  } finally { SDK.retired = saved; }
});

test('ac is part of the beacon: leaving it out fails the shape, and null is made up on a browser that has userActivation', async () => {
  const left = await run((s) => ({ bn: s.bn, n: 1, signals: full({ ac: undefined }) }));
  assert.match(detail(left, 'unverified_client'), /shape/, JSON.stringify(left.reasons));
  assert.equal(left.client, 'unverified');
  const nul = await run((s) => ({ bn: s.bn, n: 1, signals: full({ ac: null }) }));
  assert.match(detail(nul, 'unverified_client'), /activation/, JSON.stringify(nul.reasons));
  assert.notEqual(nul.verdict, 'accept');
  // An older Safari has no userActivation, so the real script sends null there and must not be held to it.
  const safari = await run((s) => ({ bn: s.bn, n: 1, signals: full({ ac: null }) }), { ua: OLD_SAFARI });
  assert.ok(!codes(safari).includes('unverified_client'), JSON.stringify(safari.reasons));
  assert.equal(safari.client, 'corroborated');
});

test('a tampered runtime on its own is no longer a clean accept (review at the default settings)', async () => {
  const v = await run((s) => ({ bn: s.bn, n: 1, signals: full({ tp: ['performance.now'] }) }));
  const t = v.reasons.find((r) => r.code === 'tampered_runtime');
  assert.ok(t && t.weight >= 40, JSON.stringify(v.reasons));
  assert.equal(v.verdict, 'review', JSON.stringify(v));
});

test('an edited copy (unknown fingerprint) is a reject, not a 30-point accept', async () => {
  const v = await run((s) => ({ bn: s.bn, n: 1, signals: full({ sh: 'deadbeef' }) }));
  assert.match(detail(v, 'tampered_runtime'), /pyrmi\.js/);
  assert.equal(v.verdict, 'reject', JSON.stringify(v));
});

test('D, the known limit: a script that copies the real beacon with a real page clock still corroborates; trusted() is the gate for sensitive actions', async () => {
  const v = await run((s) => ({ bn: s.bn, n: 1, signals: full() }));
  assert.equal(v.verdict, 'accept');
  assert.equal(v.client, 'corroborated'); // documented: telemetry can't tell this from a browser
  assert.equal(trusted(v), true);
  // ...but anything short of a corroborated accept is not trusted, including the review the sample used to let through.
  const r = await run((s) => ({ bn: s.bn, n: 1, signals: full({ pt: null }) }));
  assert.equal(trusted(r), false);
  assert.equal(trusted({ verdict: 'review', client: 'corroborated' }), false);
  assert.equal(trusted({ verdict: 'accept', client: 'unverified' }), false);
  assert.equal(trusted({ ok: false, verdict: 'accept', unverified: true }), false); // failOpen when Pyrmi is unreachable
  assert.equal(trusted(null), false);
});
