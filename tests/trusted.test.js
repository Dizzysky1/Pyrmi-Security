'use strict';
// trusted: the gate for payouts, prizes and account changes must not move with a project's thresholds.
//   node --test tests/*.test.js
// Re-test of round 8: a project that raised reviewAt to 50 got trusted(v) === true for a tampered runtime, and one at
// 80 for a webdriver session, because trusted only looked at accept + client. These failed on main before the fix.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
process.env.PYRMI_SITE_GUARD = 'off';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');
const { trusted } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { await B.fakeTurnstile(); server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let ipn = 1;
const rawCall = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', 'X-Forwarded-For': '203.0.113.' + ipn, ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, body: await r.json().catch(() => null) };
};
const call = B.wrap(rawCall);

// A project with the given thresholds, one session from a real-looking page, one beacon, then the server's verdict.
async function verdict(settings, signals, noHuman) {
  ipn++;
  const p = (await call('POST', '/api/v1/project', { name: 'tuned', origins: ['https://shop.example'] })).body.project;
  const auth = { Authorization: 'Bearer ' + p.secretKey };
  // These tests are about trusted, not the minimum time: let the action through as soon as the beacon is in.
  assert.equal((await call('PATCH', '/api/v1/project', { settings: { minDurationMs: 0, ...(settings || {}) } }, auth)).status, 200);
  const s = (await call('POST', '/api/v1/session', { site: p.publicKey }, { Origin: 'https://shop.example' })).body;
  assert.equal((await B.beacon(call, s, { pt: 1300, ...(signals || {}) })).status, 200);
  await wait(1300);
  // signed in the page and forwarded with the browser's context, the way pyrmi-server sends it (round 11)
  const client = { ua: 'test-ua', ip: '203.0.113.' + ipn, sfs: 'same-site' };
  // and with a Turnstile pass solved on the session's page for this session, which Pyrmi confirms itself (round 12)
  const turnstile = noHuman ? undefined : B.human(s, 'shop.example');
  return (await call('POST', '/api/v1/verify', { token: s.token, player: 'p1', request: B.sign(s, { player: 'p1' }), client, turnstile }, auth)).body;
}
const codes = (v) => v.reasons.map((r) => r.code);

test('reviewAt 50: a tampered runtime is an accept, but never trusted', async () => {
  const v = await verdict({ reviewAt: 50, rejectAt: 100 }, { tp: ['performance.now'] });
  assert.equal(v.verdict, 'accept', JSON.stringify(v));
  assert.equal(v.client, 'corroborated');
  assert.deepEqual(codes(v), ['tampered_runtime']);
  assert.equal(v.trusted, false);
  assert.equal(trusted(v), false);
});

test('reviewAt 80: a webdriver session is an accept, but never trusted', async () => {
  const v = await verdict({ reviewAt: 80, rejectAt: 100 }, { wd: true });
  assert.equal(v.verdict, 'accept', JSON.stringify(v));
  assert.ok(codes(v).includes('automation'));
  assert.equal(v.trusted, false);
  assert.equal(trusted(v), false);
});

test('every soft reason that means cheating keeps trusted false at any threshold', async () => {
  for (const sig of [{ ut: 3 }, { ih: 2 }, { tp: ['Date.now'] }, { au: ['puppeteer'] }]) {
    const v = await verdict({ reviewAt: 100, rejectAt: 100 }, sig);
    assert.equal(v.verdict, 'accept', JSON.stringify(sig));
    assert.equal(v.trusted, false, JSON.stringify(sig) + ' ' + JSON.stringify(codes(v)));
    assert.equal(trusted(v), false);
  }
});

test('trusted needs the browser to have seen a real key press or click (ac: true), whatever the user agent', async () => {
  const quiet = await verdict(null, { ac: null, k: 1, p: 1 });
  assert.equal(quiet.verdict, 'accept'); assert.equal(quiet.client, 'corroborated');
  assert.equal(quiet.trusted, false, 'ac: null (say, an old Safari) is not enough for trusted');
  assert.equal((await verdict(null, { ac: false, k: 1, p: 1 })).trusted, false);
});

test('default thresholds: a clean session, or one with only harmless reasons, is trusted', async () => {
  const clean = await verdict(null, {});
  assert.equal(clean.verdict, 'accept'); assert.equal(clean.trusted, true, JSON.stringify(clean)); assert.equal(trusted(clean), true);
  const sentry = await verdict(null, { wr: ['fetch', 'setTimeout'], dt: 1 });
  assert.deepEqual(codes(sentry).sort(), ['devtools_open', 'wrapped_runtime']);
  assert.equal(sentry.trusted, true); assert.equal(trusted(sentry), true);
  const tamper = await verdict(null, { tp: ['performance.now'] });
  assert.equal(tamper.verdict, 'review'); assert.equal(tamper.trusted, false);
});

test('requireHumanCheck: off (the default), a clean session with no human check is trusted; on, it is an accept, never trusted', async () => {
  const off = await verdict({}, {}, true);
  assert.equal(off.verdict, 'accept', JSON.stringify(off)); assert.equal(off.human, 'none');
  assert.equal(off.trusted, true); assert.equal(trusted(off), true);
  const on = await verdict({ requireHumanCheck: true }, {}, true);
  assert.equal(on.verdict, 'accept', JSON.stringify(on)); assert.equal(on.human, 'none');
  assert.equal(on.trusted, false); assert.equal(trusted(on), false);
  const passed = await verdict({ requireHumanCheck: true }, {});
  assert.equal(passed.human, 'ok'); assert.equal(passed.trusted, true);
});

test('pyrmi-server trusted(): needs the server\'s own true and harmless reasons, whatever shape v arrives in', () => {
  const base = { ok: true, verdict: 'accept', client: 'corroborated' };
  assert.equal(trusted({ ...base, trusted: false, reasons: [] }), false, 'the server said no');
  assert.equal(trusted({ ...base, trusted: true, reasons: [{ code: 'wrapped_runtime' }, { code: 'ip_changed' }] }), true);
  // a reshaped or cached v can't get through
  for (const t of ['true', 1, null, undefined]) assert.equal(trusted({ ...base, trusted: t, reasons: [] }), false, String(t));
  assert.equal(trusted({ ...base, trusted: true, reasons: [{ code: 'tampered_runtime' }] }), false, 'a true next to bad reasons');
  assert.equal(trusted({ ...base, trusted: true, reasons: [{ code: 'some_new_reason' }] }), false, 'unknown reasons are not trusted');
  for (const r of ['oops', {}, null, undefined]) assert.equal(trusted({ ...base, trusted: true, reasons: r }), false);
  assert.equal(trusted({ ...base, ok: undefined, trusted: true, reasons: [] }), false);
  assert.equal(trusted({ ...base, trusted: true, verdict: 'review' }), false);
  assert.equal(trusted({ ok: false, verdict: 'accept', client: 'corroborated', trusted: true, unverified: true }), false);
});
