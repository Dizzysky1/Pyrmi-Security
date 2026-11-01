'use strict';
// Second audit (A2-xx): proof-of-concept tests for the issues found, against the in-memory store.
// Each test failed on main before its fix landed.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
const test = require('node:test');
const assert = require('node:assert');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const { signals, order } = require('./_browser');

let ipn = 10;
const nextIp = () => '198.51.100.' + (ipn++);
const UA = 'audit-ua';
async function freshProject(settings) {
  const ip = nextIp();
  const p = await core.createProject({ name: 'Audit', origins: ['https://audit.example'] }, ip, 'owner-audit');
  // These tests send unsealed tokens on purpose; signed actions (the round 12 default) are covered in round11/12.
  const project = await core.updateSettings(await core.loadProject(p.pid), { requireSignedRequests: false, ...(settings || {}) });
  return { ...p, project, ip };
}
async function cleanSession(project, ip) {
  const s = await core.startSession(project, { ip, ua: UA, origin: 'https://audit.example' }, { pt: 0 });
  // a beacon as the browser script sends it, from the page that started the session (see tests/_browser.js)
  await core.recordSignals({ token: s.token, ...order(s), signals: signals() }, { ip, ua: UA, origin: 'https://audit.example', sfs: 'same-site' });
  return s;
}

// A2-01: two rotations racing (an attacker with a stolen key hammering rotate) both map a new key to the project, but
// only one is stored as the project's key, so the other is never revoked by later rotations: the stolen access
// survives the owner rotating. Only the key the project currently records may work.
test('A2-01: a key left behind by racing rotations stops working once the owner rotates', async () => {
  const { project, secretKey } = await freshProject();
  // Two rotations with the same old key race: exactly one wins, the other gets a 409 and its key is never stored.
  const raced = await Promise.allSettled([core.rotateSecret(project, secretKey), core.rotateSecret(project, secretKey)]);
  const won = raced.filter((r) => r.status === 'fulfilled').map((r) => r.value);
  const lost = raced.filter((r) => r.status === 'rejected').map((r) => r.reason);
  assert.equal(won.length, 1, JSON.stringify(raced.map((r) => r.status)));
  assert.equal(lost[0].status, 409);
  assert.ok(['rotate_in_progress', 'key_changed'].includes(lost[0].code), lost[0].code);
  assert.equal((await core.projectBySecretKey(won[0])).pid, project.pid);
  // once one rotation finished, the old key can't rotate again
  await assert.rejects(core.rotateSecret(project, secretKey), (e) => e.status === 409 && e.code === 'key_changed');
  const fresh = await core.rotateSecret(await core.loadProject(project.pid)); // the owner rotates from the account
  assert.equal(await core.projectBySecretKey(secretKey), null);
  assert.equal(await core.projectBySecretKey(won[0]), null, 'the raced key must be dead after the owner rotates');
  assert.equal((await core.projectBySecretKey(fresh)).pid, project.pid);
});

// A2-02: the "already used" marker lived for the project's CURRENT sessionTtlSec + 1h. Lower the TTL after tokens were
// issued and the marker expired long before the token did, so the same token was accepted a second time.
test('A2-02: the single-use marker outlives the token even if the session TTL is lowered later', async () => {
  const { project, ip } = await freshProject({ sessionTtlSec: 86400, minDurationMs: 0 });
  const s = await cleanSession(project, ip);
  const lowered = await core.updateSettings(project, { sessionTtlSec: 60 });
  const v = await core.verify(lowered, { token: s.token, player: 'a' }, { ip });
  assert.equal(v.verdict, 'accept');
  const ttl = Number(await kv.cmd('TTL', 'ps:used:' + s.session));
  assert.ok(ttl * 1000 >= s.expiresAt - Date.now(), 'marker TTL ' + ttl + 's must cover the token\'s remaining life');
  // and by the time the marker runs out, the token has expired too, so it is never accepted twice
  const realNow = Date.now, later = Date.now() + ttl * 1000 + 1000;
  Date.now = () => later;
  try {
    const again = await core.verify(lowered, { token: s.token, player: 'a' }, { ip });
    assert.equal(again.verdict, 'reject');
    assert.ok(again.reasons.some((r) => r.code === 'expired'), JSON.stringify(again.reasons.map((r) => r.code)));
  } finally { Date.now = realNow; }
});

// A2-03: the 2 s grace meant for clock skew on impossible_time also let a client-claimed durationMs satisfy
// minDurationMs (and dilute maxScorePerSec) on a token used the instant it was issued.
test('A2-03: a claimed duration can\'t beat minDurationMs or the per-second cap', async () => {
  const { project, ip } = await freshProject({ minDurationMs: 1500 });
  const s = await cleanSession(project, ip);
  const v = await core.verify(project, { token: s.token, durationMs: 2000, player: 'b' }, { ip });
  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'too_short'), JSON.stringify(v.reasons.map((r) => r.code)));

  const r = await freshProject({ maxScorePerSec: 10 });
  const s2 = await cleanSession(r.project, r.ip);
  await new Promise((ok) => setTimeout(ok, 1100));
  // ~1.1 s really elapsed: 25 points is ~23/s; claiming 3.1 s used to make it look like 8/s
  const v2 = await core.verify(r.project, { token: s2.token, score: 25, durationMs: 3100, player: 'b' }, { ip: r.ip });
  assert.ok(v2.reasons.some((x) => x.code === 'score_too_fast'), JSON.stringify(v2.reasons.map((x) => x.code)));
});

// A2-05: the wrong-key cap was checked before the key, so anyone sharing a network (an office, a school, mobile CGNAT,
// a serverless egress pool) could lock the real owner out of the dashboard and project API with 20 junk keys.
test('A2-05: wrong keys from a shared network can\'t lock out the right key', async () => {
  const { pid, secretKey } = await freshProject();
  const shared = nextIp();
  for (let i = 0; i < 25; i++) await core.projectForKey('sk_' + 'x'.repeat(30) + i, shared).catch(() => {});
  assert.equal((await core.projectForKey(secretKey, shared)).pid, pid);
  await assert.rejects(core.projectForKey('sk_' + 'y'.repeat(30), shared), (e) => e.status === 429, 'wrong keys stay capped');
});

// A2-07: OAuth state cookies and session tokens are signed with the same key and format. Anyone can get a signed
// state token (just start a sign-in), so it must never pass as a session token.
test('A2-07: a signed token of another kind is not a session token', async () => {
  const other = await C.signToken({ p: 'github', s: 'state', v: 'verifier-verifier', e: Date.now() + 600e3 });
  await assert.rejects(core.recordSignals({ token: other, signals: {} }, { ip: nextIp(), ua: UA }), (e) => e.code === 'invalid_token');
  const { project, ip } = await freshProject();
  const forged = await C.signToken({ p: project.pid, s: 'x', v: 'oauth', i: Date.now() - 5000, e: Date.now() + 600e3 });
  const v = await core.verify(project, { token: forged, player: 'c' }, { ip });
  assert.ok(v.reasons.some((r) => r.code === 'invalid_token'));
});
