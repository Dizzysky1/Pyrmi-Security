'use strict';
// Regression tests for backend security audit round 2 (High #1/#2, Medium #1/#3-#10/#13, Low hardening).
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const tls = require('tls');

const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const accounts = require('../api/_lib/accounts');
const smtp = require('../api/_lib/smtp');
const { readJson, cors } = require('../api/_lib/http');
const { serve } = require('../scripts/dev.js');
const SDK = require('../api/_lib/sdk-build.json');
const B = require('./_browser');

let base, server;
test.before(async () => {
  await B.fakeTurnstile();
  server = http.createServer(serve);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(() => server.close());

let ipSeq = 1;
const nextIp = () => '198.18.' + Math.floor(ipSeq / 250) + '.' + ((ipSeq++ % 250) + 1);

const withEnv = async (vars, fn) => {
  const saved = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
};

// ---- 1. High #1: Beacon Nonce (bn) & Sequence (n) Check Bypass ----

test('1. High #1: recordSignals refuses missing/wrong bn before first beacon, including n without bn', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0', CH = '"Chromium";v="156"', O = 'https://bn.example';
  const p = await core.createProject({ name: 'BnStrict', origins: [O], settings: { minDurationMs: 0, maxScore: 100 } }, ip, 'u_bn');
  const project = await core.loadProject(p.pid);
  const s = await core.startSession(project, { ip, ua: UA, ch: CH, origin: O }, { pt: 100 });
  const ctx = { ip, ua: UA, origin: O, sfs: 'same-origin' };

  // n without bn BEFORE victim's first beacon -> 409 wrong_session
  await assert.rejects(
    core.recordSignals({ token: s.token, n: 1, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  // Omitting both bn and n with current/missing/edited sh -> 409 wrong_session
  await assert.rejects(
    core.recordSignals({ token: s.token, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  await assert.rejects(
    core.recordSignals({ token: s.token, signals: { wd: true } }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  // Non-string bn (ToPrimitive hazard) -> 409 wrong_session, not 500
  await assert.rejects(
    core.recordSignals({ token: s.token, bn: { toString: 1, valueOf: 1 }, n: 1, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );

  // Even previous build inside grace period CANNOT supply n without bn
  const prev = SDK.previous[SDK.previous.length - 1];
  const savedRetired = { ...(SDK.retired || {}) };
  SDK.retired = { ...savedRetired, [prev]: Date.now() - 1000 };
  try {
    await assert.rejects(
      core.recordSignals({ token: s.token, n: 1, signals: B.signals({ pt: 100, sh: prev, wd: true }) }, ctx),
      (e) => e.status === 409 && e.code === 'wrong_session'
    );
  } finally {
    SDK.retired = savedRetired;
  }

  // Victim session is completely untouched and still verifies clean & trusted
  assert.equal(await kv.cmd('HGET', 'ps:s:' + s.session, 'sig'), null);
  assert.equal(await kv.cmd('HGET', 'ps:s:' + s.session, 'n'), null);
  assert.equal((await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 100, k: 2, p: 3 }) }, ctx)).ok, true);
  const v = await core.verify(project, {
    token: s.token, score: 10,
    request: B.sign(s, { score: 10 }),
    client: { ua: UA, ip, ch: CH, sfs: 'same-origin' },
  }, { ip });
  assert.equal(v.verdict, 'accept');
  assert.equal(v.client, 'corroborated');
  assert.equal(v.trusted, true);
});

// ---- 2. High #2: Atomic Lua kv.hit / kv.hitCmd & Strict EVAL Allowlist ----

test('2. High #2: kv.hit sets/preserves TTL atomically, repairs TTL -1, and pipeline blocks arbitrary EVAL', async () => {
  await assert.rejects(kv.pipeline([['EVAL', 'return 1', 0]]), /own key prefixing/);
  assert.throws(() => kv._mem.run(['EVAL', 'return 1', '0']), /unsupported EVAL/);

  const k = 'ps:test:hit:' + Date.now();
  assert.equal(await kv.hit(k, 60), 1);
  const ttl1 = Number(await kv.cmd('TTL', k));
  assert.ok(ttl1 > 0 && ttl1 <= 60);

  // Subsequent hit increments without resetting TTL
  assert.equal(await kv.hit(k, 60), 2);
  // Key with missing expiry (TTL -1) gets repaired atomically
  const kNoTtl = 'ps:test:nottl:' + Date.now();
  await kv.cmd('SET', kNoTtl, '5');
  assert.equal(await kv.cmd('TTL', kNoTtl), -1);
  assert.equal(await kv.hit(kNoTtl, 120), 6);
  const repaired = Number(await kv.cmd('TTL', kNoTtl));
  assert.ok(repaired > 0 && repaired <= 120, 'TTL -1 repaired to ' + repaired);

  // Prefixing on internal EVAL commands
  await withEnv({ PYRMI_KV_PREFIX: 'custompre:' }, async () => {
    const pk = 'ps:test:pre:' + Date.now();
    assert.equal(await kv.hit(pk, 60), 1);
    assert.equal(kv._mem.get('custompre:' + pk), '1');
    assert.equal(kv._mem.get(pk), undefined);
  });
});

// ---- 3. Medium #1: Block Runtime sk_ From Mutating/Rotating Account-Owned Projects ----

test('3. Medium #1: /api/v1/project blocks PATCH and rotate with sk_ for account-owned projects (including mid-lock claim race)', async () => {
  const p = await accounts.createSite('u_own_m1_' + Date.now(), { name: 'OwnedSite', origins: ['https://own.example'] }, nextIp());
  const auth = { Authorization: 'Bearer ' + p.secretKey, 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp() };

  // GET stays allowed
  const g = await fetch(base + '/api/v1/project', { headers: auth });
  assert.equal(g.status, 200);

  // PATCH and rotate are blocked with 403 owned
  const pat = await fetch(base + '/api/v1/project', { method: 'PATCH', headers: auth, body: JSON.stringify({ name: 'Hijacked', settings: { minDurationMs: 0 } }) });
  assert.equal(pat.status, 403);
  assert.equal((await pat.json()).error, 'owned');

  const rot = await fetch(base + '/api/v1/project?action=rotate', { method: 'POST', headers: auth, body: '{}' });
  assert.equal(rot.status, 403);
  assert.equal((await rot.json()).error, 'owned');

  // Unowned project stays mutable via sk_, unless claimed right before withKeyLock re-check
  const anon = await core.createProject({ name: 'AnonRace', origins: ['https://anon.example'] }, nextIp());
  const origWithLock = core.withKeyLock;
  let injected = false;
  core.withKeyLock = async (pid, fn) => {
    if (!injected && pid === anon.pid) {
      injected = true;
      await kv.cmd('HSET', 'ps:p:' + anon.pid, 'owner', 'u_racer_claim');
    }
    return origWithLock(pid, fn);
  };
  try {
    const racedPatch = await fetch(base + '/api/v1/project', {
      method: 'PATCH',
      headers: { Authorization: 'Bearer ' + anon.secretKey, 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp() },
      body: JSON.stringify({ name: 'Sneak' }),
    });
    assert.equal(racedPatch.status, 403);
    assert.equal((await racedPatch.json()).error, 'owned');
  } finally {
    core.withKeyLock = origWithLock;
  }
});

// ---- 4. Medium #3: Atomic withKeyLock Lua Compare-and-Delete & 30s TTL ----

test('4. Medium #3: withKeyLock uses 30s TTL and atomic compare-and-delete unlock', async () => {
  const pid = 'p_lock_' + Date.now();
  let seenTtl = 0;
  await core.withKeyLock(pid, async () => {
    seenTtl = Number(await kv.cmd('TTL', 'ps:rot:' + pid));
    // Simulate another holder replacing the lock token (e.g. after stall/takeover)
    await kv.cmd('SET', 'ps:rot:' + pid, 'other-holder-token', 'EX', 30);
  });
  assert.ok(seenTtl > 20 && seenTtl <= 30, 'lock TTL should be ~30s, got ' + seenTtl);
  // Original holder's unlock must NOT delete the other holder's lock!
  assert.equal(await kv.cmd('GET', 'ps:rot:' + pid), 'other-holder-token');
  assert.equal(await kv.unlock('ps:rot:' + pid, 'wrong-token'), 0);
  assert.equal(await kv.unlock('ps:rot:' + pid, 'other-holder-token'), 1);
  assert.equal(await kv.cmd('GET', 'ps:rot:' + pid), null);
});

// ---- 5. Medium #4: Atomic recordSignals() Merge in Redis ----

test('5. Medium #4: concurrent recordSignals merges flags atomically, keeps HSETNX f/g, and rejects stale/regressed races', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0', O = 'https://atomic.example';
  const p = await core.createProject({ name: 'AtomicSig', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_atom');
  const project = await core.loadProject(p.pid);
  const s = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 100 });
  const ctx = { ip, ua: UA, origin: O, sfs: 'same-origin' };

  // Intercept round-trip 2 of beacon 1 so beacon 1 and beacon 2 both read the same initial empty session,
  // then beacon 1 commits followed by beacon 2 (simulating concurrent in-flight requests).
  const origPipeline = kv.pipeline;
  let holdB1, releaseB1;
  const b1Waiting = new Promise((r) => { holdB1 = r; });
  const b1Go = new Promise((r) => { releaseB1 = r; });
  let evalCount = 0;
  kv.pipeline = async (cmds) => {
    if (cmds.length === 1 && cmds[0][0] === 'EVAL' && cmds[0][3] === 'ps:s:' + s.session) {
      evalCount++;
      if (evalCount === 1) {
        holdB1();
        await b1Go;
      }
    }
    return origPipeline.call(kv, cmds);
  };

  try {
    // Beacon 1 carries n=2 (hl: true, k: 10, gt: 20) and pauses before its atomic Lua write
    const p1 = core.recordSignals({ token: s.token, bn: s.bn, n: 2, signals: B.signals({ pt: 150, hl: true, k: 10, gt: 20 }) }, ctx);
    await b1Waiting;
    // Beacon 2 carries n=1 (wd: true, k: 5, gt: 10) and commits FIRST
    const r2 = await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 120, wd: true, k: 5, gt: 10 }) }, ctx);
    assert.deepEqual(r2, { ok: true });
    releaseB1();
    const r1 = await p1;
    assert.deepEqual(r1, { ok: true });
  } finally {
    kv.pipeline = origPipeline;
  }

  const h = kv.pairs(await kv.cmd('HGETALL', 'ps:s:' + s.session));
  const sig = JSON.parse(h.sig);
  assert.equal(h.b, '2');
  assert.equal(h.n, '2');
  assert.equal(sig.wd, true, 'sticky wd from beacon 1 preserved despite concurrent merge');
  assert.equal(sig.hl, true, 'sticky hl from beacon 2 merged');
  assert.equal(JSON.parse(h.f).gt, 10, 'HSETNX preserved first mark f');
  assert.equal(JSON.parse(h.g).gt, 10, 'HSETNX preserved first game-time mark g');
  assert.equal(JSON.parse(h.l).gt, 20, 'last mark moved to n=2');

  // If n=3 lands before a concurrent n=2, the stale one is dropped atomically inside Lua
  const r3 = await core.recordSignals({ token: s.token, bn: s.bn, n: 3, signals: B.signals({ pt: 200, k: 2 }) }, ctx);
  assert.deepEqual(r3, { ok: true });
  const sigAfter = JSON.parse(await kv.cmd('HGET', 'ps:s:' + s.session, 'sig'));
  assert.ok(sigAfter.uv.includes('counters'), 'counter regression caught');
});

// ---- 6. Medium #5: /verify Limiter Keyed on /64 Network t.nh & network(ip) in recordSignals/guardSite ----

test('6. Medium #5: session token embeds nh, /verify rate-limits by IPv6 /64, and recordSignals uses network(ip)', async () => {
  const O = 'https://ipv6.example', UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: 'IPv6', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, nextIp(), 'u_v6');
  const project = await core.loadProject(p.pid);

  const v6a = '2001:db8:cafe:1::1';
  const v6b = '2001:db8:cafe:1::dead:beef'; // same /64
  const v6c = '2001:db8:cafe:2::1'; // different /64

  const s = await core.startSession(project, { ip: v6a, ua: UA, origin: O }, { pt: 0 });
  const tok = await C.readToken(s.token);
  assert.equal(tok.nh, await C.fingerprint('ip', core.network(v6a)), 'token embeds /64 network fingerprint nh');

  // Beacon from same /64 does NOT set ipc; beacon from different /64 DOES
  await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 0 }) }, { ip: v6b, ua: UA, origin: O, sfs: 'same-origin' });
  assert.equal(JSON.parse(await kv.cmd('HGET', 'ps:s:' + s.session, 'sig')).ipc, false, 'same /64 does not flag ip_changed');
  await core.recordSignals({ token: s.token, bn: s.bn, n: 2, signals: B.signals({ pt: 10 }) }, { ip: v6c, ua: UA, origin: O, sfs: 'same-origin' });
  assert.equal(JSON.parse(await kv.cmd('HGET', 'ps:s:' + s.session, 'sig')).ipc, true, 'different /64 flags ip_changed');

  // /verify rate limit groups distinct IPv6 addresses in the same /64
  await withEnv({ PYRMI_VERIFIES_PER_MIN: '2' }, async () => {
    const s1 = await core.startSession(project, { ip: '2001:db8:beef:1::1', ua: UA, origin: O }, { pt: 0 });
    const s2 = await core.startSession(project, { ip: '2001:db8:beef:1::2', ua: UA, origin: O }, { pt: 0 });
    const s3 = await core.startSession(project, { ip: '2001:db8:beef:1::3', ua: UA, origin: O }, { pt: 0 });
    const sOther = await core.startSession(project, { ip: '2001:db8:beef:2::1', ua: UA, origin: O }, { pt: 0 });

    const v1 = await core.verify(project, { token: s1.token }, { ip: nextIp() });
    const v2 = await core.verify(project, { token: s2.token }, { ip: nextIp() });
    const v3 = await core.verify(project, { token: s3.token }, { ip: nextIp() });
    const vOther = await core.verify(project, { token: sOther.token }, { ip: nextIp() });

    assert.ok(!v1.reasons.some((r) => r.code === 'rate_limited'));
    assert.ok(!v2.reasons.some((r) => r.code === 'rate_limited'));
    assert.ok(v3.reasons.some((r) => r.code === 'rate_limited'), '3rd verify from same /64 is rate-limited');
    assert.ok(!vOther.reasons.some((r) => r.code === 'rate_limited'), 'different /64 is unaffected');
  });
});

// ---- 7. Medium #6: relayed() bound Flag & Strict Sec-Fetch-Site ----

test('7. Medium #6: relayed() requires !why && !!sess.uh && !!sess.nh for bound and validates Sec-Fetch-Site', async () => {
  const UA = 'Mozilla/5.0 Chrome/156.0';
  const uh = await C.fingerprint('ua', UA);
  const nh = await C.fingerprint('ip', '192.0.2.10');

  // Missing sess.nh or sess.uh -> bound: false
  assert.equal((await core.relayed({ ua: UA, ip: '192.0.2.10', sfs: 'same-origin' }, { uh }, UA)).bound, false);
  assert.equal((await core.relayed({ ua: UA, ip: '192.0.2.10', sfs: 'same-origin' }, { nh }, UA)).bound, false);

  // Mismatched UA -> why non-empty -> bound: false
  const diffUa = await core.relayed({ ua: 'curl/8.0', ip: '192.0.2.10', sfs: 'same-origin' }, { uh, nh }, 'curl/8.0');
  assert.equal(diffUa.bound, false);
  assert.match(diffUa.detail, /different browser/);

  // Invalid Sec-Fetch-Site -> rejected with invalid fetch metadata & bound: false
  for (const badSfs of ['bogus', 'same-origin ', 'SAME-ORIGIN', 123, { toString: 1 }]) {
    const r = await core.relayed({ ua: UA, ip: '192.0.2.10', sfs: badSfs }, { uh, nh }, UA);
    assert.equal(r.bound, false, 'bad sfs ' + JSON.stringify(badSfs));
    assert.match(r.detail, /invalid fetch metadata/, 'bad sfs ' + JSON.stringify(badSfs));
  }

  // All 4 standard Sec-Fetch-Site values are accepted
  for (const okSfs of ['same-origin', 'same-site', 'cross-site', 'none']) {
    const r = await core.relayed({ ua: UA, ip: '192.0.2.10', sfs: okSfs }, { uh, nh }, UA);
    assert.equal(r.bound, true, okSfs);
    assert.equal(r.detail, '', okSfs);
  }
});

// ---- 8. Medium #7: Double-Negative Slice Bug in kv._mem ----

test('8. Medium #7: kv._mem ZREMRANGEBYRANK/ZRANGE/ZREVRANGE/LTRIM/LRANGE handle negative out-of-bounds end cleanly', async () => {
  const zk = 'ps:test:zslice:' + Date.now();
  await kv.cmd('ZADD', zk, 1, 'a', 2, 'b', 3, 'c', 4, 'd', 5, 'e');
  // Previously end = 5 + (-7) = -2 -> end + 1 = -1 -> slice(0, -1) deleted 4 of 5 elements!
  assert.equal(await kv.cmd('ZREMRANGEBYRANK', zk, 0, -7), 0);
  assert.equal(await kv.cmd('ZCARD', zk), 5);
  assert.deepEqual(await kv.cmd('ZRANGE', zk, 0, -7), []);
  assert.deepEqual(await kv.cmd('ZREVRANGE', zk, 0, -7), []);
  assert.equal(await kv.cmd('ZREMRANGEBYRANK', zk, 0, -1001), 0);
  assert.equal(await kv.cmd('ZCARD', zk), 5);
  // Deleting bottom 2 when keeping top 3 (0..-4 on 5 items -> indices 0..1)
  assert.equal(await kv.cmd('ZREMRANGEBYRANK', zk, 0, -4), 2);
  assert.deepEqual(await kv.cmd('ZRANGE', zk, 0, -1), ['c', 'd', 'e']);

  const lk = 'ps:test:lslice:' + Date.now();
  await kv.cmd('LPUSH', lk, '1', '2', '3', '4', '5');
  assert.deepEqual(await kv.cmd('LRANGE', lk, 0, -7), []);
  assert.deepEqual(await kv.cmd('LRANGE', lk, -10, -8), []);
  assert.deepEqual(await kv.cmd('LRANGE', lk, -10, 1), ['5', '4']);
  await kv.cmd('LTRIM', lk, 0, -7);
  assert.deepEqual(await kv.cmd('LRANGE', lk, 0, -1), []);
});

// ---- 9. Medium #8: ToPrimitive & Pre-Parsed Primitive Crash Guards ----

test('9. Medium #8: {toString:1,valueOf:1} objects and pre-parsed primitives never cause 500 crashes', async () => {
  const poison = { toString: 1, valueOf: 1 };

  // readJson pre-parsed primitives
  for (const prim of [123, true, false, [1, 2, 3], null]) {
    assert.deepEqual(await readJson({ headers: {}, body: prim }, 1024), {}, 'readJson ' + JSON.stringify(prim));
  }

  const ip = nextIp(), O = 'https://prim.example', UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: poison, origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_prim');
  assert.equal(p.name, 'Untitled project');
  const project = await core.loadProject(p.pid);

  // Bad setting / bad origin with poison object -> 400, not 500
  await assert.rejects(core.updateSettings(project, { maxScore: poison }), (e) => e.status === 400 && e.code === 'bad_setting');
  await assert.rejects(core.updateSettings(project, { origins: poison }), (e) => e.status === 400 && e.code === 'bad_origin');
  await assert.rejects(core.updateSettings(project, { origins: [poison] }), (e) => e.status === 400 && e.code === 'bad_origin');

  // startSession with poison pt -> succeeds with empty pt0
  const s = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: poison });
  assert.equal(await kv.cmd('HGET', 'ps:s:' + s.session, 'pt0'), '');

  // recordSignals with poison n & poison signal fields -> no 500
  const dropped = await core.recordSignals({ token: s.token, bn: s.bn, n: poison, signals: B.signals({ pt: poison, k: poison, au: [poison] }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
  assert.equal(dropped.dropped, 'stale');
  const okSig = await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: poison, k: poison, au: [poison] }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
  assert.equal(okSig.ok, true);

  // verify with poison score, durationMs, player, request, replay, client -> returns verdict, not 500
  const v = await core.verify(project, {
    token: s.token,
    score: poison,
    durationMs: poison,
    player: poison,
    request: { fields: {}, ts: poison, sig: poison },
    replay: { check: 'mismatch', detail: poison },
    client: { ua: poison, ip: poison, ch: poison, sfs: poison },
    turnstile: { token: 't', secret: 's', action: poison },
  }, { ip });
  assert.equal(v.ok, true);
  assert.equal(v.verdict, 'reject');
  assert.ok(v.reasons.some((r) => r.code === 'bad_score'));
  assert.ok(v.reasons.some((r) => r.code === 'bad_signature'));
});

// ---- 10. Medium #9: Skip logVerdict() on Rate-Limited Verifies ----

test('10. Medium #9: rate-limited verifies skip logVerdict completely even for genuine sessions', async () => {
  const ip = nextIp(), O = 'https://rlskip.example', UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: 'RLSkip', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_rls');
  const project = await core.loadProject(p.pid);

  await withEnv({ PYRMI_VERIFIES_PER_MIN: '1' }, async () => {
    const s1 = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s1.token, bn: s1.bn, n: 1, signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
    assert.equal((await core.verify(project, { token: s1.token, player: 'alice' }, { ip })).verdict, 'accept');

    const day = core.ymd(Date.now());
    const statBefore = kv.pairs(await kv.cmd('HGETALL', 'ps:st:' + p.pid + ':' + day));

    // Genuine unused session s2 hits rate_limited -> stats, events, and player records MUST NOT change; ps:used released
    const s2 = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s2.token, bn: s2.bn, n: 1, signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
    const v2 = await core.verify(project, { token: s2.token, player: 'bob_rl' }, { ip });
    assert.ok(v2.reasons.some((r) => r.code === 'rate_limited'));
    assert.equal(await kv.cmd('GET', 'ps:used:' + s2.session), null, 'unused token released');

    const statAfter = kv.pairs(await kv.cmd('HGETALL', 'ps:st:' + p.pid + ':' + day));
    assert.equal(statAfter.reject || '0', statBefore.reject || '0', 'daily reject stat untouched');
    assert.equal(statAfter['r:rate_limited'], undefined, 'rate_limited reason stat untouched');
    assert.equal(await kv.cmd('EXISTS', 'ps:pl:' + p.pid + ':bob_rl'), 0, 'player detail hash not created');
    assert.equal(await kv.cmd('ZSCORE', 'ps:plr:' + p.pid, 'bob_rl'), null, 'player not added to recent index');
    assert.equal(await kv.cmd('ZSCORE', 'ps:plf:' + p.pid, 'bob_rl'), null, 'player not added to flagged index');
  });
});

// ---- 11. Medium #10: Email Enumeration Oracle Past Cap ----

test('11. Medium #10: emailVerify returns identical bad_code for missing, wrong, and over-tries codes', async () => {
  await withEnv({ RESEND_API_KEY: 're_test' }, async () => {
    const email = 'no-oracle@example.com', rid = C.randomId(16);
    let code = '';
    await accounts.emailStart({ email }, nextIp(), async (m) => { code = /(\d{6})/.exec(m.subject)[1]; }, { rid });
    const bad = code === '111111' ? '222222' : '111111';

    let missingErr;
    await accounts.emailVerify({ email: 'never-asked@example.com', code: bad }, nextIp(), { rid }).catch((e) => { missingErr = e; });
    assert.equal(missingErr.status, 400);
    assert.equal(missingErr.code, 'bad_code');

    // Exceed CODE_TRIES (5) + 1 more try -> still exact same bad_code status/code/message!
    for (let i = 0; i < 6; i++) {
      let err;
      await accounts.emailVerify({ email, code: bad }, nextIp(), { rid }).catch((e) => { err = e; });
      assert.equal(err.status, missingErr.status);
      assert.equal(err.code, missingErr.code);
      assert.equal(err.message, missingErr.message);
    }
  });
});

// ---- 12. Medium #13 & Low Hardening ----

test('12a. inProduction checks NODE_ENV, and PYRMI_PUBLIC_URL strictly pins siteAllowedOrigins & checkCsrf', async () => {
  await withEnv({ VERCEL_ENV: undefined, PYRMI_ENV: undefined, NODE_ENV: 'production', PYRMI_PUBLIC_URL: 'https://pyrmi.com' }, async () => {
    assert.equal(core.inProduction(), true);
    assert.deepEqual(core.siteAllowedOrigins('spoofed.example'), ['https://pyrmi.com']);
    // checkCsrf refuses raw Host header when PYRMI_PUBLIC_URL is set
    assert.throws(
      () => accounts.checkCsrf({ method: 'POST', headers: { 'x-pyrmi-csrf': '1', host: 'spoofed.example', origin: 'https://spoofed.example' } }),
      (e) => e.status === 403 && e.code === 'csrf'
    );
    // And accepts the pinned PYRMI_PUBLIC_URL origin
    accounts.checkCsrf({ method: 'POST', headers: { 'x-pyrmi-csrf': '1', host: 'spoofed.example', origin: 'https://pyrmi.com' } });
  });
});

test('12b. revokeAllSessions bumps per-user rev epoch (closing signIn race) and device marks expire in 90 days', async () => {
  await withEnv({ RESEND_API_KEY: 're_test' }, async () => {
    const email = 'rev-race@example.com', rid = C.randomId(16);
    let code = '';
    await accounts.emailStart({ email }, nextIp(), async (m) => { code = /(\d{6})/.exec(m.subject)[1]; }, { rid });

    // Intercept signIn's SET ps:auth:... to fire revokeAllSessions concurrently mid-signIn!
    const origCmd = kv.cmd;
    let raced = false;
    let uidSeen = null;
    kv.cmd = async (...args) => {
      if (!raced && args[0] === 'SET' && String(args[1]).startsWith('ps:auth:')) {
        raced = true;
        uidSeen = String(args[2]).split(':')[0];
        await origCmd.call(kv, 'HINCRBY', 'ps:u:' + uidSeen, 'rev', 1);
      }
      return origCmd.call(kv, ...args);
    };
    let signRes;
    try {
      signRes = await accounts.emailVerify({ email, code }, nextIp(), { rid });
    } finally {
      kv.cmd = origCmd;
    }
    assert.equal(raced, true);
    const sidCookie = signRes.setCookies.find((c) => c.startsWith(accounts.SESSION_COOKIE + '=')).split(';')[0];
    // Even though signIn finished writing ps:auth + ZADD after rev bumped, currentUser MUST reject it!
    assert.equal(await accounts.currentUser({ headers: { cookie: sidCookie } }), null, 'raced sign-in invalidated by rev epoch');

    // A fresh sign-in AFTER revokeAllSessions works immediately (even within the same millisecond)
    const rid2 = C.randomId(16);
    await accounts.emailStart({ email }, nextIp(), async (m) => { code = /(\d{6})/.exec(m.subject)[1]; }, { rid: rid2 });
    const fresh = await accounts.emailVerify({ email, code }, nextIp(), { rid: rid2 });
    const freshCookie = fresh.setCookies.find((c) => c.startsWith(accounts.SESSION_COOKIE + '=')).split(';')[0];
    assert.equal((await accounts.currentUser({ headers: { cookie: freshCookie } })).email, email);

    // Device mark has 90-day Max-Age and 3-part id.exp.mac format
    const devHeader = fresh.setCookies.find((c) => c.startsWith(accounts.DEV_COOKIE + '='));
    assert.match(devHeader, /Max-Age=7776000\b/, '90-day Max-Age on __Host-pyrmi_dev');
    const devVal = decodeURIComponent(devHeader.split(';')[0].split('=')[1]);
    const parts = devVal.split('.');
    assert.equal(parts.length, 3, 'device mark format is id.exp.mac');
    const exp = Number(parts[1]);
    const nowSec = Math.floor(Date.now() / 1000);
    assert.ok(exp > nowSec + 89 * 86400 && exp <= nowSec + 90 * 86400 + 5);

    // An expired device mark does NOT bypass the address hourly cap
    await withEnv({ PYRMI_EMAIL_CODES_PER_ADDRESS_TOTAL: '1' }, async () => {
      const target = 'devexp@example.com';
      await accounts.emailStart({ email: target }, nextIp(), async () => {}, { rid: C.randomId(16) });
      // Forge an expired device mark with valid HMAC using Date.now override
      const realNow = Date.now;
      let expiredMark;
      try {
        Date.now = () => realNow() - 91 * 86400 * 1000;
        const rExp = C.randomId(16);
        let cExp = '';
        await accounts.emailStart({ email: 'devexp2@example.com' }, nextIp(), async (m) => { cExp = /(\d{6})/.exec(m.subject)[1]; }, { rid: rExp });
        const vExp = await accounts.emailVerify({ email: 'devexp2@example.com', code: cExp }, nextIp(), { rid: rExp });
        expiredMark = decodeURIComponent(vExp.setCookies.find((c) => c.startsWith(accounts.DEV_COOKIE + '=')).split(';')[0].split('=')[1]);
      } finally {
        Date.now = realNow;
      }
      await accounts.emailStart({ email: 'devexp2@example.com' }, nextIp(), async () => {}, { rid: C.randomId(16) });
      await assert.rejects(
        accounts.emailStart({ email: 'devexp2@example.com' }, nextIp(), async () => {}, { rid: C.randomId(16), device: expiredMark }),
        (e) => e.status === 429,
        'expired device mark must not bypass cap'
      );
    });
  });
});

test('12c. BEACON_SHAPE rejects negative/fractional counters, and crypto domain-separates OAuth vs session tokens', async () => {
  const ip = nextIp(), O = 'https://shape.example', UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: 'IntShape', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_sh');
  const project = await core.loadProject(p.pid);

  for (const bad of [{ k: -1 }, { p: 1.5 }, { dt: -2 }, { ut: 0.25 }]) {
    const s = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 0, ...bad }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
    const v = await core.verify(project, { token: s.token }, { ip });
    assert.equal(v.client, 'unverified', JSON.stringify(bad));
    assert.match((v.reasons.find((r) => r.code === 'unverified_client') || {}).detail || '', /shape/, JSON.stringify(bad));
  }

  // Cryptographic HMAC domain separation
  const oauthTok = await C.signToken({ p: 'github', s: 'st', v: 'ver', e: Date.now() + 60e3 }, 'oauth');
  assert.equal(await C.readToken(oauthTok), null, 'OAuth token fails default session HMAC domain');
  assert.equal((await C.readToken(oauthTok, 'oauth')).p, 'github');
  const sessTok = await C.signToken({ v: 1, p: 'p1', s: 's1', i: 1, e: 2 });
  assert.equal(await C.readToken(sessTok, 'oauth'), null, 'Session token fails OAuth HMAC domain');
  assert.equal((await C.readToken(sessTok)).p, 'p1');
});

test('12d. smtp accepts textless RFC 5321 replies, caps reply queue, handles STARTTLS close, and omits SNI for IP hosts', async () => {
  // 1. Textless replies (220\r\n, 250\r\n, 235\r\n, 354\r\n, 221\r\n)
  const textlessSrv = net.createServer((sock) => {
    let buf = '', inData = false;
    sock.write('220\r\n');
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (inData) { if (line === '.') { inData = false; sock.write('250\r\n'); } continue; }
        if (/^EHLO/.test(line)) sock.write('250-ok\r\n250\r\n');
        else if (/^AUTH/.test(line)) sock.write('235\r\n');
        else if (/^(MAIL|RCPT)/.test(line)) sock.write('250\r\n');
        else if (line === 'DATA') { inData = true; sock.write('354\r\n'); }
        else if (line === 'QUIT') { sock.write('221\r\n'); sock.end(); }
      }
    });
  });
  await new Promise((r) => textlessSrv.listen(0, '127.0.0.1', r));
  try {
    await smtp.send({ to: 'a@example.com', subject: 'hi', text: 'ok' }, { host: '127.0.0.1', port: textlessSrv.address().port, user: 'u', pass: 'p' });
  } finally { textlessSrv.close(); }

  // 2. Reply queue cap (> 100 unsolicited replies) aborts cleanly
  const queueFlood = net.createServer((sock) => {
    let burst = '';
    for (let i = 0; i < 110; i++) burst += '220 ok\r\n';
    sock.write(burst);
  });
  await new Promise((r) => queueFlood.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(
      smtp.send({ to: 'a@example.com', subject: 'hi', text: 'ok' }, { host: '127.0.0.1', port: queueFlood.address().port, user: 'u', pass: 'p' }),
      /smtp_too_many_replies/
    );
  } finally { queueFlood.close(); }

  // 3. STARTTLS close aborts immediately without hanging for timeoutMs, and omits SNI for IP literal
  const tlsCloseSrv = net.createServer((sock) => {
    let buf = '';
    sock.write('220 hi\r\n');
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (/^EHLO/.test(line)) sock.write('250-hi\r\n250 STARTTLS\r\n');
        else if (line === 'STARTTLS') { sock.write('220 go\r\n'); sock.end(); }
      }
    });
  });
  await new Promise((r) => tlsCloseSrv.listen(0, '127.0.0.1', r));
  const origTlsConnect = tls.connect;
  let seenTlsOpts = null;
  tls.connect = (opts, ...rest) => { seenTlsOpts = opts; return origTlsConnect.call(tls, opts, ...rest); };
  const t0 = Date.now();
  try {
    await assert.rejects(
      smtp.send({ to: 'a@example.com', subject: 'hi', text: 'ok' }, { host: '127.0.0.1', port: tlsCloseSrv.address().port, user: 'u', pass: 'p', timeoutMs: 5000 })
    );
  } finally {
    tls.connect = origTlsConnect;
    tlsCloseSrv.close();
  }
  assert.ok(Date.now() - t0 < 2000, 'STARTTLS close failed fast instead of timing out');
  assert.equal('servername' in seenTlsOpts, false, 'SNI servername omitted for IP literal host');
});

test('12e. /api/v1/sites checks CSRF before Redis lookups, and http.cors rejects malformed Origins', async () => {
  let kvCalls = 0;
  const origPipeline = kv.pipeline;
  kv.pipeline = async (cmds) => { kvCalls++; return origPipeline.call(kv, cmds); };
  try {
    const r = await fetch(base + '/api/v1/sites', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: accounts.SESSION_COOKIE + '=' + 'A'.repeat(43),
        'X-Forwarded-For': nextIp(),
      },
      body: JSON.stringify({ name: 'NoCsrf', origins: ['https://x.example'] }),
    });
    assert.equal(r.status, 403);
    assert.equal((await r.json()).error, 'csrf');
    assert.equal(kvCalls, 0, 'CSRF rejection on /sites performs zero KV lookups');
  } finally {
    kv.pipeline = origPipeline;
  }

  // http.cors rejects non-http(s), paths, and CR/LF origins
  const runCors = (origin) => {
    const hdrs = {};
    const ok = cors({ headers: { origin } }, { setHeader: (k, v) => { hdrs[k] = v; } }, null);
    return { ok, acao: hdrs['Access-Control-Allow-Origin'] || null };
  };
  for (const bad of ['javascript:alert(1)', 'file:///etc/passwd', 'https://a.example/path', 'https://a.example\r\nX-Inject: 1', 'not a url']) {
    const r = runCors(bad);
    assert.equal(r.ok, false, bad);
    assert.equal(r.acao, null, bad);
  }
  const good = runCors('https://good.example:8443');
  assert.equal(good.ok, true);
  assert.equal(good.acao, 'https://good.example:8443');
});
