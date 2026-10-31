'use strict';
// Unit tests for the storage-backed core helpers, against the in-memory store.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const kv = require('../api/_lib/kv');
const core = require('../api/_lib/core');

// F-09: deleting a project must free the capacity slot it took, or delete+create would exhaust PYRMI_MAX_PROJECTS.
test('deleting a project decrements the capacity counter', async () => {
  const before = Number((await kv.cmd('GET', 'ps:projects')) || 0);
  const p = await core.createProject({ name: 'Temp', origins: ['https://t.example'] }, '198.51.100.21', 'owner-x');
  assert.equal(Number(await kv.cmd('GET', 'ps:projects')), before + 1);
  await core.deleteProject(await core.loadProject(p.pid));
  assert.equal(Number(await kv.cmd('GET', 'ps:projects')), before, 'count should return to where it started');
});

// F-05: a limiter must expire on its own. The old bump() re-set the TTL on every call, so repeated requests kept the
// key alive forever and an address could be locked out permanently. The TTL must be set once and then count down.
test('a rate-limit window keeps counting down instead of being reset on every hit', async () => {
  const ip = '203.0.113.55';
  const C = require('../api/_lib/crypto');
  const key = 'ps:rl:ttltest:' + await C.fingerprint('ip', ip);
  await core.limitIp(ip, 'ttltest', 100, 'PYRMI_NOPE', 1000);
  const ttl1 = Number(await kv.cmd('TTL', key));
  assert.ok(ttl1 > 0 && ttl1 <= 100, 'TTL should be set on first hit: ' + ttl1);
  await new Promise((r) => setTimeout(r, 1100));
  await core.limitIp(ip, 'ttltest', 100, 'PYRMI_NOPE', 1000); // a later hit must NOT push the TTL back up
  const ttl2 = Number(await kv.cmd('TTL', key));
  assert.ok(ttl2 < ttl1, 'TTL must keep counting down, not reset (was ' + ttl1 + ', now ' + ttl2 + ')');
});

// F-13: a multi-key DEL only prefixed its first key, so under the production prefix a "deleted" project still
// resolved — its public key kept minting sessions. F-14: a repeat delete must stay a no-op and never go negative.
test('under a key prefix, deleting a project removes every key and stays idempotent (F-13/F-14)', async () => {
  const savedPre = process.env.PYRMI_KV_PREFIX;
  process.env.PYRMI_KV_PREFIX = 'live:'; // the exact production path: VERCEL_ENV=production -> prefix "live:"
  try {
    const before = Number((await kv.cmd('GET', 'ps:projects')) || 0);
    const p = await core.createProject({ name: 'Doomed', origins: ['https://t.example'] }, '198.51.100.61', 'owner-del');
    assert.ok(await core.loadProject(p.pid), 'project should exist before delete');
    await core.deleteProject(await core.loadProject(p.pid));
    assert.equal(await core.loadProject(p.pid), null, 'the project record must be gone');
    assert.equal(await core.projectByPublicKey(p.publicKey), null, 'its public key must no longer mint sessions (F-13)');
    assert.equal(await core.projectBySecretKey(p.secretKey), null, 'its secret key must no longer resolve');
    assert.equal(Number(await kv.cmd('GET', 'ps:projects')), before, 'the capacity slot is returned exactly once');
    await core.deleteProject({ pid: p.pid, publicKey: p.publicKey, demo: false }); // delete again
    const after = Number(await kv.cmd('GET', 'ps:projects'));
    assert.ok(after === before && after >= 0, 'a repeat delete is a no-op and never goes negative (F-14): ' + after);
  } finally {
    if (savedPre === undefined) delete process.env.PYRMI_KV_PREFIX; else process.env.PYRMI_KV_PREFIX = savedPre;
  }
});

// F-09: createProject did INCR before the capacity check, so an over-cap attempt permanently inflated the counter.
test('a create rejected for being over capacity leaves the project counter unchanged (F-09)', async () => {
  const savedMax = process.env.PYRMI_MAX_PROJECTS;
  const p0 = await core.createProject({ name: 'Cap filler', origins: ['https://t.example'] }, '198.51.100.70', 'owner-cap0');
  try {
    const at = Number(await kv.cmd('GET', 'ps:projects'));
    process.env.PYRMI_MAX_PROJECTS = String(at); // now exactly at capacity
    await assert.rejects(() => core.createProject({ name: 'Over', origins: ['https://t.example'] }, '198.51.100.71', 'owner-cap'),
      (e) => e.status === 403 && e.code === 'at_capacity');
    assert.equal(Number(await kv.cmd('GET', 'ps:projects')), at, 'a rejected create must not inflate the counter');
  } finally {
    if (savedMax === undefined) delete process.env.PYRMI_MAX_PROJECTS; else process.env.PYRMI_MAX_PROJECTS = savedMax;
    await core.deleteProject(await core.loadProject(p0.pid)); // clean up the filler
  }
});

// F-07: origin_required was cosmetic — with no allowed origins a project accepted a session from any Origin header,
// so its public key could be drained from anywhere. With PYRMI_REQUIRE_ORIGINS on, a project must register an origin
// and sessions are bound to it (missing OR unmatched Origin is rejected). Existing origin-less projects are only
// locked out when the flag is deliberately turned on, which is the migration step.
test('with origin enforcement on, a project must register an origin and sessions are bound to it (F-07)', async () => {
  const savedReq = process.env.PYRMI_REQUIRE_ORIGINS, savedPre = process.env.PYRMI_KV_PREFIX;
  process.env.PYRMI_REQUIRE_ORIGINS = '1';
  process.env.PYRMI_KV_PREFIX = 'live:';
  try {
    const before = Number((await kv.cmd('GET', 'ps:projects')) || 0);
    await assert.rejects(() => core.createProject({ name: 'No origins' }, '198.51.100.80', 'owner-o'),
      (e) => e.status === 400 && e.code === 'origins_required');
    assert.equal(Number(await kv.cmd('GET', 'ps:projects')), before, 'a rejected create must not touch the capacity counter');
    const p = await core.createProject({ name: 'Bound', origins: ['https://app.example'] }, '198.51.100.81', 'owner-o');
    const proj = await core.loadProject(p.pid);
    const s = await core.startSession(proj, { ip: '203.0.113.1', ua: 'x', origin: 'https://app.example' });
    assert.ok(s.token, 'a matching Origin starts a session');
    await assert.rejects(() => core.startSession(proj, { ip: '203.0.113.2', ua: 'x', origin: 'https://evil.example' }),
      (e) => e.status === 403 && e.code === 'origin_not_allowed', 'an unmatched Origin is rejected');
    await assert.rejects(() => core.startSession(proj, { ip: '203.0.113.3', ua: 'x', origin: '' }),
      (e) => e.status === 403, 'a missing Origin is rejected');
    // An existing origin-less project can no longer mint sessions once enforcement is on.
    const legacy = { pid: 'p_legacy', name: 'Legacy', publicKey: 'pk_legacy', demo: false, settings: { ...DEFAULTS_ORIGINS() } };
    await assert.rejects(() => core.startSession(legacy, { ip: '203.0.113.4', ua: 'x', origin: 'https://whatever.example' }),
      (e) => e.status === 403 && e.code === 'origin_required', 'an origin-less project is refused under enforcement');
  } finally {
    if (savedReq === undefined) delete process.env.PYRMI_REQUIRE_ORIGINS; else process.env.PYRMI_REQUIRE_ORIGINS = savedReq;
    if (savedPre === undefined) delete process.env.PYRMI_KV_PREFIX; else process.env.PYRMI_KV_PREFIX = savedPre;
  }
});
function DEFAULTS_ORIGINS() { return { origins: [], reviewAt: 40, rejectAt: 70, minDurationMs: 1200, sessionTtlSec: 3600, maxScore: null, maxScorePerSec: null, strictClock: false }; }

// F-19: the public /demo endpoint lets anyone pick the visitor label, and a genuine demo session made logVerdict
// write a 30-day per-player hash for each — unbounded growth in the shared store. The demo must keep no per-player
// hashes, and a real project's per-player hashes must be capped the same way its recent-players index is.
test('the demo keeps no per-player hashes and real projects cap them (F-19)', async () => {
  const savedPre = process.env.PYRMI_KV_PREFIX;
  process.env.PYRMI_KV_PREFIX = 'live:';
  try {
    const demo = await core.loadProject(core.DEMO.pid);
    for (let i = 0; i < 8; i++) {
      const s = await core.startSession(demo, { ip: '203.0.113.' + (120 + i), ua: 'x', origin: '' });
      await core.verify(demo, { token: s.token, score: 1, player: 'visitor-' + (2000 + i).toString(16) }, { ip: '203.0.113.' + (120 + i) });
    }
    const plKeys = [...kv._mem.data.keys()].filter((k) => k.includes(':ps:pl:' + core.DEMO.pid + ':'));
    assert.equal(plKeys.length, 0, 'the demo must not persist any per-player hash, got ' + plKeys.length);
    assert.ok(Number(await kv.cmd('ZCARD', 'ps:plr:' + core.DEMO.pid)) > 0, 'the bounded recent-players index is still kept');

    // Real project: seed the index and hashes just past the cap, then one genuine verdict trims both.
    const p = await core.createProject({ name: 'Capped', origins: ['https://real.example'] }, '198.51.100.90', 'owner-c');
    const pid = p.pid, seed = [];
    for (let i = 0; i < 1001; i++) seed.push(['ZADD', 'ps:plr:' + pid, i + 1, 'old' + i], ['HSET', 'ps:pl:' + pid + ':old' + i, 'x', '1']);
    await kv.pipeline(seed);
    const proj = await core.loadProject(pid);
    const s = await core.startSession(proj, { ip: '203.0.113.200', ua: 'x', origin: 'https://real.example' });
    await core.verify(proj, { token: s.token, score: 1, player: 'fresh' }, { ip: '203.0.113.200' });
    assert.equal(Number(await kv.cmd('ZCARD', 'ps:plr:' + pid)), 1000, 'the recent-players index is held at the cap');
    assert.equal(Number(await kv.cmd('EXISTS', 'ps:pl:' + pid + ':old0')), 0, 'the evicted player\'s hash is deleted, not orphaned');
    assert.equal(Number(await kv.cmd('EXISTS', 'ps:pl:' + pid + ':fresh')), 1, 'the newest player\'s hash is kept');
  } finally {
    if (savedPre === undefined) delete process.env.PYRMI_KV_PREFIX; else process.env.PYRMI_KV_PREFIX = savedPre;
  }
});

// Delete leftovers: "delete site" is sold as deletion, but per-visitor (ps:pl) and daily-stat (ps:st) keys used to
// survive the delete. Deleting a project must take its visitor and stats data with it.
test('deleting a project also removes its per-player and daily-stat keys (delete leftovers)', async () => {
  const savedPre = process.env.PYRMI_KV_PREFIX;
  process.env.PYRMI_KV_PREFIX = 'live:';
  try {
    const p = await core.createProject({ name: 'Purge me', origins: ['https://purge.example'] }, '198.51.100.95', 'owner-p');
    const proj = await core.loadProject(p.pid);
    const s = await core.startSession(proj, { ip: '203.0.113.210', ua: 'x', origin: 'https://purge.example' });
    await core.verify(proj, { token: s.token, score: 1, player: 'alice' }, { ip: '203.0.113.210' });
    assert.equal(Number(await kv.cmd('EXISTS', 'ps:pl:' + p.pid + ':alice')), 1, 'a per-player hash exists before delete');
    const stKeysBefore = [...kv._mem.data.keys()].filter((k) => k.includes(':ps:st:' + p.pid + ':')).length;
    assert.ok(stKeysBefore > 0, 'a daily-stat key exists before delete');
    await core.deleteProject(await core.loadProject(p.pid));
    assert.equal(Number(await kv.cmd('EXISTS', 'ps:pl:' + p.pid + ':alice')), 0, 'the per-player hash is gone after delete');
    assert.equal([...kv._mem.data.keys()].filter((k) => k.includes(':ps:pl:' + p.pid + ':')).length, 0, 'no per-player hash survives');
    assert.equal([...kv._mem.data.keys()].filter((k) => k.includes(':ps:st:' + p.pid + ':')).length, 0, 'no daily-stat key survives');
  } finally {
    if (savedPre === undefined) delete process.env.PYRMI_KV_PREFIX; else process.env.PYRMI_KV_PREFIX = savedPre;
  }
});
