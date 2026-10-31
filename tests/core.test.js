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
  const p = await core.createProject({ name: 'Temp' }, '198.51.100.21', 'owner-x');
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
    const p = await core.createProject({ name: 'Doomed' }, '198.51.100.61', 'owner-del');
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
  const p0 = await core.createProject({ name: 'Cap filler' }, '198.51.100.70', 'owner-cap0');
  try {
    const at = Number(await kv.cmd('GET', 'ps:projects'));
    process.env.PYRMI_MAX_PROJECTS = String(at); // now exactly at capacity
    await assert.rejects(() => core.createProject({ name: 'Over' }, '198.51.100.71', 'owner-cap'),
      (e) => e.status === 403 && e.code === 'at_capacity');
    assert.equal(Number(await kv.cmd('GET', 'ps:projects')), at, 'a rejected create must not inflate the counter');
  } finally {
    if (savedMax === undefined) delete process.env.PYRMI_MAX_PROJECTS; else process.env.PYRMI_MAX_PROJECTS = savedMax;
    await core.deleteProject(await core.loadProject(p0.pid)); // clean up the filler
  }
});
