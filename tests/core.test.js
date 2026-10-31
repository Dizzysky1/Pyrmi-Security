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
