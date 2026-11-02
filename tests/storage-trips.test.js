'use strict';
// How many storage round trips the busy endpoints take. Self-hosted servers pay for each one in latency (and on some
// hosts in function time), so the hot paths batch their Redis commands: a beacon is 2 round trips, a verify 4.
// Runs the real Upstash REST client against a stand-in Upstash server that uses the in-memory store underneath, and
// checks the limits those batched calls count still hold.
delete process.env.PYRMI_KV; // the REST client, not the in-process store
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = '100000';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');

const trips = { n: 0, cmds: [] };
let kv, core, C, B, base, upstash, server;
let p;

test.before(async () => {
  upstash = http.createServer((req, res) => {
    let b = ''; req.on('data', (c) => { b += c; }); req.on('end', () => {
      const cmds = JSON.parse(b); trips.n++; trips.cmds.push(...cmds.map((c) => c[0]));
      const out = cmds.map((c) => { try { return { result: kv._mem.run(c.map(String)) }; } catch (e) { return { error: e.message }; } });
      res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(out));
    });
  });
  await new Promise((r) => upstash.listen(0, r));
  process.env.KV_REST_API_URL = 'http://127.0.0.1:' + upstash.address().port;
  process.env.KV_REST_API_TOKEN = 'test';
  kv = require('../api/_lib/kv'); core = require('../api/_lib/core'); C = require('../api/_lib/crypto'); B = require('./_browser');
  const { serve } = require('../scripts/dev.js');
  server = http.createServer(serve); await new Promise((r) => server.listen(0, r));
  base = 'http://127.0.0.1:' + server.address().port;
  p = await core.createProject({ name: 'Trips', origins: ['https://g.example'], settings: { minDurationMs: 0, maxScore: 1e6 } }, '198.51.100.9', 'owner-trips');
});
test.after(() => { server.close(); upstash.close(); });

const UA = 'Mozilla/5.0 Chrome/130.0', CH = '"Chromium";v="130"';
const raw = async (method, path, body, headers) => {
  const r = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': UA, 'Sec-CH-UA': CH, ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, headers: r.headers, body: await r.json() };
};
const call = (...a) => B.wrap(raw)(...a);
const counted = async (fn) => { const n0 = trips.n, c0 = trips.cmds.length; const r = await fn(); return { r, trips: trips.n - n0, cmds: trips.cmds.slice(c0) }; };
const start = async (ip) => (await call('POST', '/api/v1/session', { site: p.publicKey }, { Origin: 'https://g.example', ...(ip ? { 'X-Forwarded-For': ip } : {}) })).body;
const sealed = (s) => {
  const fields = { score: 10, player: 'alice' }, ts = Date.now();
  return raw('POST', '/api/v1/verify', { token: s.token, score: 10, player: 'alice', request: { fields, ts, sig: C.requestMac(s.rk, s.session, ts, C.canon(fields)) }, client: { ua: UA, ch: CH, sfs: 'same-site', ip: '127.0.0.1' } }, { Authorization: 'Bearer ' + p.secretKey });
};

test('a beacon takes 2 round trips, the first one too', async () => {
  const s = await start();
  for (let i = 0; i < 3; i++) {
    const { r, trips: n } = await counted(() => B.beacon(call, s, { gt: 100 + i }));
    assert.equal(r.status, 200);
    assert.equal(n, 2, 'beacon ' + (i + 1));
  }
  const h = kv.pairs(await kv.cmd('HGETALL', 'ps:s:' + s.session));
  assert.equal(h.b, '3');
  assert.equal(JSON.parse(h.f).gt, 100, 'the first mark is kept');
  assert.equal(JSON.parse(h.g).gt, 100, 'the first mark with game time is kept');
  assert.equal(JSON.parse(h.l).gt, 102, 'the last mark moves on');
});

test('a verify takes 4 round trips and a replay is still caught', async () => {
  const s = await start();
  await B.beacon(call, s, {});
  const first = await counted(() => sealed(s));
  assert.equal(first.r.body.verdict, 'accept', JSON.stringify(first.r.body.reasons));
  assert.equal(first.r.body.trusted, true);
  assert.equal(first.trips, 4);
  const again = await counted(() => sealed(s));
  assert.ok(again.r.body.reasons.some((x) => x.code === 'token_reused'));
  assert.equal(again.r.body.verdict, 'reject');
  assert.ok(again.trips <= 4);
});

test('a secret-key lookup reads the project once, and a stale key opens nothing', async () => {
  const { r, trips: n, cmds } = await counted(() => raw('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + p.secretKey }));
  assert.equal(r.status, 200);
  assert.deepEqual(cmds.slice(0, 2), ['GET', 'HGETALL']);
  assert.equal(n, 3, 'key lookup (2) and the per-site limit (1)');
  // A ps:sk entry the project no longer records (a lost rotation race) is refused.
  const q = await core.createProject({ name: 'Stale', origins: ['https://g.example'] }, '198.51.100.10', 'owner-trips');
  const old = q.secretKey;
  const fresh = await core.rotateSecret(await core.loadProject(q.pid), old);
  await kv.cmd('SET', 'ps:sk:' + C.sha256(old), q.pid); // put the old mapping back
  assert.equal(await core.projectBySecretKey(old), null);
  assert.equal((await core.projectBySecretKey(fresh)).pid, q.pid);
});

test('the beacon limit counts every beacon, unreadable ones too, before anything else refuses it', async () => {
  const saved = process.env.PYRMI_SIGNALS_PER_IP;
  process.env.PYRMI_SIGNALS_PER_IP = '3';
  const ip = '203.0.113.77';
  try {
    const s = await start(ip);
    const h = { 'Content-Type': 'text/plain', 'X-Forwarded-For': ip, Origin: 'https://g.example' };
    assert.equal((await raw('POST', '/api/v1/signal', '{not json', h)).status, 400);
    assert.equal((await raw('POST', '/api/v1/signal', JSON.stringify({ token: 'bad', signals: {} }), h)).status, 400);
    const good = () => raw('POST', '/api/v1/signal', JSON.stringify({ token: s.token, ...B.order(s), signals: B.signals() }), { ...h, 'Sec-Fetch-Site': 'same-site' });
    assert.equal((await good()).status, 200, 'the third call is within the limit');
    const over = await raw('POST', '/api/v1/signal', JSON.stringify({ token: 'bad', signals: {} }), h);
    assert.equal(over.status, 429, 'over the limit wins over a bad token');
    assert.equal(over.headers.get('retry-after'), '600');
    assert.equal((await raw('POST', '/api/v1/signal', '{', h)).status, 429, 'and over an unreadable body');
    const late = await good();
    assert.equal(late.status, 429, 'a good beacon over the limit is refused too');
    assert.equal(kv.pairs(await kv.cmd('HGETALL', 'ps:s:' + s.session)).b, '1', 'and changes nothing');
  } finally { if (saved === undefined) delete process.env.PYRMI_SIGNALS_PER_IP; else process.env.PYRMI_SIGNALS_PER_IP = saved; }
});

test('beacons still stop when the project is gone or its key was rotated', async () => {
  const q = await core.createProject({ name: 'Gone', origins: ['https://g.example'], settings: { minDurationMs: 0 } }, '198.51.100.11', 'owner-trips');
  const sess = (await call('POST', '/api/v1/session', { site: q.publicKey }, { Origin: 'https://g.example' })).body;
  assert.equal((await B.beacon(call, sess, {})).status, 200);
  await core.rotateSecret(await core.loadProject(q.pid), q.secretKey);
  const r = await B.beacon(call, sess, {});
  assert.equal(r.status, 410); assert.equal(r.body.error, 'revoked');
  const sess2 = (await call('POST', '/api/v1/session', { site: q.publicKey }, { Origin: 'https://g.example' })).body;
  await core.deleteProject(await core.loadProject(q.pid));
  assert.equal((await B.beacon(call, sess2, {})).status, 410);
});
