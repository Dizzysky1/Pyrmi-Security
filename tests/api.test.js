'use strict';
// End-to-end tests for the API with the in-memory store:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const beacon = (token, signals) => call('POST', '/api/v1/signal', JSON.stringify({ token, signals: { pt: 1000, k: 5, p: 3, ...signals } }), { 'Content-Type': 'text/plain' });

let pk, sk;

test('create project returns keys once', async () => {
  const r = await call('POST', '/api/v1/project', { name: 'Test Game', origins: ['https://game.example'] });
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
  await beacon(s.token, {});
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
  await beacon(s.token, { wd: true, ut: 12 });
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
  await beacon(s.token, {});
  const v = await call('POST', '/api/v1/verify', { token: s.token, user: 'carol@example.com' }, { Authorization: 'Bearer ' + sk });
  assert.equal(v.body.verdict, 'accept', JSON.stringify(v.body));
  assert.equal(v.body.player, 'carol@example.com');
  assert.equal(v.body.score, null);
});

// ---- the homepage sandbox ----
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

test('sandbox: a normal request is accepted, a replay of it is rejected', async () => {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_demo_sandbox' })).body;
  await beacon(s.token, {});
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
  await beacon(s2.token, {});
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
  await beacon(s.token, {});
  const lied = await pyrmi.verify({ token: s.token, score: 50, player: 'sdk', replay: [1, 2, 3], simulate: () => ({ score: 20 }) });
  assert.equal(lied.verdict, 'reject');
  assert.ok(lied.reasons.some((r) => r.code === 'replay_mismatch'));
  const down = new Pyrmi({ secretKey: sk, endpoint: 'http://127.0.0.1:9/api/v1', timeoutMs: 500 });
  assert.equal((await down.verify({ token: 'x', score: 1 })).verdict, 'reject');
});
