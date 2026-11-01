'use strict';
// Sealed numbers and the replay check's seed.
//   node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const { Pyrmi, sessionOf } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

test('1. canon refuses numbers it can\'t check exactly', () => {
  for (const v of [Infinity, -Infinity, NaN, -0, 2 ** 53, -(2 ** 53), 1e21]) {
    assert.throws(() => C.canon({ a: [{ b: v }] }), (e) => e.code === 'CANON_BAD_NUMBER', String(v));
  }
  assert.equal(C.canon({ a: 0, b: 2 ** 53 - 1, c: 1.5, d: null }), '{"a":0,"b":9007199254740991,"c":1.5,"d":null}');
});

// A session, a beacon, then a signed action with the fields given. Returns what /verify answers.
async function signedVerify(project, fields, rawFields) {
  const H = { 'Content-Type': 'text/plain', Origin: 'https://game.example', 'X-Forwarded-For': '198.51.100.77' };
  const s = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: H, body: JSON.stringify({ site: project.publicKey, pt: 1 }) })).json();
  const ts = Date.now();
  // What the page signed, in its canonical form (written out: the old canon accepted these values).
  const sig = C.requestMac(await C.requestKey(s.session), s.session, ts, typeof fields === 'string' ? fields : C.canon(fields));
  // What arrives on the wire: the signed body rewritten.
  const body = '{"token":' + JSON.stringify(s.token) + ',"request":{"fields":' + rawFields + ',"ts":' + ts + ',"sig":"' + sig + '"}}';
  const r = await fetch(base + '/api/v1/verify', { method: 'POST', headers: { Authorization: 'Bearer ' + project.secretKey, 'Content-Type': 'application/json' }, body });
  return { v: await r.json(), s };
}

test('2. a sealed null rewritten to 1e999, or 0 to -0, or a big whole number nudged, is a bad signature', async () => {
  const p = await core.createProject({ name: 'n', origins: ['https://game.example'] }, '198.51.100.70');
  for (const [fields, raw] of [
    ['{"discount":null}', '{"discount":-1e999}'],
    ['{"qty":0}', '{"qty":-0}'],
    ['{"item":9007199254740992}', '{"item":9007199254740993}'],
  ]) {
    const { v } = await signedVerify(p, fields, raw);
    assert.equal(v.signed, 'bad', raw + ' ' + JSON.stringify(v.reasons));
    assert.ok(v.reasons.some((r) => r.code === 'bad_signature'));
  }
  const { v } = await signedVerify(p, { qty: 0 }, '{"qty":0}');
  assert.equal(v.signed, 'ok', 'an honest one still checks');
});

test('3. pyrmi-server refuses a sealed number JSON would change on the way', async () => {
  const pyrmi = new Pyrmi({ secretKey: 'sk_' + 'x'.repeat(40), endpoint: 'http://127.0.0.1:9/api/v1' });
  for (const bad of [Infinity, -0, 2 ** 60]) {
    const v = await pyrmi.verify({ sealed: { a: { b: bad }, pyrmi: { token: 't.x', ts: 1, sig: 'x'.repeat(43) } } });
    assert.equal(v.verdict, 'reject'); assert.equal(v.reasons[0].code, 'pyrmi_refused', String(bad));
  }
});

test('4. simulate gets the session\'s own seed from the token, and verify answers it', async () => {
  const p = await core.createProject({ name: 'r', origins: ['https://game.example'], settings: { minDurationMs: 0, requireSignedRequests: false } }, '198.51.100.71');
  const s = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: { 'Content-Type': 'text/plain', Origin: 'https://game.example' }, body: JSON.stringify({ site: p.publicKey }) })).json();
  assert.deepEqual(sessionOf(s.token), { seed: s.seed, session: s.session });
  const pyrmi = new Pyrmi({ secretKey: p.secretKey, endpoint: base + '/api/v1' });
  let got = null;
  const v = await pyrmi.verify({ token: s.token, replay: [1, 2], simulate: (inputs, ctx) => { got = ctx; return { score: undefined }; } });
  assert.deepEqual(got, { seed: s.seed, session: s.session });
  assert.equal(v.seed, s.seed);
  assert.deepEqual(sessionOf('junk'), { seed: null, session: null });
});
