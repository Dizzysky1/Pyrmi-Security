'use strict';
// pyrmi-server on runtimes with no Node globals (Cloudflare Workers, Deno, edge functions): no Buffer, no process.
// The package is loaded into a bare context that has only the web APIs those runtimes share, and must work the same.
const test = require('node:test');
const assert = require('node:assert');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'packages', 'pyrmi-server', 'index.js'), 'utf8');

function load(fetchImpl) {
  const module = { exports: {} };
  const ctx = vm.createContext({
    module, exports: module.exports, console, fetch: fetchImpl, AbortSignal, TextEncoder, TextDecoder, atob, URLSearchParams,
  });
  vm.runInContext(SRC, ctx, { filename: 'pyrmi-server/index.js' });
  assert.equal(vm.runInContext('typeof Buffer + typeof process', ctx), 'undefinedundefined', 'the context really has no Node globals');
  return module.exports;
}
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');

test('pyrmi-server loads and verifies with no Buffer or process', async () => {
  let sent = null;
  const P = load(async (url, init) => {
    sent = { url, init };
    return { ok: true, status: 200, json: async () => ({ ok: true, verdict: 'accept', risk: 0, client: 'corroborated', trusted: true, reasons: [] }) };
  });
  // No process.env here, so a missing key is the package's own error, not a ReferenceError.
  assert.throws(() => new P.Pyrmi({}), /pass \{ secretKey/);
  const pyrmi = new P.Pyrmi({ secretKey: 'sk_' + 'a'.repeat(30), endpoint: 'https://self.example/api/v1/' });
  const v = await pyrmi.verify({ token: 'tok', score: 5, player: 'p1' });
  assert.equal(v.verdict, 'accept');
  assert.equal(sent.url, 'https://self.example/api/v1/verify');
  assert.equal(sent.init.headers.Authorization, 'Bearer sk_' + 'a'.repeat(30));
  assert.deepEqual(JSON.parse(sent.init.body).score, 5);
  assert.equal(P.trusted(v), true);
});

test('the 16 KB cap counts UTF-8 bytes without Buffer, as it does on Node', async () => {
  let calls = 0;
  const P = load(async () => { calls++; return { ok: true, status: 200, json: async () => ({ ok: true, verdict: 'accept', reasons: [] }) }; });
  const pyrmi = new P.Pyrmi({ secretKey: 'sk_' + 'b'.repeat(30) });
  // 6000 three-byte characters: 18 KB as UTF-8, though only 6000 JavaScript characters.
  const v = await pyrmi.verify({ token: 'tok', player: '€'.repeat(6000) });
  assert.equal(v.verdict, 'reject');
  assert.match(v.reasons[0].text, /larger than 16 KB/);
  assert.equal(calls, 0, 'nothing was sent');
});

test('the session seed is read from the token without Buffer', async () => {
  const P = load(async () => ({ ok: true, status: 200, json: async () => ({ ok: true, verdict: 'accept', reasons: [] }) }));
  // Every padding length, and text that isn't ASCII.
  for (const s of ['a', 'ab', 'abc', 'abcd', 'café-€']) {
    assert.deepEqual({ ...P.sessionOf(b64u({ seed: 42, s }) + '.mac') }, { seed: 42, session: s });
  }
  assert.deepEqual({ ...P.sessionOf('%%%.mac') }, { seed: null, session: null });
  let seen = null;
  const pyrmi = new P.Pyrmi({ secretKey: 'sk_' + 'c'.repeat(30) });
  await pyrmi.verify({ token: b64u({ seed: 7, s: 'sess1' }) + '.mac', score: 1, simulate: (r, info) => { seen = { ...info }; return { score: 1 }; } });
  assert.deepEqual(seen, { seed: 7, session: 'sess1' });
});

test('clientOf reads a Fetch API Request (Workers, Deno) the same way', () => {
  const P = load(async () => ({}));
  const req = { headers: new Headers({ 'user-agent': 'UA', 'sec-ch-ua': 'CH', 'sec-fetch-site': 'same-origin', 'x-forwarded-for': '203.0.113.9' }) };
  assert.deepEqual({ ...P.clientOf(req, 1) }, { ua: 'UA', ch: 'CH', sfs: 'same-origin', ip: '203.0.113.9' });
  assert.deepEqual({ ...P.clientOf(req, 0) }, { ua: 'UA', ch: 'CH', sfs: 'same-origin', ip: '' });
});

test('on Node, the package still reads its keys from the environment', () => {
  const saved = process.env.PYRMI_SECRET_KEY;
  process.env.PYRMI_SECRET_KEY = 'sk_' + 'd'.repeat(30);
  try {
    const { Pyrmi } = require('../packages/pyrmi-server');
    assert.equal(new Pyrmi().secretKey, 'sk_' + 'd'.repeat(30));
  } finally { if (saved === undefined) delete process.env.PYRMI_SECRET_KEY; else process.env.PYRMI_SECRET_KEY = saved; }
});
