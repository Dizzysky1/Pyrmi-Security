'use strict';
// Replay checks in pyrmi-server, wrong keys at /verify and the edge headers:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const core = require('../api/_lib/core');
const { Pyrmi } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const answering = (body) => async () => ({ ok: true, status: 200, json: async () => body });

test('simulate only runs for a session Pyrmi confirmed, with the seed Pyrmi answered', async () => {
  const p = await core.createProject({ name: 'h1', origins: ['https://game.example'], settings: { minDurationMs: 0, requireSignedRequests: false, maxScore: 100 } }, '198.51.100.90');
  const pyrmi = new Pyrmi({ secretKey: p.secretKey, endpoint: base + '/api/v1' });
  let runs = 0;
  const simulate = () => { runs++; return { score: 1 }; };
  // A token Pyrmi doesn't accept is a reject before anything is replayed.
  const made = await pyrmi.verify({ token: b64u({ v: 1, p: p.pid, s: 'x', i: Date.now(), e: Date.now() + 1e6, seed: 1 }) + '.bad', score: 1, replay: [1], simulate });
  assert.equal(made.verdict, 'reject');
  assert.equal(runs, 0);
  // A genuine session gets its own seed.
  const s = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: { 'Content-Type': 'text/plain', Origin: 'https://game.example' }, body: JSON.stringify({ site: p.publicKey }) })).json();
  let got = null;
  const v = await pyrmi.verify({ token: s.token, score: 1, replay: [1, 2], simulate: (r, ctx) => { runs++; got = ctx; return { score: 1 }; } });
  assert.equal(runs, 1);
  assert.deepEqual(got, { seed: s.seed, session: s.session });
  assert.equal(v.replay, 'match');
});

test('the seed simulate gets is the one Pyrmi answered, and a different session id is refused', async () => {
  const realFetch = global.fetch;
  try {
    const pyrmi = new Pyrmi({ secretKey: 'sk_' + 'h'.repeat(30), endpoint: 'https://self.example/api/v1' });
    const token = b64u({ seed: 7, s: 'sess1' }) + '.mac';
    let seen = null;
    global.fetch = answering({ ok: true, verdict: 'accept', risk: 0, reasons: [], seed: 9, session: 'sess1' });
    const ok = await pyrmi.verify({ token, score: 1, replay: [], simulate: (r, ctx) => { seen = ctx; return { score: 1 }; } });
    assert.deepEqual(seen, { seed: 9, session: 'sess1' });
    assert.equal(ok.replay, 'match');
    seen = null;
    global.fetch = answering({ ok: true, verdict: 'accept', risk: 0, reasons: [], seed: 9, session: 'other' });
    const off = await pyrmi.verify({ token, score: 1, replay: [], simulate: (r, ctx) => { seen = ctx; return { score: 1 }; } });
    assert.equal(seen, null);
    assert.equal(off.verdict, 'reject');
    assert.equal(off.trusted, false);
    assert.equal(off.reasons[0].code, 'replay_mismatch');
    global.fetch = answering({ ok: true, verdict: 'accept', risk: 0, reasons: [], seed: null, session: 'sess1' });
    assert.equal((await pyrmi.verify({ token, score: 1, replay: [], simulate: () => ({ score: 1 }) })).verdict, 'reject');
  } finally { global.fetch = realFetch; }
});

test('a replay over maxReplayBytes is a mismatch and is never run', async () => {
  const realFetch = global.fetch;
  let sent = null;
  try {
    global.fetch = async (url, init) => { sent = JSON.parse(init.body); return { ok: true, status: 200, json: async () => ({ ok: true, verdict: 'reject', risk: 100, reasons: [{ code: 'replay_mismatch' }] }) }; };
    const pyrmi = new Pyrmi({ secretKey: 'sk_' + 'i'.repeat(30), endpoint: 'https://self.example/api/v1', maxReplayBytes: 1000 });
    let runs = 0;
    const v = await pyrmi.verify({ token: 't.x', score: 1, replay: new Array(2000).fill(1), simulate: () => { runs++; return { score: 1 }; } });
    assert.equal(runs, 0);
    assert.equal(sent.replay.check, 'mismatch');
    assert.equal(v.verdict, 'reject');
    const loop = {}; loop.self = loop;
    await pyrmi.verify({ token: 't.x', score: 1, replay: loop, simulate: () => { runs++; return { score: 1 }; } });
    assert.equal(runs, 0);
    assert.equal(sent.replay.check, 'mismatch');
  } finally { global.fetch = realFetch; }
});

test('wrong secret keys at /verify are capped per network; the right key always works', async () => {
  const saved = process.env.PYRMI_VERIFY_BAD_KEYS_PER_MIN;
  process.env.PYRMI_VERIFY_BAD_KEYS_PER_MIN = '5';
  try {
    const p = await core.createProject({ name: 'h2', origins: ['https://game.example'] }, '198.51.100.91');
    const post = (key, ip) => fetch(base + '/api/v1/verify', { method: 'POST', headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json', 'X-Forwarded-For': ip }, body: '{}' });
    const ip = '198.51.100.92';
    for (let i = 0; i < 20; i++) assert.equal((await post('junk', ip)).status, 401, 'a malformed key is never looked up, so not counted');
    for (let i = 0; i < 5; i++) assert.equal((await post('sk_' + 'w'.repeat(29) + i, ip)).status, 401);
    const over = await post('sk_' + 'w'.repeat(30), ip);
    assert.equal(over.status, 429);
    assert.equal(over.headers.get('retry-after'), '60');
    assert.equal((await post(p.secretKey, ip)).status, 200, 'the right key still works from that network');
    assert.equal((await post('sk_' + 'w'.repeat(30), '198.51.100.93')).status, 401, 'another network is not affected');
  } finally { if (saved === undefined) delete process.env.PYRMI_VERIFY_BAD_KEYS_PER_MIN; else process.env.PYRMI_VERIFY_BAD_KEYS_PER_MIN = saved; }
});

test('edge headers: isolation headers on pages, the browser script stays embeddable', () => {
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'vercel.json'), 'utf8'));
  for (const r of v.headers) for (const h of r.headers) if (h.key === 'Content-Security-Policy') assert.match(h.value, /upgrade-insecure-requests/, r.source);
  const get = (src, key) => { const r = v.headers.find((x) => x.source === src); const h = r && r.headers.find((x) => x.key === key); return h && h.value; };
  assert.equal(get('/sdk/(.*)', 'Cross-Origin-Resource-Policy'), 'cross-origin');
  assert.equal(get('/sdk/(.*)', 'Access-Control-Allow-Origin'), '*');
  const pages = v.headers.find((r) => r.headers.some((h) => h.key === 'Cross-Origin-Opener-Policy'));
  assert.equal(get(pages.source, 'Cross-Origin-Opener-Policy'), 'same-origin');
  assert.equal(get(pages.source, 'Cross-Origin-Resource-Policy'), 'same-origin');
  assert.notEqual(get(pages.source, 'Access-Control-Allow-Origin'), '*');
  assert.ok(!v.headers.some((r) => r.headers.some((h) => h.key === 'Cross-Origin-Embedder-Policy')), 'no COEP (it would block fonts and Turnstile)');
  // The page rule must not reach the browser script, its builds or the API (whose CORS is set per project).
  const re = new RegExp('^' + pages.source + '$');
  for (const p of ['/', '/dashboard/', '/docs/', '/og.png', '/blog/x/']) assert.ok(re.test(p), p);
  for (const p of ['/sdk/pyrmi.js', '/sdk/1.4.0/pyrmi.js', '/api/v1/session', '/api/v1/signal', '/install.md', '/llms.txt']) assert.ok(!re.test(p), p);
});
