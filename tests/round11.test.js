'use strict';
// Round 11: the tester's CDP toolkit, reproduced locally against the in-memory store (never against pyrmi.com).
//   1. clean automation (a real Chrome driven over CDP with trusted input): accept, corroborated, trusted
//   2. session relay: a clean page mints the session and sends the beacons, then Node sends the action with its token
//   3. wire rewrite: the page sends 55, CDP's Fetch.requestPaused changes it to 88 on the way out
// plus the coercion the follow-up found ("1e3", [1000] and true were taken as numbers).
// What these show stopped: 2 and 3, and the trusted flag on a session with no real input. What they show still passes,
// by design: a relay that copies the browser's user agent and client hints from the same network, and code running in
// the page itself asking the script to sign (see README "What this does and doesn't stop").
//   node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// The sandbox has requireHumanCheck on, so trusted needs a Turnstile pass Pyrmi confirms itself. Its endpoint uses pyrmi.com's own keys; here
// they point at a stand-in for Cloudflare (tests/_browser.js fakeTurnstile).
process.env.TURNSTILE_SITE_KEY = 'test-site-key';
process.env.TURNSTILE_SECRET_KEY = '0x-test-turnstile-secret';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const { trusted } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { await B.fakeTurnstile(); server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let ipn = 1;
const nextIp = () => '192.0.2.' + (ipn++);
const CHROME = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36';
const CH = '"Chromium";v="156", "Google Chrome";v="156", "Not.A/Brand";v="99"';
const post = async (p, body, headers) => {
  const r = await fetch(base + '/api/v1' + p, { method: 'POST', headers: { 'Content-Type': 'text/plain', ...(headers || {}) }, body: JSON.stringify(body) });
  return { status: r.status, body: await r.json() };
};
const codes = (v) => v.reasons.map((r) => r.code);
// The headers a real Chrome tab on pyrmi.com sends with every request the page makes.
const tab = (ip) => ({ Origin: base, 'Sec-Fetch-Site': 'same-origin', 'User-Agent': CHROME, 'Sec-CH-UA': CH, 'X-Forwarded-For': ip });

// harvest.mjs: a clean page mints a sandbox session and lets a beacon go out, with the given input counts.
async function harvest(ip, sig) {
  const h = tab(ip);
  const s = (await post('/session', { site: 'pk_demo_sandbox', pt: 1000 }, h)).body;
  assert.ok(s.token && s.rk, JSON.stringify(s));
  await wait(1600);
  const r = await post('/signal', { token: s.token, ...B.order(s), signals: B.signals({ pt: 2600, ...(sig || {}) }) }, h);
  assert.equal(r.status, 200, JSON.stringify(r.body));
  return s;
}
const sealed = (s, fields) => { const q = B.sign(s, fields); return { ...q.fields, pyrmi: { token: s.token, ts: q.ts, sig: q.sig } }; };
// ...with the sandbox's human check solved on the page for this session (round 12), sealed in with the rest
const HOST = () => new URL(base).hostname;
const sealedH = (s, fields) => sealed(s, { ...fields, turnstile: B.human(s, HOST(), { action: 'sandbox' }).token });

test('1. the honest page (clean browser, real input, sealed action) is still a trusted accept', async () => {
  const ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
  const v = (await post('/demo', sealedH(s, { value: 77, visitor: 'visitor-f7e71e' }), tab(ip))).body;
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.signed, 'ok'); assert.equal(v.bound, true); assert.equal(v.human, 'ok');
  assert.equal(v.trusted, true); assert.equal(trusted(v), true);
});

test('2. session relay: the action sent from Node with a harvested token is flagged and never trusted', async () => {
  const ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
  // run.mjs phase 2 / the curl in the README: same network, the token, a Node user agent, no browser fetch metadata
  const node = { 'User-Agent': 'pyrmi-bypass/1.0 (node)', 'X-Forwarded-For': ip, 'Content-Type': 'application/json' };
  const v = (await post('/demo', { token: s.token, value: 123, visitor: 'visitor' }, node)).body;
  assert.ok(codes(v).includes('relayed_session'), JSON.stringify(v.reasons));
  assert.equal(v.verdict, 'review');
  assert.equal(v.trusted, false); assert.equal(trusted(v), false);
  assert.equal(v.signed, 'none');
});

test('2b. a relay that copies the user agent but not the client hints, or drops the fetch metadata, is still caught', async () => {
  let ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
  let v = (await post('/demo', sealed(s, { value: 5, visitor: 'visitor' }), { ...tab(ip), 'Sec-CH-UA': '"Node";v="22"' })).body;
  assert.match((v.reasons.find((r) => r.code === 'relayed_session') || {}).detail || '', /client hints/);
  assert.equal(v.trusted, false);
  ip = nextIp(); s = await harvest(ip, { k: 1, p: 3 });
  const h = tab(ip); delete h['Sec-Fetch-Site'];
  v = (await post('/demo', sealed(s, { value: 5, visitor: 'visitor' }), h)).body;
  assert.match((v.reasons.find((r) => r.code === 'relayed_session') || {}).detail || '', /not sent by a browser/);
  assert.equal(v.trusted, false);
});

test('2c. a relay that copies every browser header and signs in the page is bound and signed, but not trusted without the human check', async () => {
  // The sandbox has requireHumanCheck on, so trusted also needs a Turnstile pass solved for this session on its page.
  let ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
  let v = (await post('/demo', sealed(s, { value: 42, visitor: 'visitor' }), tab(ip))).body;
  assert.equal(v.signed, 'ok'); assert.equal(v.bound, true); assert.equal(v.human, 'none');
  assert.equal(v.trusted, false);
  ip = nextIp(); s = await harvest(ip, { k: 1, p: 3 });
  v = (await post('/demo', sealedH(s, { value: 42, visitor: 'visitor' }), tab(ip))).body;
  assert.equal(v.trusted, true);
});

test('3. wire rewrite: the page signs 55, 88 goes out; rejected with bad_signature', async () => {
  const ip = nextIp(), s = await harvest(ip, { k: 0, p: 3 });
  const body = sealed(s, { value: 55, visitor: 'visitor' });
  body.value = 88;
  const v = (await post('/demo', body, tab(ip))).body;
  assert.equal(v.verdict, 'reject');
  assert.ok(codes(v).includes('bad_signature'), JSON.stringify(v.reasons));
  assert.equal(v.signed, 'bad'); assert.equal(v.trusted, false);
  // any change counts: an added field, a different visitor, the same fields signed by another session's key
  const s2 = await harvest(nextIp(), { k: 1, p: 3 });
  const extra = sealed(s2, { value: 55, visitor: 'visitor' }); extra.bonus = 1;
  assert.ok(codes((await post('/demo', extra, tab(ip))).body).includes('bad_signature'));
  const s3 = await harvest(ip, { k: 1, p: 3 }), s4 = await harvest(ip, { k: 1, p: 3 });
  const swapped = sealed(s3, { value: 55, visitor: 'visitor' }); swapped.pyrmi.token = s4.token;
  assert.ok(codes((await post('/demo', swapped, tab(ip))).body).includes('bad_signature'));
});

test('3b. a stale or malformed signature is a reject; an unsigned action on a sealed-only project is too', async () => {
  const ip = nextIp();
  const p = await core.createProject({ name: 'Sealed', origins: [base] }, ip, 'owner-r11');
  let project = await core.loadProject(p.pid);
  project = await core.updateSettings(project, { minDurationMs: 0 });
  const mint = async () => {
    const s = await core.startSession(project, { ip, ua: CHROME, origin: base, ch: CH }, { pt: 0 });
    await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: CHROME, origin: base, sfs: 'same-origin' });
    return s;
  };
  const client = { ua: CHROME, ip, ch: CH, sfs: 'same-origin' };
  let s = await mint();
  const old = B.sign(s, { a: 1 }, Date.now() - 10 * 60e3);
  let v = await core.verify(project, { token: s.token, request: old, client }, { ip });
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('bad_signature'));
  s = await mint();
  v = await core.verify(project, { token: s.token, request: { fields: { a: 1 }, ts: Date.now(), sig: 'x' }, client }, { ip });
  assert.ok(codes(v).includes('bad_signature'));
  // a new project takes sealed actions only (round 12 default): unsigned is a reject
  assert.equal(project.settings.requireSignedRequests, true);
  s = await mint();
  v = await core.verify(project, { token: s.token, client }, { ip });
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('unsigned_request'));
  s = await mint();
  v = await core.verify(project, { token: s.token, request: B.sign(s, { a: 1 }), client, turnstile: B.human(s, HOST()) }, { ip });
  assert.equal(v.verdict, 'accept'); assert.equal(v.trusted, true, JSON.stringify(v));
  // turned off on purpose, unsigned is an ordinary verdict again, and still never trusted, even with a human check
  project = await core.updateSettings(project, { requireSignedRequests: false });
  s = await mint();
  v = await core.verify(project, { token: s.token, client, turnstile: B.human(s, HOST()) }, { ip });
  assert.equal(v.verdict, 'accept'); assert.equal(v.human, 'ok'); assert.equal(v.trusted, false);
});

test('4. trusted needs real input counted on the page, not just the activation flag', async () => {
  // harvest.json: ac true from one --activate click before start(), then k 0 and p 0 on the session itself
  let ip = nextIp(), s = await harvest(ip, { k: 0, p: 0, h: 1 });
  let v = (await post('/demo', sealed(s, { value: 42, visitor: 'visitor' }), tab(ip))).body;
  assert.equal(v.verdict, 'accept'); assert.equal(v.signed, 'ok');
  assert.equal(v.trusted, false, 'no input on the session');
  ip = nextIp(); s = await harvest(ip, { k: 1, p: 0 });
  assert.equal((await post('/demo', sealed(s, { value: 42, visitor: 'visitor' }), tab(ip))).body.trusted, false, 'one key press is not enough');
  ip = nextIp(); s = await harvest(ip, { k: 0, p: 3 });
  assert.equal((await post('/demo', sealedH(s, { value: 42, visitor: 'visitor' }), tab(ip))).body.trusted, true, 'one real click is');
});

test('5. a session factory is cut off per site and network within a minute; other sites and networks are not', async () => {
  const saved = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN;
  process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = '5';
  try {
    const ip = nextIp();
    const a = await core.createProject({ name: 'A', origins: ['https://a.example'] }, nextIp(), 'owner-r11');
    const b = await core.createProject({ name: 'B', origins: ['https://b.example'] }, nextIp(), 'owner-r11');
    const pa = await core.loadProject(a.pid), pb = await core.loadProject(b.pid);
    for (let i = 0; i < 5; i++) await core.startSession(pa, { ip, ua: CHROME, origin: 'https://a.example' }, { pt: 0 });
    await assert.rejects(core.startSession(pa, { ip, ua: CHROME, origin: 'https://a.example' }, { pt: 0 }), (e) => e.status === 429 && e.code === 'rate_limited');
    await core.startSession(pb, { ip, ua: CHROME, origin: 'https://b.example' }, { pt: 0 });
    await core.startSession(pa, { ip: nextIp(), ua: CHROME, origin: 'https://a.example' }, { pt: 0 });
  } finally {
    if (saved === undefined) delete process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN; else process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = saved;
  }
});

test('6. a value has to be a number: "1e3", [1000], true and "1001" are bad_score, 1000 passes', async () => {
  for (const value of ['1e3', [1000], true, '1001', '42', { n: 1 }]) {
    const ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
    const v = (await post('/demo', sealed(s, { value, visitor: 'visitor' }), tab(ip))).body;
    assert.equal(v.verdict, 'reject', JSON.stringify(value));
    assert.ok(codes(v).includes('bad_score'), JSON.stringify(value) + ' ' + JSON.stringify(v.reasons));
  }
  const ip = nextIp(), s = await harvest(ip, { k: 1, p: 3 });
  assert.equal((await post('/demo', sealed(s, { value: 1000, visitor: 'visitor' }), tab(ip))).body.verdict, 'accept');
});

test('a project from before round 11: a pinned 1.3.0 page still corroborates, but unsigned is no longer trusted (round 12)', async () => {
  const pid = 'p_r11legacy' + C.randomId(4), pk = 'pk_r11legacy' + C.randomId(8);
  const old = { reviewAt: 40, rejectAt: 70, maxScore: null, maxScorePerSec: null, minDurationMs: 0, origins: [base], sessionTtlSec: 3600, strictClock: false };
  await kv.cmd('HSET', 'ps:p:' + pid, 'name', 'Legacy', 'pk', pk, 'created', Date.now(), 'settings', JSON.stringify(old));
  await kv.cmd('SET', 'ps:pk:' + pk, pid);
  const project = await core.loadProject(pid);
  assert.equal(project.settings.requireSignedRequests, false, 'old projects keep taking unsigned actions');
  const ip = nextIp();
  const s = await core.startSession(project, { ip, ua: CHROME, origin: base }, { pt: 0 });
  const pinned = Object.keys(B.SDK.supported)[0];
  assert.equal(B.SDK.supported[pinned], '1.3.0');
  await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0, sh: pinned }) }, { ip, ua: CHROME, origin: base, sfs: 'same-origin' });
  const v = await core.verify(project, { token: s.token }, { ip });
  assert.equal(v.client, 'corroborated', JSON.stringify(v.reasons));
  assert.equal(v.verdict, 'accept');
  assert.equal(v.trusted, false, 'unsigned, unbound and no human check: trusted on every project needs all three now');
});

test('the request key is per session, derived on the server, and never in the token', async () => {
  const s = await harvest(nextIp(), {});
  const sid = JSON.parse(Buffer.from(s.token.split('.')[0], 'base64url').toString()).s;
  assert.equal(s.rk, await C.requestKey(sid));
  assert.ok(!s.token.includes(s.rk));
  assert.notEqual((await harvest(nextIp(), {})).rk, s.rk);
  // the canonical form ignores key order and undefined, as JSON.parse on the server would see it
  assert.equal(C.canon({ b: 1, a: [1, 'x', { d: undefined, c: null }] }), '{"a":[1,"x",{"c":null}],"b":1}');
});

test('pyrmi-server: verify({ sealed, req }) sends the signature and the browser context; a rewritten body is rejected', async () => {
  const { Pyrmi } = require('../packages/pyrmi-server');
  const ip = nextIp();
  const p = await core.createProject({ name: 'Server', origins: [base] }, ip, 'owner-r11');
  let project = await core.loadProject(p.pid);
  project = await core.updateSettings(project, { minDurationMs: 0, maxScore: 1000, requireHumanCheck: true });
  const pyrmi = new Pyrmi({ secretKey: p.secretKey, endpoint: base + '/api/v1', turnstileSecret: B.TS_SECRET, trustProxyHops: 1 });
  const req = { headers: { 'user-agent': CHROME, 'sec-ch-ua': CH, 'sec-fetch-site': 'same-origin', 'x-forwarded-for': ip } };
  const mint = async () => {
    const s = await core.startSession(project, { ip, ua: CHROME, origin: base, ch: CH }, { pt: 0 });
    await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: CHROME, origin: base, sfs: 'same-origin' });
    return s;
  };
  let s = await mint();
  let v = await pyrmi.verify({ sealed: sealed(s, { score: 500 }), score: 500, req, user: 'u1' });
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons)); assert.equal(v.signed, 'ok'); assert.equal(v.bound, true);
  assert.equal(v.human, 'none'); assert.equal(trusted(v), false, 'no human check sent');
  s = await mint();
  v = await pyrmi.verify({ sealed: sealed(s, { score: 500 }), score: 500, req, user: 'u1', turnstile: B.human(s, HOST()).token });
  assert.equal(v.human, 'ok', JSON.stringify(v.reasons)); assert.equal(trusted(v), true);
  s = await mint();
  const body = sealed(s, { score: 500 }); body.score = 900;
  v = await pyrmi.verify({ sealed: body, score: body.score, req, user: 'u1' });
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('bad_signature'));
  s = await mint();
  v = await pyrmi.verify({ sealed: sealed(s, { score: 500 }), score: 500, req: { headers: { ...req.headers, 'user-agent': 'curl/8.7' } }, user: 'u1' });
  assert.ok(codes(v).includes('relayed_session')); assert.equal(trusted(v), false);
});
