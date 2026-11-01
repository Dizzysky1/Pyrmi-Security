'use strict';
// Security hardening: the optional human check for trusted, sealed scores and players, client evidence, pyrmi-server's
// address and response handling, limits, session epochs and CORS. Email sign-in is in accounts.test.js.
//   node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';
process.env.TURNSTILE_SITE_KEY = 'test-site-key';
process.env.TURNSTILE_SECRET_KEY = '0x-test-turnstile-secret';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const crypto = require('crypto');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');
const core = require('../api/_lib/core');
const turnstile = require('../api/_lib/turnstile');
const { Pyrmi, trusted, clientOf } = require('../packages/pyrmi-server');

let base, server;
test.before(async () => { await B.fakeTurnstile(); server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const codes = (v) => v.reasons.map((r) => r.code);
let ipn = 1;
const nextIp = () => '198.51.100.' + (ipn++);

// A client written from the public SDK alone: canonical JSON and an HMAC, no Pyrmi internals.
const canon = (v) => (Array.isArray(v) ? '[' + v.map((x) => (x === undefined ? 'null' : canon(x))).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined).map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
    : JSON.stringify(v));
async function noBrowser(extraBody) {
  const H = { 'Content-Type': 'text/plain', Origin: base, 'Sec-Fetch-Site': 'same-origin', 'X-Forwarded-For': nextIp(),
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36',
    'Sec-CH-UA': '"Chromium";v="156", "Google Chrome";v="156", "Not.A/Brand";v="99"' };
  const post = async (p, b) => (await fetch(base + '/api/v1' + p, { method: 'POST', headers: H, body: JSON.stringify(b) })).json();
  const t0 = Date.now();
  const s = await post('/session', { site: 'pk_demo_sandbox', pt: 100 });
  await wait(1700);
  const signals = { wd: false, hl: false, au: [], tp: [], wr: [], dt: 0, ut: 0, ih: 0, k: 2, p: 3, h: 0, pt: 100 + (Date.now() - t0), gt: null, sh: B.SDK.hash, ac: true };
  assert.equal((await post('/signal', { token: s.token, bn: s.bn, n: 1, signals })).ok, true);
  const fields = { value: 42, visitor: 'visitor-abc', ...(extraBody ? extraBody(s) : {}) };
  const ts = Date.now();
  const sig = crypto.createHmac('sha256', Buffer.from(s.rk, 'base64url')).update('pyrmi.req.v1\n' + s.session + '\n' + ts + '\n' + canon(fields)).digest('base64url');
  return post('/demo', { ...fields, pyrmi: { token: s.token, ts, sig } });
}

test('1. a client with no human check gets an accept, never trusted, where the human check is on', async () => {
  const v = await noBrowser();
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.client, 'corroborated'); assert.equal(v.signed, 'ok'); assert.equal(v.bound, true); // all self-reported
  assert.equal(v.human, 'none');
  assert.equal(v.trusted, false); assert.equal(trusted(v), false);
});

test('1b. a made-up human check from that script fails, and says so', async () => {
  const v = await noBrowser(() => ({ turnstile: 'XXXX.DUMMY.TOKEN' }));
  assert.equal(v.human, 'failed');
  assert.ok(codes(v).includes('human_check_failed'), JSON.stringify(v.reasons));
  assert.equal(v.trusted, false);
});

// A project's /verify, the way a site's server calls it, with a clean session and a sealed action.
async function verifyWith(turnstileFor, opts) {
  const o = opts || {};
  const ip = nextIp();
  const p = await core.createProject({ name: 'R12', origins: ['https://shop.example'] }, ip, 'owner-r12');
  const project = await core.updateSettings(await core.loadProject(p.pid), { minDurationMs: 0, maxScore: 1000, ...(o.open ? { requireOrigins: false, origins: [] } : {}) });
  const UA = 'Mozilla/5.0 Chrome/156.0', CH = '"Chromium";v="156"';
  const s = await core.startSession(project, { ip, ua: UA, origin: 'https://shop.example', ch: CH }, { pt: 0 });
  await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: 'https://shop.example', sfs: 'same-site' });
  if (o.before) await o.before(s);
  const client = { ua: UA, ip, ch: CH, sfs: 'same-site', ...(o.client || {}) };
  for (const k of Object.keys(client)) if (client[k] === undefined) delete client[k];
  return core.verify(project, { token: s.token, request: B.sign(s, o.fields || { a: 1 }), client, turnstile: turnstileFor(s), ...(o.body || {}) }, { ip });
}

test('2. the human check is bound to the session, the page, the time and the action', async () => {
  let v = await verifyWith((s) => B.human(s, 'shop.example'));
  assert.equal(v.human, 'ok'); assert.equal(v.trusted, true, JSON.stringify(v));
  const detail = (x) => (x.reasons.find((r) => r.code === 'human_check_failed') || {}).detail;
  v = await verifyWith((s) => B.human(s, 'shop.example', { cdata: 'someOtherSession' }));
  assert.equal(v.trusted, false); assert.match(detail(v), /different session/);
  v = await verifyWith((s) => B.human(s, 'evil.example'));
  assert.equal(v.trusted, false); assert.match(detail(v), /different site/);
  v = await verifyWith((s) => B.human(s, 'shop.example', { challenge_ts: new Date(Date.now() - 3600e3).toISOString() }));
  assert.equal(v.trusted, false); assert.match(detail(v), /before the session/);
  v = await verifyWith((s) => ({ ...B.human(s, 'shop.example', { action: 'login' }), action: 'payout' }));
  assert.equal(v.trusted, false); assert.match(detail(v), /different action/);
  v = await verifyWith((s) => ({ ...B.human(s, 'shop.example'), secret: '0x-someone-elses-secret' }));
  assert.equal(v.trusted, false); assert.match(detail(v), /not passed/);
});

test('2b. a reused pass is refused, and an unreachable Cloudflare means not trusted, without a penalty', async () => {
  const saved = turnstile.endpoint;
  try {
    let tok;
    const ip = nextIp();
    const p = await core.createProject({ name: 'R12b', origins: ['https://shop.example'] }, ip, 'owner-r12');
    const project = await core.updateSettings(await core.loadProject(p.pid), { minDurationMs: 0 });
    const mint = async () => {
      const s = await core.startSession(project, { ip, ua: 'UA', origin: 'https://shop.example' }, { pt: 0 });
      await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: 'UA', origin: 'https://shop.example', sfs: 'same-site' });
      return s;
    };
    const s = await mint();
    tok = B.human(s, 'shop.example');
    const client = { ua: 'UA', ip, sfs: 'same-site' };
    assert.equal((await core.verify(project, { token: s.token, request: B.sign(s, {}), client, turnstile: tok }, { ip })).trusted, true);
    const res = await core.checkHuman(tok, s.session, { o: 'https://shop.example', i: Date.now() - 1000 }, ip);
    assert.deepEqual(res, { state: 'failed', detail: 'already used' });
    turnstile.endpoint = 'http://127.0.0.1:1/unreachable';
    const s2 = await mint();
    const v = await core.verify(project, { token: s2.token, request: B.sign(s2, {}), client, turnstile: B.human(s2, 'shop.example') }, { ip });
    assert.equal(v.human, 'unavailable'); assert.equal(v.trusted, false); assert.equal(v.verdict, 'accept');
    assert.ok(!codes(v).includes('human_check_failed'));
  } finally { turnstile.endpoint = saved; }
});

test('2c. the score and player Pyrmi checks are the ones the page signed', async () => {
  const H = (s) => B.human(s, 'shop.example');
  // signed { score: 1 }, sent score 100: was accept, signed ok, trusted
  let v = await verifyWith(H, { fields: { score: 1 }, body: { score: 100 } });
  assert.equal(v.verdict, 'reject'); assert.equal(v.signed, 'bad'); assert.equal(v.trusted, false);
  assert.match(v.reasons.find((r) => r.code === 'bad_signature').detail, /score differs/);
  v = await verifyWith(H, { fields: { score: 100 }, body: { score: 100 } });
  assert.equal(v.trusted, true, JSON.stringify(v.reasons));
  // a score that matches none of the signed values keeps its verdict but isn't trusted
  v = await verifyWith(H, { fields: { value: 1 }, body: { score: 100 } });
  assert.equal(v.verdict, 'accept'); assert.ok(codes(v).includes('score_not_signed')); assert.equal(v.trusted, false);
  v = await verifyWith(H, { fields: { value: 100 }, body: { score: 100 } });
  assert.equal(v.trusted, true);
  // the documented one-liner sends no score: the signed one is checked against maxScore (1000 here)
  v = await verifyWith(H, { fields: { score: 5000 } });
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('score_over_max')); assert.equal(v.score, 5000);
  v = await verifyWith(H, { fields: { score: 50 } });
  assert.equal(v.verdict, 'accept'); assert.equal(v.score, 50); assert.equal(v.trusted, true);
  v = await verifyWith(H, { fields: { player: 'alice' }, body: { player: 'mallory' } });
  assert.equal(v.verdict, 'reject'); assert.match(v.reasons.find((r) => r.code === 'bad_signature').detail, /player differs/);
});

test('2d. another network, or missing client evidence, is never trusted', async () => {
  const H = (s) => B.human(s, 'shop.example');
  let v = await verifyWith(H, { client: { ip: '203.0.113.200' } });
  assert.ok(codes(v).includes('ip_changed')); assert.equal(v.verdict, 'accept'); assert.equal(v.trusted, false);
  for (const missing of ['ip', 'ch', 'sfs']) {
    v = await verifyWith(H, { client: { [missing]: undefined } });
    assert.equal(v.bound, false, missing); assert.equal(v.trusted, false, missing); assert.equal(v.verdict, 'accept', missing);
  }
  // present but empty client hints, from a browser that sent them at session start: a different client
  v = await verifyWith(H, { client: { ch: '' } });
  assert.match((v.reasons.find((r) => r.code === 'relayed_session') || {}).detail || '', /client hints/);
  assert.equal(v.trusted, false);
});

test('2e. a "__proto__" key on the wire can\'t hide from the signature (sandbox, raw API and pyrmi-server)', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0';
  const tab = { 'Content-Type': 'text/plain', Origin: base, 'Sec-Fetch-Site': 'same-origin', 'User-Agent': UA, 'X-Forwarded-For': ip };
  const s = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: tab, body: JSON.stringify({ site: 'pk_demo_sandbox', pt: 1000 }) })).json();
  await wait(1600);
  await fetch(base + '/api/v1/signal', { method: 'POST', headers: tab, body: JSON.stringify({ token: s.token, ...B.order(s), signals: B.signals({ pt: 2600 }) }) });
  const q = B.sign(s, { value: 5, visitor: 'visitor' });
  const raw = '{"__proto__":{"isAdmin":true},' + JSON.stringify({ ...q.fields, pyrmi: { token: s.token, ts: q.ts, sig: q.sig } }).slice(1);
  const v = await (await fetch(base + '/api/v1/demo', { method: 'POST', headers: tab, body: raw })).json();
  assert.equal(v.verdict, 'reject'); assert.equal(v.signed, 'bad');
  assert.match(v.reasons.find((r) => r.code === 'bad_signature').detail, /__proto__/);
  // the raw API: fields carrying an own "__proto__" (as JSON.parse makes it) are refused outright
  const t = { s: 'x', i: Date.now() - 1000 };
  assert.deepEqual(await core.checkSigned({ fields: JSON.parse('{"__proto__":{},"a":1}'), ts: Date.now(), sig: 'A'.repeat(43) }, t, Date.now()), { state: 'bad', detail: 'forbidden key __proto__' });
  // pyrmi-server keeps it as a field and sends it, so Pyrmi sees it
  let sent;
  const saved = global.fetch;
  global.fetch = async (u, o) => { sent = JSON.parse(o.body); return new Response(JSON.stringify({ ok: true, verdict: 'reject', risk: 100, reasons: [] }), { status: 200 }); };
  try {
    await new Pyrmi({ secretKey: 'sk_' + 'x'.repeat(30), endpoint: 'http://local.invalid/api/v1' }).verify({ sealed: JSON.parse('{"__proto__":{"isAdmin":true},"value":5,"pyrmi":{"token":"t","ts":1,"sig":"s"}}'), client: {} });
  } finally { global.fetch = saved; }
  assert.ok(Object.prototype.hasOwnProperty.call(sent.request.fields, '__proto__'));
  // the general case: any key the page didn't sign, added on the wire, is a bad signature ("arrived exactly as sealed")
  for (const extra of ['{"isAdmin":true,', '{"constructor":{"prototype":{"x":1}},', '{"prototype":1,']) {
    const s2 = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: tab, body: JSON.stringify({ site: 'pk_demo_sandbox', pt: 1000 }) })).json();
    await wait(1600);
    await fetch(base + '/api/v1/signal', { method: 'POST', headers: tab, body: JSON.stringify({ token: s2.token, ...B.order(s2), signals: B.signals({ pt: 2600 }) }) });
    const q2 = B.sign(s2, { value: 5, visitor: 'visitor' });
    const v2 = await (await fetch(base + '/api/v1/demo', { method: 'POST', headers: tab, body: extra + JSON.stringify({ ...q2.fields, pyrmi: { token: s2.token, ts: q2.ts, sig: q2.sig } }).slice(1) })).json();
    assert.equal(v2.signed, 'bad', extra); assert.equal(v2.verdict, 'reject', extra);
  }
  // reserved labels keep a distinct, visible player name, and KV hashes keep a "__proto__" field
  assert.notEqual(core.cleanPlayer('__proto__'), '__proto__'); assert.match(core.cleanPlayer('__proto__'), /^__proto__~[0-9a-f]{8}$/);
  assert.equal(core.cleanPlayer('alice'), 'alice');
  assert.equal(require('../api/_lib/kv').pairs(['__proto__', 'x', 'a', 'b']).__proto__, 'x');
});

test('2f. a client claiming Safari (or any browser) that sends no fetch metadata is never bound', async () => {
  const ok = (ua) => core.sendsFetchMetadata(ua);
  assert.equal(ok('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15'), true);
  assert.equal(ok('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15'), true);
  assert.equal(ok('Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1'), true);
  assert.equal(ok('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15'), false);
  const SAFARI = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15';
  const OLD = SAFARI.replace('17.4', '15.6');
  const sess = { uh: await require('../api/_lib/crypto').fingerprint('ua', SAFARI) };
  let r = await core.relayed({ ua: SAFARI, ip: '192.0.2.1', ch: '', sfs: '' }, sess, SAFARI);
  assert.match(r.detail, /not sent by a browser/);
  r = await core.relayed({ ua: OLD, ip: '192.0.2.1', ch: '', sfs: '' }, {}, OLD);
  assert.equal(r.bound, false); assert.equal(r.detail, '');
  r = await core.relayed({ ua: SAFARI, ip: '192.0.2.1', ch: '', sfs: 'same-origin' }, sess, SAFARI);
  assert.equal(r.bound, true); assert.equal(r.detail, '');
});

test('2g. a NaN or Infinity score through pyrmi-server is a reject, not a skipped cap', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: 'R12n', origins: ['https://shop.example'] }, ip, 'owner-r12');
  const project = await core.updateSettings(await core.loadProject(p.pid), { minDurationMs: 0, maxScore: 1000, requireSignedRequests: false });
  const saved = global.fetch;
  global.fetch = async (u, o) => new Response(JSON.stringify(await core.verify(project, JSON.parse(o.body), { ip })), { status: 200 });
  try {
    const px = new Pyrmi({ secretKey: 'sk_' + 'x'.repeat(30), endpoint: 'http://local.invalid/api/v1' });
    for (const score of [JSON.parse('1e400'), Number('abc'), -Infinity]) {
      const s = await core.startSession(project, { ip, ua: UA, origin: 'https://shop.example' }, { pt: 0 });
      await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: 'https://shop.example', sfs: 'same-site' });
      const v = await px.verify({ token: s.token, score, client: { ua: UA, ip, sfs: 'same-site' } });
      assert.equal(v.verdict, 'reject', String(score)); assert.ok(codes(v).includes('bad_score'), String(score));
    }
  } finally { global.fetch = saved; }
  // a signed score that arrived as null (how JSON carries Infinity) is refused too
  const v = await verifyWith((s) => B.human(s, 'shop.example'), { fields: { score: null } });
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('bad_score'));
});

test('2h. deleting the same project from several requests at once gives back one slot', async () => {
  const kv = require('../api/_lib/kv');
  const a = await core.createProject({ name: 'Race', origins: ['https://race.example'] }, nextIp(), 'owner-race');
  const before = Number(await kv.cmd('GET', 'ps:projects'));
  const pa = await core.loadProject(a.pid);
  await Promise.all([core.deleteProject(pa), core.deleteProject(pa), core.deleteProject(pa)]);
  assert.equal(Number(await kv.cmd('GET', 'ps:projects')), before - 1);
  await assert.rejects(kv.pipeline([['RENAME', 'a', 'b']]), /own key prefixing/);
});

test('2i. keyless junk from a shared network can\'t lock the owner out of /project or /dashboard', async () => {
  const p = await core.createProject({ name: 'Owner', origins: ['https://o.example'] }, nextIp(), 'owner-p04');
  const nat = nextIp();
  const get = async (path, key) => (await fetch(base + '/api/v1' + path, { headers: { 'X-Forwarded-For': nat, ...(key ? { Authorization: 'Bearer ' + key } : {}) } })).status;
  for (const path of ['/project', '/dashboard']) {
    for (let i = 0; i < 70; i++) await get(path);
    for (let i = 0; i < 25; i++) await get(path, 'sk_' + 'w'.repeat(30) + i);
    assert.equal(await get(path, p.secretKey), 200, path);
  }
});

test('2j. a beacon counter that jumps far ahead is dropped, so it can\'t freeze the session', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0';
  const p = await core.createProject({ name: 'N', origins: ['https://n.example'] }, ip, 'owner-n');
  const project = await core.loadProject(p.pid);
  const s = await core.startSession(project, { ip, ua: UA, origin: 'https://n.example' }, { pt: 0 });
  const ctx = { ip, ua: UA, origin: 'https://n.example', sfs: 'same-origin' };
  assert.equal((await core.recordSignals({ token: s.token, bn: s.bn, n: 2 ** 53 - 1, signals: B.signals({ pt: 0 }) }, ctx)).dropped, 'out_of_order');
  assert.equal((await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 0 }) }, ctx)).ok, true);
  assert.equal((await core.recordSignals({ token: s.token, bn: s.bn, n: 3, signals: B.signals({ pt: 0 }) }, ctx)).dropped, undefined);
});

test('2k. more proxy hops than X-Forwarded-For entries falls back to the socket, never the caller\'s own entry', async () => {
  const req = { headers: { 'x-forwarded-for': '203.0.113.66' }, socket: { remoteAddress: '10.0.0.9' } };
  assert.equal(clientOf(req, 2).ip, '10.0.0.9');
  const { clientIp } = require('../api/_lib/http');
  const saved = process.env.PYRMI_PROXY_HOPS;
  try { process.env.PYRMI_PROXY_HOPS = '2'; assert.equal(clientIp(req), '10.0.0.9'); } finally { if (saved === undefined) delete process.env.PYRMI_PROXY_HOPS; else process.env.PYRMI_PROXY_HOPS = saved; }
});

test('2l. non-string inputs are refused, not a 500 (email sign-in, the sandbox, the client sent to verify)', async () => {
  const accounts = require('../api/_lib/accounts');
  const saved = process.env.RESEND_API_KEY; process.env.RESEND_API_KEY = 're_test';
  try {
    const odd = JSON.parse('{"toString":null}');
    await assert.rejects(accounts.emailStart({ email: odd }, nextIp(), async () => {}), (e) => e.status === 400);
    await assert.rejects(accounts.emailVerify({ email: 'a@b.co', code: odd }, nextIp(), {}), (e) => e.status >= 400 && e.status < 500);
  } finally { if (saved === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = saved; }
  const v = await verifyWith((s) => B.human(s, 'shop.example'), { client: { ua: JSON.parse('{"toString":null}'), ip: JSON.parse('{"toString":null}') } });
  assert.equal(v.ok, true); assert.equal(v.trusted, false);
});

test('2m. claiming a key-only project issues a new key; the old holder loses it', async () => {
  const accounts = require('../api/_lib/accounts');
  const p = await core.createProject({ name: 'Anon', origins: ['https://a.example'] }, nextIp());
  const site = await accounts.claimSite('u_r12_' + Date.now(), p.secretKey);
  assert.match(site.secretKey, /^sk_/);
  assert.equal(await core.projectBySecretKey(p.secretKey), null);
  assert.equal((await core.projectBySecretKey(site.secretKey)).pid, p.pid);
});

test('2o. rotating the key or claiming the project ends sessions started before it; a deleted project takes no beacons', async () => {
  const accounts = require('../api/_lib/accounts');
  const UA = 'Mozilla/5.0 Chrome/156.0', O = 'https://e.example';
  const mk = async (owner) => {
    const ip = nextIp();
    const p = await core.createProject({ name: 'Epoch', origins: [O] }, ip, owner);
    await core.updateSettings(await core.loadProject(p.pid), { minDurationMs: 0, maxScore: 1000 });
    return { p, ip };
  };
  const live = async (pid, ip) => {
    const s = await core.startSession(await core.loadProject(pid), { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-site' });
    return s;
  };
  const beacon = (s, ip) => core.recordSignals({ token: s.token, bn: s.bn, n: 2, signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-site' });
  const check = async (pid, s, ip) => core.verify(await core.loadProject(pid), { token: s.token, request: B.sign(s, { a: 1 }), client: { ua: UA, ip, sfs: 'same-site' } }, { ip });

  // Rotation
  let { p, ip } = await mk('owner-ep');
  let before = await live(p.pid, ip);
  await core.rotateSecret(await core.loadProject(p.pid), p.secretKey);
  let v = await check(p.pid, before, ip);
  assert.equal(v.verdict, 'reject'); assert.ok(codes(v).includes('invalid_token'), JSON.stringify(v.reasons));
  await assert.rejects(beacon(before, ip), (e) => e.status === 410 && e.code === 'revoked');
  const after = await live(p.pid, ip);
  v = await check(p.pid, after, ip);
  assert.ok(!codes(v).includes('invalid_token'), JSON.stringify(v.reasons));

  // Claim, with or without a new key
  for (const keepKey of [false, true]) {
    ({ p, ip } = await mk());
    before = await live(p.pid, ip);
    await accounts.claimSite('u_ep_' + keepKey + Date.now(), p.secretKey, { keepKey });
    v = await check(p.pid, before, ip);
    assert.ok(codes(v).includes('invalid_token'), 'keepKey ' + keepKey + ': ' + JSON.stringify(v.reasons));
  }

  // Delete
  ({ p, ip } = await mk('owner-ep'));
  before = await live(p.pid, ip);
  await core.deleteProject(await core.loadProject(p.pid));
  await assert.rejects(beacon(before, ip), (e) => e.status === 410);
});

test('2p. with the human check on, loosened caps don\'t make a run trusted, and a pass checked with another secret fails', async () => {
  const ip = nextIp(), O = 'https://g.example', UA = 'Mozilla/5.0 Chrome/156.0', CH = '"Chromium";v="156"';
  const p = await core.createProject({ name: 'Loose', origins: [O] }, ip, 'owner-loose');
  // What someone holding sk_ can do through /project: loosen the policy and add a page of their own.
  const loose = await core.updateSettings(await core.projectBySecretKey(p.secretKey), { maxScore: null, requireScoreLimit: false, minDurationMs: 0,
    requireSignedRequests: false, signedTrust: false, requireHumanCheck: true, origins: [O, 'https://other.example'] });
  // (signedTrust: false is stored, but every project's trusted() needs the seal whatever it says.)
  const run = async (origin, turnstile) => {
    const s = await core.startSession(loose, { ip, ua: UA, origin, ch: CH }, { pt: 0 });
    await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin, sfs: 'same-site' });
    return core.verify(loose, { token: s.token, score: 999999, request: B.sign(s, { score: 999999 }), client: { ua: UA, ip, ch: CH, sfs: 'same-site' },
      ...(turnstile ? { turnstile: turnstile(s) } : {}) }, { ip });
  };
  let v = await run(O);
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons)); // loose caps let any score through...
  assert.equal(v.trusted, false); assert.equal(trusted(v), false); // ...but with the switch on there's no trusted without a pass
  // A pass is checked with the secret the site's server sends; one checked with another secret fails.
  v = await run('https://other.example', (s) => ({ ...B.human(s, 'other.example'), secret: '0x-some-other-secret' }));
  assert.equal(v.trusted, false); assert.equal(v.human, 'failed');
});

test('2n. one site\'s session allowance can\'t lock a network out of another site; a rejected text score isn\'t logged as a number', async () => {
  const saved = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN; process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = '100000';
  try {
    const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0';
    const demo = await core.loadProject(core.DEMO.pid);
    const shop = await core.loadProject((await core.createProject({ name: 'Shop', origins: ['https://shop.example'] }, nextIp(), 'o')).pid);
    let refused = false;
    for (let i = 0; i < 160 && !refused; i++) await core.startSession(demo, { ip, ua: UA, origin: 'https://evil.example' }, { pt: 0 }).catch(() => { refused = true; });
    assert.equal(refused, true, 'the sandbox allowance does run out');
    await core.startSession(shop, { ip, ua: UA, origin: 'https://shop.example' }, { pt: 0 }); // and the shop still works
    const p = await core.updateSettings(shop, { minDurationMs: 0, maxScore: 1000, requireSignedRequests: false });
    const ip2 = nextIp();
    const s = await core.startSession(p, { ip: ip2, ua: UA, origin: 'https://shop.example' }, { pt: 0 });
    const v = await core.verify(p, { token: s.token, score: '10' }, { ip: ip2 });
    assert.equal(v.verdict, 'reject'); assert.equal(v.score, null);
    assert.deepEqual(core.warnings({ origins: ['x'], minDurationMs: 1, maxScore: null, maxScorePerSec: 10, requireScoreLimit: true }).map((w) => w.code), ['per_sec_only']);
  } finally { if (saved === undefined) delete process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN; else process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = saved; }
});

test('3. new projects take sealed actions only; old ones keep taking unsigned ones, never trusted; the human check is a switch', async () => {
  assert.equal(core.DEFAULTS.requireSignedRequests, true);
  assert.equal(core.LEGACY_DEFAULTS.requireSignedRequests, false);
  assert.equal(core.isTrusted('accept', 'corroborated', [], true, { inputs: 9, signed: 'none', bound: true, human: 'ok' }), false);
  assert.equal(core.isTrusted('accept', 'corroborated', [], true, { inputs: 9, signed: 'ok', bound: false, human: 'ok' }), false);
  assert.equal(core.DEFAULTS.requireHumanCheck, false); assert.equal(core.DEMO.settings.requireHumanCheck, true);
  const t = (human, requireHuman) => core.isTrusted('accept', 'corroborated', [], true, { inputs: 9, signed: 'ok', bound: true, human, requireHuman });
  assert.equal(t('none', false), true); assert.equal(t('ok', false), true);
  assert.equal(t('unavailable', false), false); assert.equal(t('failed', false), false); // a pass that was sent must be ok
  assert.equal(t('none', true), false); assert.equal(t('unavailable', true), false); assert.equal(t('ok', true), true);
});

test('4. pyrmi-server ignores X-Forwarded-For unless told how many proxies wrote it', () => {
  const req = { headers: { 'x-forwarded-for': '6.6.6.6, 198.51.100.4', 'user-agent': 'UA' }, socket: { remoteAddress: '192.0.2.50' } };
  assert.equal(clientOf(req).ip, '192.0.2.50', 'the caller typed 6.6.6.6');
  assert.equal(clientOf(req, 0).ip, '192.0.2.50');
  assert.equal(clientOf(req, 1).ip, '198.51.100.4');
  assert.equal(clientOf(req, 2).ip, '6.6.6.6');
  assert.equal(clientOf({ headers: { 'x-forwarded-for': '6.6.6.6' } }).ip, '');
});

test('5. pyrmi-server: a 200 that is not a verdict is a reject (or failOpen\'s unverified accept), never {}', async () => {
  const junk = http.createServer((q, r) => { r.statusCode = 200; r.setHeader('Content-Type', 'text/html'); r.end('<html>checking your browser</html>'); });
  await new Promise((r) => junk.listen(0, '127.0.0.1', r));
  const empty = http.createServer((q, r) => { r.statusCode = 200; r.setHeader('Content-Type', 'application/json'); r.end('{"ok":true}'); });
  await new Promise((r) => empty.listen(0, '127.0.0.1', r));
  try {
    for (const srv of [junk, empty]) {
      const endpoint = 'http://127.0.0.1:' + srv.address().port;
      const v = await new Pyrmi({ secretKey: 'sk_test', endpoint }).verify({ token: 'x' });
      assert.equal(v.verdict, 'reject'); assert.equal(v.unverified, true); assert.equal(trusted(v), false);
      const open = await new Pyrmi({ secretKey: 'sk_test', endpoint, failOpen: true }).verify({ token: 'x' });
      assert.equal(open.verdict, 'accept'); assert.equal(open.unverified, true); assert.equal(trusted(open), false);
    }
  } finally { junk.close(); empty.close(); }
});

test('6. anonymous demo dashboard lookups don\'t use up a site owner\'s dashboard allowance', async () => {
  const saved = process.env.PYRMI_DEMO_DASHBOARD_PER_MIN;
  process.env.PYRMI_DEMO_DASHBOARD_PER_MIN = '3';
  try {
    const ip = nextIp();
    const p = await core.createProject({ name: 'Dash', origins: ['https://shop.example'] }, ip, 'owner-r12');
    const get = (q, h) => fetch(base + '/api/v1/dashboard' + q, { headers: { 'X-Forwarded-For': ip, ...(h || {}) } });
    for (let i = 0; i < 3; i++) assert.equal((await get('?demo=1')).status, 200);
    assert.equal((await get('?demo=1')).status, 429);
    assert.equal((await get('', { Authorization: 'Bearer ' + p.secretKey })).status, 200);
  } finally { if (saved === undefined) delete process.env.PYRMI_DEMO_DASHBOARD_PER_MIN; else process.env.PYRMI_DEMO_DASHBOARD_PER_MIN = saved; }
});

test('7. CORS lane: no trusted on an open site, Origin null never echoed, wrong keys capped, /signal errors opaque', async () => {
  // a site with no allowed origins is open to any page, so it can still accept but is never trusted.
  assert.equal((await verifyWith((s) => B.human(s, 'shop.example'))).trusted, true);
  const open = await verifyWith((s) => B.human(s, 'shop.example'), { open: true });
  assert.equal(open.verdict, 'accept'); assert.equal(open.human, 'ok'); assert.equal(open.trusted, false);
  const post = async (p, body, h) => { const r = await fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'text/plain', ...h }, body: JSON.stringify(body) }); return { status: r.status, acao: r.headers.get('access-control-allow-origin') }; };
  // Origin: null is never echoed, so a sandboxed or data: page can't read a session answer.
  const ip = nextIp();
  const p = await core.createProject({ name: 'R12c', origins: ['https://shop.example'] }, ip, 'owner-r12');
  await core.updateSettings(await core.loadProject(p.pid), { requireOrigins: false, origins: [] });
  const n = await post('/api/v1/session', { site: p.publicKey }, { Origin: 'null', 'X-Forwarded-For': ip });
  assert.equal(n.acao, null);
  assert.equal((await post('/api/v1/session', { site: p.publicKey }, { Origin: 'https://any.example', 'X-Forwarded-For': ip })).acao, 'https://any.example');
  // wrong public keys are capped per network; the answer stays readable for a developer's typo.
  const saved = process.env.PYRMI_UNKNOWN_SITE_PER_IP;
  process.env.PYRMI_UNKNOWN_SITE_PER_IP = '3';
  try {
    const ip2 = nextIp(), h = { Origin: 'https://any.example', 'X-Forwarded-For': ip2 };
    for (let i = 0; i < 3; i++) { const r = await post('/api/v1/session', { site: 'pk_nosuchsite' + i }, h); assert.equal(r.status, 404); assert.equal(r.acao, 'https://any.example'); }
    assert.equal((await post('/api/v1/session', { site: 'pk_nosuchsite9' }, h)).status, 429);
  } finally { if (saved === undefined) delete process.env.PYRMI_UNKNOWN_SITE_PER_IP; else process.env.PYRMI_UNKNOWN_SITE_PER_IP = saved; }
  // another page can't read /signal's answer for a bad token.
  const g = await post('/api/v1/signal', { token: 'junk', signals: {} }, { Origin: 'https://evil.example', 'X-Forwarded-For': nextIp() });
  assert.equal(g.status, 400); assert.equal(g.acao, null);
});

test('8. the dashboard\'s same-origin check and OAuth return address ignore a typed X-Forwarded-Host off Vercel', () => {
  const accounts = require('../api/_lib/accounts');
  const csrf = (h) => { try { accounts.checkCsrf({ method: 'POST', headers: { 'x-pyrmi-csrf': '1', host: 'pyrmi.example', ...h } }); return 'pass'; } catch (_) { return 'refused'; } };
  const savedV = process.env.VERCEL_ENV, savedU = process.env.PYRMI_PUBLIC_URL;
  try {
    delete process.env.VERCEL_ENV; delete process.env.PYRMI_PUBLIC_URL;
    assert.equal(csrf({ origin: 'https://evil.example', 'x-forwarded-host': 'evil.example' }), 'refused');
    assert.equal(csrf({ origin: 'https://pyrmi.example' }), 'pass');
    process.env.PYRMI_PUBLIC_URL = 'https://dash.example';
    assert.equal(csrf({ origin: 'https://dash.example' }), 'pass');
    process.env.VERCEL_ENV = 'production'; delete process.env.PYRMI_PUBLIC_URL;
    assert.equal(csrf({ origin: 'https://pyrmi.com', 'x-forwarded-host': 'pyrmi.com' }), 'pass');
    // the OAuth return address comes from the request's own Host off Vercel.
    delete process.env.VERCEL_ENV;
    assert.equal(accounts.baseUrl({ headers: { host: 'pyrmi.example', 'x-forwarded-host': 'evil.example' } }), 'https://pyrmi.example');
  } finally {
    if (savedV === undefined) delete process.env.VERCEL_ENV; else process.env.VERCEL_ENV = savedV;
    if (savedU === undefined) delete process.env.PYRMI_PUBLIC_URL; else process.env.PYRMI_PUBLIC_URL = savedU;
  }
});

test('9. a long user agent is only read for its first 1 KB', () => {
  const long = 'Mozilla/5.0 Version/17.0 ' + 'a'.repeat(15000) + ' Safari/605';
  const t = process.hrtime.bigint();
  for (let i = 0; i < 20; i++) core.sendsFetchMetadata('OS 17_0 ' + ' '.repeat(15000));
  assert.equal(core.sendsFetchMetadata(long), false);
  assert.ok(Number(process.hrtime.bigint() - t) / 1e6 < 200);
  assert.equal(core.sendsFetchMetadata('Mozilla/5.0 (Macintosh) AppleWebKit/605 Version/17.0 Safari/605'), true);
});
