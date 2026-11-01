'use strict';
// Retest of b127c08 (round 10): secure defaults for new projects, quota and email caps a spread-out source can't
// drain, a pinned SDK with Subresource Integrity, a signing secret that fails closed, and the small items.
//   node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const accounts = require('../api/_lib/accounts');
const { signals, order } = require('./_browser');

let ipn = 10;
const nextIp = () => '203.0.114.' + (ipn++);
const UA = 'r10-ua', ORIGIN = 'https://r10.example';
const page = (ip, origin) => ({ ip, ua: UA, origin: origin === undefined ? ORIGIN : origin, sfs: 'same-site' });
const withEnv = async (vars, fn) => {
  const saved = {};
  for (const [k, v] of Object.entries(vars)) { saved[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally { for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } }
};
const codes = (v) => v.reasons.map((r) => r.code);
// A clean session whose start the server recorded `ago` ms in the past (so the minimum time is met without waiting).
async function aged(project, ip, ago) {
  const s = await core.startSession(project, page(ip), { pt: 0 });
  const then = Date.now() - ago;
  await kv.cmd('HSET', 'ps:s:' + s.session, 'i', then);
  const token = await C.signToken({ ...(await C.readToken(s.token)), i: then });
  await core.recordSignals({ token, ...order(s), signals: signals({ pt: ago }) }, page(ip));
  return { ...s, token };
}

test('a new project must name the pages that will run the script', async () => {
  await assert.rejects(core.createProject({ name: 'Open' }, nextIp(), 'owner-r10'), (e) => e.status === 400 && e.code === 'origins_required');
  // asking to skip it at creation doesn't work either
  await assert.rejects(core.createProject({ name: 'Open', settings: { requireOrigins: false } }, nextIp(), 'owner-r10'), (e) => e.code === 'origins_required');
  const p = await core.createProject({ name: 'Bound', origins: [ORIGIN] }, nextIp(), 'owner-r10');
  assert.equal(p.settings.minDurationMs, 1500);
  assert.equal(p.settings.requireOrigins, true);
  assert.equal(p.settings.requireScoreLimit, true);
  // and can't quietly clear them later
  const project = await core.loadProject(p.pid);
  await assert.rejects(core.updateSettings(project, { origins: [] }), (e) => e.status === 400 && e.code === 'origins_required');
  // turning it off is a deliberate choice, and the dashboard says the project is open
  const open = await core.updateSettings(project, { origins: [], requireOrigins: false });
  assert.deepEqual(open.settings.origins, []);
  assert.deepEqual((await core.dashboard(open)).warnings.map((w) => w.code), ['open']);
});

test('a new project rejects an instant action and a value with no limit, until it is set up', async () => {
  const p = await core.createProject({ name: 'Game', origins: [ORIGIN] }, nextIp(), 'owner-r10');
  let project = await core.updateSettings(await core.loadProject(p.pid), { requireSignedRequests: false }); // about the gate, not sealing
  const ip = nextIp();
  const quick = await core.startSession(project, page(ip), { pt: 0 });
  assert.ok(codes(await core.verify(project, { token: quick.token, player: 'p' }, { ip })).includes('too_short'));
  const noLimit = await core.verify(project, { token: (await aged(project, ip, 5000)).token, score: 999999, player: 'p' }, { ip });
  assert.equal(noLimit.verdict, 'reject');
  assert.deepEqual(codes(noLimit), ['no_score_limit']);
  project = await core.updateSettings(project, { maxScore: 1000 });
  const ok = await core.verify(project, { token: (await aged(project, ip, 5000)).token, score: 500, player: 'p' }, { ip });
  assert.equal(ok.verdict, 'accept', JSON.stringify(ok.reasons));
  // an action with no value needs no limit
  const plain = await core.verify(project, { token: (await aged(project, ip, 5000)).token, player: 'p' }, { ip });
  assert.equal(plain.verdict, 'accept');
});

test('a project made before secure defaults keeps working exactly as it did, and the dashboard warns', async () => {
  const pid = 'p_legacy' + C.randomId(4), pk = 'pk_legacy' + C.randomId(8);
  const old = { reviewAt: 40, rejectAt: 70, maxScore: null, maxScorePerSec: null, minDurationMs: 0, origins: [], sessionTtlSec: 3600, strictClock: false };
  await kv.cmd('HSET', 'ps:p:' + pid, 'name', 'Legacy', 'pk', pk, 'created', Date.now(), 'settings', JSON.stringify(old));
  await kv.cmd('SET', 'ps:pk:' + pk, pid);
  const project = await core.loadProject(pid);
  assert.equal(project.settings.requireOrigins, false);
  assert.equal(project.settings.requireScoreLimit, false);
  const ip = nextIp();
  const s = await core.startSession(project, page(ip, 'https://anywhere.example'), { pt: 0 });
  await core.recordSignals({ token: s.token, ...order(s), signals: signals() }, page(ip, 'https://anywhere.example'));
  const v = await core.verify(project, { token: s.token, score: 10, player: 'x' }, { ip });
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.deepEqual((await core.dashboard(project)).warnings.map((w) => w.code), ['open', 'instant', 'no_score_limit']);
  // a server that wants every project bound can still say so
  await withEnv({ PYRMI_REQUIRE_ORIGINS: 'all' }, () => assert.rejects(core.startSession(project, page(nextIp()), { pt: 0 }), (e) => e.code === 'origin_required'));
  // and one that wants none can turn the rule off
  await withEnv({ PYRMI_REQUIRE_ORIGINS: 'off' }, async () => {
    const p = await core.createProject({ name: 'Anywhere' }, nextIp(), 'owner-r10');
    assert.equal(p.settings.requireOrigins, false);
  });
});

test('session quota: a few heavy networks cut themselves off, not the players who come after them', async () => {
  await withEnv({ PYRMI_SESSIONS_PER_DAY: '10', PYRMI_SESSIONS_PER_IP_OVER_QUOTA: '2', PYRMI_SESSIONS_HARD_PER_DAY: '14', PYRMI_SESSIONS_PER_IP: '1000' }, async () => {
    const p = await core.createProject({ name: 'Popular', origins: [ORIGIN] }, nextIp(), 'owner-r10');
    const project = await core.loadProject(p.pid);
    const heavy = ['198.18.0.1', '198.18.0.2'];
    const start = (ip) => core.startSession(project, page(ip), { pt: 0 });
    for (let i = 0; i < 5; i++) for (const ip of heavy) await start(ip); // 10: the soft limit
    assert.equal((await core.dashboard(project)).warnings.some((w) => w.code === 'quota'), true, 'warned before the limit');
    // the drainers are now refused...
    for (const ip of heavy) await assert.rejects(start(ip), (e) => e.status === 429 && e.code === 'quota');
    // ...but a player on another network still gets in, twice
    await start('198.18.1.1'); await start('198.18.1.1');
    await assert.rejects(start('198.18.1.1'), (e) => e.code === 'quota');
    // refused requests don't count against the project
    assert.equal(Number(await kv.cmd('GET', 'ps:q:' + project.pid + ':' + core.ymd(Date.now()))), 12);
    // and the hard ceiling still bounds it
    await start('198.18.2.1'); await start('198.18.3.1');
    await assert.rejects(start('198.18.4.1'), (e) => e.code === 'quota' && /daily session limit/.test(e.message));
  });
});

test('per-network limits count a whole IPv6 /64 as one network', async () => {
  assert.equal(core.network('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(core.network('2001:0db8:0001:0002:ffff:ffff:ffff:ffff'), '2001:db8:1:2::/64');
  assert.equal(core.network('::ffff:192.0.2.7'), '192.0.2.7');
  assert.equal(core.network('192.0.2.7'), '192.0.2.7');
  await withEnv({ PYRMI_SESSIONS_PER_IP_PER_DAY: '3' }, async () => {
    const p = await core.createProject({ name: 'V6', origins: [ORIGIN] }, nextIp(), 'owner-r10');
    const project = await core.loadProject(p.pid);
    for (let i = 1; i <= 3; i++) await core.startSession(project, page('2001:db8:5:5::' + i), { pt: 0 });
    await assert.rejects(core.startSession(project, page('2001:db8:5:5:dead:beef::9'), { pt: 0 }), (e) => e.code === 'quota');
    await core.startSession(project, page('2001:db8:5:6::1'), { pt: 0 });
  });
});

test('the signing secret fails closed: no secret, no tokens, and nothing kept in the store', async () => {
  await withEnv({ PYRMI_SECRET: undefined, PYRMI_KV: 'upstash' }, async () => {
    await assert.rejects(C.signToken({ v: 1 }), (e) => e.status === 503 && e.code === 'secret_not_configured');
    await assert.rejects(C.readToken('x.y'), (e) => e.status === 503);
  });
  await withEnv({ PYRMI_SECRET: 'too-short', PYRMI_KV: 'upstash' }, () => assert.rejects(C.fingerprint('ip', '1.2.3.4'), (e) => e.status === 503));
  // the in-memory store (dev, tests, previews with no Redis) uses a secret for this process only, written nowhere
  await withEnv({ PYRMI_SECRET: undefined }, async () => {
    const tok = await C.signToken({ v: 1 });
    assert.deepEqual(await C.readToken(tok), { v: 1 });
    assert.equal(await kv.cmd('GET', 'ps:secret'), null);
  });
  assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '../api/_lib/crypto.js'), 'utf8'), /ps:secret'/);
});

test('player labels that needed cleaning no longer collide', () => {
  const a = core.cleanPlayer('a<b'), b = core.cleanPlayer('a>b'), c = core.cleanPlayer('a/b');
  assert.equal(new Set([a, b, c]).size, 3);
  assert.match(a, /^a_b~[0-9a-f]{8}$/);
  assert.equal(core.cleanPlayer('alice'), 'alice'); // ordinary labels are unchanged
  assert.equal(core.cleanPlayer('carol@example.com'), 'carol@example.com');
  assert.equal(core.cleanPlayer(''), 'anonymous');
});

test('pyrmi.com\'s public dashboard shows no session ids and no network labels', async () => {
  await withEnv({ PYRMI_SITE_GUARD: undefined }, async () => {
    const site = await core.loadProject(core.SITE.pid);
    const ip = nextIp();
    const s = await core.startSession(site, page(ip, 'https://pyrmi.com'), { pt: 0 });
    await core.guardSite(s.token, ip).catch(() => {}); // logs a verdict either way
    const d = await core.dashboard(site);
    assert.ok(d.events.length > 0);
    assert.ok(d.events.every((e) => !('sid' in e) && e.player === 'visitor'), JSON.stringify(d.events[0]));
    assert.deepEqual(d.players, []);
    assert.ok(!JSON.stringify(d).includes('net-'));
  });
});

test('projects made without an account can fill only their own share of the server', async () => {
  const anonNow = Number((await kv.cmd('GET', 'ps:projects:anon')) || 0);
  await withEnv({ PYRMI_MAX_ANON_PROJECTS: String(anonNow + 1), PYRMI_PROJECTS_PER_IP: '50' }, async () => {
    const ip = nextIp();
    const anon = await core.createProject({ name: 'Key only', origins: [ORIGIN] }, ip);
    await assert.rejects(core.createProject({ name: 'Key only 2', origins: [ORIGIN] }, ip), (e) => e.status === 403 && e.code === 'at_capacity');
    // signed-in sites are unaffected
    await core.createProject({ name: 'Mine', origins: [ORIGIN] }, ip, 'owner-r10');
    // claiming the key-only project into an account frees its slot
    await accounts.claimSite('u_r10' + C.randomId(4), anon.secretKey);
    await core.createProject({ name: 'Key only 3', origins: [ORIGIN] }, ip);
  });
});

test('the browser script is served from a pinned path with an integrity hash everywhere it is shown', () => {
  const root = path.join(__dirname, '..');
  const meta = require('../api/_lib/sdk-build.json');
  const file = fs.readFileSync(path.join(root, 'sdk', meta.version, 'pyrmi.js'));
  assert.equal(meta.path, '/sdk/' + meta.version + '/pyrmi.js');
  assert.equal(meta.integrity, 'sha384-' + crypto.createHash('sha384').update(file).digest('base64'));
  assert.ok(file.equals(fs.readFileSync(path.join(root, 'sdk/pyrmi.js'))), 'the alias serves the same build');
  for (const f of ['index.html', 'install.md', 'docs/index.html', 'dashboard/index.html']) {
    const text = fs.readFileSync(path.join(root, f), 'utf8');
    assert.doesNotMatch(text, /src="(?:https:\/\/pyrmi\.com)?\/sdk\/pyrmi\.js"/, f + ' still points at the unpinned alias');
    assert.ok(text.includes(meta.path + '" integrity="' + meta.integrity + '" crossorigin="anonymous"'), f);
  }
  assert.ok(fs.readFileSync(path.join(root, 'dashboard/app.js'), 'utf8').includes("SDK_PATH = '" + meta.path + "', SDK_SRI = '" + meta.integrity + "'"));
  const v = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
  const cache = (src) => v.headers.find((h) => h.source === src).headers.find((h) => h.key === 'Cache-Control').value;
  assert.match(cache('/sdk/(\\d+\\.\\d+\\.\\d+)/pyrmi.js'), /immutable/);
  assert.match(cache('/sdk/pyrmi.js'), /max-age=300/);
});
