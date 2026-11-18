'use strict';
// Regression tests for API, Auth, Crypto, KV, Turnstile and SMTP hardening.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';

const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const { Readable } = require('stream');

const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const core = require('../api/_lib/core');
const accounts = require('../api/_lib/accounts');
const turnstile = require('../api/_lib/turnstile');
const smtp = require('../api/_lib/smtp');
const { readJson } = require('../api/_lib/http');
const { serve } = require('../scripts/dev.js');
const B = require('./_browser');

let base, server;
test.before(async () => {
  await B.fakeTurnstile();
  server = http.createServer(serve);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = 'http://127.0.0.1:' + server.address().port;
});
test.after(() => server.close());

let ipOct = 1;
const nextIp = () => '198.19.' + Math.floor(ipOct / 250) + '.' + ((ipOct++ % 250) + 1);

const withEnv = async (vars, fn) => {
  const saved = {};
  for (const [k, v] of Object.entries(vars)) {
    saved[k] = process.env[k];
    if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(saved)) {
      if (v === undefined) delete process.env[k]; else process.env[k] = v;
    }
  }
};

async function signInViaEmail(email) {
  return withEnv({ RESEND_API_KEY: 're_test' }, async () => {
    let code = '';
    const rid = C.randomId(16);
    await accounts.emailStart({ email }, nextIp(), async (m) => { code = /(\d{6})/.exec(m.subject)[1]; }, { rid });
    return accounts.emailVerify({ email, code }, nextIp(), { rid });
  });
}

// ---- 1. Unauthenticated Redis amplification ----

test('1a. signOut validates SID_RE before KV, pipelines GET+DEL, and revoke-all skips redundant signOut', async () => {
  const sign = await signInViaEmail('signout-pipe@example.com');
  const sessionCookie = sign.setCookies.find((c) => c.startsWith(accounts.SESSION_COOKIE + '=')).split(';')[0];

  let pipeCalls = 0, cmdCalls = 0;
  const origPipeline = kv.pipeline, origCmd = kv.cmd;
  kv.pipeline = async (cmds) => { pipeCalls++; return origPipeline.call(kv, cmds); };
  kv.cmd = async (...a) => { cmdCalls++; return origCmd.call(kv, ...a); };
  try {
    for (const bad of ['', 'short', 'x'.repeat(100), 'not!valid!sid!' + 'a'.repeat(29)]) {
      const setCookie = await accounts.signOut({ headers: { cookie: accounts.SESSION_COOKIE + '=' + bad } });
      assert.match(setCookie, /Max-Age=0/);
    }
    assert.equal(pipeCalls + cmdCalls, 0, 'malformed cookies in signOut must do zero KV calls');

    await accounts.signOut({ headers: { cookie: sessionCookie } });
    assert.equal(pipeCalls, 1, 'valid signOut batches GET+DEL in 1 pipeline');
    assert.equal(cmdCalls, 1, 'and 1 ZREM on ps:usess:<uid>');
    assert.equal(Number(await origCmd.call(kv, 'ZCARD', 'ps:usess:' + sign.uid)), 0, 'session removed from user index');
  } finally {
    kv.pipeline = origPipeline;
    kv.cmd = origCmd;
  }

  // POST /api/v1/me?action=revoke-all should not call signOut() redundantly
  const sign2 = await signInViaEmail('revoke-clean@example.com');
  const cookie2 = sign2.setCookies.find((c) => c.startsWith(accounts.SESSION_COOKIE + '=')).split(';')[0];
  let getDelAfterRevoke = 0;
  const origPipe2 = kv.pipeline;
  kv.pipeline = async (cmds) => {
    if (cmds.length === 2 && cmds[0][0] === 'GET' && cmds[1][0] === 'DEL' && String(cmds[0][1]).includes('ps:auth:')) getDelAfterRevoke++;
    return origPipe2.call(kv, cmds);
  };
  try {
    const r = await fetch(base + '/api/v1/me?action=revoke-all', {
      method: 'POST',
      headers: { Cookie: cookie2, 'X-Pyrmi-CSRF': '1', 'X-Forwarded-For': nextIp() },
    });
    assert.equal(r.status, 200);
    assert.equal(getDelAfterRevoke, 0, 'revoke-all clears cookie directly without calling signOut GET+DEL');
    assert.match(r.headers.getSetCookie().join(';'), /Max-Age=0/);
  } finally {
    kv.pipeline = origPipe2;
  }
});

test('1b. /session rate-limits repeated 403 origin mismatches without burning project quota, and rejects missing Origin upfront under all policy', async () => {
  const ownerIp = nextIp(), attackerIp = nextIp();
  const p = await core.createProject({ name: 'OriginRL', origins: ['https://allowed.example'] }, ownerIp, 'u_orl');
  await withEnv({ PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN: '3' }, async () => {
    for (let i = 0; i < 3; i++) {
      const r = await fetch(base + '/api/v1/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-Forwarded-For': attackerIp },
        body: JSON.stringify({ site: p.publicKey }),
      });
      assert.equal(r.status, 403);
      assert.equal(r.headers.get('access-control-allow-origin'), null);
    }
    const over = await fetch(base + '/api/v1/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', 'X-Forwarded-For': attackerIp },
      body: JSON.stringify({ site: p.publicKey }),
    });
    assert.equal(over.status, 429, '4th bad-origin session attempt is rate-limited');
    assert.equal(Number((await kv.cmd('GET', 'ps:q:' + p.pid + ':' + core.ymd(Date.now()))) || 0), 0, 'refused origins never burn daily quota');
  });

  // Under PYRMI_REQUIRE_ORIGINS=all, missing Origin for non-builtin sites fails before projectByPublicKey
  await withEnv({ PYRMI_REQUIRE_ORIGINS: 'all' }, async () => {
    let kvReads = 0;
    const origPipeline = kv.pipeline;
    kv.pipeline = async (cmds) => { kvReads++; return origPipeline.call(kv, cmds); };
    try {
      const r = await fetch(base + '/api/v1/session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp() },
        body: JSON.stringify({ site: p.publicKey }),
      });
      assert.equal(r.status, 403);
      assert.equal((await r.json()).error, 'origin_required');
      assert.equal(kvReads, 0, 'rejected before any KV lookup');
    } finally {
      kv.pipeline = origPipeline;
    }
  });
});

test('1c. projectForKey caches wrong-key bursts in memory while letting valid keys through', async () => {
  const ip = nextIp();
  const p = await core.createProject({ name: 'MissCache', origins: ['https://mc.example'] }, nextIp(), 'u_mc');
  await withEnv({ PYRMI_BAD_KEYS_PER_IP: '2' }, async () => {
    assert.equal(await core.projectForKey('sk_' + 'a'.repeat(30), ip), null);
    assert.equal(await core.projectForKey('sk_' + 'b'.repeat(30), ip), null);
    await assert.rejects(core.projectForKey('sk_' + 'c'.repeat(30), ip), (e) => e.status === 429);

    // Subsequent misses hit the in-memory miss cache and issue zero rate-limit INCRs
    let incrCount = 0;
    const origPipeline = kv.pipeline;
    kv.pipeline = async (cmds) => {
      if (cmds.some((c) => String(c[0]).toUpperCase() === 'INCR')) incrCount++;
      return origPipeline.call(kv, cmds);
    };
    try {
      await assert.rejects(core.projectForKey('sk_' + 'd'.repeat(30), ip), (e) => e.status === 429 && e.retryAfter === 900);
      assert.equal(incrCount, 0, 'cached badkey burst skips Redis INCR');
      // Valid key from the same network still works
      assert.equal((await core.projectForKey(p.secretKey, ip)).pid, p.pid);
    } finally {
      kv.pipeline = origPipeline;
    }
  });
});

// ---- 2. guardSite Origin & Client Binding ----

test('2. guardSite enforces client/IP binding with req (keeping 2-arg calls compatible) and restricts SITE Origin in production', async () => {
  const CHROME = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/156.0.0.0 Safari/537.36';
  const CH = '"Chromium";v="156"';
  const site = await core.loadProject(core.SITE.pid);
  await core.updateSettings(site, {}).catch(() => {}); // demo_locked

  const mintSite = async (ip) => {
    const s = await core.startSession(site, { ip, ua: CHROME, ch: CH, origin: 'https://pyrmi.com', host: 'pyrmi.com' }, { pt: 0 });
    const then = Date.now() - 2000;
    await kv.cmd('HSET', 'ps:s:' + s.session, 'i', then);
    const tok = await C.signToken({ ...(await C.readToken(s.token)), i: then });
    await core.recordSignals({ token: tok, bn: s.bn, n: 1, signals: B.signals({ pt: 2000 }) }, { ip, ua: CHROME, origin: 'https://pyrmi.com', sfs: 'same-origin' });
    return tok;
  };

  // 2-arg call keeps working even if IP differs
  const ip1 = nextIp(), ip2 = nextIp();
  const tok2Arg = await mintSite(ip1);
  assert.equal((await core.guardSite(tok2Arg, ip2)).verdict, 'accept');

  // 3-arg call with ip_changed rejects
  const tokIp = await mintSite(ip1);
  const browserReq = { headers: { 'user-agent': CHROME, 'sec-ch-ua': CH, 'sec-fetch-site': 'same-origin' } };
  await assert.rejects(core.guardSite(tokIp, ip2, browserReq), (e) => e.status === 403 && e.code === 'blocked_by_pyrmi' && e.reasons.includes('ip_changed'));

  // 3-arg call with relayed_session (curl UA or missing Sec-Fetch-Site) rejects
  const tokRelay = await mintSite(ip1);
  await assert.rejects(core.guardSite(tokRelay, ip1, { headers: { 'user-agent': 'curl/8.5.0' } }),
    (e) => e.status === 403 && e.reasons.includes('relayed_session'));

  // Matching browser & IP passes 3-arg guardSite
  const tokOk = await mintSite(ip1);
  assert.equal((await core.guardSite(tokOk, ip1, browserReq)).verdict, 'accept');

  // Production SITE startSession rejects mismatched Origin when PYRMI_PUBLIC_URL is set
  await withEnv({ PYRMI_ENV: 'production', PYRMI_KV_PREFIX: '', PYRMI_PUBLIC_URL: 'https://pyrmi.com' }, async () => {
    const rBad = await fetch(base + '/api/v1/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', Host: 'pyrmi.com', 'X-Forwarded-For': nextIp() },
      body: JSON.stringify({ site: core.SITE.publicKey, pt: 0 }),
    });
    assert.equal(rBad.status, 403);
    assert.equal(rBad.headers.get('access-control-allow-origin'), null);

    const rOk = await fetch(base + '/api/v1/session', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'https://pyrmi.com', Host: 'pyrmi.com', 'X-Forwarded-For': nextIp() },
      body: JSON.stringify({ site: core.SITE.publicKey, pt: 0 }),
    });
    assert.equal(rOk.status, 200);
    assert.equal(rOk.headers.get('access-control-allow-origin'), 'https://pyrmi.com');
  });
});

// ---- 3. Beacon Sabotage ----

test('3. leaked token without private bn cannot poison a victim session (stays corroborated and trusted)', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0', CH = '"Chromium";v="156"', O = 'https://victim.example';
  const p = await core.createProject({ name: 'NoSabotage', origins: [O], settings: { minDurationMs: 0, maxScore: 100 } }, ip, 'u_sab');
  const project = await core.loadProject(p.pid);
  const s = await core.startSession(project, { ip, ua: UA, ch: CH, origin: O }, { pt: 100 });
  const ctx = { ip, ua: UA, origin: O, sfs: 'same-origin' };

  // Attacker with leaked token guesses wrong bn BEFORE victim's first beacon -> 409, session untouched
  await assert.rejects(
    core.recordSignals({ token: s.token, bn: 'wrong_bn_123', n: 1, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  assert.equal((await kv.cmd('HGET', 'ps:s:' + s.session, 'sig')), null, 'session sig not poisoned before first beacon');

  // Victim sends real beacon #1
  assert.equal((await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 100, k: 2, p: 3 }) }, ctx)).ok, true);

  // Attacker sends beacon omitting bn/n, or with wrong bn, AFTER sess.n > 0 -> 409, session untouched
  await assert.rejects(
    core.recordSignals({ token: s.token, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  await assert.rejects(
    core.recordSignals({ token: s.token, bn: s.bn, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );
  await assert.rejects(
    core.recordSignals({ token: s.token, bn: 'wrong_bn_456', n: 2, signals: B.signals({ pt: 100, wd: true }) }, ctx),
    (e) => e.status === 409 && e.code === 'wrong_session'
  );

  // Victim's verify is still clean, corroborated, and trusted!
  const v = await core.verify(project, {
    token: s.token, score: 10,
    request: B.sign(s, { score: 10 }),
    client: { ua: UA, ip, ch: CH, sfs: 'same-origin' },
  }, { ip });
  assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
  assert.equal(v.client, 'corroborated');
  assert.equal(v.trusted, true);
});

// ---- 4. Key Rotation/Delete, Site Claim & Email OTP Races ----

test('4a. rotateLocked rejects deleted projects (404), and deleteSite runs under withKeyLock', async () => {
  const p = await core.createProject({ name: 'GoneRot', origins: ['https://gr.example'] }, nextIp(), 'u_gr');
  const loaded = await core.loadProject(p.pid);
  await core.deleteProject(loaded);
  await assert.rejects(core.rotateSecret(loaded), (e) => e.status === 404 && e.code === 'not_found');
  assert.equal(await core.loadProject(p.pid), null, 'deleted project was not resurrected by rotateLocked');

  // deleteSite respects ps:rot:<pid> key lock
  const p2 = await accounts.createSite('u_lockdel', { name: 'LockedDel', origins: ['https://ld.example'] }, nextIp());
  const owned = await accounts.ownedSite('u_lockdel', p2.pid);
  await kv.cmd('SET', 'ps:rot:' + p2.pid, 'busy-token', 'NX', 'EX', 10);
  await assert.rejects(accounts.deleteSite('u_lockdel', owned), (e) => e.status === 409 && e.code === 'rotate_in_progress');
  await kv.cmd('DEL', 'ps:rot:' + p2.pid);
  await accounts.deleteSite('u_lockdel', owned);
  assert.equal(await core.loadProject(p2.pid), null);
});

test('4b. claimSite: idempotent at cap, counts wrong keys, and rolls back concurrent cap overflow', async () => {
  await withEnv({ PYRMI_SITES_PER_USER: '1', PYRMI_BAD_KEYS_PER_IP: '2' }, async () => {
    const uid = 'u_claim_cap_' + Date.now();
    const anon1 = await core.createProject({ name: 'Anon1', origins: ['https://a1.example'] }, nextIp());
    const anon2 = await core.createProject({ name: 'Anon2', origins: ['https://a2.example'] }, nextIp());

    // Claiming anon1 with keepKey: true fills the 1-site cap; repeating idempotent claim still returns 200
    const claimed = await accounts.claimSite(uid, anon1.secretKey, { keepKey: true, ip: nextIp() });
    assert.equal(claimed.pid, anon1.pid);
    const idemp = await accounts.claimSite(uid, anon1.secretKey, { keepKey: true, ip: nextIp() });
    assert.equal(idemp.pid, anon1.pid);

    // Wrong keys in claimSite count toward projectForKey rate limit
    const badIp = nextIp();
    await assert.rejects(accounts.claimSite(uid, 'sk_' + 'z'.repeat(30), { ip: badIp }), (e) => e.status === 404);
    await assert.rejects(accounts.claimSite(uid, 'sk_' + 'y'.repeat(30), { ip: badIp }), (e) => e.status === 404);
    await assert.rejects(accounts.claimSite(uid, 'sk_' + 'w'.repeat(30), { ip: badIp }), (e) => e.status === 429);

    // Simulate concurrent cap overflow between pre-check ZCARD and ZADD inside claimSite
    const uid2 = 'u_claim_race_' + Date.now();
    const origCmd = kv.cmd;
    let injected = false;
    kv.cmd = async (...args) => {
      if (!injected && args[0] === 'HSETNX' && args[1] === 'ps:p:' + anon2.pid && args[2] === 'owner') {
        injected = true;
        await origCmd.call(kv, 'ZADD', 'ps:us:' + uid2, Date.now(), 'p_already_there');
      }
      return origCmd.call(kv, ...args);
    };
    try {
      await assert.rejects(accounts.claimSite(uid2, anon2.secretKey, { ip: nextIp() }), (e) => e.status === 403 && e.code === 'too_many_sites');
    } finally {
      kv.cmd = origCmd;
    }
    assert.equal(Number(await kv.cmd('ZCARD', 'ps:us:' + uid2)), 1, 'rolled back over-cap ZADD');
    const stillAnon = await core.projectBySecretKey(anon2.secretKey);
    assert.ok(stillAnon && stillAnon.owner === null, 'project stayed unowned with original key intact');
  });
});

test('4c. emailVerify enforces atomic DEL === 1, and emailStart harmonizes daily-cap 429 across known/unknown', async () => {
  await withEnv({ RESEND_API_KEY: 're_test', PYRMI_EMAIL_KNOWN_PER_DAY: '1' }, async () => {
    const day = core.ymd(Date.now());
    await kv.cmd('DEL', 'ps:rl:emailknown:' + day);

    const mails = [];
    const mailer = async (m) => { mails.push(m); };
    const email = 'otp-race@example.com', rid = C.randomId(16);
    await accounts.emailStart({ email }, nextIp(), mailer, { rid });
    const code = /(\d{6})/.exec(mails[0].subject)[1];

    // Simulate lost DEL race (another concurrent verify deleted the code first)
    const origCmd = kv.cmd;
    let racedOnce = false;
    kv.cmd = async (...args) => {
      if (!racedOnce && args[0] === 'DEL' && String(args[1]).startsWith('ps:ec:')) {
        racedOnce = true;
        await origCmd.call(kv, ...args);
        return 0; // simulate losing the atomic DEL to the concurrent request
      }
      return origCmd.call(kv, ...args);
    };
    try {
      await assert.rejects(accounts.emailVerify({ email, code }, nextIp(), { rid }), (e) => e.status === 400 && e.code === 'bad_code');
    } finally {
      kv.cmd = origCmd;
    }

    // Now test emailStart known vs unknown when PYRMI_EMAIL_KNOWN_PER_DAY (1) is reached
    const knownEmail = 'known-cap-eq@example.com';
    await kv.cmd('SET', 'ps:ue:' + C.sha256(knownEmail), 'u_known_eq');
    assert.deepEqual(await accounts.emailStart({ email: knownEmail }, nextIp(), mailer, { rid: C.randomId(16) }), { sent: true });
    // Now emailknown === 1 (at cap): BOTH known (without device mark) and unknown get the exact same 429
    let errKnown, errUnknown;
    await accounts.emailStart({ email: knownEmail }, nextIp(), mailer, { rid: C.randomId(16) }).catch((e) => { errKnown = e; });
    await accounts.emailStart({ email: 'brand-new-addr@example.com' }, nextIp(), mailer, { rid: C.randomId(16) }).catch((e) => { errUnknown = e; });
    assert.ok(errKnown && errUnknown);
    assert.equal(errKnown.status, 429);
    assert.equal(errUnknown.status, 429);
    assert.equal(errKnown.message, errUnknown.message);
    await kv.cmd('DEL', 'ps:rl:emailknown:' + day);
  });
});

// ---- 5. /verify Flood Protection & Warm Isolate ensureBuiltin ----

test('5a. /verify rate_limited skips logVerdict when !genuine, omits ps:ev LPUSH when genuine, and preserves unused tokens', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0', O = 'https://vflood.example';
  const p = await core.createProject({ name: 'VFlood', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_vf');
  const project = await core.loadProject(p.pid);

  let s2;
  await withEnv({ PYRMI_VERIFIES_PER_MIN: '1' }, async () => {
    const s1 = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s1.token, bn: s1.bn, n: 1, signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
    const v1 = await core.verify(project, { token: s1.token, player: 'p1' }, { ip });
    assert.equal(v1.verdict, 'accept');

    // Unused genuine token s2 hits rate_limited: not pushed to ps:ev, and ps:used:<s2> is released!
    s2 = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
    await core.recordSignals({ token: s2.token, bn: s2.bn, n: 1, signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
    const v2 = await core.verify(project, { token: s2.token, player: 'p2' }, { ip });
    assert.equal(v2.verdict, 'reject');
    assert.ok(v2.reasons.some((r) => r.code === 'rate_limited'));
    assert.equal(await kv.cmd('GET', 'ps:used:' + s2.session), null, 'unused token was not permanently burned by rate limit');
    const evs = (await kv.cmd('LRANGE', 'ps:ev:' + p.pid, 0, -1)).map((x) => JSON.parse(x));
    assert.equal(evs.length, 1, 'rate_limited genuine call did not LPUSH into ps:ev');

    //Already-used token s1 replayed during rate_limited keeps its ps:used marker!
    const v1Replay = await core.verify(project, { token: s1.token, player: 'p1' }, { ip });
    assert.ok(v1Replay.reasons.some((r) => r.code === 'token_reused'));
    assert.equal(await kv.cmd('GET', 'ps:used:' + s1.session), '1', 'already-used token stays marked used');

    // !genuine flood past PYRMI_VERIFIES_PER_MIN skips logVerdict completely (1 KV pipeline total)
    const junkIp = nextIp();
    await core.verify(project, { token: 'forged.1' }, { ip: junkIp });
    let pipelines = 0;
    const origPipeline = kv.pipeline;
    kv.pipeline = async (cmds) => { pipelines++; return origPipeline.call(kv, cmds); };
    try {
      const vj = await core.verify(project, { token: 'forged.2' }, { ip: junkIp });
      assert.ok(vj.reasons.some((r) => r.code === 'rate_limited'));
      assert.equal(pipelines, 1, '!genuine rate_limited verify skips logVerdict completely');
    } finally {
      kv.pipeline = origPipeline;
    }
  });

  // Once rate limit clears (normal limit restored), s2 still verifies as a clean accept!
  const v2Retry = await core.verify(project, { token: s2.token, player: 'p2' }, { ip });
  assert.equal(v2Retry.verdict, 'accept', 'un-burned token works once rate limit clears: ' + JSON.stringify(v2Retry.reasons));
});

test('5b. ensureBuiltin coalesces concurrent cold-start seeds and re-seeds if wiped in a warm isolate', async () => {
  await core.loadProject(core.DEMO.pid);
  // Wipe ps:p:sandbox in a warm isolate where builtinReady already has 'sandbox'
  await kv.cmd('DEL', 'ps:p:' + core.DEMO.pid, 'ps:pk:' + core.DEMO.publicKey);

  let seedPipelines = 0;
  const origPipeline = kv.pipeline;
  kv.pipeline = async (cmds) => {
    if (cmds.some((c) => c[0] === 'HSETNX' && String(c[1]).endsWith('ps:p:' + core.DEMO.pid))) seedPipelines++;
    return origPipeline.call(kv, cmds);
  };
  try {
    const [a, b, c] = await Promise.all([
      core.loadProject(core.DEMO.pid),
      core.loadProject(core.DEMO.pid),
      core.projectByPublicKey(core.DEMO.publicKey),
    ]);
    assert.ok(a && b && c);
    assert.equal(a.publicKey, core.DEMO.publicKey);
    assert.equal(c.pid, core.DEMO.pid);
    assert.equal(seedPipelines, 1, 'concurrent re-seed coalesced into a single pipeline');
  } finally {
    kv.pipeline = origPipeline;
  }
});

// ---- 6. Edge-Case Tightening ----

test('6a. core.network normalizes IPv4/IPv6 ports, zones, and dotted/hex IPv4-mapped IPv6', () => {
  assert.equal(core.network('192.0.2.7:8080'), '192.0.2.7');
  assert.equal(core.network('::ffff:192.0.2.7'), '192.0.2.7');
  assert.equal(core.network('[::ffff:192.0.2.7]:443'), '192.0.2.7');
  assert.equal(core.network('0:0:0:0:0:ffff:192.0.2.7'), '192.0.2.7');
  assert.equal(core.network('::ffff:c000:0207'), '192.0.2.7');
  assert.equal(core.network('0000:0000:0000:0000:0000:ffff:c000:0207'), '192.0.2.7');
  assert.equal(core.network('[2001:db8:1:2:aaaa::1]:54321'), '2001:db8:1:2::/64');
  assert.equal(core.network('fe80::1%eth0'), 'fe80:0:0:0::/64');
  assert.equal(core.network('[fe80::1%en0]:8080'), 'fe80:0:0:0::/64');
  assert.equal(core.network('999.0.2.7'), '999.0.2.7');
  assert.equal(core.network('2001:12345:1:2::1'), '2001:12345:1:2::1');
});

test('6b. corroborate, cleanSignals and startSession enforce uniform pt in [0, 1e13)', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0', O = 'https://pt.example';
  const p = await core.createProject({ name: 'PtBounds', origins: [O], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_pt');
  const project = await core.loadProject(p.pid);

  // pt >= 1e13 at session start and beacon must flag clock instead of canceling out drift and bypassing speed_hack
  const s = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 1e13 });
  assert.equal(await kv.cmd('HGET', 'ps:s:' + s.session, 'pt0'), '', 'pt >= 1e13 ignored at startSession');
  await core.recordSignals({ token: s.token, bn: s.bn, n: 1, signals: B.signals({ pt: 1e13 + 100 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
  const v = await core.verify(project, { token: s.token }, { ip });
  assert.equal(v.client, 'unverified');
  assert.match((v.reasons.find((r) => r.code === 'unverified_client') || {}).detail || '', /clock/);

  // Negative raw.pt on beacon also flags clock
  const sNeg = await core.startSession(project, { ip, ua: UA, origin: O }, { pt: 0 });
  await core.recordSignals({ token: sNeg.token, bn: sNeg.bn, n: 1, signals: B.signals({ pt: -10 }) }, { ip, ua: UA, origin: O, sfs: 'same-origin' });
  const vNeg = await core.verify(project, { token: sNeg.token }, { ip });
  assert.match((vNeg.reasons.find((r) => r.code === 'unverified_client') || {}).detail || '', /clock/);
});

test('6c. crypto.canon and checkSigned reject nested own "__proto__" at every depth', async () => {
  const nestedObj = JSON.parse('{"outer":{"__proto__":{"admin":true}}}');
  const nestedArr = JSON.parse('{"items":[{"__proto__":1}]}');
  assert.throws(() => C.canon(nestedObj), (e) => e.code === 'CANON_PROTO');
  assert.throws(() => C.canon(nestedArr), (e) => e.code === 'CANON_PROTO');

  const now = Date.now(), t = { s: 'sid_proto', i: now - 1000 };
  for (const fields of [nestedObj, nestedArr]) {
    const res = await core.checkSigned({ fields, ts: now, sig: 'A'.repeat(43) }, t, now);
    assert.deepEqual(res, { state: 'bad', detail: 'forbidden key __proto__' });
  }
});

test('6d. demo.js rejects sig-stripped pyrmi envelopes as bad_signature while keeping direct { pyrmi: { token } } unsigned', async () => {
  const ip = nextIp(), UA = 'Mozilla/5.0 Chrome/156.0';
  const h = { 'Content-Type': 'application/json', Origin: base, 'Sec-Fetch-Site': 'same-origin', 'User-Agent': UA, 'X-Forwarded-For': ip };

  const mintAgedDemo = async () => {
    const s = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: h, body: JSON.stringify({ site: core.DEMO.publicKey, pt: 0 }) })).json();
    const then = Date.now() - 2000;
    await kv.cmd('HSET', 'ps:s:' + s.session, 'i', then);
    const tok = await C.signToken({ ...(await C.readToken(s.token)), i: then });
    await fetch(base + '/api/v1/signal', { method: 'POST', headers: h, body: JSON.stringify({ token: tok, bn: s.bn, n: 1, signals: B.signals({ pt: 2000 }) }) });
    return { ...s, token: tok };
  };

  // Stripping sig while keeping ts in pyrmi envelope -> bad_signature (reject), NOT silent downgrade to accept!
  const s1 = await mintAgedDemo();
  const stripped = await (await fetch(base + '/api/v1/demo', {
    method: 'POST', headers: h,
    body: JSON.stringify({ value: 42, visitor: 'visitor-a1b2', pyrmi: { token: s1.token, ts: Date.now() } }),
  })).json();
  assert.equal(stripped.verdict, 'reject');
  assert.equal(stripped.signed, 'bad');
  assert.ok(stripped.reasons.some((r) => r.code === 'bad_signature'));

  // sandbox.js `direct` cheat action ({ value, visitor, pyrmi: { token } } with neither ts nor sig) stays unsigned
  const s2 = await (await fetch(base + '/api/v1/session', { method: 'POST', headers: { 'Content-Type': 'text/plain', 'X-Forwarded-For': ip }, body: JSON.stringify({ site: core.DEMO.publicKey }) })).json();
  const direct = await (await fetch(base + '/api/v1/demo', {
    method: 'POST', headers: h,
    body: JSON.stringify({ value: 42, visitor: 'visitor-a1b2', pyrmi: { token: s2.token } }),
  })).json();
  assert.equal(direct.verdict, 'reject');
  assert.equal(direct.signed, 'none');
  assert.ok(direct.reasons.some((r) => r.code === 'no_client'));
});

test('6e. turnstile.check fails closed when hostnames are empty and prioritizes PYRMI_PUBLIC_URL over Host', async () => {
  await withEnv({
    TURNSTILE_SITE_KEY: 'ts-site',
    TURNSTILE_SECRET_KEY: B.TS_SECRET,
    TURNSTILE_HOSTNAMES: undefined,
    PYRMI_PUBLIC_URL: undefined,
  }, async () => {
    const makeTok = (hostname, action) => B.human({ session: 's1' }, hostname, { action }).token;
    // Empty host with no env hostnames/URL -> fails closed!
    await assert.rejects(turnstile.check(makeTok('evil.example', 'signin'), '192.0.2.1', 'signin', ''),
      (e) => e.status === 403 && e.code === 'turnstile_failed');

    // PYRMI_PUBLIC_URL takes precedence over caller-supplied host
    process.env.PYRMI_PUBLIC_URL = 'https://pyrmi.com';
    await assert.rejects(turnstile.check(makeTok('spoofed.example', 'signin'), '192.0.2.1', 'signin', 'spoofed.example'),
      (e) => e.status === 403 && e.code === 'turnstile_failed');
    const ok = await turnstile.check(makeTok('pyrmi.com', 'signin'), '192.0.2.1', 'signin', 'spoofed.example');
    assert.equal(ok.success, true);
  });
});

test('6f. http.readJson rejects oversized Content-Length upfront (413) and normalizes top-level arrays to {}', async () => {
  let readAttempted = false;
  const fakeStream = new Readable({ read() { readAttempted = true; this.push('{"a":1}'); this.push(null); } });
  fakeStream.headers = { 'content-length': '99999' };
  await assert.rejects(readJson(fakeStream, 1024), (e) => e.status === 413 && e.code === 'body_too_large');
  assert.equal(readAttempted, false, 'stream not read when Content-Length exceeds max');

  const arrStream = Readable.from(['[1, 2, 3]']);
  arrStream.headers = {};
  assert.deepEqual(await readJson(arrStream, 1024), {});
  assert.deepEqual(await readJson({ headers: {}, body: [1, 2, 3] }, 1024), {});
});

test('6g. smtp strips CR/LF/<> in fallback addr, caps reply buffer & line count, and cleanEmail rejects control chars', async () => {
  for (const bad of ['a\x00@example.com', '\x07a@example.com', 'a@example.com\x7f', 'a@example.com\r\n', 'a\x1b@example.com']) {
    assert.equal(accounts.cleanEmail(bad), null, JSON.stringify(bad));
  }
  assert.equal(accounts.cleanEmail('Valid.User@example.com '), 'valid.user@example.com');

  // Fallback addr() prevents RCPT TO / MAIL FROM command injection
  const seen = [];
  const srv = net.createServer((sock) => {
    let buf = '', inData = false;
    sock.write('220 ok\r\n');
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (inData) { if (line === '.') { inData = false; sock.write('250 sent\r\n'); } continue; }
        seen.push(line);
        if (/^EHLO/.test(line)) sock.write('250 AUTH PLAIN\r\n');
        else if (/^AUTH/.test(line)) sock.write('235 ok\r\n');
        else if (/^(MAIL|RCPT)/.test(line)) sock.write('250 ok\r\n');
        else if (line === 'DATA') { inData = true; sock.write('354 go\r\n'); }
        else if (line === 'QUIT') { sock.write('221 bye\r\n'); sock.end(); }
      }
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    await smtp.send({
      from: 'sender@pyrmi.com>\r\nMAIL FROM:<evil@attacker.com',
      to: 'victim@example.com\r\nRCPT TO:<bcc@attacker.com>',
      subject: 'test', text: 'hi',
    }, { host: '127.0.0.1', port: srv.address().port, user: 'u', pass: 'p' });
  } finally { srv.close(); }
  assert.equal(seen.filter((l) => l.startsWith('MAIL FROM:')).length, 1);
  assert.equal(seen.filter((l) => l.startsWith('RCPT TO:')).length, 1);
  assert.ok(seen.includes('MAIL FROM:<sender@pyrmi.com>'), JSON.stringify(seen));
  assert.ok(seen.includes('RCPT TO:<victim@example.com>'), JSON.stringify(seen));

  // Oversized >100 multiline SMTP greeting aborts cleanly and destroys socket
  const floodSrv = net.createServer((sock) => {
    for (let i = 0; i < 105; i++) sock.write('220-line' + i + '\r\n');
    sock.write('220 end\r\n');
  });
  await new Promise((r) => floodSrv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(
      smtp.send({ to: 'a@example.com', subject: 's', text: 't' }, { host: '127.0.0.1', port: floodSrv.address().port, user: 'u', pass: 'p' }),
      /smtp_too_many_lines/
    );
  } finally { floodSrv.close(); }

  // Oversized >64 KB single line without CRLF aborts cleanly
  const bigSrv = net.createServer((sock) => { sock.write('220 ' + 'A'.repeat(70000)); });
  await new Promise((r) => bigSrv.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(
      smtp.send({ to: 'a@example.com', subject: 's', text: 't' }, { host: '127.0.0.1', port: bigSrv.address().port, user: 'u', pass: 'p' }),
      /smtp_reply_too_large/
    );
  } finally { bigSrv.close(); }
});

test('6h. trimPlayers evicts exact ZREM members, and kv._mem sweeps expired keys past 5000', async () => {
  const ip = nextIp();
  const p = await core.createProject({ name: 'TrimExact', origins: ['https://te.example'], settings: { minDurationMs: 0, requireSignedRequests: false } }, ip, 'u_te');
  const seed = [];
  for (let i = 0; i < 1001; i++) seed.push(['ZADD', 'ps:plr:' + p.pid, i + 1, 'pl' + i], ['HSET', 'ps:pl:' + p.pid + ':pl' + i, 'accept', '1']);
  await kv.pipeline(seed);

  // Intercept ZRANGE in trimPlayers to simulate pl0 getting re-promoted right before eviction
  const origCmd = kv.cmd;
  let promoted = false;
  kv.cmd = async (...args) => {
    const r = await origCmd.call(kv, ...args);
    if (!promoted && args[0] === 'ZRANGE' && args[1] === 'ps:plr:' + p.pid) {
      promoted = true;
      await origCmd.call(kv, 'ZADD', 'ps:plr:' + p.pid, Date.now() + 99999, 'pl0');
    }
    return r;
  };
  try {
    const proj = await core.loadProject(p.pid);
    const s = await core.startSession(proj, { ip, ua: 'ua', origin: 'https://te.example' }, { pt: 0 });
    await core.verify(proj, { token: s.token, player: 'newest' }, { ip });
  } finally {
    kv.cmd = origCmd;
  }
  // Because ZREM targeted the exact `gone` list (pl0, pl1) rather than ZREMRANGEBYRANK 0..1, pl2 was NOT wrongly evicted!
  assert.notEqual(await kv.cmd('ZSCORE', 'ps:plr:' + p.pid, 'pl2'), null, 'innocent shifted member pl2 was not evicted');

  // kv._mem expiry sweep when exp.size > 5000
  const beforeExp = kv._mem.exp.size;
  const past = Date.now() - 1000;
  for (let i = 0; i < 5005; i++) {
    kv._mem.data.set('sweep:' + i, '1');
    kv._mem.exp.set('sweep:' + i, past);
  }
  assert.ok(kv._mem.exp.size > 5000);
  await kv.cmd('GET', 'sweep:trigger');
  assert.equal(kv._mem.data.has('sweep:0'), false);
  assert.ok(kv._mem.exp.size <= beforeExp, 'expired entries swept on _mem.run, remaining: ' + kv._mem.exp.size);
});
