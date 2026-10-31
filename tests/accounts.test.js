'use strict';
// Signing in (email codes, GitHub, Google) and per-account sites, against fake providers:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const auth = require('../api/v1/auth/[provider].js');
const kv = require('../api/_lib/kv');
const C = require('../api/_lib/crypto');
const accounts = require('../api/_lib/accounts');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const B = require('./_browser');
const rawCall = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, redirect: 'manual', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) { /* redirect */ }
  return { status: r.status, body: json, headers: r.headers };
};
const call = B.wrap(rawCall);
const beacon = (s, signals) => B.beacon(call, s, signals);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function siteToken() {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_pyrmi_site' }, { Origin: 'https://pyrmi.com' })).body;
  await beacon(s, {});
  await wait(1300);
  return s.token;
}
const cookieOf = (res, name) => {
  for (const c of res.headers.getSetCookie()) if (c.startsWith(name + '=')) return c.split(';')[0];
  return null;
};
const idToken = (claims) => 'x.' + Buffer.from(JSON.stringify(claims)).toString('base64url') + '.sig';

async function signIn(sub, email, extra) {
  const start = await call('GET', '/api/v1/auth/google');
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  assert.equal(loc.host, 'accounts.google.com');
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  const stateCookie = cookieOf(start, '__Host-pyrmi_oauth');
  auth.hooks = { exchange: async (form) => {
    assert.ok(form.code_verifier && form.client_secret === 'test-google-secret');
    return { id_token: idToken({ iss: 'https://accounts.google.com', aud: 'test-google-id', sub, email, email_verified: true, name: 'Person ' + sub, exp: Date.now() / 1000 + 300, ...extra }) };
  } };
  const back = await call('GET', '/api/v1/auth/google?code=abc&state=' + loc.searchParams.get('state'), undefined, { Cookie: stateCookie });
  return { res: back, cookie: cookieOf(back, '__Host-pyrmi_session') };
}
const as = (cookie, extra) => ({ Cookie: cookie, 'X-Pyrmi-CSRF': '1', ...(extra || {}) });

test('with nothing set up, every way in says so', async () => {
  const me = await call('GET', '/api/v1/me');
  assert.equal(me.status, 401);
  assert.deepEqual(me.body.providers, { email: false, github: false, google: false });
  assert.equal((await call('GET', '/api/v1/auth/google')).status, 503);
  assert.equal((await call('GET', '/api/v1/auth/github')).status, 503);
  assert.equal((await call('POST', '/api/v1/auth/email?action=start', { email: 'a@example.com' }, { 'X-Pyrmi-CSRF': '1' })).status, 503);
  assert.equal((await call('GET', '/api/v1/auth/nope')).status, 404);
});

let alice, bob, sitePid, siteSk, sitePk;

test('Google sign-in: state, PKCE and a verified email are required', async () => {
  process.env.GOOGLE_CLIENT_ID = 'test-google-id';
  process.env.GOOGLE_CLIENT_SECRET = 'test-google-secret';
  const forged = await call('GET', '/api/v1/auth/google?code=abc&state=nope');
  assert.equal(forged.status, 302);
  assert.match(forged.headers.get('location'), /signin=bad_state/);
  const unverified = await signIn('333', 'eve@example.com', { email_verified: false });
  assert.match(unverified.res.headers.get('location'), /signin=bad_id_token/);
  assert.equal(unverified.cookie, null);
  const wrongAud = await signIn('333', 'eve@example.com', { aud: 'someone-else' });
  assert.match(wrongAud.res.headers.get('location'), /signin=bad_id_token/);

  const a = await signIn('111', 'alice@example.com');
  assert.equal(a.res.headers.get('location'), '/dashboard/');
  const set = a.res.headers.getSetCookie().find((c) => c.startsWith('__Host-pyrmi_session='));
  assert.match(set, /HttpOnly/); assert.match(set, /Secure/); assert.match(set, /SameSite=Lax/);
  alice = a.cookie;
  bob = (await signIn('222', 'bob@example.com')).cookie;
  const me = await call('GET', '/api/v1/me', undefined, { Cookie: alice });
  assert.equal(me.body.user.email, 'alice@example.com');
  assert.deepEqual(me.body.sites, []);
});

test('adding a site needs the CSRF header, a same-site request and a clean Pyrmi token', async () => {
  const noHeader = await call('POST', '/api/v1/sites', { name: 'Alice shop', origins: ['https://alice.example'] }, { Cookie: alice });
  assert.equal(noHeader.status, 403);
  const crossSite = await call('POST', '/api/v1/sites', { name: 'Alice shop', origins: ['https://alice.example'] }, as(alice, { 'Sec-Fetch-Site': 'cross-site' }));
  assert.equal(crossSite.status, 403);
  const otherOrigin = await call('POST', '/api/v1/sites', { name: 'Alice shop', origins: ['https://alice.example'] }, as(alice, { Origin: 'https://evil.example' }));
  assert.equal(otherOrigin.status, 403);
  const noToken = await call('POST', '/api/v1/sites', { name: 'Alice shop', origins: ['https://alice.example'] }, as(alice));
  assert.equal(noToken.status, 403);
  assert.equal(noToken.body.error, 'blocked_by_pyrmi');
  const ok = await call('POST', '/api/v1/sites', { name: 'Alice shop', origins: ['https://alice.example'], pyrmiToken: await siteToken() }, as(alice));
  assert.equal(ok.status, 201, JSON.stringify(ok.body));
  ({ pid: sitePid, secretKey: siteSk, publicKey: sitePk } = ok.body.project);
  assert.equal(ok.body.project.owner, undefined);
  const list = await call('GET', '/api/v1/me', undefined, { Cookie: alice });
  assert.equal(list.body.sites.length, 1);
  assert.equal(list.body.sites[0].status.connected, false);
});

test('one account can never see or change another account\'s site', async () => {
  assert.deepEqual((await call('GET', '/api/v1/me', undefined, { Cookie: bob })).body.sites, []);
  assert.equal((await call('GET', '/api/v1/sites?pid=' + sitePid, undefined, as(bob))).status, 404);
  assert.equal((await call('PATCH', '/api/v1/sites?pid=' + sitePid, { name: 'mine now' }, as(bob))).status, 404);
  assert.equal((await call('POST', '/api/v1/sites?pid=' + sitePid + '&action=rotate', {}, as(bob))).status, 404);
  assert.equal((await call('DELETE', '/api/v1/sites?pid=' + sitePid, undefined, as(bob))).status, 404);
  assert.equal((await call('POST', '/api/v1/sites?action=claim', { secretKey: siteSk }, as(bob))).status, 409);
  assert.equal((await call('GET', '/api/v1/sites?pid=' + sitePid)).status, 401);
  assert.equal((await call('GET', '/api/v1/sites?pid=' + sitePid, undefined, as(alice))).status, 200);
});

test('the connection check turns green once the page and the server have both reported', async () => {
  const s = (await call('POST', '/api/v1/session', { site: sitePk }, { Origin: 'https://alice.example' })).body;
  let d = await call('GET', '/api/v1/sites?pid=' + sitePid, undefined, as(alice));
  assert.ok(d.body.status.page > 0 && !d.body.status.server && !d.body.status.connected);
  await beacon(s, {});
  await call('POST', '/api/v1/verify', { token: s.token, user: 'shopper' }, { Authorization: 'Bearer ' + siteSk });
  d = await call('GET', '/api/v1/sites?pid=' + sitePid, undefined, as(alice));
  assert.equal(d.body.status.connected, true);
  assert.equal(d.body.events.length, 1);
});

test('settings, rotation and delete work for the owner', async () => {
  const u = await call('PATCH', '/api/v1/sites?pid=' + sitePid, { settings: { maxScore: 50 } }, as(alice));
  assert.equal(u.body.project.settings.maxScore, 50);
  const r = await call('POST', '/api/v1/sites?pid=' + sitePid + '&action=rotate', {}, as(alice));
  assert.match(r.body.secretKey, /^sk_/);
  assert.equal((await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + siteSk })).status, 401);
  assert.equal((await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + r.body.secretKey })).status, 200);
  assert.equal((await call('DELETE', '/api/v1/sites?pid=' + sitePid, undefined, as(alice))).status, 200);
  assert.deepEqual((await call('GET', '/api/v1/me', undefined, { Cookie: alice })).body.sites, []);
  assert.equal((await call('GET', '/api/v1/project', undefined, { Authorization: 'Bearer ' + r.body.secretKey })).status, 401);
});

test('a key-only project can be claimed with its secret key', async () => {
  const k = await call('POST', '/api/v1/project', { name: 'Old project', origins: ['https://t.example'], pyrmiToken: await siteToken() }, { 'X-Forwarded-For': '198.51.100.7' });
  assert.equal(k.status, 201, JSON.stringify(k.body));
  const c = await call('POST', '/api/v1/sites?action=claim', { secretKey: k.body.project.secretKey }, as(bob));
  assert.equal(c.status, 200);
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: bob })).body.sites[0].name, 'Old project');
  assert.equal((await call('POST', '/api/v1/sites?action=claim', { secretKey: k.body.project.secretKey }, as(alice))).status, 409);
});

test('signing out ends the session for good', async () => {
  assert.equal((await call('POST', '/api/v1/me?action=signout', {}, { Cookie: alice })).status, 403);
  const out = await call('POST', '/api/v1/me?action=signout', {}, as(alice));
  assert.equal(out.status, 200);
  assert.match(out.headers.getSetCookie()[0], /Max-Age=0/);
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: alice })).status, 401);
});

// ---- email codes ----

const sent = [];
const askCode = async (email, headers) => call('POST', '/api/v1/auth/email?action=start', { email, pyrmiToken: await siteToken() }, { 'X-Pyrmi-CSRF': '1', ...(headers || {}) });
const lastCode = () => /\b(\d{6})\b/.exec(sent[sent.length - 1].text)[1];

test('email sign-in: a one-time code, hashed, single use, and no clue whether the address has an account', async () => {
  process.env.RESEND_API_KEY = 're_test';
  auth.mailer = async (m) => { sent.push(m); };
  assert.equal((await call('GET', '/api/v1/me')).body.providers.email, true);
  // needs the CSRF header and a clean Pyrmi token
  assert.equal((await call('POST', '/api/v1/auth/email?action=start', { email: 'carol@example.com', pyrmiToken: await siteToken() })).status, 403);
  assert.equal((await call('POST', '/api/v1/auth/email?action=start', { email: 'carol@example.com' }, { 'X-Pyrmi-CSRF': '1' })).body.error, 'blocked_by_pyrmi');
  assert.equal((await askCode('not an email')).status, 400);
  // a new address and a known one get the same answer
  const fresh = await askCode('Carol@Example.com ');
  const known = await askCode('bob@example.com');
  assert.deepEqual(fresh.body, known.body);
  assert.equal(sent.length, 2);
  assert.equal(sent[0].to, 'carol@example.com');
  const bobCode = lastCode();
  // the code is stored only as a hash
  const kv = require('../api/_lib/kv');
  const stored = await kv.cmd('HGET', 'ps:ec:' + require('../api/_lib/crypto').sha256('bob@example.com'), 'h');
  assert.ok(stored && !stored.includes(bobCode));
  // one address is one account: bob's code signs in to the account he made with Google
  const wrong = await call('POST', '/api/v1/auth/email?action=verify', { email: 'bob@example.com', code: bobCode === '000000' ? '111111' : '000000' }, { 'X-Pyrmi-CSRF': '1' });
  assert.equal(wrong.status, 400);
  const ok = await call('POST', '/api/v1/auth/email?action=verify', { email: 'bob@example.com', code: bobCode }, { 'X-Pyrmi-CSRF': '1' });
  assert.equal(ok.status, 200);
  const c = cookieOf(ok, '__Host-pyrmi_session');
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: c })).body.sites[0].name, 'Old project');
  // and it can't be used twice
  assert.equal((await call('POST', '/api/v1/auth/email?action=verify', { email: 'bob@example.com', code: bobCode }, { 'X-Pyrmi-CSRF': '1' })).status, 400);
});

test('email codes: wrong tries from one network lock only that network, and codes are capped per address', async () => {
  const mine = { 'X-Forwarded-For': '203.0.113.9' }, theirs = { 'X-Forwarded-For': '198.51.100.77' };
  await askCode('dave@example.com', mine);
  const code = lastCode(), bad = code === '999999' ? '888888' : '999999';
  const verify = (c, h) => call('POST', '/api/v1/auth/email?action=verify', { email: 'dave@example.com', code: c }, { 'X-Pyrmi-CSRF': '1', ...h });
  // someone else guessing from their own network burns their tries, not the owner's
  for (let i = 0; i < 5; i++) assert.equal((await verify(bad, theirs)).body.error, 'bad_code');
  assert.equal((await verify(code, theirs)).body.error, 'too_many_tries');
  assert.equal((await verify(code, mine)).status, 200, 'the owner can still use the code');
  // the same five starts from somebody else's network no longer lock the owner out of new codes
  for (let i = 0; i < 5; i++) await askCode('dave@example.com', theirs);
  assert.equal((await askCode('dave@example.com', theirs)).status, 429);
  assert.equal((await askCode('dave@example.com', mine)).status, 200);
  // and there is still a cap on the address as a whole
  let last;
  for (let i = 0; i < 20; i++) last = await askCode('dave@example.com', { 'X-Forwarded-For': '203.0.113.' + (100 + i) });
  assert.equal(last.status, 429);
});

test('email codes are deleted after enough wrong tries from everywhere', async () => {
  await askCode('erin@example.com', { 'X-Forwarded-For': '203.0.113.10' });
  const code = lastCode(), bad = code === '999999' ? '888888' : '999999';
  for (let n = 0; n < 6; n++) for (let i = 0; i < 5; i++) await call('POST', '/api/v1/auth/email?action=verify', { email: 'erin@example.com', code: bad }, { 'X-Pyrmi-CSRF': '1', 'X-Forwarded-For': '192.0.2.' + (50 + n) });
  const r = await call('POST', '/api/v1/auth/email?action=verify', { email: 'erin@example.com', code }, { 'X-Pyrmi-CSRF': '1', 'X-Forwarded-For': '203.0.113.10' });
  assert.equal(r.body.error, 'too_many_tries');
});

// ---- GitHub ----

test('GitHub sign-in uses the primary verified email and lands in the same account', async () => {
  process.env.GITHUB_CLIENT_ID = 'test-gh-id';
  process.env.GITHUB_CLIENT_SECRET = 'test-gh-secret';
  const start = await call('GET', '/api/v1/auth/github');
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  assert.equal(loc.host, 'github.com');
  assert.match(loc.searchParams.get('redirect_uri'), /\/api\/v1\/auth\/github$/);
  const state = cookieOf(start, '__Host-pyrmi_oauth');
  let emails = [{ email: 'bob@other.example', primary: true, verified: false }, { email: 'bob@example.com', primary: false, verified: true }];
  auth.hooks = { github: {
    exchange: async (form) => { assert.equal(form.client_secret, 'test-gh-secret'); assert.ok(form.code_verifier); return { access_token: 'gho_test' }; },
    get: async (p) => (p === '/user/emails' ? emails : { login: 'bobcodes' }),
  } };
  const back1 = await call('GET', '/api/v1/auth/github?code=x&state=' + loc.searchParams.get('state'), undefined, { Cookie: state });
  assert.match(back1.headers.get('location'), /signin=no_verified_email/);
  // a Google state cookie can't finish a GitHub sign-in
  const g = await call('GET', '/api/v1/auth/google');
  const gs = new URL(g.headers.get('location')).searchParams.get('state');
  const cross = await call('GET', '/api/v1/auth/github?code=x&state=' + gs, undefined, { Cookie: cookieOf(g, '__Host-pyrmi_oauth') });
  assert.match(cross.headers.get('location'), /signin=bad_state/);
  emails = [{ email: 'Bob@Example.com', primary: true, verified: true }];
  const start2 = await call('GET', '/api/v1/auth/github');
  const back = await call('GET', '/api/v1/auth/github?code=x&state=' + new URL(start2.headers.get('location')).searchParams.get('state'), undefined, { Cookie: cookieOf(start2, '__Host-pyrmi_oauth') });
  assert.equal(back.headers.get('location'), '/dashboard/');
  const me = await call('GET', '/api/v1/me', undefined, { Cookie: cookieOf(back, '__Host-pyrmi_session') });
  assert.equal(me.body.user.email, 'bob@example.com');
  assert.equal(me.body.sites[0].name, 'Old project');
});

// F-05: the per-address email-code limit must count its window down, not reset it on every request. The old code
// re-set the TTL on each call, so an address under a steady stream of requests could be locked out indefinitely.
test('the per-address email-code window counts down instead of resetting on every request (F-05)', async () => {
  const saved = process.env.RESEND_API_KEY;
  process.env.RESEND_API_KEY = 'test-resend-key'; // just enough for emailConfigured() to be true
  const email = 'lockout-f05@example.com';
  const key = 'ps:rl:emailto:' + C.sha256(email);
  const mailer = async () => { /* don't actually send anything */ };
  try {
    await accounts.emailStart({ email }, '198.51.100.9', mailer);
    const ttl1 = Number(await kv.cmd('TTL', key));
    assert.ok(ttl1 > 0 && ttl1 <= 3600, 'window should be set on the first code: ' + ttl1);
    await wait(1100);
    await accounts.emailStart({ email }, '198.51.100.9', mailer); // a later code must NOT push the TTL back up
    const ttl2 = Number(await kv.cmd('TTL', key));
    assert.ok(ttl2 < ttl1, 'the window must keep counting down, not reset (was ' + ttl1 + ', now ' + ttl2 + ')');
  } finally {
    if (saved === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = saved;
  }
});

// F-11: the /sites IP limiter used to run before requireUser, so an unauthenticated caller could burn the shared
// network bucket (and pile up KV writes). With the limiter behind auth, anonymous calls never reach it.
test('the /sites IP limiter never runs for an unauthenticated request (F-11)', async () => {
  const saved = process.env.PYRMI_ACCOUNT_CALLS_PER_MIN;
  process.env.PYRMI_ACCOUNT_CALLS_PER_MIN = '1'; // if the limiter ran pre-auth, the second anonymous call would be 429
  try {
    const a = await call('GET', '/api/v1/sites?pid=p_nope');
    const b = await call('GET', '/api/v1/sites?pid=p_nope');
    assert.equal(a.status, 401, 'an anonymous call should be rejected as signed out');
    assert.equal(b.status, 401, 'a second anonymous call must still be 401, not 429 — the limiter sits behind auth');
  } finally {
    if (saved === undefined) delete process.env.PYRMI_ACCOUNT_CALLS_PER_MIN; else process.env.PYRMI_ACCOUNT_CALLS_PER_MIN = saved;
  }
});

// F-07: an ordinary project's sessions were origin-unbound when its allowlist was empty, so a bare script could mint
// them. A real browser always sends an Origin, so one is now required for non-builtin projects.
test('an ordinary project requires a browser Origin to start a session (F-07)', async () => {
  const u = (await signIn('707', 'f07@example.com')).cookie;
  const created = await call('POST', '/api/v1/sites', { name: 'F07 shop', origins: ['https://f07.example'], pyrmiToken: await siteToken() }, as(u));
  const pk = created.body.project.publicKey; // a fresh project with an empty origins allowlist
  const noOrigin = await call('POST', '/api/v1/session', { site: pk });
  assert.equal(noOrigin.status, 403);
  const withOrigin = await call('POST', '/api/v1/session', { site: pk }, { Origin: 'https://f07.example' });
  assert.equal(withOrigin.status, 200);
});

// A2-08: createSite checked the per-owner cap and then added, as two steps, so parallel POSTs could both pass the
// check and race past the cap. With a re-check-and-rollback after reserving, concurrent creates can't exceed it.
test('parallel site creates cannot race past the per-owner cap (A2-08)', async () => {
  const savedCap = process.env.PYRMI_SITES_PER_USER;
  process.env.PYRMI_SITES_PER_USER = '2';
  const uid = 'u_race_' + Date.now();
  try {
    await accounts.createSite(uid, { name: 'one', origins: ['https://t.example'] }, '198.51.100.51');
    await Promise.allSettled([
      accounts.createSite(uid, { name: 'two', origins: ['https://t.example'] }, '198.51.100.52'),
      accounts.createSite(uid, { name: 'three', origins: ['https://t.example'] }, '198.51.100.53'),
    ]);
    const card = Number(await kv.cmd('ZCARD', 'ps:us:' + uid));
    assert.ok(card <= 2, 'owner must never exceed the cap, even under concurrent creates (was ' + card + ')');
  } finally {
    if (savedCap === undefined) delete process.env.PYRMI_SITES_PER_USER; else process.env.PYRMI_SITES_PER_USER = savedCap;
  }
});

// F-20: a request carrying a malformed session cookie must not reach KV. currentUser used to GET ps:auth for any
// present cookie (even junk), one uncapped Redis read per hit; now a cookie that isn't a well-formed session id is
// rejected before any KV call, and sessionSid() lets the handler cap the lookups that do happen with a separate bucket.
test('a malformed session cookie never triggers a KV read (F-20)', async () => {
  const cookie = (v) => ({ headers: { cookie: accounts.SESSION_COOKIE + '=' + v } });
  // sessionSid only accepts the 43-char base64url shape a real session id has.
  assert.equal(accounts.sessionSid(cookie('short')), null, 'too-short cookie is rejected');
  assert.equal(accounts.sessionSid(cookie('!!!not-base64url-at-all!!!')), null, 'non-base64url cookie is rejected');
  assert.equal(accounts.sessionSid(cookie('x'.repeat(200))), null, 'over-long cookie is rejected');
  const good = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v'; // 43 base64url chars
  assert.equal(accounts.sessionSid(cookie(good)), good, 'a well-formed session id is accepted');

  // Count ps:auth GETs while reading a few junk cookies: there must be none.
  const orig = kv.cmd; let authReads = 0;
  kv.cmd = async (...a) => { if (a[0] === 'GET' && String(a[1]).includes('ps:auth:')) authReads++; return orig(...a); };
  try {
    for (const v of ['short', '!!!bad!!!', 'x'.repeat(200), '']) assert.equal(await accounts.currentUser(cookie(v)), null);
    assert.equal(authReads, 0, 'malformed cookies must cost zero KV reads, got ' + authReads);
    await accounts.currentUser(cookie(good)); // a well-formed (but unknown) id is allowed to do its one lookup
    assert.equal(authReads, 1, 'a well-formed id does exactly one lookup');
  } finally { kv.cmd = orig; }
});

// F-24: per-IP (10/600s) and per-address (5/hour) limits don't bound the TOTAL number of sign-in emails, so a script
// rotating IPs and addresses could email-bomb inboxes and burn login@pyrmi.com's reputation. A global per-day cap
// bounds the blast radius however the source is spread. (Uses a stub mailer; no real mail is sent.)
// Retest of b127c08: that cap covered everyone, so filling it locked every user out of email sign-in until midnight.
// It now covers new addresses only, answers them the same as anyone else, and people with an account still get codes.
test('email sign-in: the server-wide cap bounds codes to new addresses and never locks out existing accounts (F-24)', async () => {
  const savedCap = process.env.PYRMI_EMAIL_STARTS_PER_DAY, savedResend = process.env.RESEND_API_KEY;
  process.env.PYRMI_EMAIL_STARTS_PER_DAY = '3';
  process.env.RESEND_API_KEY = 'test-key'; // make email sign-in "configured" without real SMTP
  await kv.cmd('DEL', 'ps:rl:emailstart:' + require('../api/_lib/core').ymd(Date.now())); // isolate from other tests' sends
  const sent = [];
  const mailer = async (m) => { sent.push(m.to); };
  try {
    const known = 'already-here@example.com';
    await kv.cmd('SET', 'ps:ue:' + require('../api/_lib/crypto').sha256(known), 'u_known' + Date.now());
    for (let i = 0; i < 3; i++) assert.deepEqual(await accounts.emailStart({ email: 'bomb' + i + '@example.com' }, '198.51.100.' + (200 + i), mailer), { sent: true });
    // over the cap: a new address gets the same answer, but no mail goes out
    assert.deepEqual(await accounts.emailStart({ email: 'bomb9@example.com' }, '198.51.100.250', mailer), { sent: false });
    assert.equal(sent.length, 3, 'no more than the cap of codes go to new addresses, got ' + sent.length);
    // an address that already has an account still gets its code
    assert.deepEqual(await accounts.emailStart({ email: known }, '198.51.100.251', mailer), { sent: true });
    assert.equal(sent[sent.length - 1], known);
    // and the HTTP answer is the same either way, so the cap says nothing about which addresses have accounts
    const a = await call('POST', '/api/v1/auth/email?action=start', { email: 'bomb10@example.com', pyrmiToken: await siteToken() }, { 'X-Pyrmi-CSRF': '1', 'Sec-Fetch-Site': 'same-origin', 'X-Forwarded-For': '198.51.100.252' });
    assert.equal(a.status, 200); assert.deepEqual(a.body, { ok: true });
  } finally {
    if (savedCap === undefined) delete process.env.PYRMI_EMAIL_STARTS_PER_DAY; else process.env.PYRMI_EMAIL_STARTS_PER_DAY = savedCap;
    if (savedResend === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = savedResend;
  }
});

test('email sign-in: each network has its own daily share of codes', async () => {
  const saved = process.env.PYRMI_EMAIL_CODES_PER_IP_PER_DAY, savedResend = process.env.RESEND_API_KEY;
  process.env.PYRMI_EMAIL_CODES_PER_IP_PER_DAY = '2';
  process.env.RESEND_API_KEY = 'test-key';
  const mailer = async () => {};
  try {
    for (let i = 0; i < 2; i++) await accounts.emailStart({ email: 'net' + i + '@example.com' }, '2001:db8:aa::' + (i + 1), mailer);
    // another address in the same IPv6 /64 is the same network
    await assert.rejects(() => accounts.emailStart({ email: 'net9@example.com' }, '2001:db8:aa::ffff', mailer), (e) => e.status === 429);
    await accounts.emailStart({ email: 'net9@example.com' }, '2001:db8:bb::1', mailer); // another network is fine
  } finally {
    if (saved === undefined) delete process.env.PYRMI_EMAIL_CODES_PER_IP_PER_DAY; else process.env.PYRMI_EMAIL_CODES_PER_IP_PER_DAY = saved;
    if (savedResend === undefined) delete process.env.RESEND_API_KEY; else process.env.RESEND_API_KEY = savedResend;
  }
});

// The GET /api/v1/me limiter used to run before auth, like the old /sites one (F-11), so an anonymous flood could
// burn a shared network's bucket and lock that network's signed-in users out of the dashboard's "am I signed in?"
// check. A signed-out /me does no KV lookup, so it must never be limited; the limiter now runs only when a
// well-formed session cookie is present (same class as F-11/F-20).
test('the /me IP limiter never runs for a request with no session cookie', async () => {
  const saved = process.env.PYRMI_ACCOUNT_CALLS_PER_MIN;
  process.env.PYRMI_ACCOUNT_CALLS_PER_MIN = '1'; // if the limiter ran before auth, the second anonymous call would be 429
  try {
    const a = await call('GET', '/api/v1/me');
    const b = await call('GET', '/api/v1/me');
    assert.equal(a.status, 401, 'a signed-out /me should answer 401');
    assert.equal(b.status, 401, 'a second signed-out /me must still be 401, not 429 — the limiter sits behind a valid cookie');
  } finally {
    if (saved === undefined) delete process.env.PYRMI_ACCOUNT_CALLS_PER_MIN; else process.env.PYRMI_ACCOUNT_CALLS_PER_MIN = saved;
  }
});

// Q4/Q10: there was no per-user session index and no way to revoke all sessions — a stale or stolen cookie could
// only be ended one key at a time or by rotating the signing secret. signIn now indexes each session under the user,
// and POST /me?action=revoke-all ends them all at once.
test('revoke-all ends every session for the account (Q4/Q10)', async () => {
  const one = (await signIn('rev1', 'revoke@example.com')).cookie;
  const two = (await signIn('rev1', 'revoke@example.com')).cookie; // same account, a second device
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: one })).status, 200);
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: two })).status, 200);
  const r = await call('POST', '/api/v1/me?action=revoke-all', {}, as(two));
  assert.equal(r.status, 200, JSON.stringify(r.body));
  assert.ok(r.body.revoked >= 2, 'both sessions should be revoked, got ' + JSON.stringify(r.body));
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: one })).status, 401, 'the other device is signed out');
  assert.equal((await call('GET', '/api/v1/me', undefined, { Cookie: two })).status, 401, 'the calling device is signed out');
});

// M10: claimSite read p.owner, checked, then HSET owner + ZADD with no CAS, so two concurrent claims of an unowned
// project could both pass the check and both write owner — last writer wins, and the loser got a 200 but then found
// the site gone (dangling index entry, no audit). The single-threaded in-memory harness serialises two HTTP claims,
// so the race can't be reproduced by firing concurrent requests; instead inject the exact window deterministically —
// set an owner between claimSite's check and its write, and confirm the claim refuses to clobber it (HSETNX returns
// 0 -> 409). Old code wrote the owner unconditionally via a pipeline HSET, so this interceptor never fires and the
// claim wrongly succeeds, which makes the assert.rejects below fail on the old code.
test('claimSite will not overwrite an owner that appears mid-claim (M10)', async () => {
  const core = require('../api/_lib/core');
  const created = await call('POST', '/api/v1/project', { name: 'CAS race', origins: ['https://cas.example'], pyrmiToken: await siteToken() });
  const skc = created.body.project.secretKey, pidc = created.body.project.pid;
  const origCmd = kv.cmd;
  let injected = false;
  kv.cmd = function (...args) {
    if (!injected && args[0] === 'HSETNX' && args[1] === 'ps:p:' + pidc && args[2] === 'owner') {
      injected = true; // a racer takes ownership first, in the window between this claim's check and its write
      return origCmd.call(kv, 'HSET', 'ps:p:' + pidc, 'owner', 'u_racer').then(() => origCmd.call(kv, ...args));
    }
    return origCmd.call(kv, ...args);
  };
  try {
    await assert.rejects(() => accounts.claimSite('u_me', skc), (e) => e.status === 409, 'claimSite must not clobber an owner that appeared mid-claim');
    assert.ok(injected, 'the ownership write went through HSETNX (the atomic path)');
    const p = await core.loadProject(pidc);
    assert.equal(p.owner, 'u_racer', 'the racer keeps ownership; the claim did not overwrite it');
  } finally { kv.cmd = origCmd; }
});
