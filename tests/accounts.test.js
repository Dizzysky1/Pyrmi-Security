'use strict';
// Signing in (email codes, GitHub, Google) and per-account sites, against fake providers:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const auth = require('../api/v1/auth/[provider].js');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, redirect: 'manual', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) { /* redirect */ }
  return { status: r.status, body: json, headers: r.headers };
};
const beacon = (s, signals) => call('POST', '/api/v1/signal', JSON.stringify({ token: s.token, signals: { pt: 1000, k: 5, p: 3, au: [], tp: [], ...signals } }), { 'Content-Type': 'text/plain' });
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function siteToken() {
  const s = (await call('POST', '/api/v1/session', { site: 'pk_pyrmi_site' })).body;
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
  const noHeader = await call('POST', '/api/v1/sites', { name: 'Alice shop' }, { Cookie: alice });
  assert.equal(noHeader.status, 403);
  const crossSite = await call('POST', '/api/v1/sites', { name: 'Alice shop' }, as(alice, { 'Sec-Fetch-Site': 'cross-site' }));
  assert.equal(crossSite.status, 403);
  const otherOrigin = await call('POST', '/api/v1/sites', { name: 'Alice shop' }, as(alice, { Origin: 'https://evil.example' }));
  assert.equal(otherOrigin.status, 403);
  const noToken = await call('POST', '/api/v1/sites', { name: 'Alice shop' }, as(alice));
  assert.equal(noToken.status, 403);
  assert.equal(noToken.body.error, 'blocked_by_pyrmi');
  const ok = await call('POST', '/api/v1/sites', { name: 'Alice shop', pyrmiToken: await siteToken() }, as(alice));
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
  const s = (await call('POST', '/api/v1/session', { site: sitePk })).body;
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
  const k = await call('POST', '/api/v1/project', { name: 'Old project', pyrmiToken: await siteToken() }, { 'X-Forwarded-For': '198.51.100.7' });
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

test('email codes die after 5 wrong tries and are capped per address', async () => {
  await askCode('dave@example.com', { 'X-Forwarded-For': '203.0.113.9' });
  const code = lastCode(), bad = code === '999999' ? '888888' : '999999';
  for (let i = 0; i < 5; i++) assert.equal((await call('POST', '/api/v1/auth/email?action=verify', { email: 'dave@example.com', code: bad }, { 'X-Pyrmi-CSRF': '1' })).body.error, 'bad_code');
  const locked = await call('POST', '/api/v1/auth/email?action=verify', { email: 'dave@example.com', code }, { 'X-Pyrmi-CSRF': '1' });
  assert.equal(locked.body.error, 'too_many_tries');
  for (let i = 0; i < 4; i++) await askCode('dave@example.com', { 'X-Forwarded-For': '203.0.113.' + (20 + i) });
  assert.equal((await askCode('dave@example.com', { 'X-Forwarded-For': '203.0.113.40' })).status, 429);
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
