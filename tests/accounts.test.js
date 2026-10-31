'use strict';
// Sign in with Google and per-account sites, against a fake Google token endpoint:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const { serve } = require('../scripts/dev.js');
const google = require('../api/v1/google.js');

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());

const call = async (method, p, body, headers) => {
  const r = await fetch(base + p, { method, redirect: 'manual', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua', ...(headers || {}) }, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body) });
  const text = await r.text();
  let json = null; try { json = JSON.parse(text); } catch (_) { /* redirect */ }
  return { status: r.status, body: json, headers: r.headers };
};
const FIELDS = ['wd', 'hl', 'au', 'tp', 'dt', 'ut', 'ih', 'k', 'p', 'h', 'pt', 'gt', 'sh'];
function encode(sig, x) {
  const out = {};
  FIELDS.forEach((f, i) => { out[x.f[i]] = sig[f] === undefined ? null : sig[f]; });
  const json = JSON.stringify(out), key = Buffer.from(x.k, 'base64url');
  return Buffer.from([...json].map((c, i) => (c.charCodeAt(0) ^ key[i % key.length] ^ (i * 7)) & 255)).toString('base64url');
}
const beacon = (s, signals) => call('POST', '/api/v1/signal', JSON.stringify({ token: s.token, [s.x.n]: encode({ pt: 1000, k: 5, p: 3, au: [], tp: [], ...signals }, s.x) }), { 'Content-Type': 'text/plain' });
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
  const start = await call('GET', '/api/v1/google');
  assert.equal(start.status, 302);
  const loc = new URL(start.headers.get('location'));
  assert.equal(loc.host, 'accounts.google.com');
  assert.equal(loc.searchParams.get('code_challenge_method'), 'S256');
  const stateCookie = cookieOf(start, '__Host-pyrmi_oauth');
  google.exchange = async (form) => {
    assert.ok(form.code_verifier && form.client_secret === 'test-google-secret');
    return { id_token: idToken({ iss: 'https://accounts.google.com', aud: 'test-google-id', sub, email, email_verified: true, name: 'Person ' + sub, exp: Date.now() / 1000 + 300, ...extra }) };
  };
  const back = await call('GET', '/api/v1/google?code=abc&state=' + loc.searchParams.get('state'), undefined, { Cookie: stateCookie });
  return { res: back, cookie: cookieOf(back, '__Host-pyrmi_session') };
}
const as = (cookie, extra) => ({ Cookie: cookie, 'X-Pyrmi-CSRF': '1', ...(extra || {}) });

test('without Google set up, sign-in says so', async () => {
  const me = await call('GET', '/api/v1/me');
  assert.equal(me.status, 401);
  assert.equal(me.body.google, false);
  assert.equal((await call('GET', '/api/v1/google')).status, 503);
});

let alice, bob, sitePid, siteSk, sitePk;

test('Google sign-in: state, PKCE and a verified email are required', async () => {
  process.env.GOOGLE_CLIENT_ID = 'test-google-id';
  process.env.GOOGLE_CLIENT_SECRET = 'test-google-secret';
  const forged = await call('GET', '/api/v1/google?code=abc&state=nope');
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
