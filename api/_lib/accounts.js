'use strict';
// Accounts: Sign in with Google, signed-in sessions, and the sites each person owns.
//
// - Google sign-in is the standard authorization-code flow with PKCE. The ID token comes straight from Google's token
//   endpoint over TLS, which is what lets us trust it without fetching Google's signing keys (OpenID Connect 3.1.3.7).
//   Google's own access and refresh tokens are never stored.
// - A signed-in session is a random 32-byte cookie (HttpOnly, Secure, SameSite=Lax, __Host- prefixed). Only its
//   SHA-256 is stored, so a copy of the database can't be used to sign in.
// - Every change made with that cookie must also carry the X-Pyrmi-CSRF header and come from this site (Origin and
//   Sec-Fetch-Site), so another site can't make a signed-in browser change anything.
// - Every site query is scoped to its owner: someone else's site answers 404, the same as one that doesn't exist.

const crypto = require('crypto');
const kv = require('./kv');
const C = require('./crypto');
const core = require('./core');
const { httpError } = require('./http');

const SESSION_COOKIE = '__Host-pyrmi_session';
const STATE_COOKIE = '__Host-pyrmi_oauth';
const SESSION_TTL = 7 * 86400;
const MAX_SITES = 10;

const intEnv = (k, d) => { const n = parseInt(process.env[k], 10); return Number.isFinite(n) && n > 0 ? n : d; };

function googleConfigured() { return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET); }

// The address Google sends people back to. PYRMI_PUBLIC_URL pins it (it must match the redirect URI registered in
// Google Cloud); otherwise it's this deployment's own address.
function baseUrl(req) {
  if (process.env.PYRMI_PUBLIC_URL) return process.env.PYRMI_PUBLIC_URL.replace(/\/+$/, '');
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  return proto + '://' + String(req.headers['x-forwarded-host'] || req.headers.host);
}
function redirectUri(req) { return baseUrl(req) + '/api/v1/google'; }

// ---- cookies ----------------------------------------------------------------------------------------------------

function readCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function cookie(name, value, maxAge) {
  return name + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAge;
}

// ---- Google -----------------------------------------------------------------------------------------------------

async function googleStart(req) {
  if (!googleConfigured()) throw httpError(503, 'google_not_configured', 'Sign in with Google isn\'t set up on this server yet.');
  const state = C.randomId(24), verifier = C.randomId(48);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const signed = await C.signToken({ s: state, v: verifier, e: Date.now() + 600e3 });
  const q = new URLSearchParams({
    client_id: process.env.GOOGLE_CLIENT_ID, redirect_uri: redirectUri(req), response_type: 'code', scope: 'openid email profile',
    state, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account',
  });
  return { location: 'https://accounts.google.com/o/oauth2/v2/auth?' + q, setCookie: cookie(STATE_COOKIE, signed, 600) };
}

async function googleCallback(req, params, exchange) {
  if (!googleConfigured()) throw httpError(503, 'google_not_configured', 'Sign in with Google isn\'t set up on this server yet.');
  if (params.get('error')) throw httpError(400, 'google_cancelled', 'Google sign-in was cancelled.');
  const st = await C.readToken(readCookies(req)[STATE_COOKIE]);
  const state = params.get('state'), code = params.get('code');
  if (!st || !state || !C.safeEqual(st.s, state) || Date.now() > st.e || !code) throw httpError(400, 'bad_state', 'That sign-in link expired or didn\'t come from this site. Try again.');
  const tokens = await (exchange || exchangeCode)({
    code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET,
    redirect_uri: redirectUri(req), grant_type: 'authorization_code', code_verifier: st.v,
  });
  const claims = readIdToken(tokens && tokens.id_token);
  if (!claims) throw httpError(400, 'bad_id_token', 'Google sent back something we couldn\'t read.');
  const now = Date.now() / 1000;
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss) || claims.aud !== process.env.GOOGLE_CLIENT_ID ||
      !(claims.exp > now) || !claims.sub || claims.email_verified !== true || !claims.email) {
    throw httpError(400, 'bad_id_token', 'Google didn\'t confirm a verified email for this account.');
  }
  const uid = 'g_' + String(claims.sub).replace(/[^\w]/g, '').slice(0, 40);
  const name = String(claims.name || claims.email).replace(/[\u0000-\u001f<>]/g, '').slice(0, 80);
  const email = String(claims.email).slice(0, 120);
  await kv.cmd('HSET', 'ps:u:' + uid, 'email', email, 'name', name, 'last', Date.now());
  await kv.cmd('HSETNX', 'ps:u:' + uid, 'created', Date.now());
  const sid = C.randomId(32);
  await kv.cmd('SET', 'ps:auth:' + C.sha256(sid), uid, 'EX', SESSION_TTL);
  return { uid, setCookies: [cookie(SESSION_COOKIE, sid, SESSION_TTL), cookie(STATE_COOKIE, '', 0)] };
}

async function exchangeCode(form) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw httpError(400, 'google_exchange_failed', 'Google didn\'t accept the sign-in. Try again.');
  return r.json();
}

function readIdToken(jwt) {
  if (typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (_) { return null; }
}

// ---- signed-in requests -------------------------------------------------------------------------------------------

async function currentUser(req) {
  const sid = readCookies(req)[SESSION_COOKIE];
  if (!sid || sid.length > 100) return null;
  const uid = await kv.cmd('GET', 'ps:auth:' + C.sha256(sid));
  if (!uid) return null;
  const u = kv.pairs(await kv.cmd('HGETALL', 'ps:u:' + uid));
  return u.email ? { uid, email: u.email, name: u.name || u.email } : null;
}

async function requireUser(req) {
  const u = await currentUser(req);
  if (!u) throw httpError(401, 'signed_out', 'Sign in to see your sites.');
  return u;
}

// Changes made with the session cookie: a header only this site's script sends, and a same-site origin.
function checkCsrf(req) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return;
  const site = req.headers['sec-fetch-site'];
  if (req.headers['x-pyrmi-csrf'] !== '1' || (site && site !== 'same-origin')) throw httpError(403, 'csrf', 'Refused: this request didn\'t come from the Pyrmi dashboard.');
  const origin = req.headers.origin;
  if (origin && origin !== 'null') {
    let host = ''; try { host = new URL(origin).host; } catch (_) { /* bad origin */ }
    if (host !== String(req.headers['x-forwarded-host'] || req.headers.host)) throw httpError(403, 'csrf', 'Refused: this request didn\'t come from the Pyrmi dashboard.');
  }
}

async function signOut(req) {
  const sid = readCookies(req)[SESSION_COOKIE];
  if (sid) await kv.cmd('DEL', 'ps:auth:' + C.sha256(sid));
  return cookie(SESSION_COOKIE, '', 0);
}

// ---- sites --------------------------------------------------------------------------------------------------------

function status(p) {
  return { page: p.lastSession || 0, server: p.lastVerify || 0, connected: !!(p.lastSession && p.lastVerify) };
}

async function listSites(uid) {
  const pids = await kv.cmd('ZREVRANGE', 'ps:us:' + uid, 0, MAX_SITES * 2);
  const out = [];
  for (const pid of pids || []) {
    const p = await core.loadProject(pid);
    if (p && p.owner === uid) out.push({ pid, name: p.name, publicKey: p.publicKey, created: p.created, status: status(p) });
  }
  return out;
}

async function createSite(uid, body, ip) {
  if (num(await kv.cmd('ZCARD', 'ps:us:' + uid)) >= intEnv('PYRMI_SITES_PER_USER', MAX_SITES)) throw httpError(403, 'too_many_sites', 'You have the most sites an account can have. Delete one first.');
  const p = await core.createProject(body, ip, uid);
  await kv.cmd('ZADD', 'ps:us:' + uid, Date.now(), p.pid);
  return p;
}

// Brings a project made with the older key-only flow into this account. Its secret key is the proof of ownership.
async function claimSite(uid, sk) {
  const p = await core.projectBySecretKey(sk);
  if (!p || p.demo) throw httpError(404, 'not_found', 'No project has that secret key.');
  if (p.owner && p.owner !== uid) throw httpError(409, 'owned', 'That project already belongs to another account.');
  if (num(await kv.cmd('ZCARD', 'ps:us:' + uid)) >= intEnv('PYRMI_SITES_PER_USER', MAX_SITES)) throw httpError(403, 'too_many_sites', 'You have the most sites an account can have. Delete one first.');
  await kv.pipeline([['HSET', 'ps:p:' + p.pid, 'owner', uid], ['ZADD', 'ps:us:' + uid, Date.now(), p.pid]]);
  return { pid: p.pid, name: p.name, publicKey: p.publicKey };
}

async function ownedSite(uid, pid) {
  const p = typeof pid === 'string' && /^p_[\w-]{4,20}$/.test(pid) ? await core.loadProject(pid) : null;
  if (!p || p.owner !== uid) throw httpError(404, 'not_found', 'No site with that id in your account.');
  return p;
}

async function deleteSite(uid, p) {
  await core.deleteProject(p);
  await kv.cmd('ZREM', 'ps:us:' + uid, p.pid);
}

const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);

module.exports = {
  googleConfigured, googleStart, googleCallback, readIdToken, currentUser, requireUser, checkCsrf, signOut,
  listSites, createSite, claimSite, ownedSite, deleteSite, status, SESSION_COOKIE, STATE_COOKIE,
};
