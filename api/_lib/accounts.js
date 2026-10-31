'use strict';
// Accounts: three ways to sign in (a one-time code by email, GitHub, Google), signed-in sessions, and the sites each
// person owns.
//
// - Every way in ends at a verified email address, and one address is one account, whichever way was used.
// - Email codes are 6 digits, live 10 minutes, are stored only as a keyed hash, die after 5 wrong tries, and are capped
//   per address and per network. Asking for a code answers the same whether or not the address has an account.
// - GitHub and Google use the authorization-code flow with PKCE and a signed state cookie. Their tokens are used once
//   to read the verified email and never stored. Google's ID token comes straight from its token endpoint over TLS,
//   which is what lets us trust it without fetching Google's signing keys (OpenID Connect 3.1.3.7).
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
const smtp = require('./smtp');

const SESSION_COOKIE = '__Host-pyrmi_session';
const STATE_COOKIE = '__Host-pyrmi_oauth';
const SESSION_TTL = 7 * 86400;
const MAX_SITES = 10;
const CODE_TTL = 600;
const CODE_TRIES = 5;

const intEnv = (k, d) => { const n = parseInt(process.env[k], 10); return Number.isFinite(n) && n > 0 ? n : d; };

function googleConfigured() { return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET); }
function githubConfigured() { return !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET); }
// Sign-in codes go out through a normal mailbox over SMTP when SMTP_* is set, otherwise through Resend.
function emailConfigured() { return !!(smtp.config() || process.env.RESEND_API_KEY); }
function providers() { return { email: emailConfigured(), github: githubConfigured(), google: googleConfigured() }; }

// The address GitHub and Google send people back to. PYRMI_PUBLIC_URL pins it (it must match what's registered with
// them); otherwise it's this deployment's own address.
function baseUrl(req) {
  if (process.env.PYRMI_PUBLIC_URL) return process.env.PYRMI_PUBLIC_URL.replace(/\/+$/, '');
  const proto = String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim();
  return proto + '://' + String(req.headers['x-forwarded-host'] || req.headers.host);
}
function redirectUri(req, provider) { return baseUrl(req) + '/api/v1/auth/' + provider; }

// ---- cookies ----------------------------------------------------------------------------------------------------

function readCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (_) { /* bad cookie */ } }
  }
  return out;
}
function cookie(name, value, maxAge) {
  return name + '=' + encodeURIComponent(value) + '; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=' + maxAge;
}

// ---- one account per verified email -----------------------------------------------------------------------------

function cleanEmail(v) {
  const e = String(v || '').trim().toLowerCase();
  return e.length <= 254 && /^[^\s@<>()",;:\\]+@[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(e) ? e : null;
}

async function signIn(email, name, via) {
  const key = 'ps:ue:' + C.sha256(email);
  let uid = await kv.cmd('GET', key);
  if (!uid) {
    await kv.cmd('SET', key, 'u_' + C.randomId(12), 'NX');
    uid = await kv.cmd('GET', key);
  }
  const clean = String(name || email).replace(/[\u0000-\u001f<>]/g, '').slice(0, 80);
  await kv.cmd('HSET', 'ps:u:' + uid, 'email', email.slice(0, 254), 'name', clean, 'last', Date.now(), 'via', via);
  await kv.cmd('HSETNX', 'ps:u:' + uid, 'created', Date.now());
  const sid = C.randomId(32);
  await kv.cmd('SET', 'ps:auth:' + C.sha256(sid), uid, 'EX', SESSION_TTL);
  return { uid, setCookies: [cookie(SESSION_COOKIE, sid, SESSION_TTL), cookie(STATE_COOKIE, '', 0)] };
}

// ---- email codes ------------------------------------------------------------------------------------------------

async function codeHash(email, code) {
  return crypto.createHmac('sha256', await C.secret()).update('email-code:' + email + ':' + code).digest('base64url');
}

async function emailStart(body, ip, mailer) {
  if (!emailConfigured()) throw httpError(503, 'email_not_configured', 'Email sign-in isn\'t set up on this server yet.');
  const email = cleanEmail(body.email);
  if (!email) throw httpError(400, 'bad_email', 'That doesn\'t look like an email address.');
  const per = 'ps:rl:emailto:' + C.sha256(email);
  const [n] = await kv.pipeline([['INCR', per], ['EXPIRE', per, 3600]]);
  if (Number(n) > intEnv('PYRMI_EMAIL_CODES_PER_ADDRESS', 5)) throw httpError(429, 'rate_limited', 'Too many codes sent to that address. Try again in an hour.');
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  await kv.cmd('HSET', 'ps:ec:' + C.sha256(email), 'h', await codeHash(email, code), 'n', 0);
  await kv.cmd('EXPIRE', 'ps:ec:' + C.sha256(email), CODE_TTL);
  await (mailer || sendMail)({
    to: email,
    subject: 'Your Pyrmi sign-in code: ' + code,
    text: 'Your Pyrmi Security sign-in code is ' + code + '.\n\nIt works once, for the next 10 minutes. If you didn\'t ask for it, ignore this email: nobody can sign in without the code.\n\npyrmi.com',
    html: '<p>Your Pyrmi Security sign-in code is</p><p style="font:600 28px/1 monospace;letter-spacing:6px">' + code + '</p>' +
      '<p>It works once, for the next 10 minutes. If you didn\'t ask for it, ignore this email: nobody can sign in without the code.</p><p>pyrmi.com</p>',
  });
}

async function emailVerify(body) {
  if (!emailConfigured()) throw httpError(503, 'email_not_configured', 'Email sign-in isn\'t set up on this server yet.');
  const email = cleanEmail(body.email), code = String(body.code || '').replace(/\D/g, '');
  const wrong = httpError(400, 'bad_code', 'That code didn\'t work. Check it, or ask for a new one.');
  if (!email || code.length !== 6) throw wrong;
  const key = 'ps:ec:' + C.sha256(email);
  const tries = Number(await kv.cmd('HINCRBY', key, 'n', 1));
  const stored = await kv.cmd('HGET', key, 'h');
  if (!stored) { await kv.cmd('DEL', key); throw wrong; }
  if (tries > CODE_TRIES) { await kv.cmd('DEL', key); throw httpError(400, 'too_many_tries', 'Too many wrong codes. Ask for a new one.'); }
  if (!C.safeEqual(stored, await codeHash(email, code))) throw wrong;
  await kv.cmd('DEL', key);
  return signIn(email, email, 'email');
}

async function sendMail(msg) {
  const failed = () => httpError(502, 'email_failed', 'We couldn\'t send the email just now. Try again in a minute.');
  const cfg = smtp.config();
  if (cfg) {
    try {
      await smtp.send({ from: process.env.PYRMI_EMAIL_FROM || undefined, ...msg }, cfg);
    } catch (e) {
      console.error('[pyrmi] smtp send failed', String(e && e.message || e).slice(0, 120));
      throw failed();
    }
    return;
  }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.PYRMI_EMAIL_FROM || 'Pyrmi Security <login@pyrmi.com>', ...msg }),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) {
    console.error('[pyrmi] email send failed', r.status, (await r.text().catch(() => '')).slice(0, 300));
    throw failed();
  }
}

// ---- GitHub and Google ------------------------------------------------------------------------------------------

const OAUTH = {
  github: {
    configured: githubConfigured, name: 'GitHub',
    authorize: 'https://github.com/login/oauth/authorize', scope: 'read:user user:email',
    id: () => process.env.GITHUB_CLIENT_ID, secret: () => process.env.GITHUB_CLIENT_SECRET,
  },
  google: {
    configured: googleConfigured, name: 'Google',
    authorize: 'https://accounts.google.com/o/oauth2/v2/auth', scope: 'openid email profile', extra: { prompt: 'select_account' },
    id: () => process.env.GOOGLE_CLIENT_ID, secret: () => process.env.GOOGLE_CLIENT_SECRET,
  },
};

function notConfigured(p) { return httpError(503, p + '_not_configured', 'Sign in with ' + OAUTH[p].name + ' isn\'t set up on this server yet.'); }

async function oauthStart(req, provider) {
  const o = OAUTH[provider];
  if (!o.configured()) throw notConfigured(provider);
  const state = C.randomId(24), verifier = C.randomId(48);
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const signed = await C.signToken({ p: provider, s: state, v: verifier, e: Date.now() + 600e3 });
  const q = new URLSearchParams({
    client_id: o.id(), redirect_uri: redirectUri(req, provider), response_type: 'code', scope: o.scope,
    state, code_challenge: challenge, code_challenge_method: 'S256', ...(o.extra || {}),
  });
  return { location: o.authorize + '?' + q, setCookie: cookie(STATE_COOKIE, signed, 600) };
}

// Checks the state, then hands the code to the provider's own step, which returns the verified email.
async function oauthCallback(req, provider, params, hooks) {
  const o = OAUTH[provider];
  if (!o.configured()) throw notConfigured(provider);
  if (params.get('error')) throw httpError(400, 'cancelled', o.name + ' sign-in was cancelled.');
  const st = await C.readToken(readCookies(req)[STATE_COOKIE]);
  const state = params.get('state'), code = params.get('code');
  if (!st || st.p !== provider || !state || !C.safeEqual(st.s, state) || Date.now() > st.e || !code) {
    throw httpError(400, 'bad_state', 'That sign-in link expired or didn\'t come from this site. Try again.');
  }
  const form = { code, client_id: o.id(), client_secret: o.secret(), redirect_uri: redirectUri(req, provider), grant_type: 'authorization_code', code_verifier: st.v };
  const who = provider === 'github' ? await githubIdentity(form, hooks) : await googleIdentity(form, hooks);
  return signIn(who.email, who.name, provider);
}

async function googleIdentity(form, hooks) {
  const tokens = await ((hooks && hooks.exchange) || googleExchange)(form);
  const claims = readIdToken(tokens && tokens.id_token);
  if (!claims) throw httpError(400, 'bad_id_token', 'Google sent back something we couldn\'t read.');
  const now = Date.now() / 1000;
  const email = cleanEmail(claims.email);
  if (!['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss) || claims.aud !== process.env.GOOGLE_CLIENT_ID ||
      !(claims.exp > now) || !claims.sub || claims.email_verified !== true || !email) {
    throw httpError(400, 'bad_id_token', 'Google didn\'t confirm a verified email for this account.');
  }
  return { email, name: claims.name };
}

async function googleExchange(form) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw httpError(400, 'exchange_failed', 'Google didn\'t accept the sign-in. Try again.');
  return r.json();
}

function readIdToken(jwt) {
  if (typeof jwt !== 'string') return null;
  const parts = jwt.split('.');
  if (parts.length !== 3) return null;
  try { return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')); } catch (_) { return null; }
}

// GitHub: swap the code for a token, read the primary verified email, then forget the token.
async function githubIdentity(form, hooks) {
  const api = (hooks && hooks.github) || githubApi;
  const t = await api.exchange(form);
  if (!t || !t.access_token) throw httpError(400, 'exchange_failed', 'GitHub didn\'t accept the sign-in. Try again.');
  const [emails, user] = await Promise.all([api.get('/user/emails', t.access_token), api.get('/user', t.access_token)]);
  const primary = Array.isArray(emails) ? emails.find((e) => e && e.primary && e.verified) : null;
  const email = primary && cleanEmail(primary.email);
  if (!email) throw httpError(400, 'no_verified_email', 'Your GitHub account has no verified primary email. Verify one on GitHub and try again.');
  return { email, name: (user && (user.name || user.login)) || email };
}

const githubApi = {
  async exchange(form) {
    const r = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST', headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(form), signal: AbortSignal.timeout(8000),
    });
    return r.ok ? r.json() : null;
  },
  async get(path, token) {
    const r = await fetch('https://api.github.com' + path, {
      headers: { Authorization: 'Bearer ' + token, Accept: 'application/vnd.github+json', 'User-Agent': 'pyrmi-security', 'X-GitHub-Api-Version': '2022-11-28' },
      signal: AbortSignal.timeout(8000),
    });
    if (!r.ok) throw httpError(400, 'exchange_failed', 'GitHub didn\'t share your account details. Try again.');
    return r.json();
  },
};

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
  providers, googleConfigured, githubConfigured, emailConfigured, oauthStart, oauthCallback, emailStart, emailVerify, OAUTH,
  readIdToken, cleanEmail, sendMail, currentUser, requireUser, checkCsrf, signOut,
  listSites, createSite, claimSite, ownedSite, deleteSite, status, SESSION_COOKIE, STATE_COOKIE,
};
