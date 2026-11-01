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
// A real session id is base64url of 32 random bytes (crypto.randomId(32)) -> exactly 43 url-safe chars. Matching
// the shape lets us reject a junk cookie before any KV lookup, so a flood of forged cookies can't drive Redis reads (F-20).
const SID_RE = /^[A-Za-z0-9_-]{43}$/;
const MAX_SITES = 10;
const CODE_TTL = 600;
const CODE_TRIES = 5;        // wrong tries on a code before it's deleted (only its own browser can try it)
// A code belongs to the browser that asked for it. Asking sets this cookie (a random id), the code is kept under the
// address and that id, and only a verify carrying the same cookie can try it.
const EC_COOKIE = '__Host-pyrmi_ec';
// A browser that has signed in to an account before carries a device mark for it (an id and a MAC over the address),
// and it can still be sent codes when others have used up the address's hourly cap. Nobody can make one without the
// server's secret. New browsers can still use GitHub and Google when the cap is full.
const DEV_COOKIE = '__Host-pyrmi_dev';
const RID_RE = /^[A-Za-z0-9_-]{22}$/;
const newRid = () => C.randomId(16);
const codeKey = (email, rid) => 'ps:ec:' + C.sha256(email) + ':' + C.sha256(rid);
async function deviceMac(email, id) {
  return crypto.createHmac('sha256', await C.secret()).update('pyrmi.dev.v1.' + C.sha256(email) + '.' + id).digest('base64url');
}
async function deviceMark(email) { const id = newRid(); return id + '.' + await deviceMac(email, id); }
async function knownDevice(email, mark) {
  const [id, mac] = String(mark || '').split('.');
  return !!(id && mac && RID_RE.test(id) && C.safeEqual(mac, await deviceMac(email, id)));
}

const intEnv = (k, d) => { const n = parseInt(process.env[k], 10); return Number.isFinite(n) && n > 0 ? n : d; };
// Signed-in session lifetime. Env-tunable so it can be lowered without a deploy; the default is kept at 7 days
// because shortening it signs everyone out sooner (a product/UX call). Recommend setting PYRMI_SESSION_TTL_DAYS lower.
const sessionTtlSec = () => intEnv('PYRMI_SESSION_TTL_DAYS', 7) * 86400;

function googleConfigured() { return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET); }
function githubConfigured() { return !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET); }
// Sign-in codes go out through a normal mailbox over SMTP when SMTP_* is set, otherwise through Resend.
function emailConfigured() { return !!(smtp.config() || process.env.RESEND_API_KEY); }
function providers() { return { email: emailConfigured(), github: githubConfigured(), google: googleConfigured() }; }

// This deployment's own host. X-Forwarded-Host is only read on Vercel, whose edge writes it itself; anywhere else a
// caller can type it, so the request's own Host is used. A self-host behind a proxy that rewrites
// Host sets PYRMI_PUBLIC_URL instead.
function ownHost(req) {
  const fwd = process.env.VERCEL_ENV ? String(req.headers['x-forwarded-host'] || '').split(',')[0].trim() : '';
  return fwd || String(req.headers.host || '');
}
// The address GitHub and Google send people back to. PYRMI_PUBLIC_URL pins it (it must match what's registered with
// them); otherwise it's this deployment's own address.
function baseUrl(req) {
  if (process.env.PYRMI_PUBLIC_URL) return process.env.PYRMI_PUBLIC_URL.replace(/\/+$/, '');
  const proto = process.env.VERCEL_ENV ? String(req.headers['x-forwarded-proto'] || 'https').split(',')[0].trim() : 'https';
  const host = ownHost(req);
  return (/^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host) ? 'http' : proto) + '://' + host;
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
  const e = (typeof v === 'string' ? v : '').trim().toLowerCase(); // a non-string (an object with no toString) threw a 500
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
  const sid = C.randomId(32), sidh = C.sha256(sid), ttl = sessionTtlSec();
  await kv.cmd('SET', 'ps:auth:' + sidh, uid, 'EX', ttl);
  // Index this session under the user so every session can be revoked at once. Before this there was no per-user
  // index and no revoke-all: a stolen or stale cookie could only be ended by deleting that one key or rotating the
  // whole signing secret. The index is a ZSET (member = session hash), bounded by its own TTL and cleared on
  // revoke-all. (Q4/Q10)
  await kv.cmd('ZADD', 'ps:usess:' + uid, Date.now(), sidh);
  await kv.cmd('EXPIRE', 'ps:usess:' + uid, ttl + 86400);
  return { uid, setCookies: [cookie(SESSION_COOKIE, sid, ttl), cookie(STATE_COOKIE, '', 0), cookie(DEV_COOKIE, await deviceMark(email), 400 * 86400)] };
}

// ---- email codes ------------------------------------------------------------------------------------------------

async function codeHash(email, code) {
  return crypto.createHmac('sha256', await C.secret()).update('email-code:' + email + ':' + code).digest('base64url');
}

// Hour-long counter whose TTL is set with the key, in the same request (see core's bump()).
async function hourly(key) {
  const r = await kv.pipeline([['SET', key, '0', 'EX', 3600, 'NX'], ['INCR', key]]);
  return Number(r[1]);
}

// opts: { rid, device } from the requesting browser's cookies (EC_COOKIE, DEV_COOKIE); the endpoint sets EC_COOKIE.
async function emailStart(body, ip, mailer, opts) {
  const o = opts || {};
  const rid = RID_RE.test(String(o.rid || '')) ? o.rid : newRid();
  if (!emailConfigured()) throw httpError(503, 'email_not_configured', 'Email sign-in isn\'t set up on this server yet.');
  const email = cleanEmail(body.email);
  if (!email) throw httpError(400, 'bad_email', 'That doesn\'t look like an email address.');
  // Codes to one address are limited per network, so somebody else asking for codes to your address can't use up
  // your hourly allowance (they used to lock the owner out for an hour with five requests). A looser cap on the
  // address as a whole still bounds how many codes one inbox can be sent.
  const ah = C.sha256(email), ipf = await C.fingerprint('ip', core.network(ip));
  const tooMany = () => { const e = httpError(429, 'rate_limited', 'Too many codes sent to that address. Try again in an hour.'); e.retryAfter = 3600; return e; };
  if (await hourly('ps:rl:emailto:' + ah + ':' + ipf) > intEnv('PYRMI_EMAIL_CODES_PER_ADDRESS', 5)) throw tooMany();
  const device = await knownDevice(email, o.device);
  if (await hourly('ps:rl:emailto:' + ah) > intEnv('PYRMI_EMAIL_CODES_PER_ADDRESS_TOTAL', 20) && !device) throw tooMany();
  const day = core.ymd(Date.now());
  // One network's share of the day's codes, whatever addresses it asks for.
  if (await core.hit('ps:rl:emailnet:' + ipf + ':' + day, 2 * 86400) > intEnv('PYRMI_EMAIL_CODES_PER_IP_PER_DAY', 30)) {
    const e = httpError(429, 'rate_limited', 'Too many sign-in codes from your network today. Try again tomorrow or use another sign-in method.'); e.retryAfter = 3600; throw e;
  }
  // Per-network and per-address limits don't bound the TOTAL: rotating both lets a script send one code to each of
  // many addresses, bombing inboxes and burning the sender's reputation, so the server's codes are capped too (F-24).
  // That cap used to cover everyone, so 50 networks could pause email sign-in for the whole server until midnight
  // (retest of b127c08). Now it only covers addresses with no account yet: people who already have one keep getting
  // codes (bounded per address above and by a larger backstop). Past the cap a new address gets the same answer as any
  // other, so the cap doesn't tell anyone which addresses have accounts, but no mail is sent; the dashboard says to
  // use GitHub or Google if a code doesn't come. Crossing 80% of either cap is logged (see core.nearLimit).
  const known = Number(await kv.cmd('EXISTS', 'ps:ue:' + ah)) > 0;
  if (known) {
    const n = await core.hit('ps:rl:emailknown:' + day, 2 * 86400), cap = intEnv('PYRMI_EMAIL_KNOWN_PER_DAY', 5000);
    await core.nearLimit('email-known', n, cap, day);
    // A browser that signed in to this account before still gets its code past the cap.
    if (n > cap && !device) { const e = httpError(429, 'rate_limited', 'Email sign-in is busy right now. Try again later or use another sign-in method.'); e.retryAfter = 3600; throw e; }
  } else {
    const hour = new Date().toISOString().slice(0, 13).replace(/\D/g, '');
    const [d, h] = await Promise.all([core.hit('ps:rl:emailstart:' + day, 2 * 86400), core.hit('ps:rl:emailnew:' + hour, 7200)]);
    const dayCap = intEnv('PYRMI_EMAIL_STARTS_PER_DAY', 500), hourCap = intEnv('PYRMI_EMAIL_NEW_PER_HOUR', 100);
    await core.nearLimit('email-new', d, dayCap, day);
    if (d > dayCap || h > hourCap) return { sent: false };
  }
  const code = String(crypto.randomInt(0, 1e6)).padStart(6, '0');
  await kv.pipeline([['HSET', codeKey(email, rid), 'h', await codeHash(email, code), 'n', 0], ['EXPIRE', codeKey(email, rid), CODE_TTL]]);
  await (mailer || sendMail)({
    to: email,
    subject: 'Your Pyrmi sign-in code: ' + code,
    text: 'Your Pyrmi Security sign-in code is ' + code + '.\n\nIt works once, for the next 10 minutes. If you didn\'t ask for it, ignore this email: nobody can sign in without the code.\n\npyrmi.com',
    html: '<p>Your Pyrmi Security sign-in code is</p><p style="font:600 28px/1 monospace;letter-spacing:6px">' + code + '</p>' +
      '<p>It works once, for the next 10 minutes. If you didn\'t ask for it, ignore this email: nobody can sign in without the code.</p><p>pyrmi.com</p>',
  });
  return { sent: true };
}

// opts: { rid } from the browser's EC_COOKIE. Only the browser that asked for the code can try it, CODE_TRIES times.
async function emailVerify(body, ip, opts) {
  if (!emailConfigured()) throw httpError(503, 'email_not_configured', 'Email sign-in isn\'t set up on this server yet.');
  const email = cleanEmail(body.email), code = (typeof body.code === 'string' || typeof body.code === 'number' ? String(body.code) : '').replace(/\D/g, '');
  const wrong = httpError(400, 'bad_code', 'That code didn\'t work. Check it, or ask for a new one.');
  const rid = String((opts && opts.rid) || '');
  if (!email || code.length !== 6 || !RID_RE.test(rid)) throw wrong;
  const key = codeKey(email, rid);
  const [n, stored] = await kv.pipeline([['HINCRBY', key, 'n', 1], ['HGET', key, 'h']]);
  if (!stored) { await kv.cmd('DEL', key); throw wrong; }
  const tooMany = httpError(400, 'too_many_tries', 'Too many wrong codes. Ask for a new one.');
  if (Number(n) > CODE_TRIES) { await kv.cmd('DEL', key); throw tooMany; }
  if (!C.safeEqual(stored, await codeHash(email, code))) {
    if (Number(n) >= CODE_TRIES) await kv.cmd('DEL', key);
    throw wrong;
  }
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

// The session id from the cookie, but only if it's well-formed. A missing or malformed cookie returns null with no
// KV call, so junk cookies cost nothing (F-20). Callers can use this to decide whether a request is worth a lookup.
function sessionSid(req) {
  const sid = readCookies(req)[SESSION_COOKIE];
  return sid && SID_RE.test(sid) ? sid : null;
}

async function currentUser(req) {
  const sid = sessionSid(req);
  if (!sid) return null;
  const sidh = C.sha256(sid);
  const uid = await kv.cmd('GET', 'ps:auth:' + sidh);
  if (!uid) return null;
  // Only sessions in the per-user index count. Sessions from before the index existed were never in it, so
  // revoke-all couldn't end them; now they simply stop working (a one-time sign-in again), and revoke-all, which
  // clears the index, ends every session there is.
  const [inIndex, h] = await kv.pipeline([['ZSCORE', 'ps:usess:' + uid, sidh], ['HGETALL', 'ps:u:' + uid]]);
  if (inIndex === null || inIndex === undefined) return null;
  const u = kv.pairs(h);
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
  // Compare the whole origin (scheme, host and port), and refuse Origin: null, which sandboxed iframes and some
  // redirects send. Plain http is only accepted from this machine, for local development.
  const origin = req.headers.origin;
  if (origin !== undefined) {
    const refused = () => httpError(403, 'csrf', 'Refused: this request didn\'t come from the Pyrmi dashboard.');
    let u = null; try { u = new URL(origin); } catch (_) { throw refused(); }
    const host = ownHost(req);
    const local = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/.test(host);
    let pinned = ''; try { pinned = process.env.PYRMI_PUBLIC_URL ? new URL(process.env.PYRMI_PUBLIC_URL).origin : ''; } catch (_) {}
    if (u.origin !== (local && u.protocol === 'http:' ? 'http://' : 'https://') + host && !(pinned && u.origin === pinned)) throw refused();
  }
}

async function signOut(req) {
  const sid = readCookies(req)[SESSION_COOKIE];
  if (sid) {
    const sidh = C.sha256(sid);
    const uid = await kv.cmd('GET', 'ps:auth:' + sidh);
    await kv.cmd('DEL', 'ps:auth:' + sidh);
    if (uid) await kv.cmd('ZREM', 'ps:usess:' + uid, sidh); // keep the per-user index in step (Q4/Q10)
  }
  return cookie(SESSION_COOKIE, '', 0);
}

// Revoke every signed-in session for a user at once: delete each indexed ps:auth entry, then clear the index.
// Backs POST /api/v1/me?action=revoke-all, so a user — or a response to a suspected compromise — can sign out
// everywhere without rotating the signing secret. Returns how many sessions were ended. (Q4/Q10)
async function revokeAllSessions(uid) {
  const members = (await kv.cmd('ZRANGE', 'ps:usess:' + uid, 0, -1)) || [];
  if (members.length) await kv.cmd('DEL', ...members.map((h) => 'ps:auth:' + h));
  await kv.cmd('DEL', 'ps:usess:' + uid);
  return members.length;
}

// ---- sites --------------------------------------------------------------------------------------------------------

function status(p) {
  return { page: p.lastSession || 0, server: p.lastVerify || 0, connected: !!(p.lastSession && p.lastVerify) };
}

async function listSites(uid) {
  // Read every site the account has (bounded by the per-account cap, whatever it is set to), not a fixed number.
  const pids = await kv.cmd('ZREVRANGE', 'ps:us:' + uid, 0, Math.max(intEnv('PYRMI_SITES_PER_USER', MAX_SITES), MAX_SITES) * 2 - 1);
  const out = [];
  for (const pid of pids || []) {
    const p = await core.loadProject(pid);
    if (p && p.owner === uid) out.push({ pid, name: p.name, publicKey: p.publicKey, created: p.created, status: status(p) });
  }
  return out;
}

async function createSite(uid, body, ip) {
  const key = 'ps:us:' + uid, cap = intEnv('PYRMI_SITES_PER_USER', MAX_SITES);
  if (num(await kv.cmd('ZCARD', key)) >= cap) throw httpError(403, 'too_many_sites', 'You have the most sites an account can have. Delete one first.');
  const p = await core.createProject(body, ip, uid);
  await kv.cmd('ZADD', key, Date.now(), p.pid);
  // The pre-check and the add are two steps, so parallel creates can both pass it. Re-check after reserving the slot
  // and roll this one back if we went over, so concurrent POSTs can't exceed the per-owner cap (A2-08).
  if (num(await kv.cmd('ZCARD', key)) > cap) {
    await kv.cmd('ZREM', key, p.pid);
    await core.deleteProject(await core.loadProject(p.pid));
    throw httpError(403, 'too_many_sites', 'You have the most sites an account can have. Delete one first.');
  }
  return p;
}

// Brings a project made with the older key-only flow into this account. Its secret key is the proof of ownership.
// Claiming moves a key-only project into an account. By default it also issues a new secret key, so only the new
// owner holds one.
// keepKey: true skips that, for an owner who knows no one else has the key and can't redeploy right away.
async function claimSite(uid, sk, opts) {
  const found = await core.projectBySecretKey(sk);
  if (!found || found.demo) throw httpError(404, 'not_found', 'No project has that secret key.');
  if (found.owner && found.owner !== uid) throw httpError(409, 'owned', 'That project already belongs to another account.');
  if (num(await kv.cmd('ZCARD', 'ps:us:' + uid)) >= intEnv('PYRMI_SITES_PER_USER', MAX_SITES)) throw httpError(403, 'too_many_sites', 'You have the most sites an account can have. Delete one first.');
  // The whole claim runs under the project's key lock, the same one a rotation takes, and checks the key again there,
  // so a claim either completes with a key only the new owner has, or changes nothing.
  return core.withKeyLock(found.pid, async () => {
    const p = await core.projectBySecretKey(sk);
    if (!p || p.pid !== found.pid) throw httpError(404, 'not_found', 'No project has that secret key.');
    // Take ownership atomically. HSETNX sets owner only while the project is still unowned, so exactly one racing claim
    // wins; only that winner adds the per-user index entry. (M10)
    const won = num(await kv.cmd('HSETNX', 'ps:p:' + p.pid, 'owner', uid), 0);
    if (!won) {
      const current = await core.loadProject(p.pid);
      if (current && current.owner === uid) return { pid: p.pid, name: p.name, publicKey: p.publicKey }; // already ours (idempotent)
      throw httpError(409, 'owned', 'That project already belongs to another account.');
    }
    await kv.cmd('ZADD', 'ps:us:' + uid, Date.now(), p.pid);
    // It now belongs to an account, so it stops counting against the key-only project cap.
    if (Number(await kv.cmd('HDEL', 'ps:p:' + p.pid, 'anon')) > 0) await core.releaseAnon();
    const secretKey = opts && opts.keepKey === true ? undefined : await core.rotateLocked(p, sk);
    // A claim ends the sessions started before it either way; the rotation already did when it ran.
    if (!secretKey) await kv.cmd('HINCRBY', 'ps:p:' + p.pid, 'ep', 1);
    return { pid: p.pid, name: p.name, publicKey: p.publicKey, ...(secretKey ? { secretKey } : {}) };
  });
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
  baseUrl, providers, googleConfigured, githubConfigured, emailConfigured, oauthStart, oauthCallback, emailStart, emailVerify, OAUTH,
  readIdToken, cleanEmail, sendMail, currentUser, requireUser, sessionSid, checkCsrf, signOut, revokeAllSessions,
  listSites, createSite, claimSite, ownedSite, deleteSite, status, SESSION_COOKIE, STATE_COOKIE, EC_COOKIE, DEV_COOKIE, readCookies, cookie, CODE_TTL, RID_RE,
};
