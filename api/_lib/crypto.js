'use strict';
const crypto = require('crypto');
const kv = require('./kv');

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const randomId = (bytes) => crypto.randomBytes(bytes || 12).toString('base64url');

function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

// Signing secret: PYRMI_SECRET, 32+ characters. With no secret set the server fails closed: every call that signs or
// checks a token answers 503 until it's set. It used to fall back to a random secret kept in Redis under ps:secret, so
// anyone who could read the store (a leaked KV token, a shared preview) could forge any session token.
// The one exception is the in-memory store (PYRMI_KV=memory: local dev, tests, previews with no Redis), which keeps
// nothing past the process anyway: there a random secret for this process is used, and never written anywhere.
let cached = null;
async function secret() {
  const env = process.env.PYRMI_SECRET;
  if (env && env.length >= 32) return env;
  if (process.env.PYRMI_KV === 'memory') return cached || (cached = randomId(48));
  const e = new Error('This server is not set up yet: PYRMI_SECRET is ' + (env ? 'shorter than 32 characters.' : 'not set.'));
  e.status = 503; e.code = 'secret_not_configured';
  console.error('[pyrmi] ' + e.message + ' Refusing to sign or check tokens.');
  throw e;
}

// Salted hash so raw IPs / user agents are never stored.
async function fingerprint(kind, value) {
  const s = await secret();
  return crypto.createHmac('sha256', s).update(kind + ':' + value).digest('base64url').slice(0, 12);
}

// token = base64url(json) "." base64url(hmac)
async function signToken(payload) {
  const body = b64u(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', await secret()).update('pyrmi.v1.' + body).digest('base64url');
  return body + '.' + mac;
}

async function readToken(token) {
  if (typeof token !== 'string' || token.length > 2048) return null;
  const dot = token.indexOf('.');
  if (dot < 1) return null;
  const body = token.slice(0, dot), mac = token.slice(dot + 1);
  const want = crypto.createHmac('sha256', await secret()).update('pyrmi.v1.' + body).digest('base64url');
  if (!safeEqual(mac, want)) return null;
  try { return JSON.parse(Buffer.from(body, 'base64url').toString('utf8')); } catch (_) { return null; }
}

// Signed requests (round 11). Each session gets its own request key, handed to the browser script with the session and
// never put in the token. The script uses it to sign the action the page sends (HMAC over the session id, a timestamp
// and the action's fields), and the server recomputes it at /verify. A request rewritten on the wire (a proxy, CDP's
// Fetch domain) or replayed with a lifted token can't carry a valid signature, because neither ever saw the key.
// It's derived from PYRMI_SECRET and the session id, so nothing extra is stored. It is NOT proof of a person: code
// running in the real page can ask the script to sign whatever it likes.
async function requestKey(sid) {
  return crypto.createHmac('sha256', await secret()).update('pyrmi.rk.v1.' + sid).digest('base64url');
}
// The same canonical form the browser script builds: JSON with object keys sorted at every level and undefined
// values left out, so a server that parsed the JSON and a page that built the object agree byte for byte.
function canon(v) {
  if (Array.isArray(v)) return '[' + v.map((x) => (x === undefined || typeof x === 'function' ? 'null' : canon(x))).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort().filter((k) => v[k] !== undefined && typeof v[k] !== 'function').map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  }
  const j = JSON.stringify(v);
  return j === undefined ? 'null' : j;
}
function requestMac(rk, sid, ts, fieldsCanon) {
  return crypto.createHmac('sha256', Buffer.from(String(rk), 'base64url')).update('pyrmi.req.v1\n' + sid + '\n' + ts + '\n' + fieldsCanon).digest('base64url');
}

module.exports = { requestKey, canon, requestMac, b64u, sha256, randomId, safeEqual, secret, fingerprint, signToken, readToken, randomUint32: () => crypto.randomBytes(4).readUInt32LE(0) };
