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

module.exports = { b64u, sha256, randomId, safeEqual, secret, fingerprint, signToken, readToken, randomUint32: () => crypto.randomBytes(4).readUInt32LE(0) };
