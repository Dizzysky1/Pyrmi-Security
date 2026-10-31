'use strict';
// Cloudflare Turnstile: a human check on pyrmi.com's own forms (sign-in codes, new sites, account changes).
// Browser telemetry can't stop a script that copies the real one exactly (README, "Threat model"); Turnstile is a
// separate, independent check run by Cloudflare. Off until both keys are set, so nothing changes for a self-hosted
// copy or a preview without them:
//   TURNSTILE_SITE_KEY    the widget's site key (public, sent to the page)
//   TURNSTILE_SECRET_KEY  its secret key (server only)
//   TURNSTILE_HOSTNAMES   optional, comma-separated: the page hostnames a token may come from (default: the host the
//                         request was sent to, so a token solved on another site that uses the same widget is refused)
// When it's on it fails closed: a missing, used or failed token is refused, and so is a request while Cloudflare can't
// be reached, because letting those through would make the check optional for anyone who can block one request.
const { httpError } = require('./http');
const kv = require('./kv');
const { sha256 } = require('./crypto');

const VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const TOKEN_TTL = 600; // Cloudflare tokens live 300 s; keep the used-token record for twice that

function configured() { return !!(process.env.TURNSTILE_SITE_KEY && process.env.TURNSTILE_SECRET_KEY); }
function siteKey() { return configured() ? process.env.TURNSTILE_SITE_KEY : null; }
function hostnames(host) {
  const set = String(process.env.TURNSTILE_HOSTNAMES || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (set.length) return set;
  const h = String(host || '').toLowerCase().replace(/:\d+$/, '');
  return h ? [h] : [];
}

const failed = (msg) => httpError(403, 'turnstile_failed', msg || 'The human check didn\'t pass. Try again.');

// Checks a token from the page against Cloudflare. `action` is the name the page gave the widget for this form, and
// Cloudflare's answer must carry exactly that action; `host` is the request's Host header (see TURNSTILE_HOSTNAMES).
// Each token is accepted once: Cloudflare refuses a duplicate itself, and a hash of every accepted token is kept for
// 10 minutes so a token can't be replayed here even if that ever changed. Returns null when Turnstile is off,
// Cloudflare's answer when it passed; throws otherwise.
async function check(token, ip, action, host) {
  if (!configured()) return null;
  if (typeof token !== 'string' || !token || token.length > 2048) throw httpError(403, 'turnstile_required', 'Complete the human check and try again.');
  let r = null;
  try {
    const form = new URLSearchParams({ secret: process.env.TURNSTILE_SECRET_KEY, response: token });
    if (ip) form.set('remoteip', String(ip));
    const res = await fetch(module.exports.endpoint || VERIFY_URL, { method: 'POST', body: form, signal: AbortSignal.timeout(8000) });
    r = await res.json();
  } catch (_) {
    throw httpError(503, 'turnstile_unavailable', 'The human check couldn\'t be confirmed right now. Try again in a moment.');
  }
  if (!r || r.success !== true) throw failed();
  if (action && r.action !== action) throw failed('The human check was for a different form. Try again.');
  const allowed = hostnames(host);
  if (allowed.length && !allowed.includes(String(r.hostname || '').toLowerCase())) throw failed('The human check came from a different site. Try again.');
  const fresh = await kv.cmd('SET', 'ts:used:' + sha256(token), '1', 'NX', 'EX', TOKEN_TTL);
  if (!fresh) throw failed('That human check was already used. Try again.');
  return r;
}

module.exports = { configured, siteKey, check, VERIFY_URL, endpoint: null }; // tests swap in a fake endpoint
