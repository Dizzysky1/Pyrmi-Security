'use strict';
// pyrmi-server: ask Pyrmi Security for a verdict before your server trusts an action (a sign-up, a vote, a score,
// a checkout). No dependencies.
//
//   const { Pyrmi } = require('pyrmi-server');
//   const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });
//   const v = await pyrmi.verify({ sealed: req.body, req, user }); // the page sent Pyrmi.seal({ ... }) as JSON
//   (or the older form: pyrmi.verify({ token, user }); add score: n to check a number too)
//   if (v.verdict !== 'reject') doTheThing(...);             // everyday actions: let review through, flagged
//                                                            // (v.verdict is always accept, review or reject here)
//   if (trusted(v)) payOut(...);                             // sensitive ones: only a corroborated accept
//   const t = await pyrmi.verifyTurnstile(body.turnstileToken, { remoteip, action: 'payout' });
//   if (trusted(v, t)) payOut(...);                          // ...plus Cloudflare Turnstile, a check that doesn't
//                                                            // depend on Pyrmi's browser telemetry at all

class Pyrmi {
  constructor(opts) {
    opts = opts || {};
    this.secretKey = opts.secretKey || process.env.PYRMI_SECRET_KEY;
    this.endpoint = String(opts.endpoint || process.env.PYRMI_ENDPOINT || 'https://pyrmi.com/api/v1').replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs || 8000;
    // If Pyrmi is unreachable: false = reject the action, true = accept it unverified. Only true or 'true' turns it on.
    this.failOpen = opts.failOpen === true || opts.failOpen === 'true';
    this.trustProxyHops = opts.trustProxyHops || 0; // proxies of yours in front of this server (for the caller's address)
    // Optional: your own Cloudflare Turnstile widget's secret key, for verifyTurnstile().
    this.turnstileSecret = opts.turnstileSecret || process.env.TURNSTILE_SECRET_KEY || null;
    this.turnstileEndpoint = opts.turnstileEndpoint || 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    if (!this.secretKey || !/^sk_/.test(this.secretKey)) throw new Error('pyrmi-server: pass { secretKey: "sk_..." } or set PYRMI_SECRET_KEY');
    if (typeof window !== 'undefined' && typeof document !== 'undefined') throw new Error('pyrmi-server: this runs on your server only, never in the browser');
  }

  // Returns { verdict: 'accept'|'review'|'reject', risk, client: 'corroborated'|'unverified'|'none', trusted, reasons, session, player, score }.
  // user is an alias for player. score is optional: send it when the action carries a number you want capped.
  // simulate (optional): (replay, { seed, session }) => ({ score, durationMs }) re-runs a deterministic app from its
  // recorded inputs on your server, seeded with the session's own seed (from the token, never from the body). If it
  // gives a different score, the verdict is 'reject' with reason replay_mismatch.
  //
  // sealed (recommended): the parsed JSON body your page sent, made by Pyrmi.seal({ ... }) in the browser. Its pyrmi
  // part carries the token and the signature, and Pyrmi checks the rest arrived exactly as the page signed it, so a
  // value changed on the way (a proxy, a debugger rewriting the request) is a reject (bad_signature).
  // req: your incoming request (Node, Express, Next.js API routes). Its User-Agent, Sec-CH-UA, Sec-Fetch-Site and the
  // caller's address are sent along, and Pyrmi checks they match the browser that started the session, so a session
  // handed to another client (a harvested token used by a script) is flagged (relayed_session). Or pass client: {...}.
  // Behind your own proxies, set trustProxyHops so the address is read from the right X-Forwarded-For entry.
  async verify(input) {
    const { durationMs, replay, simulate } = input || {};
    const sealed = input && input.sealed && typeof input.sealed === 'object' ? input.sealed : null;
    // With sealed, the score defaults to the sealed body's own `score`, so the value Pyrmi caps is the one the page
    // signed. A different score passed here than the signed one is a reject (bad_signature).
    let score = input && input.score !== undefined ? input.score : sealed && typeof sealed.score === 'number' ? sealed.score : undefined;
    // NaN and Infinity have no JSON form, so they're sent as text, which Pyrmi rejects (bad_score).
    if (typeof score === 'number' && !Number.isFinite(score)) score = String(score);
    let dur = durationMs;
    if (typeof dur === 'number' && !Number.isFinite(dur)) dur = String(dur);
    const seal = sealed && sealed.pyrmi && typeof sealed.pyrmi === 'object' ? sealed.pyrmi : null;
    const token = input && input.token !== undefined ? input.token : seal ? seal.token : undefined;
    let request;
    if (seal && seal.sig !== undefined) {
      // A null-prototype copy, so every key in the parsed body stays a field and is sent as one.
      const fields = Object.create(null);
      for (const k of Object.keys(sealed)) if (k !== 'pyrmi') fields[k] = sealed[k];
      request = { fields, ts: seal.ts, sig: seal.sig };
    }
    const client = input && input.client ? input.client : input && input.req ? clientOf(input.req, this.trustProxyHops) : undefined;
    const player = input && input.player !== undefined ? input.player : input && input.user;
    // The human check for trusted (round 12): the Turnstile token your page got from a widget rendered with
    // cdata: session (the id Pyrmi.start() answers), sent along with your Turnstile secret key so Pyrmi can confirm it
    // with Cloudflare itself. Pyrmi uses the key for that one call and never stores or logs it. Pass it as
    // turnstile: token (or { token, action }); with sealed, a `turnstile` field in the sealed body is used by default.
    let human;
    const tin = input && input.turnstile !== undefined ? input.turnstile : sealed && typeof sealed.turnstile === 'string' ? sealed.turnstile : undefined;
    const ttoken = tin && typeof tin === 'object' ? tin.token : tin;
    if (typeof ttoken === 'string' && ttoken && this.turnstileSecret) human = { token: ttoken, secret: this.turnstileSecret, action: tin && typeof tin === 'object' && tin.action !== undefined ? tin.action : undefined };
    // A sealed number JSON can't carry exactly (Infinity, NaN, -0, a whole number past 2^53) is refused here.
    if (request) { const bad = badNumber(request.fields); if (bad) return refusal('the sealed field ' + bad + ' is a number that can\'t be checked exactly'); }
    let replayCheck = { check: 'none' };
    if (typeof simulate === 'function') {
      try {
        // The session's own seed and id, read from the token (never take the seed from the request body). The token isn't
        // checked here; Pyrmi checks it in this same call.
        const r = await simulate(replay, sessionOf(token));
        const same = r && Number(r.score) === Number(score) && (durationMs == null || r.durationMs == null || Math.abs(r.durationMs - durationMs) <= 50);
        replayCheck = same ? { check: 'match' } : { check: 'mismatch', detail: 'replay gave ' + (r ? r.score : 'nothing') + ', claimed ' + score };
      } catch (e) {
        replayCheck = { check: 'mismatch', detail: 'replay failed: ' + String(e && e.message).slice(0, 80) };
      }
    }
    // failOpen covers Pyrmi being down (no answer, a timeout, a 5xx), never something the caller can cause.
    // An oversized or malformed action, or a 4xx answer to it (413 too large, 400, 403, 429), is a reject.
    const refuse = refusal;
    let payload;
    try { payload = JSON.stringify({ token, score, durationMs: dur, player, replay: replayCheck, request, client, turnstile: human }); } catch (e) { return refuse('it could not be sent (' + (e && e.message) + ')'); }
    if (Buffer.byteLength(payload) > 16 * 1024) return refuse('it is larger than 16 KB');
    try {
      const res = await fetch(this.endpoint + '/verify', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + this.secretKey, 'Content-Type': 'application/json' },
        body: payload,
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const body = await res.json().catch(() => null);
      if (res.status >= 400 && res.status < 500 && res.status !== 401) return refuse((body && (body.message || body.error)) || 'HTTP ' + res.status);
      if (!res.ok) throw Object.assign(new Error((body && body.message) || 'Pyrmi returned ' + res.status), { code: (body && body.error) || 'http_' + res.status, status: res.status });
      // Anything without a real verdict (an HTML page from a proxy, a wrong endpoint) is treated as Pyrmi being
      // unreachable: reject, unless you chose failOpen.
      if (!body || body.ok !== true || !['accept', 'review', 'reject'].includes(body.verdict)) throw new Error('Pyrmi sent something that isn\'t a verdict');
      return body;
    } catch (e) {
      if (e && e.status === 401) throw e; // a wrong key is a setup bug, not an outage
      return { ok: false, verdict: this.failOpen ? 'accept' : 'reject', risk: null, reasons: [{ code: 'pyrmi_unreachable', text: 'Could not reach Pyrmi: ' + (e && e.message) }], unverified: true };
    }
  }

  // Checks a Cloudflare Turnstile token from your page (the widget's cf-turnstile-response) with Cloudflare.
  // Returns { success, errorCodes, hostname, action }. Fails closed: no secret, no token, a token Cloudflare already
  // saw, a different action or hostname than you expect, or Cloudflare being unreachable all give success: false.
  // opts: remoteip (the visitor's IP), action (what your widget's data-action was), hostname (your site's host).
  async verifyTurnstile(token, opts) {
    opts = opts || {};
    const no = (code, r) => ({ success: false, errorCodes: [code], hostname: r && r.hostname, action: r && r.action });
    if (!this.turnstileSecret) return no('missing-input-secret');
    if (typeof token !== 'string' || !token || token.length > 2048) return no('missing-input-response');
    let r;
    try {
      const form = new URLSearchParams({ secret: this.turnstileSecret, response: token });
      if (opts.remoteip) form.set('remoteip', String(opts.remoteip));
      const res = await fetch(this.turnstileEndpoint, { method: 'POST', body: form, signal: AbortSignal.timeout(this.timeoutMs) });
      r = await res.json();
    } catch (e) {
      return no('turnstile-unreachable');
    }
    if (!r || r.success !== true) return { success: false, errorCodes: (r && r['error-codes']) || ['failed'], hostname: r && r.hostname, action: r && r.action };
    if (opts.action && r.action !== opts.action) return no('action-mismatch', r);
    if (opts.hostname && r.hostname !== opts.hostname) return no('hostname-mismatch', r);
    return { success: true, errorCodes: [], hostname: r.hostname, action: r.action };
  }
}

const refusal = (why) => ({ ok: false, verdict: 'reject', risk: null, reasons: [{ code: 'pyrmi_refused', text: 'Pyrmi refused the action: ' + why }], unverified: true });

// The first sealed field (by path) holding a number JSON can't carry exactly, or null.
function badNumber(v, path, depth) {
  path = path || ''; depth = depth || 0;
  if (depth > 64) return null; // Pyrmi refuses deeper nesting itself
  if (typeof v === 'number') return !Number.isFinite(v) || Object.is(v, -0) || (Number.isInteger(v) && !Number.isSafeInteger(v)) ? (path || 'value') : null;
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) { const b = badNumber(v[k], path ? path + '.' + k : k, depth + 1); if (b) return b; }
  }
  return null;
}

// { seed, session } from a session token's payload (base64url JSON before the dot), for simulate. Not checked here.
function sessionOf(token) {
  try {
    const t = JSON.parse(Buffer.from(String(token).split('.')[0], 'base64url').toString('utf8'));
    return { seed: Number.isFinite(t.seed) ? t.seed : null, session: typeof t.s === 'string' ? t.s : null };
  } catch (_) { return { seed: null, session: null }; }
}

// What a browser's request says about the browser: forwarded to Pyrmi so it can tell whether the action comes from the
// browser that started the session. Works with Node's IncomingMessage and anything shaped like it (Express, Next.js).
function clientOf(req, hops) {
  const h = (req && req.headers) || {};
  const get = (k) => { const v = typeof h.get === 'function' ? h.get(k) : h[k]; return Array.isArray(v) ? v[0] : v; };
  const xff = String(get('x-forwarded-for') || '').split(',').map((x) => x.trim()).filter(Boolean);
  // With no proxies of yours (trustProxyHops 0, the default) X-Forwarded-For is ignored, since the caller can type it. Behind
  // your own proxies, the entry that many from the right is the one your nearest proxy wrote. On a platform that
  // overwrites the header itself (Vercel, Netlify, Cloudflare), set trustProxyHops: 1.
  // Fewer entries than hops means the request skipped your proxies (all of it is the caller's): use the socket.
  const ip = (hops > 0 && xff.length >= hops ? xff[xff.length - hops] : '') || (req.socket && req.socket.remoteAddress) || '';
  return { ua: String(get('user-agent') || ''), ch: String(get('sec-ch-ua') || ''), sfs: String(get('sec-fetch-site') || ''), ip: String(ip) };
}

// The gate for anything that matters (payouts, prizes, leaderboards, account changes). Pyrmi works it out on the
// server as `trusted`: an accept whose telemetry it corroborated, sealed in the page and sent from the same browser,
// with no reason beyond the harmless ones below, and, if the site turned on requireHumanCheck, a Turnstile pass Pyrmi
// confirmed with Cloudflare itself for this session (send turnstile: to verify()). Everything else Pyrmi sees is
// reported by the client, so treat trusted as "looks like a real browser" unless the human check is on. It doesn't
// move with your reviewAt/rejectAt. A review is never trusted, nor is the stand-in verdict from failOpen when Pyrmi is
// down. Pair it with your own limits (maxScore, minDurationMs, rate limits) and, for a deterministic game, simulate.
// You can also pass a result from verifyTurnstile() as the second argument to require a check you ran yourself.
const TRUST_ALLOWS = new Set(['wrapped_runtime', 'devtools_open', 'ip_changed', 'idle_input']);
function trusted(v, turnstile) {
  if (arguments.length > 1 && !(turnstile && turnstile.success === true)) return false;
  if (!v || typeof v !== 'object' || v.ok !== true || v.unverified || v.verdict !== 'accept' || v.client !== 'corroborated') return false;
  // Only the boolean true Pyrmi sends counts, and the reasons must still all be harmless. Pyrmi servers have sent
  // `trusted` since round 9; an older one gets false here.
  if (v.trusted !== true || !Array.isArray(v.reasons)) return false;
  return v.reasons.every((r) => r && typeof r === 'object' && TRUST_ALLOWS.has(r.code));
}

module.exports = { Pyrmi, trusted, clientOf, sessionOf, TRUST_ALLOWS };
module.exports.default = Pyrmi;
