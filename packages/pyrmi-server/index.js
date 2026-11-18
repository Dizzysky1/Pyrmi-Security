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
//
// Runs on Node 18+, and on runtimes with no Node globals (Cloudflare Workers, Deno, Bun, edge functions): it only
// needs fetch, AbortSignal.timeout, TextEncoder/TextDecoder and atob. Where there's no process.env, pass the keys as
// options.

// Environment variables where there are any (Node, Bun, Workers with nodejs_compat), none elsewhere.
const envVar = (k) => (typeof process !== 'undefined' && process && process.env ? process.env[k] : undefined);
const MAX_RESPONSE_BYTES = 64 * 1024;
const HTTP_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', 'local.invalid']);

class Pyrmi {
  constructor(opts) {
    if (opts !== undefined && (opts === null || typeof opts !== 'object' || Array.isArray(opts))) {
      throw new Error('pyrmi-server: options must be an object');
    }
    opts = opts || {};
    this.secretKey = opts.secretKey !== undefined ? opts.secretKey : envVar('PYRMI_SECRET_KEY');
    if (typeof this.secretKey !== 'string' || !/^sk_/.test(this.secretKey)) {
      throw new Error('pyrmi-server: pass { secretKey: "sk_..." } or set PYRMI_SECRET_KEY');
    }
    if (typeof window !== 'undefined' && typeof document !== 'undefined') {
      throw new Error('pyrmi-server: this runs on your server only, never in the browser');
    }
    const rawEndpoint = opts.endpoint !== undefined ? opts.endpoint : (envVar('PYRMI_ENDPOINT') || 'https://pyrmi.com/api/v1');
    this.endpoint = cleanEndpoint(rawEndpoint, 'endpoint', true);
    const rawTsEndpoint = opts.turnstileEndpoint !== undefined ? opts.turnstileEndpoint : 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    this.turnstileEndpoint = cleanEndpoint(rawTsEndpoint, 'turnstileEndpoint', false);
    if (opts.timeoutMs !== undefined && !(typeof opts.timeoutMs === 'number' && Number.isFinite(opts.timeoutMs) && opts.timeoutMs > 0)) {
      throw new Error('pyrmi-server: timeoutMs must be a positive finite number');
    }
    this.timeoutMs = opts.timeoutMs !== undefined ? opts.timeoutMs : 8000;
    // If Pyrmi is unreachable: false = reject the action, true = accept it unverified. Only true or 'true' turns it on.
    this.failOpen = opts.failOpen === true || opts.failOpen === 'true';
    if (opts.trustProxyHops !== undefined && !(typeof opts.trustProxyHops === 'number' && Number.isInteger(opts.trustProxyHops) && opts.trustProxyHops >= 0)) {
      throw new Error('pyrmi-server: trustProxyHops must be a non-negative integer');
    }
    this.trustProxyHops = opts.trustProxyHops !== undefined ? opts.trustProxyHops : 0; // proxies of yours in front of this server (for the caller's address)
    if (opts.trustedIpHeader !== undefined && opts.trustedIpHeader !== null) {
      if (typeof opts.trustedIpHeader !== 'string') throw new Error('pyrmi-server: trustedIpHeader must be a header name like "cf-connecting-ip"');
      const th = opts.trustedIpHeader.trim().toLowerCase();
      if (!th || !/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(th) || th === 'x-forwarded-for' || th === 'forwarded') {
        throw new Error('pyrmi-server: trustedIpHeader must be a single-IP header name like "cf-connecting-ip"');
      }
      this.trustedIpHeader = th;
    } else {
      this.trustedIpHeader = null;
    }
    // Optional: your own Cloudflare Turnstile widget's secret key, for verifyTurnstile().
    this.turnstileSecret = opts.turnstileSecret || envVar('TURNSTILE_SECRET_KEY') || null;
    // The biggest replay (as JSON) simulate is given; anything larger is a mismatch without being run.
    this.maxReplayBytes = Number.isFinite(opts.maxReplayBytes) && opts.maxReplayBytes > 0 ? opts.maxReplayBytes : 64 * 1024;
  }

  // Returns { verdict: 'accept'|'review'|'reject', risk, client: 'corroborated'|'unverified'|'none', trusted, reasons, session, player, score }.
  // user is an alias for player. score is optional: send it when the action carries a number you want capped.
  // simulate (optional): (replay, { seed, session }) => ({ score, durationMs }) re-runs a deterministic app from its
  // recorded inputs on your server, seeded with the session's own seed (never from the body). It runs only after Pyrmi
  // has confirmed the session and not rejected it, and only for a replay up to maxReplayBytes (64 KB). If it gives a
  // different score, the verdict is 'reject' with reason replay_mismatch. Keep it deterministic, free of side effects
  // and bounded in its own work (a cap on inputs or steps).
  //
  // sealed (recommended): the parsed JSON body your page sent, made by Pyrmi.seal({ ... }) in the browser. Its pyrmi
  // part carries the token and the signature, and Pyrmi checks the rest arrived exactly as the page signed it, so a
  // value changed on the way (a proxy, a debugger rewriting the request) is a reject (bad_signature).
  // req: your incoming request (Node, Express, Next.js API routes, Fetch Request). Its User-Agent, Sec-CH-UA,
  // Sec-Fetch-Site and the caller's address are sent along, and Pyrmi checks they match the browser that started the
  // session, so a session handed to another client (a harvested token used by a script) is flagged (relayed_session).
  // Or pass client: {...}. Directly inside a Cloudflare Worker, set trustedIpHeader: 'cf-connecting-ip'; behind your
  // own proxies, set trustProxyHops (e.g. 1 on Vercel alone, 2 for Cloudflare -> Vercel/ALB).
  async verify(input) {
    if (!input || typeof input !== 'object' || Array.isArray(input)) {
      return refusal('verify() expects an input object');
    }
    const { durationMs, replay, simulate } = input;
    let sealed = null, seal = null, request;
    if (input.sealed !== undefined) {
      if (!input.sealed || typeof input.sealed !== 'object' || Array.isArray(input.sealed)) {
        return refusal('the sealed body must be a JSON object', [{ code: 'bad_signature', weight: 100, text: 'The action was not sealed by Pyrmi.seal().' }], { signed: 'bad' });
      }
      sealed = input.sealed;
      seal = Object.prototype.hasOwnProperty.call(sealed, 'pyrmi') ? sealed.pyrmi : null;
      if (!seal || typeof seal !== 'object' || Array.isArray(seal)
        || typeof seal.token !== 'string' || !seal.token
        || typeof seal.ts !== 'number' || !Number.isFinite(seal.ts)
        || typeof seal.sig !== 'string' || !seal.sig) {
        return refusal('the sealed body is missing a valid pyrmi signature', [{ code: 'bad_signature', weight: 100, text: 'The action is missing a valid pyrmi signature.' }], { signed: 'bad' });
      }
      // A null-prototype copy, so every key in the parsed body stays a field and is sent as one.
      const fields = Object.create(null);
      for (const k of Object.keys(sealed)) if (k !== 'pyrmi') fields[k] = sealed[k];
      // A sealed number JSON can't carry exactly (Infinity, NaN, -0, a whole number past 2^53) is refused here.
      const bad = badNumber(fields);
      if (bad) return refusal('the sealed field ' + bad + ' is a number that can\'t be checked exactly');
      request = { fields, ts: seal.ts, sig: seal.sig };
    }
    // With sealed, the score defaults to the sealed body's own `score`, so the value Pyrmi caps is the one the page
    // signed. A different score passed here than the signed one is a reject (bad_signature).
    let score = input.score !== undefined ? input.score : sealed && typeof sealed.score === 'number' ? sealed.score : undefined;
    // NaN and Infinity have no JSON form, so they're sent as text, which Pyrmi rejects (bad_score).
    if (typeof score === 'number' && !Number.isFinite(score)) score = String(score);
    let dur = durationMs;
    if (typeof dur === 'number' && !Number.isFinite(dur)) dur = String(dur);
    const token = input.token !== undefined ? input.token : seal ? seal.token : undefined;
    if (token !== undefined && (typeof token !== 'string' || token.length > 2048)) {
      return refusal('the session token is malformed');
    }
    const client = input.client ? input.client : input.req ? clientOf(input.req, this.trustProxyHops, this.trustedIpHeader) : undefined;
    const player = input.player !== undefined ? input.player : input.user;
    // The human check for trusted (round 12): the Turnstile token your page got from a widget rendered with
    // cdata: session (the id Pyrmi.start() answers), sent along with your Turnstile secret key so Pyrmi can confirm it
    // with Cloudflare itself. Pyrmi uses the key for that one call and never stores or logs it. Pass it as
    // turnstile: token (or { token, action }); with sealed, a `turnstile` field in the sealed body is used by default.
    let human;
    const tin = input.turnstile !== undefined ? input.turnstile : sealed && typeof sealed.turnstile === 'string' ? sealed.turnstile : undefined;
    const ttoken = tin && typeof tin === 'object' ? tin.token : tin;
    if (typeof ttoken === 'string' && ttoken && this.turnstileSecret) human = { token: ttoken, secret: this.turnstileSecret, action: tin && typeof tin === 'object' && tin.action !== undefined ? tin.action : undefined };
    // The replay is run once Pyrmi has answered (below). Validate token shape first so junk calls never serialize a
    // huge replay, and treat one larger than maxReplayBytes as a mismatch without running it.
    const wantsReplay = typeof simulate === 'function';
    let replayCheck = { check: 'none' };
    if (wantsReplay) {
      if (!isShapedToken(token)) return refusal('the session token is missing or malformed');
      let size = Infinity;
      try { size = utf8Length(JSON.stringify(replay === undefined ? null : replay)); } catch (_) { /* unreadable: refused below */ }
      if (!(size <= this.maxReplayBytes)) replayCheck = { check: 'mismatch', detail: size === Infinity ? 'the replay could not be read' : 'the replay is larger than ' + this.maxReplayBytes + ' bytes' };
    }
    // failOpen covers Pyrmi being down (no answer, a timeout, a 5xx), never something the caller can cause.
    // An oversized or malformed action, a local replay mismatch, or a 4xx answer (413, 400, 403, 429) is always a reject.
    const refuse = refusal;
    let payload, v;
    try { payload = JSON.stringify({ token, score, durationMs: dur, player, replay: replayCheck, request, client, turnstile: human }); } catch (e) { return refuse('it could not be sent (' + (e && e.message) + ')'); }
    if (utf8Length(payload) > 16 * 1024) return refuse('it is larger than 16 KB');
    try {
      const res = await fetch(this.endpoint + '/verify', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + this.secretKey, 'Content-Type': 'application/json' },
        body: payload,
        redirect: 'error',
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      let body = null, overCap = false;
      try { body = await readJsonBounded(res, MAX_RESPONSE_BYTES); } catch (err) { if (err && err.overCap) overCap = true; }
      if (res.status >= 400 && res.status < 500 && res.status !== 401) return refuse((body && (body.message || body.error)) || 'HTTP ' + res.status);
      if (!res.ok) throw Object.assign(new Error((body && body.message) || 'Pyrmi returned ' + res.status), { code: (body && body.error) || 'http_' + res.status, status: res.status });
      if (overCap) throw new Error('Pyrmi response exceeded 64 KB');
      // Anything without a real verdict (an HTML page from a proxy, a wrong endpoint) is treated as Pyrmi being
      // unreachable: reject, unless you chose failOpen.
      if (!body || body.ok !== true || !['accept', 'review', 'reject'].includes(body.verdict)) throw new Error('Pyrmi sent something that isn\'t a verdict');
      v = body;
    } catch (e) {
      if (e && e.status === 401) throw e; // a wrong key is a setup bug, not an outage
      if (replayCheck.check === 'mismatch') {
        return replayFailed({ ok: false, client: 'none', unverified: true, reasons: [{ code: 'pyrmi_unreachable', text: 'Could not reach Pyrmi: ' + (e && e.message) }] }, replayCheck.detail);
      }
      return { ok: false, verdict: this.failOpen ? 'accept' : 'reject', risk: null, client: 'none', trusted: false, reasons: [{ code: 'pyrmi_unreachable', text: 'Could not reach Pyrmi: ' + (e && e.message) }], unverified: true };
    }
    if (!wantsReplay) return v;
    if (replayCheck.check !== 'none') return v.verdict === 'reject' ? v : replayFailed(v, replayCheck.detail);
    // Nothing is worth re-running for a reject. Otherwise the token got past Pyrmi's checks, so its session is real:
    // simulate gets that session's own seed and id (from Pyrmi's answer, or from the now-checked token on an older
    // server), never anything from the request body.
    if (v.verdict === 'reject') return { ...v, replay: 'none' };
    const own = sessionOf(token);
    const sess = typeof v.seed === 'number' && Number.isFinite(v.seed) && typeof v.session === 'string'
      ? { seed: v.seed, session: v.session } : v.seed === undefined ? own : null;
    if (!sess || sess.seed === null || (v.session != null && v.session !== own.session)) return replayFailed(v, 'no confirmed session to replay');
    let r;
    try { r = await simulate(replay, sess); } catch (e) { return replayFailed(v, 'replay failed: ' + String(e && e.message).slice(0, 80)); }
    const rDurOk = r && (r.durationMs === undefined || r.durationMs === null || (typeof r.durationMs === 'number' && Number.isFinite(r.durationMs)));
    const durMatch = durationMs === undefined || durationMs === null || !r || r.durationMs === undefined || r.durationMs === null
      || (typeof durationMs === 'number' && Number.isFinite(durationMs) && Math.abs(r.durationMs - durationMs) <= 50);
    const same = !!r && typeof r === 'object'
      && typeof r.score === 'number' && Number.isFinite(r.score)
      && typeof score === 'number' && Number.isFinite(score) && r.score === score
      && rDurOk && durMatch;
    return same ? { ...v, replay: 'match' } : replayFailed(v, 'replay gave ' + (r ? r.score : 'nothing') + ', claimed ' + score);
  }

  // Checks a Cloudflare Turnstile token from your page (the widget's cf-turnstile-response) with Cloudflare.
  // Returns { success, errorCodes, hostname, action }. Fails closed: no secret, no token, a token Cloudflare already
  // saw, a different action or hostname than you expect, a redirect, or Cloudflare being unreachable all give
  // success: false.
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
      const res = await fetch(this.turnstileEndpoint, { method: 'POST', body: form, redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs) });
      r = await readJsonBounded(res, MAX_RESPONSE_BYTES);
    } catch (_) {
      return no('turnstile-unreachable');
    }
    if (!r || r.success !== true) return { success: false, errorCodes: (r && r['error-codes']) || ['failed'], hostname: r && r.hostname, action: r && r.action };
    if (opts.action && r.action !== opts.action) return no('action-mismatch', r);
    if (opts.hostname && r.hostname !== opts.hostname) return no('hostname-mismatch', r);
    return { success: true, errorCodes: [], hostname: r.hostname, action: r.action };
  }
}

// Validate an API endpoint URL: https:// anywhere, or http:// only on loopback (and RFC 6761 .invalid in unit tests),
// with no credentials, query string, fragment or backslashes.
function cleanEndpoint(raw, name, trimSlash) {
  if (typeof raw !== 'string' || !raw || raw.trim() !== raw || /[\s\\?#]/.test(raw) || /^[a-zA-Z][a-zA-Z\d+.-]*:\/\/[^/?#]*@/.test(raw)) {
    throw new Error('pyrmi-server: invalid ' + name);
  }
  let protocol, hostname;
  if (typeof URL === 'function') {
    let u;
    try { u = new URL(raw); } catch (_) { throw new Error('pyrmi-server: invalid ' + name); }
    if (u.username || u.password || u.search || u.hash || !u.hostname) throw new Error('pyrmi-server: invalid ' + name);
    protocol = u.protocol;
    hostname = u.hostname.toLowerCase();
  } else {
    const m = /^(https?:)\/\/(\[::1\]|[A-Za-z\d.-]+)(?::(\d{1,5}))?(\/[^\s?#\\]*)?$/i.exec(raw);
    if (!m) throw new Error('pyrmi-server: invalid ' + name);
    if (m[3] !== undefined && (Number(m[3]) < 1 || Number(m[3]) > 65535)) throw new Error('pyrmi-server: invalid ' + name);
    protocol = m[1].toLowerCase();
    hostname = m[2].toLowerCase();
  }
  const httpLoopback = protocol === 'http:' && HTTP_HOSTS.has(hostname) && /^http:\/\/(\[::1\]|127\.0\.0\.1|localhost|local\.invalid)(?::\d+)?(?:\/|$)/i.test(raw);
  if (protocol !== 'https:' && !httpLoopback) {
    throw new Error('pyrmi-server: ' + name + ' must use https:// (or http:// on localhost/127.0.0.1/[::1])');
  }
  return trimSlash ? raw.replace(/\/+$/, '') : raw;
}

// Read a JSON response body with a strict byte ceiling before JSON.parse(), without requiring Node's Buffer.
async function readJsonBounded(res, maxBytes) {
  const over = () => Object.assign(new Error('response larger than ' + maxBytes + ' bytes'), { overCap: true });
  const cl = res && res.headers && typeof res.headers.get === 'function' ? res.headers.get('content-length') : null;
  if (cl !== null && cl !== '' && Number(cl) > maxBytes) {
    if (res.body && typeof res.body.cancel === 'function') await res.body.cancel().catch(() => {});
    throw over();
  }
  if (res && res.body && typeof res.body.getReader === 'function') {
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        const u8 = value && value.buffer ? new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength) : new Uint8Array(value);
        total += u8.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw over();
        }
        chunks.push(u8);
      }
    } finally {
      try { reader.releaseLock(); } catch (_) { /* ignore */ }
    }
    const merged = new Uint8Array(total);
    let off = 0;
    for (const ch of chunks) { merged.set(ch, off); off += ch.byteLength; }
    return JSON.parse(new TextDecoder().decode(merged));
  }
  if (res && typeof res.text === 'function') {
    const text = await res.text();
    if (utf8Length(text) > maxBytes) throw over();
    return JSON.parse(text);
  }
  const j = await res.json();
  if (utf8Length(JSON.stringify(j)) > maxBytes) throw over();
  return j;
}

function isShapedToken(t) {
  return typeof t === 'string' && t.length >= 3 && t.length <= 2048 && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(t);
}

// A reject for a replay that didn't reproduce the result. Never trusted.
const replayFailed = (v, detail) => ({ ...v, verdict: 'reject', risk: 100, trusted: false, replay: 'mismatch',
  reasons: [{ code: 'replay_mismatch', weight: 100, text: 'Replaying the recorded inputs gave a different result.', detail: String(detail).slice(0, 120) }, ...(Array.isArray(v.reasons) ? v.reasons : [])] });

const refusal = (why, extraReasons, extraFields) => ({
  ok: false,
  verdict: 'reject',
  risk: null,
  client: 'none',
  trusted: false,
  reasons: [{ code: 'pyrmi_refused', text: 'Pyrmi refused the action: ' + why }, ...(extraReasons || [])],
  unverified: true,
  ...(extraFields || {}),
});

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

// Byte length of a string as UTF-8, and base64url to UTF-8 text: Buffer on Node (as before), the web APIs elsewhere.
function utf8Length(s) {
  return typeof Buffer !== 'undefined' ? Buffer.byteLength(s) : new TextEncoder().encode(s).length;
}
function base64urlText(b) {
  if (typeof Buffer !== 'undefined') return Buffer.from(b, 'base64url').toString('utf8');
  const bin = atob(b.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((b.length + 3) % 4));
  return new TextDecoder().decode(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
}

// { seed, session } from a session token's payload (base64url JSON before the dot), for simulate. Not checked here.
function sessionOf(token) {
  try {
    if (!isShapedToken(token)) return { seed: null, session: null };
    const t = JSON.parse(base64urlText(token.split('.')[0]));
    return { seed: typeof t.seed === 'number' && Number.isFinite(t.seed) ? t.seed : null, session: typeof t.s === 'string' ? t.s : null };
  } catch (_) { return { seed: null, session: null }; }
}

const safeStr = (v) => (typeof v === 'string' ? v : v == null || typeof v === 'object' || typeof v === 'symbol' ? '' : String(v));

// What a browser's request says about the browser: forwarded to Pyrmi so it can tell whether the action comes from the
// browser that started the session. Works with Node's IncomingMessage, Express, Next.js and the Fetch API Request.
function clientOf(req, hops, trustedIpHeader) {
  if (hops && typeof hops === 'object') {
    trustedIpHeader = hops.trustedIpHeader;
    hops = hops.trustProxyHops;
  }
  const nHops = typeof hops === 'number' && Number.isInteger(hops) && hops > 0 ? hops : 0;
  const trustedHdr = typeof trustedIpHeader === 'string' && trustedIpHeader.trim() ? trustedIpHeader.trim().toLowerCase() : '';
  const h = (req && req.headers) || {};
  const getRaw = (k) => {
    if (typeof h.get === 'function') return h.get(k);
    if (Object.prototype.hasOwnProperty.call(h, k)) return h[k];
    const kl = k.toLowerCase();
    for (const key of Object.keys(h)) if (key.toLowerCase() === kl) return h[key];
    return undefined;
  };
  const get = (k) => { const v = getRaw(k); return Array.isArray(v) ? v[0] : v; };
  const getJoined = (k) => { const v = getRaw(k); return Array.isArray(v) ? v.map(safeStr).join(', ') : v; };
  let trustedIp = '';
  if (trustedHdr && trustedHdr !== 'x-forwarded-for' && trustedHdr !== 'forwarded') {
    const raw = safeStr(getJoined(trustedHdr)).trim();
    if (raw && !raw.includes(',')) trustedIp = raw;
  }
  const xff = safeStr(getJoined('x-forwarded-for')).split(',').map((x) => x.trim()).filter(Boolean);
  // With no proxies of yours (trustProxyHops 0, the default) X-Forwarded-For is ignored, since the caller can type it.
  // Directly inside a Cloudflare Worker, pass trustedIpHeader: 'cf-connecting-ip'. Behind proxies that append to
  // X-Forwarded-For, set trustProxyHops to how many there are (1 on Vercel/Netlify alone; 2 for Cloudflare -> Vercel/ALB).
  // Fewer entries than hops means the request skipped your proxies (all of it is the caller's): use the socket.
  const ip = trustedIp
    || (nHops > 0 && xff.length >= nHops ? xff[xff.length - nHops] : '')
    || safeStr(req && req.socket && req.socket.remoteAddress);
  return { ua: safeStr(get('user-agent')), ch: safeStr(get('sec-ch-ua')), sfs: safeStr(get('sec-fetch-site')), ip };
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
