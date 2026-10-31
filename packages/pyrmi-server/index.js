'use strict';
// pyrmi-server: ask Pyrmi Security for a verdict before your server trusts an action (a sign-up, a vote, a score,
// a checkout). No dependencies.
//
//   const { Pyrmi } = require('pyrmi-server');
//   const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });
//   const v = await pyrmi.verify({ sealed: req.body, req, user }); // the page sent Pyrmi.seal({ ... }) as JSON
//   (or the older form: pyrmi.verify({ token, user }); add score: n to check a number too)
//   if (v.verdict !== 'reject') doTheThing(...);             // everyday actions: let review through, flagged
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
    this.failOpen = !!opts.failOpen; // if Pyrmi is unreachable: false = reject the action, true = accept it unverified
    this.trustProxyHops = opts.trustProxyHops || 0; // proxies of yours in front of this server (for the caller's address)
    // Optional: your own Cloudflare Turnstile widget's secret key, for verifyTurnstile().
    this.turnstileSecret = opts.turnstileSecret || process.env.TURNSTILE_SECRET_KEY || null;
    this.turnstileEndpoint = opts.turnstileEndpoint || 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    if (!this.secretKey || !/^sk_/.test(this.secretKey)) throw new Error('pyrmi-server: pass { secretKey: "sk_..." } or set PYRMI_SECRET_KEY');
    if (typeof window !== 'undefined' && typeof document !== 'undefined') throw new Error('pyrmi-server: this runs on your server only, never in the browser');
  }

  // Returns { verdict: 'accept'|'review'|'reject', risk, client: 'corroborated'|'unverified'|'none', trusted, reasons, session, player, score }.
  // user is an alias for player. score is optional: send it when the action carries a number you want capped.
  // simulate (optional): (replay) => ({ score, durationMs }) re-runs a deterministic app from its recorded inputs on
  // your server. If it gives a different score, the verdict is 'reject' with reason replay_mismatch.
  //
  // sealed (recommended): the parsed JSON body your page sent, made by Pyrmi.seal({ ... }) in the browser. Its pyrmi
  // part carries the token and the signature, and Pyrmi checks the rest arrived exactly as the page signed it, so a
  // value changed on the way (a proxy, a debugger rewriting the request) is a reject (bad_signature).
  // req: your incoming request (Node, Express, Next.js API routes). Its User-Agent, Sec-CH-UA, Sec-Fetch-Site and the
  // caller's address are sent along, and Pyrmi checks they match the browser that started the session, so a session
  // handed to another client (a harvested token used by a script) is flagged (relayed_session). Or pass client: {...}.
  // Behind your own proxies, set trustProxyHops so the address is read from the right X-Forwarded-For entry.
  async verify(input) {
    const { score, durationMs, replay, simulate } = input || {};
    const sealed = input && input.sealed && typeof input.sealed === 'object' ? input.sealed : null;
    const seal = sealed && sealed.pyrmi && typeof sealed.pyrmi === 'object' ? sealed.pyrmi : null;
    const token = input && input.token !== undefined ? input.token : seal ? seal.token : undefined;
    let request;
    if (seal && seal.sig !== undefined) {
      const fields = {};
      for (const k of Object.keys(sealed)) if (k !== 'pyrmi') fields[k] = sealed[k];
      request = { fields, ts: seal.ts, sig: seal.sig };
    }
    const client = input && input.client ? input.client : input && input.req ? clientOf(input.req, this.trustProxyHops) : undefined;
    const player = input && input.player !== undefined ? input.player : input && input.user;
    let replayCheck = { check: 'none' };
    if (typeof simulate === 'function') {
      try {
        const r = await simulate(replay);
        const same = r && Number(r.score) === Number(score) && (durationMs == null || r.durationMs == null || Math.abs(r.durationMs - durationMs) <= 50);
        replayCheck = same ? { check: 'match' } : { check: 'mismatch', detail: 'replay gave ' + (r ? r.score : 'nothing') + ', claimed ' + score };
      } catch (e) {
        replayCheck = { check: 'mismatch', detail: 'replay failed: ' + String(e && e.message).slice(0, 80) };
      }
    }
    try {
      const res = await fetch(this.endpoint + '/verify', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + this.secretKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, score, durationMs, player, replay: replayCheck, request, client }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw Object.assign(new Error(body.message || 'Pyrmi returned ' + res.status), { code: body.error || 'http_' + res.status, status: res.status });
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

// What a browser's request says about the browser: forwarded to Pyrmi so it can tell whether the action comes from the
// browser that started the session. Works with Node's IncomingMessage and anything shaped like it (Express, Next.js).
function clientOf(req, hops) {
  const h = (req && req.headers) || {};
  const get = (k) => { const v = typeof h.get === 'function' ? h.get(k) : h[k]; return Array.isArray(v) ? v[0] : v; };
  const xff = String(get('x-forwarded-for') || '').split(',').map((x) => x.trim()).filter(Boolean);
  const ip = (hops > 0 ? xff[Math.max(0, xff.length - hops)] : xff[0]) || (req.socket && req.socket.remoteAddress) || req.ip || '';
  return { ua: String(get('user-agent') || ''), ch: String(get('sec-ch-ua') || ''), sfs: String(get('sec-fetch-site') || ''), ip: String(ip) };
}

// The gate for anything that matters (payouts, prizes, leaderboards, account changes). Pyrmi works it out on the
// server as `trusted`: an accept whose telemetry it corroborated, from a page a person really pressed or clicked on,
// with no reason beyond the harmless ones below. It doesn't move with your reviewAt/rejectAt, so tuning those to cut
// false positives can't make a tampered or webdriver session trusted. A review is never trusted, nor is the stand-in
// verdict from failOpen when Pyrmi is down. This still isn't proof of a person: a script that copies the real one
// closely enough can pass, so pair it with your own limits (maxScore, minDurationMs, rate limits), Turnstile, and,
// for a deterministic game, simulate. Pass a Turnstile result (from verifyTurnstile) as the second argument to
// require that too.
const TRUST_ALLOWS = new Set(['wrapped_runtime', 'devtools_open', 'ip_changed', 'idle_input']);
function trusted(v, turnstile) {
  if (arguments.length > 1 && !(turnstile && turnstile.success === true)) return false;
  if (!v || v.ok === false || v.unverified || v.verdict !== 'accept' || v.client !== 'corroborated') return false;
  if (typeof v.trusted === 'boolean') return v.trusted;
  // An older Pyrmi server that doesn't send `trusted`: the same allow-list over the reasons.
  return (v.reasons || []).every((r) => r && TRUST_ALLOWS.has(r.code));
}

module.exports = { Pyrmi, trusted, clientOf, TRUST_ALLOWS };
module.exports.default = Pyrmi;
