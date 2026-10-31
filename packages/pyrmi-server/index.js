'use strict';
// pyrmi-server: ask Pyrmi Security for a verdict before your server trusts an action (a sign-up, a vote, a score,
// a checkout). No dependencies.
//
//   const { Pyrmi } = require('pyrmi-server');
//   const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });
//   const v = await pyrmi.verify({ token, user });          // add score: n to check a number too
//   if (v.verdict !== 'reject') doTheThing(...);             // everyday actions: let review through, flagged
//   if (trusted(v)) payOut(...);                             // sensitive ones: only a corroborated accept

class Pyrmi {
  constructor(opts) {
    opts = opts || {};
    this.secretKey = opts.secretKey || process.env.PYRMI_SECRET_KEY;
    this.endpoint = String(opts.endpoint || process.env.PYRMI_ENDPOINT || 'https://pyrmi.com/api/v1').replace(/\/+$/, '');
    this.timeoutMs = opts.timeoutMs || 8000;
    this.failOpen = !!opts.failOpen; // if Pyrmi is unreachable: false = reject the action, true = accept it unverified
    if (!this.secretKey || !/^sk_/.test(this.secretKey)) throw new Error('pyrmi-server: pass { secretKey: "sk_..." } or set PYRMI_SECRET_KEY');
    if (typeof window !== 'undefined' && typeof document !== 'undefined') throw new Error('pyrmi-server: this runs on your server only, never in the browser');
  }

  // Returns { verdict: 'accept'|'review'|'reject', risk, client: 'corroborated'|'unverified'|'none', trusted, reasons, session, player, score }.
  // user is an alias for player. score is optional: send it when the action carries a number you want capped.
  // simulate (optional): (replay) => ({ score, durationMs }) re-runs a deterministic app from its recorded inputs on
  // your server. If it gives a different score, the verdict is 'reject' with reason replay_mismatch.
  async verify(input) {
    const { token, score, durationMs, replay, simulate } = input || {};
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
        body: JSON.stringify({ token, score, durationMs, player, replay: replayCheck }),
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
}

// The gate for anything that matters (payouts, prizes, leaderboards, account changes). Pyrmi works it out on the
// server as `trusted`: an accept whose telemetry it corroborated, from a page a person really pressed or clicked on,
// with no reason beyond the harmless ones below. It doesn't move with your reviewAt/rejectAt, so tuning those to cut
// false positives can't make a tampered or webdriver session trusted. A review is never trusted, nor is the stand-in
// verdict from failOpen when Pyrmi is down. This still isn't proof of a person: a script that copies the real one
// closely enough can pass, so pair it with your own limits (maxScore, minDurationMs, rate limits), Turnstile, and,
// for a deterministic game, simulate.
const TRUST_ALLOWS = new Set(['wrapped_runtime', 'devtools_open', 'ip_changed', 'idle_input']);
function trusted(v) {
  if (!v || v.ok === false || v.unverified || v.verdict !== 'accept' || v.client !== 'corroborated') return false;
  if (typeof v.trusted === 'boolean') return v.trusted;
  // An older Pyrmi server that doesn't send `trusted`: the same allow-list over the reasons.
  return (v.reasons || []).every((r) => r && TRUST_ALLOWS.has(r.code));
}

module.exports = { Pyrmi, trusted, TRUST_ALLOWS };
module.exports.default = Pyrmi;
