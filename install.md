# Pyrmi Security: install guide for coding agents

You are adding Pyrmi Security (open-source bot and tamper detection for websites, MIT) to a site. Follow these steps
in order. Pyrmi has two halves: a browser script that starts a signed session on a real page load and reports signs of
bots and tampering, and a server check that returns a verdict before the server trusts a request. Both halves are
required: the browser half alone protects nothing.

## 0. Keys

The developer needs a project from https://pyrmi.com/dashboard/ (no account needed). It gives:

- a public key `pk_...` that goes in the page, and
- a secret key `sk_...` that goes ONLY in the server environment as `PYRMI_SECRET_KEY`.

A new project is strict until it's set up: it only starts sessions on the pages registered as its allowed pages (the
developer enters them when creating it), it rejects an action sent less than 1.5 seconds after the session started
(`too_short`), and it rejects a value (`score`) until a maximum is set (`no_score_limit`: set `maxScore` or
`maxScorePerSec` in the dashboard). Tell the developer which of these apply.

If you don't have the keys, use the placeholder `pk_REPLACE_ME`, read the secret from `process.env.PYRMI_SECRET_KEY`,
and tell the developer to create a project and set the env var. Never write a real secret key into source files,
client code, logs or commits.

## 1. Pick what to protect

Find the requests where a bot, a script or a replayed request would do harm. Typical ones: sign-up, login, password
reset, contact or comment forms, votes and polls, giveaways, checkout or coupon redemption, scores, and API endpoints
that scrapers hit. Ask the developer if it isn't clear. Protect those, not every request.

## 2. Browser: add the script tag

Add once to each page that sends a protected request, before the page's own script:

```html
<script src="https://pyrmi.com/sdk/1.3.0/pyrmi.js" integrity="sha384-I4k52N6yLHLTOlv4IKBJ2FHbCPZ8Rz+nhpU7E5woSDO+zoAsGmJD9f1uW2MoDruR" crossorigin="anonymous" data-site="pk_REPLACE_ME"></script>
```

It defines `window.Pyrmi`.

## 3. Browser: send a token with each protected request

```js
// on page load (or when the protected flow begins)
let pyrmi = null;
try { pyrmi = await Pyrmi.start(); } catch (e) { pyrmi = null; } // offline: the server will decide

// right before the protected request
await Pyrmi.flush();
await fetch('/api/signup', {                    // the site's existing endpoint
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...existingFields, pyrmiToken: pyrmi && pyrmi.token }),
});
pyrmi = await Pyrmi.start().catch(() => null);  // tokens are single use: get a fresh one for the next request
```

Rules:
- Each token works for one verify only. Start a new session after each protected request.
- Send the token along with whatever the page already sends. Don't change the endpoint's other fields.
- Do not try to block devtools, right-click or copy. Pyrmi detects and reports instead.
- Apps with their own clock (a game, a timed quiz) may call `Pyrmi.mark(seconds)` as it runs.

## 4. Server: verify before trusting the request

Node.js 18+ (no dependencies):

```bash
npm install pyrmi-server
```

```js
const { Pyrmi } = require('pyrmi-server');            // or: import { Pyrmi } from 'pyrmi-server'
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });

// inside the existing handler, before anything is written or sent:
const v = await pyrmi.verify({ token: body.pyrmiToken, user: String(userIdOrEmail) });
if (v.verdict === 'reject') {
  return res.status(403).json({ error: 'blocked', reasons: v.reasons.map((r) => r.code) });
}
// v.verdict is 'accept' or 'review'. Go ahead; optionally store flagged = (v.verdict === 'review').
```

For a sensitive action (a payout, a prize, a leaderboard entry, an account change), require more than "not
rejected": only a corroborated accept.

```js
const { Pyrmi, trusted } = require('pyrmi-server');
if (!trusted(v)) return res.status(403).json({ error: 'not_verified' });
```

`trusted(v)` is true only for an `accept` with a `corroborated` client, a real key press or click seen by the
browser, and no reason other than the harmless ones (`wrapped_runtime`, `devtools_open`, `ip_changed`,
`idle_input`). The server works it out, so it doesn't loosen when the site's `reviewAt` or `rejectAt` is raised.

Telemetry is advisory: a script that copies the real one closely enough can still pass, so keep your own limits too
(`maxScore`, `minDurationMs`, rate limits) and, for a deterministic app, the replay check in section 5.

For the most sensitive actions (sign-ups that unlock something, payouts), also add a Cloudflare Turnstile widget to
that form and check its token on the server with the same call. The developer creates the widget in Cloudflare and
sets `TURNSTILE_SECRET_KEY`; the widget's `data-action` must match the `action` you check:

```js
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY }); // reads TURNSTILE_SECRET_KEY too
const t = await pyrmi.verifyTurnstile(req.body['cf-turnstile-response'], { action: 'payout', hostname: 'example.com', remoteip: ip });
if (!trusted(v, t)) return res.status(403).json({ error: 'not_verified' });
```

`verifyTurnstile` fails closed (no secret, no token, a used token, a different action or hostname, or Cloudflare
unreachable all give `success: false`). Cloudflare accepts each token once.

If the request carries a number worth capping (points, a quantity, a score), also pass `score: thatNumber` and
`durationMs` if known, and tell the developer to set the max value on the dashboard.

Any other language: one HTTPS call from the server (never from the browser):

```
POST https://pyrmi.com/api/v1/verify
Authorization: Bearer <PYRMI_SECRET_KEY>
Content-Type: application/json

{"token":"...","user":"alice@example.com"}
```

Response: `{"ok":true,"verdict":"accept"|"review"|"reject","risk":0-100,"client":"corroborated"|"unverified"|"none","reasons":[{"code":"...","text":"...","weight":..}]}`.
For a sensitive action, require `trusted == true` (set by the server: a corroborated accept with a real key press or
click and no reason beyond the harmless ones).

If the site has no server (a static site writing to Firebase or Supabase directly from the browser), say so to the
developer: a write made from the browser cannot be protected. Suggest a small serverless function (Vercel, Netlify,
Cloudflare Workers, Supabase Edge Functions) that calls verify and then does the write with a server key.

## 5. Optional: server-side replay (deterministic apps)

If the app is deterministic (same seed + same inputs = same result), record inputs, send them with the request, and
pass `replay` plus a `simulate` function that re-runs it on the server:

```js
const v = await pyrmi.verify({
  token, score, durationMs, user, replay: body.inputs,
  simulate: (inputs) => runHeadless(seed, inputs), // must return { score, durationMs? }
});
```

Inputs that don't reproduce the claimed result are rejected (`replay_mismatch`).

## 6. Tell the developer

Finish by telling the developer:
- set `PYRMI_SECRET_KEY` in the server's environment (and replace `pk_REPLACE_ME` if you used it),
- watch verdicts at https://pyrmi.com/dashboard/ and tune the limits there,
- which requests you protected and which files you changed.

## Reference

- Reasons: `invalid_token`, `wrong_project`, `expired`, `token_reused`, `impossible_time`, `too_short`,
  `score_over_max`, `score_too_fast`, `bad_score`, `replay_mismatch`, `rate_limited` (all reject);
  `automation`, `no_client`, `unverified_client`, `synthetic_input`, `speed_hack`, `time_warp`, `tampered_runtime`, `inhuman_input`,
  `ua_changed`, `idle_input`, `devtools_open`, `ip_changed` (add risk).
- Self-hosting: pass `endpoint: 'https://your-deploy.example/api/v1'` to `new Pyrmi()` and use
  `data-api="https://your-deploy.example/api/v1"` on the script tag.
- Docs for humans: https://pyrmi.com/docs/
