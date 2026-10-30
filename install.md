# Pyrmi Security: install guide for coding agents

You are adding Pyrmi Security (open-source anti-cheat for web games, MIT) to a game. Follow these steps in order.
Pyrmi has two halves: a browser script that starts a signed session per run and reports cheat signals, and a server
check that returns a verdict before a score is saved. Both halves are required: the browser half alone protects nothing.

## 0. Keys

The developer needs a project from https://pyrmi.com/dashboard/ (no account needed). It gives:

- a public key `pk_...` that goes in the page, and
- a secret key `sk_...` that goes ONLY in the server environment as `PYRMI_SECRET_KEY`.

If you don't have the keys, use the placeholder `pk_REPLACE_ME`, read the secret from `process.env.PYRMI_SECRET_KEY`,
and tell the developer to create a project and set the env var. Never write a real secret key into source files,
client code, logs or commits.

## 1. Browser: add the script tag

Add once to the HTML page that hosts the game, before the game's own script:

```html
<script src="https://pyrmi.com/sdk/pyrmi.js" data-site="pk_REPLACE_ME"></script>
```

It defines `window.Pyrmi`.

## 2. Browser: wire the run lifecycle

Find where a run/round/level starts and where it ends (game over, level complete, score submit).

```js
// where a run starts (await before the run begins if you can; it's one fast request)
let pyrmiRun = null;
try { pyrmiRun = await Pyrmi.start(); } catch (e) { pyrmiRun = null; } // offline: let them play unranked

// optional, during play (e.g. once per second): the game's own clock in seconds
Pyrmi.mark(gameTimeSeconds);

// where the run ends, BEFORE sending the score
await Pyrmi.flush();
await fetch('/api/scores', {                     // the game's existing score endpoint
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: pyrmiRun && pyrmiRun.token, score, durationMs, player }),
});
```

Rules:
- Call `Pyrmi.start()` once per run. Each token works for one score only.
- Send `token` along with whatever the game already sends. Add `durationMs` (length of the run) if the game knows it.
- If the game has a seeded RNG, you may seed it with `pyrmiRun.seed` (a uint32) so the server can replay runs (step 4).
- Do not try to block devtools or right-click. Pyrmi detects and reports instead.

## 3. Server: verify before saving

Node.js 18+ (no dependencies):

```bash
npm install pyrmi-server
```

```js
const { Pyrmi } = require('pyrmi-server');            // or: import { Pyrmi } from 'pyrmi-server'
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });

// inside the existing score handler, before the score is written anywhere:
const v = await pyrmi.verify({ token: body.token, score: body.score, durationMs: body.durationMs, player: String(playerId) });
if (v.verdict === 'reject') {
  return res.status(400).json({ error: 'score_rejected', reasons: v.reasons.map((r) => r.code) });
}
// v.verdict is 'accept' or 'review'. Save the score; optionally store flagged = (v.verdict === 'review').
```

Any other language: one HTTPS call from the server (never from the browser):

```
POST https://pyrmi.com/api/v1/verify
Authorization: Bearer <PYRMI_SECRET_KEY>
Content-Type: application/json

{"token":"...","score":123,"durationMs":45000,"player":"alice"}
```

Response: `{"ok":true,"verdict":"accept"|"review"|"reject","risk":0-100,"reasons":[{"code":"...","text":"...","weight":..}]}`.

If the game has no server (static site writing to Firebase/Supabase directly from the browser), say so to the
developer: a score written from the browser cannot be protected. Suggest a small serverless function (Vercel,
Netlify, Cloudflare Workers, Supabase Edge Functions) that calls verify and then writes the score with a server key.

## 4. Optional: server-side replay (strongest check)

If the game is deterministic (same seed + same inputs = same result), record inputs during the run, send them with
the score, and pass `replay` plus a `simulate` function that re-runs the game on the server:

```js
const v = await pyrmi.verify({
  token, score, durationMs, player, replay: body.inputs,
  simulate: (inputs) => runGameHeadless(seedFromYourRun, inputs), // must return { score, durationMs? }
});
```

A run whose inputs don't reproduce the claimed score is rejected (`replay_mismatch`).

## 5. Tell the developer

Finish by telling the developer:
- set `PYRMI_SECRET_KEY` in the server's environment (and replace `pk_REPLACE_ME` if you used it),
- watch verdicts at https://pyrmi.com/dashboard/ and tune max score and other limits there,
- which files you changed.

## Reference

- Reasons: `invalid_token`, `wrong_project`, `expired`, `token_reused`, `impossible_time`, `too_short`,
  `score_over_max`, `score_too_fast`, `bad_score`, `replay_mismatch`, `rate_limited` (all reject);
  `automation`, `no_client`, `synthetic_input`, `speed_hack`, `time_warp`, `tampered_runtime`, `inhuman_input`,
  `ua_changed`, `idle_input`, `devtools_open`, `ip_changed` (add risk).
- Self-hosting: pass `endpoint: 'https://your-deploy.example/api/v1'` to `new Pyrmi()` and use
  `data-api="https://your-deploy.example/api/v1"` on the script tag.
- Docs for humans: https://pyrmi.com/docs/
