# Pyrmi Security

Open-source bot and tamper detection for websites. MIT licensed. Live at [pyrmi.com](https://pyrmi.com).

- **Browser script** (`sdk/pyrmi.js`): one script tag. Starts a signed, single-use session on a real page load and
  reports signals (automation, scripted input, inhuman timing, replaced built-ins, clock tricks, probable devtools).
- **Server check** (`packages/pyrmi-server`, or `POST /api/v1/verify`): before trusting a request (a sign-up, a vote,
  a checkout, a score), your server gets a verdict (`accept`, `review`, `reject`), a risk score from 0 to 100, and the
  reasons.
- **Dashboard** (`/dashboard/`): every verdict, why requests were flagged, and which users keep getting flagged.
  No account needed: a project's secret key opens it.
- **Sandbox** (homepage): send a protected action normally, replay it, edit its token, send an impossible value or
  skip the page, and see the verdict. Its dashboard is public at `/dashboard/?demo=1`.

What it deliberately doesn't do: block devtools or "stop code running". Whoever owns the browser can switch any of
that off. Pyrmi treats browser signals as evidence and makes the server the gate.

## How it fits together

```
web page ──(1) POST /api/v1/session {site: pk_}──────────────▶ signed token {project, session, seed, ip/ua hash, expiry}
          ──(2) POST /api/v1/signal  {token, signals} (beacons) ▶ merged into the session record
          ──(3) request + token ─▶ your server ──(4) POST /api/v1/verify (Bearer sk_) ─▶ verdict + reasons, logged for the dashboard
```

Checks at verify time: token signature, project, expiry, single use, time since page load, the optional value caps
and replay result, and the session's browser signals (including whether any ever arrived, which catches direct API
calls and scrapers, and whether the page clock kept pace with real time).

## Repo layout

| path | what |
| --- | --- |
| `index.html`, `site.css`, `site.js` | the Pyrmi Security homepage |
| `sandbox.js` | the homepage sandbox: real honest and cheating requests against the demo project |
| `src/sdk/pyrmi.js` | the browser script, readable source |
| `sdk/pyrmi.js` | the minified build pyrmi.com serves (`node scripts/build-sdk.js`; the tests fail if it's out of date) |
| `bg/singularity.js`, `vendor/three-r170/` | the animated background (three.js r170, MIT, vendored unmodified apart from import paths) |
| `packages/pyrmi-server/` | the npm package (`pyrmi-server`), no dependencies |
| `api/v1/*.js` | Vercel Node functions: `session`, `signal`, `verify`, `project`, `dashboard`, `demo` |
| `api/_lib/` | shared server code: `core.js` (all the logic), `kv.js` (Upstash REST client + in-memory mode), `crypto.js`, `http.js` |
| `dashboard/`, `docs/`, `install.md`, `llms.txt` | dashboard, human docs, install guide for coding agents |
| `scripts/dev.js`, `scripts/build-sdk.js`, `scripts/check-no-python.js`, `tests/` | local dev server, browser script build, the no-Python build guard, end-to-end tests |

## Run it locally

Needs Node 18+. No install step: there are no dependencies.

```bash
PYRMI_KV=memory node scripts/dev.js     # http://localhost:3000, data kept in memory
node --test tests/*.test.js             # end-to-end API tests (memory store)
```

## Deploy (Vercel)

Static files plus the functions in `api/` deploy with zero config. Storage is Upstash Redis on the free tier.

| env var | needed | what |
| --- | --- | --- |
| `KV_REST_API_URL`, `KV_REST_API_TOKEN` | yes | Upstash Redis. Vercel → Storage → Upstash for Redis fills both in. (`UPSTASH_REDIS_REST_*` also works.) |
| `PYRMI_SECRET` | strongly recommended | 32+ random characters that sign session tokens. Without it, one is generated and kept in Redis, which works but means anyone with Redis access could forge tokens. |
| `PYRMI_KV_PREFIX` | no | key prefix in Redis. Defaults to `live:` in production and `preview:` on previews, so they never mix |
| `PYRMI_SIGNUPS` | no | set to `off` to stop new projects being created |
| `PYRMI_MAX_PROJECTS` | no | total project cap (default 500) |
| `PYRMI_PROJECTS_PER_IP` | no | new projects per network per day (default 3) |
| `PYRMI_SESSIONS_PER_DAY` | no | sessions per project per day (default 20000), protects the free Redis quota |
| `PYRMI_SESSIONS_PER_IP` | no | sessions per network per 10 minutes (default 150) |
| `PYRMI_VERIFIES_PER_MIN` | no | verifies per project per minute for sessions from one network (default 60) |
| `PYRMI_SIGNALS_PER_IP` | no | telemetry beacons per network per 10 minutes (default 1500) |
| `PYRMI_DASHBOARD_PER_MIN` | no | dashboard reads per network per minute (default 60) |
| `PYRMI_PROJECT_CALLS_PER_MIN` | no | project reads, edits and key rotations per network per minute (default 30) |
| `PYRMI_BAD_KEYS_PER_IP` | no | wrong secret keys per network per 15 minutes before it's locked out (default 20) |
| `PYRMI_SITE_GUARD` | no | set to `off` to stop requiring a Pyrmi token on the new-project form (for self-hosting without the dashboard page) |
| `SMTP_HOST`, `SMTP_USER`, `SMTP_PASS` | for email sign-in (option 1) | a normal mailbox to send sign-in codes from, e.g. Namecheap Private Email: `mail.privateemail.com`, the full mailbox address, and its password. Takes priority over Resend. |
| `SMTP_PORT` | no | `465` (TLS, the default) or `587` (STARTTLS, required) |
| `RESEND_API_KEY` | for email sign-in (option 2) | a [Resend](https://resend.com) API key with sending access. With neither this nor `SMTP_*` set, the email code option is hidden. |
| `PYRMI_EMAIL_FROM` | no | who sign-in codes come from, e.g. `Pyrmi Security <login@pyrmi.com>`. Over SMTP it defaults to `Pyrmi Security <SMTP_USER>` and should stay that mailbox or one of its aliases; with Resend it defaults to `Pyrmi Security <login@pyrmi.com>` and its domain must be verified there. |
| `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` | for GitHub sign-in | a GitHub OAuth App. Without them the GitHub button is hidden. |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | for Google sign-in | a Google OAuth client (Web application). Without them the Google button is hidden. |
| `PYRMI_PUBLIC_URL` | no | pins the address GitHub and Google send people back to, e.g. `https://pyrmi.com`. Defaults to the deployment's own host. |
| `PYRMI_SITES_PER_USER` | no | sites per account (default 10) |
| `PYRMI_SIGNINS_PER_IP` | no | GitHub or Google sign-ins, and email code checks, per network per 10 minutes (default 30) |
| `PYRMI_EMAIL_CODES_PER_IP` | no | sign-in codes sent per network per 10 minutes (default 10) |
| `PYRMI_EMAIL_CODES_PER_ADDRESS` | no | sign-in codes sent to one address from one network per hour (default 5) |
| `PYRMI_EMAIL_CODES_PER_ADDRESS_TOTAL` | no | sign-in codes sent to one address from anywhere per hour (default 20) |
| `PYRMI_PROXY_HOPS` | no | only when self-hosting behind your own proxies: how many there are, so the client address is read from the right of `X-Forwarded-For`. Leave unset on Vercel. |
| `PYRMI_ACCOUNT_CALLS_PER_MIN` | no | account calls per network per minute (default 60) |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | recommended in production | a [Cloudflare Turnstile](https://developers.cloudflare.com/turnstile/) widget's keys. With both set, sign-in codes, new projects and sites, and claiming, rotating or deleting a site each need a human check. Off while either is missing. |
| `TURNSTILE_HOSTNAMES` | no | comma-separated page hostnames a Turnstile token may come from, e.g. `pyrmi.com,www.pyrmi.com`. Defaults to the host the request was sent to. |

With none of the sign-in env vars set, the dashboard works with secret keys only. Each way in switches on by itself,
and one verified email is one account whichever way someone signs in.

### Human check on the dashboard (Cloudflare Turnstile)

Browser telemetry can't stop a script that copies the real one exactly, so the dashboard's own forms also use
Turnstile, a separate check run by Cloudflare. Create a widget in Cloudflare (Turnstile → Add widget, hostname your
domain, mode Managed), then set its keys as `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` for Production and
redeploy. The server checks every token with Cloudflare's siteverify: it must have passed, be for that form's action
(`signin`, `new-project`, `new-site`, `claim`, `rotate`, `delete`) and come from your hostname, and each token is
accepted once. It fails closed: if Cloudflare can't be reached the request is refused with `turnstile_unavailable`.

### Email codes from your own mailbox (SMTP)

Any mailbox that allows SMTP works. For Namecheap Private Email:

1. Set `SMTP_HOST` to `mail.privateemail.com`, `SMTP_PORT` to `465`, `SMTP_USER` to the full mailbox address
   (e.g. `login@pyrmi.com`) and `SMTP_PASS` to that mailbox's password, as a Sensitive variable in Vercel. Redeploy.
2. Private Email already publishes SPF (`include:spf.privateemail.com`) and DKIM (`privateemail._domainkey`) when the
   domain's mail is set up through Namecheap. A DMARC record (`TXT` on `_dmarc`, value `v=DMARC1; p=none;`) is optional
   but helps Gmail and Yahoo trust the mail.
3. Namecheap caps sending at 500 messages an hour per mailbox on paid plans (20 an hour on a trial) and 50 recipients
   per message. Each sign-in code is one message to one person, and Pyrmi's own caps (5 codes per address per hour, 10
   per network per 10 minutes) keep well under it.

The password is only ever sent to the mail server after the connection is encrypted; on port 587 a server that
doesn't offer STARTTLS is refused.

### Email codes (Resend)

1. Make a free account at resend.com, add the domain `pyrmi.com` under Domains, and add the DNS records it shows
   (a DKIM `TXT` record, and an `MX` and `TXT` record on its `send` subdomain) wherever the domain's DNS is hosted.
   These sit beside any existing mail records, so a mailbox already on the domain keeps working.
2. Once Resend shows the domain as verified, create an API key with sending access and set it as `RESEND_API_KEY`
   in Vercel, then redeploy.

### Sign in with GitHub

1. On GitHub, open Settings → Developer settings → OAuth Apps → New OAuth App. Homepage URL `https://pyrmi.com`,
   authorization callback URL `https://pyrmi.com/api/v1/auth/github`.
2. Copy the client ID, generate a client secret, and set both as `GITHUB_CLIENT_ID` and `GITHUB_CLIENT_SECRET` in
   Vercel, then redeploy. A GitHub OAuth App has one callback URL, so to try it on a preview, make a second app for it.

### Sign in with Google

1. In Google Cloud Console, open Google Auth Platform (APIs & Services → OAuth consent screen). Pick External, fill in
   the app name and support email, and add the scopes `openid`, `email` and `profile` (none of them need Google's review).
2. Under Clients, create a Web application client with the authorized redirect URI `https://pyrmi.com/api/v1/auth/google`.
   Add a preview address too (`https://<preview-host>/api/v1/auth/google`) to try it there.
3. In Vercel, set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, and redeploy.

## API

| method | path | auth | body / result |
| --- | --- | --- | --- |
| POST | `/api/v1/project` | a clean Pyrmi token from the dashboard page (rate limited) | `{name, origins?, pyrmiToken}` → `{project: {pid, publicKey, secretKey}}` (secret shown once) |
| GET / PATCH | `/api/v1/project` | `Bearer sk_` | project info / `{name?, settings}` |
| POST | `/api/v1/project?action=rotate` | `Bearer sk_` | new secret key, old one stops working |
| POST | `/api/v1/session` | public key in body, origin checked | `{site, pt?}` (pt: the page clock) → `{token, session, seed, expiresAt, bn}` |
| POST | `/api/v1/signal` | session token | `{token, bn, n, signals}` (plain JSON, text/plain so there's no preflight; `bn` from the session, `n` counts up) |
| POST | `/api/v1/verify` | `Bearer sk_`, server only | `{token, user?, score?, durationMs?, replay?}` → `{verdict, risk, client, reasons}` |
| GET | `/api/v1/dashboard` | `Bearer sk_` (or `?demo=1` sandbox, `?demo=site` pyrmi.com itself) | 14 days of stats, last 100 verdicts, flagged users |
| POST | `/api/v1/demo` | session token | the homepage sandbox's stand-in server: `{token, value?}` → verdict |
| POST | `/api/v1/auth/email?action=start` | CSRF header + Pyrmi token | `{email, pyrmiToken}` → emails a 6-digit code; the same answer for every address |
| POST | `/api/v1/auth/email?action=verify` | CSRF header | `{email, code}` → sets the session cookie |
| GET | `/api/v1/auth/github`, `/api/v1/auth/google` | none | starts that sign-in, then handles the redirect back and sets the session cookie |
| GET | `/api/v1/me` | session cookie | `{user, sites}` with each site's connection status, or 401 `{providers}` saying which ways in are on |
| POST | `/api/v1/me?action=signout` | session cookie + CSRF header | ends the session |
| POST | `/api/v1/sites` | session cookie + CSRF header + Pyrmi token | `{name, origins?, pyrmiToken}` → a new site in this account |
| POST | `/api/v1/sites?action=claim` | session cookie + CSRF header | `{secretKey}` moves a key-only project into this account |
| GET / PATCH / DELETE | `/api/v1/sites?pid=` | session cookie (+ CSRF header to change) | one of your sites: dashboard data, `{name?, settings}`, or delete |
| POST | `/api/v1/sites?pid=&action=rotate` | session cookie + CSRF header | new secret key for one of your sites |

## Security notes

- Secret keys are stored only as SHA-256 hashes. IPs and user agents are stored only as keyed hashes.
- `/verify` refuses requests that look like they come from a browser, so a secret key pasted into a page fails loudly.
- Client signals are treated as untrusted: only known fields are kept, with types and sizes forced.
- The dashboard page runs under a strict Content-Security-Policy and escapes all user-supplied text.
- Every endpoint is rate limited per network, per user or per project, and wrong secret keys are capped per network.
- pyrmi.com uses Pyrmi on itself: the new-project form needs a clean accept from the built-in `pyrmi-site` project.
- Signed-in sessions are a random cookie (`__Host-`, HttpOnly, Secure, SameSite=Lax) stored only as a SHA-256 hash.
  Email codes are single use, last 10 minutes, are stored only as a keyed hash, die after 5 wrong tries and are capped
  per address and per network; asking for one needs a clean Pyrmi token and never reveals whether an account exists.
  GitHub and Google sign-in use PKCE and a signed state cookie tied to the provider, and need a verified email.
  Their tokens are used once and never kept.
- Every change made with the session cookie needs the `X-Pyrmi-CSRF` header and a same-site origin.
- Each account sees only its own sites: anyone else's answers 404, the same as one that doesn't exist.
- The browser script is served as a minified build that fingerprints itself (an edited copy, or a beacon with no
  fingerprint, shows as `tampered_runtime`). Its telemetry is corroborated against what the server sees (see below).

### What the browser telemetry can and can't do

Be honest about the threat model, because it decides where you can rely on Pyrmi:

- **Client telemetry is advisory, not proof.** The beacons from the browser script (`webdriver`, headless hints,
  scripted input, devtools, clock skew, …) are sent in the clear and can only *raise* risk. They catch lazy bots,
  automation frameworks and obvious tampering. They can **never prove** a request came from a real person: anything the
  script sends, an attacker running a real browser (or replaying the documented beacon) can send too. So the absence of
  bad signals is not a guarantee — a determined attacker can present a "clean" session.
  (An earlier build XOR-encoded each session's beacons with a per-session key. That key was handed to the browser, so
  it protected nothing and is gone; pretending it did was the problem, not the encoding.)
- **Telemetry is checked against what the server saw itself, so made-up beacons don't read as clean.** Round 7
  showed ~15 lines of hand-written JSON earning the sandbox's 999 at risk 0. Now each beacon is compared with things
  the server observes on its own: the page that started the session and sent the beacon (`Origin`, and the
  `Sec-Fetch-Site` header Chrome and Firefox always add), the page's clock at session start against the server's
  clock, counters that only grow, the full field set and the script's fingerprint, and a per-session beacon nonce and
  count (so a beacon copied from another session, or sent twice, is refused). Anything that doesn't hold up adds
  `unverified_client` (+40, review by default), a beacon without the fingerprint or the fields counts as
  `tampered_runtime` too, and the verdict says `client: "corroborated" | "unverified" | "none"`. This is cost, not
  proof: a script outside a browser can still forge those headers, and a person in their own browser can send what
  the real script would, nonce and all. It stops the lazy forgery; it doesn't make telemetry trustworthy.
- **Round 8 closed the shortcuts a re-test found around that.** A script that sent the full field set still came back
  accept, risk 0, `corroborated` three ways: `pt: null` skipped the clock check, a previous build's fingerprint skipped
  the clock, activation and nonce checks, and leaving out `ac` skipped the activation check. Now the current build's
  shape requires a numeric `pt` and an `ac` (null is only accepted from browsers without `navigator.userActivation`),
  only the current build can ever be `corroborated` (an older one is `unverified_client`, `sdk_version`), and
  `tampered_runtime` weighs 40, so on its own it is a review and an edited or outdated copy of the script is a reject.
- **What still passes, and always will:** a script that copies everything the real one sends, starting its own
  session and sending a page clock that keeps time, comes back `accept` and `corroborated`, and so does a real browser
  running an edited copy. Telemetry can't tell those from a person. A re-tester put a deliberate forgery at 30 to 60
  minutes of reading this repo. That is the honest ceiling for client telemetry: a speed bump, not a boundary.
- **Gate sensitive actions on more than "not rejected".** For payouts, prizes, leaderboards and account changes, use
  `trusted(v)` from `pyrmi-server`, together with your own server-side limits. It reads `v.trusted`, which the server
  sets only for an `accept` whose `client` is `corroborated`, whose browser saw a real key press or click (`ac: true`),
  and whose every reason is harmless (`wrapped_runtime`, `devtools_open`, `ip_changed`, `idle_input`). It doesn't move
  with your thresholds: raising `reviewAt` to 50 or 80 turns a tampered runtime or webdriver session into an accept,
  but never into a trusted one. A `review` never counts. The strongest setup is all three: `trusted(v)`, a Turnstile
  check on the same request (`verifyTurnstile`, then `trusted(v, t)`), and server-side replay where the app allows it. Everyday actions (a sign-up, a comment) can let a `review` through, flagged.
- **The fingerprint is a speed bump.** The script reports a hash of its own code, and the known hashes are public (the
  built file, `api/_lib/sdk-build.json`), so it only catches a careless edit. Builds that came before stay known for
  1 day after they're replaced (`PYRMI_SDK_GRACE_DAYS`; the CDN caches the script for 5 minutes) so cached pages
  aren't called tampered, but they are never `corroborated`; after that they count as `tampered_runtime`
  (`pyrmi.js:outdated`) too. The readable source's hash is only known outside production.
- **Speeding up your own code needs no hook.** A cheat that runs the game's own simulation faster, and leaves the
  clocks and timers alone, changes nothing the script watches; `Pyrmi.mark()` reports only what your app tells it.
  For games the only anti-tamper that doesn't rely on the client is server-side: re-run the inputs (the replay /
  simulate hook in `pyrmi-server`) or make the server authoritative.
- **The hard floor is server-side and can't be forged from the browser:** the HMAC-signed session token, single-use
  replay protection, expiry, `minDurationMs` (measured from when the token was issued, so a claimed `durationMs`
  can't satisfy it), `maxScore`/`maxScorePerSec`, and the per-network / per-project rate limits and quotas. These do
  not depend on the client cooperating. (The network and browser a session started from are only compared on
  beacons, as the soft `ip_changed`/`ua_changed` signals: your server calls verify, not the visitor.)
- **So:** use `maxScore`/`maxScorePerSec`/`minDurationMs` and your own server rules for anything that matters (scores,
  payouts, sign-ups), and treat the telemetry-driven `risk`/`reasons` as a signal to flag or review, not as the sole
  gate. For a deterministic game, server-side replay (`simulate`) is the one anti-tamper check that doesn't depend on
  the client telling the truth; for bots, a CAPTCHA (Turnstile, hCaptcha) plus rate limits. pyrmi.com guards its own forms this way: the Pyrmi accept is one layer, and the per-network rate limits are the
  real cap on abuse.

### How the replaced built-ins check works

The browser script watches `performance.now`, `Date.now`, timers, `fetch`, `XMLHttpRequest.send`,
`addEventListener`, `Math.random`, `Function.prototype.toString`/`call`/`apply`/`bind`, `Object.getOwnPropertyDescriptor`
and `getPrototypeOf`, `document.createElement`, the iframe `contentWindow` getter and the `navigator` `webdriver`,
`userAgent` and `languages` getters. It does **not** decide "still native?" by looking for `[native code]` in
`toString`: a function wrapped in `.bind()` or a `Proxy` prints that too, so `performance.now = (() => 0).bind(window)`
used to pass as clean. Instead:

- **Identity since load.** It keeps a reference to each built-in (and where it lives) the moment it loads, and flags
  anything that's a different function, in a different place, or a getter where a value was, on every re-check.
- **A clean copy to compare with.** At load it opens a hidden same-origin iframe, records how that realm's own
  untouched built-ins print and where they live, and removes it. A built-in on the page that prints differently (a
  real native prints with its own name, `function now() { [native code] }`; bound functions and Proxies don't) or that
  sits somewhere else (an own property shadowing the prototype's) is flagged, even if it was replaced before the
  script loaded. Without an iframe it falls back to that exact native-with-its-name form.
- **No trusting `toString`.** It checks `Function.prototype.toString` itself against the clean copy and uses the clean
  one when the page's was replaced, and calls everything through references taken at load, so a later hook on
  `.call` or `.toString` can't answer for it. The script's own clocks, timers, `fetch` and listeners also use those
  references, and `window.Pyrmi` is frozen, so a later script can't quietly stop its beacons or swap `flush()`.
- **A fake `window.Pyrmi` planted first** (round 7). The script used to skip itself if `window.Pyrmi.version` existed.
  It now recognises only its own instance (frozen, read-only, methods that are text from the script itself), replaces
  anything else it can and reports `window.Pyrmi` as tampering. A fake defined non-configurable can't be replaced; then
  the page gets no telemetry from the script, which the server sees as `no_client` or unverified telemetry.
- **Input hidden from the script** (round 7). A capture listener that runs first can stop events before the script's
  listener sees them. The script also reads the browser's own `navigator.userActivation` (set by a real key press or
  click, whatever scripts do with the event): activated since load, but no input ever reached the script, is
  `input.hidden` (tampering). Scripted `keyup`/`pointerup`/`mouseup`/`touchend`/`wheel` now count as synthetic too
  (form `input`/`change` don't: password managers fire those by script).
- **The devtools hint reads the window sizes through getters taken at load** and watches them (round 7), so spoofing
  `outerWidth`/`innerWidth` to hide a docked panel is reported as tampering instead of hiding it. It's still only a
  hint (+10): undocked devtools change nothing it can see.

This raises the bar; it doesn't change the threat model above. Code that runs before the script and also fakes the
iframe, or an edited copy of the script, can still report a clean runtime. Load the script first in `<head>`, and keep
relying on the server-side floor.

Error trackers and frameworks (Sentry, zone.js/Angular, Datadog, New Relic) wrap timers, `requestAnimationFrame`,
`fetch`, `XMLHttpRequest.send`, `addEventListener` and `Function.prototype.toString` on ordinary sites. A change to one
of those is reported separately as `wrapped_runtime` (+5), not `tampered_runtime` (+40). None of those tools touch the
clocks, `Math.random`, `call`/`apply`/`bind`, the descriptor lookups or the `navigator` getters, so replacing any of
those stays `tampered_runtime`, whatever markers (`__sentry_original__`, `__zone_symbol__`) a replacement carries.

To see what a browser reports, open `/sdk/selftest.html` in it: it runs every trick above in a fresh frame and shows
pass or fail. Nothing is sent anywhere.

## License

MIT, see [LICENSE](LICENSE).
