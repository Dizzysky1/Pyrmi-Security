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
| `sdk/pyrmi.js` | the scrambled build pyrmi.com serves (`node scripts/build-sdk.js`; the tests fail if it's out of date) |
| `bg/singularity.js`, `vendor/three-r170/` | the animated background (three.js r170, MIT, vendored unmodified apart from import paths) |
| `packages/pyrmi-server/` | the npm package (`pyrmi-server`), no dependencies |
| `api/v1/*.js` | Vercel Node functions: `session`, `signal`, `verify`, `project`, `dashboard`, `demo` |
| `api/_lib/` | shared server code: `core.js` (all the logic), `kv.js` (Upstash REST client + in-memory mode), `crypto.js`, `http.js` |
| `dashboard/`, `docs/`, `install.md`, `llms.txt` | dashboard, human docs, install guide for coding agents |
| `scripts/dev.js`, `scripts/build-sdk.js`, `tests/` | local dev server, browser script build, end-to-end tests |
| `api/*.py` | an older endpoint on pyrmi.com, untouched |

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
| `PYRMI_VERIFIES_PER_MIN` | no | verifies per user per minute (default 30) |
| `PYRMI_SIGNALS_PER_IP` | no | telemetry beacons per network per 10 minutes (default 1500) |
| `PYRMI_DASHBOARD_PER_MIN` | no | dashboard reads per network per minute (default 60) |
| `PYRMI_PROJECT_CALLS_PER_MIN` | no | project reads, edits and key rotations per network per minute (default 30) |
| `PYRMI_BAD_KEYS_PER_IP` | no | wrong secret keys per network per 15 minutes before it's locked out (default 20) |
| `PYRMI_SITE_GUARD` | no | set to `off` to stop requiring a Pyrmi token on the new-project form (for self-hosting without the dashboard page) |
| `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | for accounts | a Google OAuth client (Web application). Without them the dashboard hides Sign in with Google and only the key login works. |
| `PYRMI_PUBLIC_URL` | no | pins the address Google sends people back to, e.g. `https://pyrmi.com`. Defaults to the deployment's own host. |
| `PYRMI_SITES_PER_USER` | no | sites per account (default 10) |
| `PYRMI_SIGNINS_PER_IP` | no | Google sign-in attempts per network per 10 minutes (default 30) |
| `PYRMI_ACCOUNT_CALLS_PER_MIN` | no | account calls per network per minute (default 60) |

### Sign in with Google

1. In Google Cloud Console, open APIs & Services → OAuth consent screen. Pick External, fill in the app name and
   support email, and add the scopes `openid`, `email` and `profile` (none of them need Google's review).
2. Under Credentials → Create credentials → OAuth client ID, pick Web application and add the authorized redirect URI
   `https://pyrmi.com/api/v1/google`. Add a preview address too (`https://<preview-host>/api/v1/google`) to try it there.
3. In Vercel, set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`, and redeploy. Set `PYRMI_PUBLIC_URL` only if the
   site is reached through more than one host name.

## API

| method | path | auth | body / result |
| --- | --- | --- | --- |
| POST | `/api/v1/project` | a clean Pyrmi token from the dashboard page (rate limited) | `{name, origins?, pyrmiToken}` → `{project: {pid, publicKey, secretKey}}` (secret shown once) |
| GET / PATCH | `/api/v1/project` | `Bearer sk_` | project info / `{name?, settings}` |
| POST | `/api/v1/project?action=rotate` | `Bearer sk_` | new secret key, old one stops working |
| POST | `/api/v1/session` | public key in body, origin checked | `{site}` → `{token, session, seed, expiresAt, x}` (`x` is this session's telemetry shape) |
| POST | `/api/v1/signal` | session token | `{token, <x.n>: encoded signals}` (text/plain ok, for sendBeacon) |
| POST | `/api/v1/verify` | `Bearer sk_`, server only | `{token, user?, score?, durationMs?, replay?}` → `{verdict, risk, reasons}` |
| GET | `/api/v1/dashboard` | `Bearer sk_` (or `?demo=1` sandbox, `?demo=site` pyrmi.com itself) | 14 days of stats, last 100 verdicts, flagged users |
| POST | `/api/v1/demo` | session token | the homepage sandbox's stand-in server: `{token, value?}` → verdict |
| GET | `/api/v1/google` | none | starts Sign in with Google, then handles Google's redirect back and sets the session cookie |
| GET | `/api/v1/me` | session cookie | `{user, sites}` with each site's connection status, or 401 `{google}` |
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
  Google sign-in uses PKCE and a signed state cookie, and needs a verified email. Google's own tokens are never kept.
- Every change made with the session cookie needs the `X-Pyrmi-CSRF` header and a same-site origin.
- Each account sees only its own sites: anyone else's answers 404, the same as one that doesn't exist.
- The browser script is served as a scrambled build that fingerprints itself, and each session has its own telemetry
  shape and key. These slow down bot authors; the server-side verdict is still the real protection.

## License

MIT, see [LICENSE](LICENSE).
