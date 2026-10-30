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
| `sdk/pyrmi.js` | the browser script |
| `packages/pyrmi-server/` | the npm package (`pyrmi-server`), no dependencies |
| `api/v1/*.js` | Vercel Node functions: `session`, `signal`, `verify`, `project`, `dashboard`, `demo` |
| `api/_lib/` | shared server code: `core.js` (all the logic), `kv.js` (Upstash REST client + in-memory mode), `crypto.js`, `http.js` |
| `dashboard/`, `docs/`, `install.md`, `llms.txt` | dashboard, human docs, install guide for coding agents |
| `scripts/dev.js`, `tests/` | local dev server and end-to-end tests |
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

## API

| method | path | auth | body / result |
| --- | --- | --- | --- |
| POST | `/api/v1/project` | none (rate limited) | `{name, origins?}` → `{project: {pid, publicKey, secretKey}}` (secret shown once) |
| GET / PATCH | `/api/v1/project` | `Bearer sk_` | project info / `{name?, settings}` |
| POST | `/api/v1/project?action=rotate` | `Bearer sk_` | new secret key, old one stops working |
| POST | `/api/v1/session` | public key in body, origin checked | `{site}` → `{token, session, seed, expiresAt}` |
| POST | `/api/v1/signal` | session token | `{token, signals}` (text/plain ok, for sendBeacon) |
| POST | `/api/v1/verify` | `Bearer sk_`, server only | `{token, user?, score?, durationMs?, replay?}` → `{verdict, risk, reasons}` |
| GET | `/api/v1/dashboard` | `Bearer sk_` (or `?demo=1`) | 14 days of stats, last 100 verdicts, flagged users |
| POST | `/api/v1/demo` | session token | the homepage sandbox's stand-in server: `{token, value?}` → verdict |

## Security notes

- Secret keys are stored only as SHA-256 hashes. IPs and user agents are stored only as keyed hashes.
- `/verify` refuses requests that look like they come from a browser, so a secret key pasted into a page fails loudly.
- Client signals are treated as untrusted: only known fields are kept, with types and sizes forced.
- The dashboard page runs under a strict Content-Security-Policy and escapes all user-supplied text.
- Every write path is rate limited per network, per user or per project.

## License

MIT, see [LICENSE](LICENSE).
