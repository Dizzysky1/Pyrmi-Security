# Hardening backlog

Things we've decided to do (or decided to leave) that are bigger than the PR that found them. Keep it short: tick an
item off in the PR that fixes it, and add new ones in the PR that finds them.

## Browser script (`src/sdk/pyrmi.js`)

- [x] **Native-function check fooled by `.bind()` / `Proxy`** (round 6). The check matched `[native code]` in
  `Function.prototype.toString`, which bound functions and Proxies also print, so
  `performance.now = (() => 0).bind(window)` read as clean and verified at risk 0. Now: identity with load-time
  references, comparison with a clean iframe realm (exact print, including the built-in's own name, and where it
  lives), a bound-name stopgap, and a trusted `toString`. Tests: `tests/sdk-tamper.test.js`.
- [x] **Sibling checks the same tricks could fool** (round 6): `Function.prototype.call/apply/bind`,
  `Object.getOwnPropertyDescriptor/getPrototypeOf`, `document.createElement`, the iframe `contentWindow` getter, and
  `navigator.webdriver/userAgent/languages` (stealth kits redefine these with `Object.defineProperty`) are now watched;
  `webdriver` is read through the load-time getter and cross-checked with the clean realm. The script's own clocks,
  timers, `fetch` and listeners use load-time references, and `window.Pyrmi` and its config are frozen.
- [x] **Run the self-test in real Firefox and Safari.** Done for round 6: real Chrome passed 29 of 29, and the owner
  reports Firefox and Safari pass too. Round 7 added watched built-ins (`navigator.userActivation`, the window sizes),
  so open `/sdk/selftest.html` in Safari and Firefox once more after it ships.
- [x] **Expected wrappers** (round 6). Changes to timers, rAF, `fetch`, XHR `send`, `addEventListener` and `toString`
  (what Sentry, zone.js/Angular, Datadog and New Relic wrap) are now `wrapped_runtime` (+5), not `tampered_runtime`
  (+40 since round 8). Recognition is by which built-in, never by library markers, which an attacker could copy.
- [ ] **Speed hacks through the wrapped group.** Scaling `setTimeout`/`setInterval` delays or rAF timestamps now costs
  only +5 unless the clocks are touched too. Sites with their own game clock should call `Pyrmi.mark()` so `time_warp`
  can catch it; a per-site "strict" setting could put the timers back at full weight.
- [x] **Input can be hidden from the script** (round 7). A capture listener on `window` registered first can
  `stopImmediatePropagation()` before ours runs (a `document` listener wouldn't help: it's stopped too). Now the
  script reads `navigator.userActivation.hasBeenActive`, which the browser sets on a real key press or click whatever
  scripts do; activated since load with no input ever reaching us is `input.hidden`. The getters are watched. Scripted
  `keyup`/`pointerup`/`mouseup`/`touchend`/`wheel` also count as synthetic. Limit: a page activated before the script
  loaded can't be checked this way.
- [x] **A pre-planted `window.Pyrmi` makes the script skip itself** (round 7). It now recognises only its own instance
  and replaces and reports anything else (`window.Pyrmi`). A non-configurable fake still can't be replaced; the page
  then sends us nothing, which the server reads as `no_client` (or `unverified_client` if the fake makes beacons up).
- [ ] **Code that ran first and also fakes the iframe.** Hooking `createElement`/`appendChild`/`contentWindow` and the
  iframe's own `toString` before the script loads can make the "clean copy" lie. Those hooks are watched, but this is
  the limit of any in-page check: document "load Pyrmi first in `<head>`" in the install guide (`install.md`, docs).
- [x] **The devtools hint is trivial to spoof** (round 7). The window sizes are read through getters taken at load and
  watched, so a spoof is reported as tampering instead of hiding the hint. Still only +10, and blind to undocked tools.
- [ ] **Self-fingerprint and all telemetry are client-sent.** An edited copy of the script can send the expected `sh`
  and an empty `tp`. Inherent to client telemetry; it stays advisory (see README, "What the browser telemetry can and
  can't do"). Round 7 made the cheap versions cost something: a missing `sh` or field set is `tampered_runtime`, old
  build hashes expire after `PYRMI_SDK_GRACE_DAYS` (1 day since round 8), the source hash isn't accepted in production, and every beacon
  is corroborated server-side (`unverified_client`, `client` on the verdict).
- [x] **Per-session HMAC key, for the action rather than the beacons** (round 11). Beacons still use the plain nonce
  and count. The action is what an attacker rewrites on the wire (the CDP re-test turned 55 into 88), so the script
  now seals it with a per-session request key that's in the session answer only, never the token. It stops a rewrite
  by anything that didn't see the session answer and a token lifted into another body. It doesn't stop code in the
  page, or something that controls the page's network, from signing whatever it likes; the README says so.
- [x] **A tampered runtime alone was an accept at the default settings** (round 8). `tampered_runtime` is now +40, so
  on its own it is a review; an edited or outdated copy of the script also fails corroboration, so it is a reject.
  Wrapped built-ins (Sentry, Angular) stay `wrapped_runtime` at +5.
- [x] **Corroboration had shortcuts** (round 8 re-test). `pt: null`, a previous build's fingerprint and a missing `ac`
  each skipped a check and came back `corroborated`. Fixed: numeric `pt` and an `ac` are required from the current
  build, only the current build can be corroborated, and the grace period for old builds is 1 day.
- [x] **`trusted(v)` followed the site's thresholds** (master list). With `reviewAt` raised to 50 or 80, a tampered
  runtime, webdriver or input-hiding session became an accept and so passed `trusted(v)`. The server now sets
  `trusted` itself from an allow-list of harmless reasons, a corroborated accept and `ac: true`, independent of
  thresholds; `pyrmi-server` uses it and falls back to the same allow-list. Tests: `tests/trusted.test.js`.
- [x] **A human check that doesn't depend on browser telemetry** (master list). Cloudflare Turnstile on sign-in codes,
  new projects and sites, claim, rotate and delete, off until `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET_KEY` are set.
  Server-side siteverify with the form's action, the page hostname, single use (Cloudflare's own plus a token hash
  kept 10 minutes) and fail closed; `pyrmi-server` offers `verifyTurnstile` and `trusted(v, t)`. `cdata` isn't used:
  the action, hostname and single use already bind a token to one form on one site. Tests: `tests/turnstile.test.js`.
- [ ] **A full mimic still corroborates.** A script that starts its own session and sends exactly what the real one
  would, page clock included, is an accept. Inherent; documented. The sample and `pyrmi-server`'s `trusted(v)` gate
  sensitive actions on a corroborated accept, and `simulate` is the check that doesn't depend on the client.
- [ ] **A per-site setting to make `unverified_client` reject** (considered). Raising it to 70 for everyone would
  reject real visitors on a single slip (a laptop that slept mid-session). A site that wants that can gate on
  `client` today; a dashboard toggle could do it server-side.

## Loader and delivery

- [x] **SDK version pinning + SRI** (round 10; round 11 keeps pinned versions on the current beacon protocol fully
  supported instead of letting them age out after a day). Serve versioned, immutable builds (e.g. `/sdk/1.2.0/pyrmi.js`) with long cache
  headers, publish their `integrity` hashes, and show the `<script ... integrity="sha384-..." crossorigin>` snippet in
  the dashboard, docs and `install.md`, keeping `/sdk/pyrmi.js` as the moving "latest". Keep `previous` fingerprints in
  `api/_lib/sdk-build.json` working for cached copies.

## Copy

- [ ] **Honesty pass on the marketing copy.** Make sure the homepage, docs and dashboard say what the README's threat
  model says: telemetry raises risk but never proves a real person, the server-side floor is the real protection, and
  "blocks devtools/tampering" means "detects and reports", not "prevents". Round 5 flagged this without a list of
  lines; do a read-through of `index.html`, `docs/index.html`, `dashboard/` and `install.md`.

## Server (master list follow-up)

- [x] **Rate-limit windows could lose their expiry.** `bump()` did INCR and then a separate EXPIRE; if the second call
  was lost the limit stuck for good. The TTL is now set with the key (`SET NX EX`, then `INCR`, in one request).
- [x] **The `/verify` limiter never fired.** It was keyed on the session id, and a token is single-use. It is now keyed
  on the network the session started from (in the signed token), default 60 a minute per project.
- [x] **Expired tokens weren't marked used**, so each replay logged a new event. They are marked now.
- [x] **Beacon sabotage.** Anyone holding a session's token could send beacons from another site and mark the real
  player's session as made up. A beacon whose Origin isn't the page that started the session is refused and changes
  nothing. A script outside a browser can still fake the Origin; see "A full mimic" above.
- [x] **`recordSignals` didn't check that token and session agree on the project** (defence in depth).
- [x] **Dead decoder for the old per-session shape key** removed.
- [x] **Key rotation raced.** Two rotations at once (the owner and someone with a stolen key) both wrote, and the last
  one kept a working key. Rotations now take a short per-project lock and a rotation with the old key only succeeds
  while that key is still current; the loser gets a 409.
- [x] **Revoke-all missed sessions from before the per-user index.** Only indexed sessions count now, so those stop
  working (a one-time sign-in again) and revoke-all ends everything.
- [x] **Email sign-in lockout.** Five code requests and six wrong guesses from anywhere locked an address out for an
  hour. Requests and wrong guesses are now counted per network, with looser caps on the address as a whole.
- [x] **CSRF check accepted `Origin: null` and compared only the host.** It now compares the full origin.
- [x] **Behind your own proxy, the client address was the first X-Forwarded-For entry** (which the client writes).
  `PYRMI_PROXY_HOPS` takes it from the right instead. Vercel is unaffected.
- [x] **The site list stopped at a fixed length** if the per-account cap was raised.
- [x] **Public demo dashboards showed session ids, and the site guard's label for a network never changed.** Session
  ids are gone from them and the label changes daily.
- [x] **The home page and docs had no CSP or frame protection.** They have both now. 405 responses send `Allow`.
- [x] **Secure defaults** (retest of b127c08). New projects must register their pages, get a 1.5 s minimum time,
  and reject a value sent with no maximum set (`no_score_limit`). Projects made before keep their settings; the
  dashboard warns when a project is instant and open. `PYRMI_REQUIRE_ORIGINS` is `new` by default (`all` binds old
  projects too).
- [x] **Quotas a spread-out source could drain.** The session quota is per network first: past the project's daily
  limit only heavy networks are refused, up to a hard ceiling, and refusals aren't counted. The email cap only covers
  addresses with no account, per hour and per day, and answers them the same either way; each network also has a
  daily share. Projects made without an account have their own smaller cap. An IPv6 /64 counts as one network. 80%
  of a limit is logged, and shown on the dashboard for a project's sessions.
- [x] **`ps:secret` fallback.** Without `PYRMI_SECRET` the API answers 503 instead of reading a secret from the store.
- [x] **The browser script was unversioned** with a 5-minute cache. Each version is now also at
  `/sdk/<version>/pyrmi.js`, cached for a year and never changed, and every snippet pins it with an integrity hash.
- [x] **pyrmi.com's public dashboard showed a per-day label for each visitor's network.** It shows "visitor" now.
- [ ] **`trusted` and network or browser changes.** `ip_changed` is allowed (phones hand over), `ua_changed` isn't.
  For payouts, a fresh check at payout time is the safer rule. Round 11 also compares the client at verify (when the
  site's server forwards it): a different browser or client hints is `relayed_session`, never trusted.
- [ ] **A relay that copies everything still passes** (round 11, by design). A real browser driven over CDP can seal
  any action in the page and send it from a script with the same headers on the same network. No client-side check
  can see that; the server gate (single use, minimum time, caps, replay, Turnstile) is what holds.
- [x] **Customer servers behind their own proxies** set `trustProxyHops` in pyrmi-server (`PYRMI_PROXY_HOPS` for a
  self-hosted API).
- [x] **Security hardening** (round 12): see PROGRESS.md.
- [x] **Player labels collided.** A label that needs cleaning gets a short hash of the original on the end, so `a<b`,
  `a>b` and `a/b` are three players. Ordinary labels are unchanged.
- [ ] **DMARC is `p=none`.** Move to `quarantine`, then `reject`, and SPF to `-all` once the reports look right.
- [ ] **`Pyrmi.token()` is readable by other scripts on the same page.** Beacons are bound to the page's origin, so
  another site can't use it; a script you load yourself can. Load only scripts you trust on protected pages.

## Architecture and infrastructure (flagged in round 5)

This repository is public, so infrastructure gaps are tracked here only in outline; the details live with the owner.

- [x] **Separate preview and production data** (stores and deployment access). Previews no longer reach the production
  store.
- [x] **Retire old deployments** that predate the round-5 removals.
- [x] **Clear orphaned keys** left in the store by the old site. None were left.
- [ ] **Old blobs in GitHub's pull-request refs** (removed files, the old author email). A force-push can't remove them;
  needs GitHub support or a fresh repository before treating history as clean.
