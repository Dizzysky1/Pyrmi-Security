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
  (+30). Recognition is by which built-in, never by library markers, which an attacker could copy.
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
  build hashes expire after `PYRMI_SDK_GRACE_DAYS`, the source hash isn't accepted in production, and every beacon
  is corroborated server-side (`unverified_client`, `client` on the verdict).
- [ ] **Per-session HMAC nonce (considered, not done).** A key the script must HMAC each beacon with would sit in the
  browser like the old XOR key, so it adds no secrecy. Round 7 uses a plain per-session nonce plus a beacon count
  instead, which does the useful part (a beacon copied from another session or sent twice is refused) without
  pretending to be more.
- [ ] **A tampered runtime alone is still an accept at the default settings** (+30, review at 40). Fine for wrapped
  built-ins on ordinary sites; arguable for an edited copy of the script on its own. Product call: weight `pyrmi.js`
  (edited) higher, or a per-site "strict" setting.

## Loader and delivery

- [ ] **SDK version pinning + SRI.** Serve versioned, immutable builds (e.g. `/sdk/1.2.0/pyrmi.js`) with long cache
  headers, publish their `integrity` hashes, and show the `<script ... integrity="sha384-..." crossorigin>` snippet in
  the dashboard, docs and `install.md`, keeping `/sdk/pyrmi.js` as the moving "latest". Keep `previous` fingerprints in
  `api/_lib/sdk-build.json` working for cached copies.

## Copy

- [ ] **Honesty pass on the marketing copy.** Make sure the homepage, docs and dashboard say what the README's threat
  model says: telemetry raises risk but never proves a real person, the server-side floor is the real protection, and
  "blocks devtools/tampering" means "detects and reports", not "prevents". Round 5 flagged this without a list of
  lines; do a read-through of `index.html`, `docs/index.html`, `dashboard/` and `install.md`.

## Architecture and infrastructure (flagged in round 5)

This repository is public, so infrastructure gaps are tracked here only in outline; the details live with the owner.

- [ ] **Separate preview and production data** (stores and deployment access). Infra, outside the repo.
- [ ] **Retire old deployments** that predate the round-5 removals. Infra, outside the repo.
- [ ] **Clear orphaned keys** left in the store by the old site (the owner runs these deletes by hand).
- [ ] **Old blobs in GitHub's pull-request refs** (removed files, the old author email). A force-push can't remove them;
  needs GitHub support or a fresh repository before treating history as clean.
