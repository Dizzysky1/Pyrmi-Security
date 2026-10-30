# PYRMI build log

One line per change, newest at the bottom.

- 2026-10-13: Added /deltastack/ coming-soon page (preview mock, features, playable Vessel, lifetime-key contest marked not live); homepage store card links to it.
- 2026-10-13: /deltastack/ — added a 3-step "how it works" strip and a 5-question FAQ (trial, lifetime key, game files, restore vanilla, platforms), based on the DeltaStack README.
- 2026-10-13: Added original WebAudio synth SFX (start, stage-up, death) to The Vessel on both pages via shared /sfx.js, with a remembered mute toggle in the HUD.
- 2026-10-13: Added PULSE, an original timing minigame on /deltastack/ (closing ring vs gold target, 3 hearts, perfect = 2 pts, speeds up, pentatonic synth notes, best kept locally); sfx.js gained note().
- 2026-10-13: Added "share best" button to The Vessel HUD on both pages (shared /share.js): phone share sheet on touch devices, otherwise copies a brag with your best time and the page link.
- 2026-10-13: SEO pass — original pixel-heart favicon (svg/ico/apple-touch), robots.txt (allows all, skips /api/), sitemap.xml (home + /deltastack/), 1200x630 share images, and full OG/Twitter/canonical tags on both pages.
- 2026-10-13: A11y/perf pass — homepage Vessel controls now only listen when the arena is focused (arrow keys/Space scroll the page again; Tab no longer starts a run), canvas is focusable + labelled, games on both pages pause while scrolled offscreen, starfield respects reduced motion, "play now" button contrast 3.5→5.1. Roadmap a–f done; later runs = polish.
- 2026-10-13: Homepage honesty/copy pass — board no longer claims scores are verified server-side or shows the dev note "hook up a score backend"; hero/meta say the weekly contest is coming soon; board shows your local best live; nav links to /deltastack/.
- 2026-10-13: Vessel touch controls switched to relative drag on both pages (slide anywhere; soul follows the motion, capped at 1.6x keyboard speed, pointer captured so drags can leave the canvas) — finger no longer covers the soul.
- 2026-10-13: Vessel (both pages): fading gold "STAGE N" banner on stage-up so progress is visible with sound muted. Noted the held-back custom-404 idea in DRAFTS.md.
- 2026-10-13: Vessel start/retry prompts (both pages) now match how input works: "click or tap" until the arena has focus, "press any key or click" once it does.
- 2026-10-30: Homepage is now Pyrmi Security (anti-cheat for web games): Node API in api/v1 on the existing Upstash store, browser script /sdk/pyrmi.js, pyrmi-server package, /dashboard/, /docs/, /install.md for agents; The Vessel made deterministic and server-replayed as the live demo with a real weekly board. MIT LICENSE. /deltastack/ and /pyrmiexploittestlol untouched.
- 2026-10-30: pyrmi.com is now only Pyrmi Security, and the product is pitched for any site, not just games. Took off The Vessel, /deltastack/, /rr/ and the /pyrmiexploittestlol challenge (all still in git history); the homepage demo is now a plain sandbox (sandbox.js + /api/v1/demo). verify takes an optional value and a user alias.
