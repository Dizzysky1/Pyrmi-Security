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
