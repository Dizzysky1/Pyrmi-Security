# Drafts and open questions for Luke

Nothing here is posted anywhere. Luke reviews and posts himself.

## Decisions needed from Luke

- **Screenshots:** copy `site/img/my-mods.png` and `site/img/compatibility.png` from the DeltaStack repo into
  `deltastack/img/` in this repo. The page swaps its mock-ups for them automatically.
- **Leaderboard database:** pick one (Upstash Redis via the Vercel Marketplace is the simplest; Neon Postgres or
  Supabase if you also want customers/keys in it) and add it to the Vercel project. Until then scores stay in the browser.
- **Selling:** the DeltaStack repo already has its own Stripe shop (lifetime $1, day pass $0.50). When you're ready,
  the page's "coming soon" can turn into a button pointing at that shop. Say where the shop lives.
- **Contest prize:** the page says "a free lifetime key." Confirm that's the prize, and how winners get it.

- **Custom 404 page (held back):** a styled 404 would be nice, but Vercel would then serve it for unknown `/api/...`
  paths too, so your `api/198fa…py` endpoint's fake "NOT_FOUND" reply would stop matching the rest of the site's
  404s and stand out. Say if you want it anyway.

## Launch post ideas (not posted)

- "Most DELTARUNE mods only work one at a time. I made a tool that stacks them. Preview + a boss fight you can play
  while you wait: pyrmi.com/deltastack"
- Short clip idea: screen-record The Vessel getting to stage 4, end card "longest survivor wins a lifetime key."
