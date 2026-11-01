# pyrmi-server

Check a browser session for bots and tampering on your server before you trust what it sent. Part of
[Pyrmi Security](https://pyrmi.com) (Apache 2.0).

```bash
npm install pyrmi-server
```

```js
const { Pyrmi } = require('pyrmi-server');
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });

// The page sends await Pyrmi.seal({ email }) as JSON. Pass the parsed body as `sealed` and the request as `req`:
// Pyrmi checks nothing changed on the way and that it came from the browser that started the session.
app.post('/signup', async (req, res) => {
  const { email } = req.body;
  const v = await pyrmi.verify({ sealed: req.body, req }); // no signed-in user yet, so no user label

  if (v.verdict === 'reject') return res.status(403).json({ error: 'blocked', reasons: v.reasons });
  await db.createUser(email, { flagged: v.verdict === 'review' });
  res.json({ ok: true });
});

// A sensitive action: only an accept whose telemetry the server corroborated. With requireHumanCheck off (the
// default) trusted means "looks like a real browser", which a script can fake: for real money turn it on (below) and
// keep your own limits too (one prize per account, a daily cap).
const { trusted } = require('pyrmi-server');
app.post('/claim-prize', async (req, res) => {
  const v = await pyrmi.verify({ sealed: req.body, req, user: req.user.id }); // a sealed `score` is checked against your caps
  if (!trusted(v)) return res.status(403).json({ error: 'not_verified' });
  await payPrize(req.user.id);
  res.json({ ok: true });
});
```

`verify` returns a verdict (`accept`, `review` or `reject`), a risk score from 0 to 100, `client`
(`corroborated`, `unverified` or `none`: whether the browser telemetry held up against what the server saw), and the
reasons. `trusted(v)` is true only for an `accept` with a `corroborated` client, a real key press or click seen by the
browser, a sealed action from the same browser and network, a Turnstile pass for the session if the site turned on
`requireHumanCheck` (below), and no reason
other than `wrapped_runtime`, `devtools_open`, `ip_changed` or `idle_input`; the server sets
it as `v.trusted`, so it doesn't loosen when the site's thresholds are raised (an older server falls back to the same
allow-list here). Browser telemetry is advisory, so a
script that copies the real one closely enough can still pass; keep your own limits too. The
browser half is one script tag; see the [docs](https://pyrmi.com/docs/).

`user` (or `player`) is only a label for the dashboard: Pyrmi can't check who anyone is. Set it on your server from
your own signed-in user (`req.user.id`), never from the request body, which the player writes: otherwise a cheater
can file their runs under someone else's name, or a fresh one each time. The dashboard's events and players are a
recent, capped view, not an audit log, so keep `v` (or its verdict, risk and reasons) with your own record of the
action.

If the request carries a number worth capping (points, a quantity, a score), pass it as `score` and set limits on
the dashboard. If your app is deterministic (a seed plus recorded inputs always gives the same result), pass
`replay` and a `simulate(replay, { seed })` function, and Pyrmi rejects any result the inputs don't reproduce. Seed
the run with the `seed` simulate is given (the session's own, from the token), never one from the request body.

A site can turn on `requireHumanCheck` (off by default) so `v.trusted` also needs a Turnstile pass for the session:
render the widget with `cData` set to the session id from `Pyrmi.start()`, seal its token into the body as
`turnstile`, and give `new Pyrmi()` your `turnstileSecret`; pyrmi-server sends both, and Pyrmi confirms the pass with
Cloudflare (this page's host, after the session started, the action you name, once). With the switch on and no pass,
`trusted` is false. See install.md for the page side.

You can also check a Turnstile token yourself, for a form with no Pyrmi session or as a second check:

```js
const t = await pyrmi.verifyTurnstile(req.body['cf-turnstile-response'], { action: 'payout', hostname: 'example.com', remoteip: req.ip });
if (!trusted(v, t)) return res.status(403).json({ error: 'not_verified' });
```

`verifyTurnstile` returns `{ success, errorCodes, hostname, action }` and fails closed: no secret, no token, a token
Cloudflare already saw, a different action or hostname than you pass, or Cloudflare being unreachable all give
`success: false`. `trusted(v, t)` needs both a trusted verdict and a passed check.

Options: `secretKey` (or `PYRMI_SECRET_KEY`), `endpoint` (for self-hosting), `timeoutMs`, `failOpen` (only `true`
turns it on; it covers Pyrmi being unreachable, never an answer it gave), `trustProxyHops` (X-Forwarded-For is
ignored unless set; `1` on Vercel, Netlify or Cloudflare), `turnstileSecret` (or `TURNSTILE_SECRET_KEY`),
`turnstileEndpoint`.

A sealed `score` is checked against the project's caps even when you pass none; a value under another name, pass as
`score:`.
