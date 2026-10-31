# pyrmi-server

Check a browser session for bots and tampering on your server before you trust what it sent. Part of
[Pyrmi Security](https://pyrmi.com) (MIT).

```bash
npm install pyrmi-server
```

```js
const { Pyrmi } = require('pyrmi-server');
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });

app.post('/signup', async (req, res) => {
  const { pyrmiToken, email } = req.body;
  const v = await pyrmi.verify({ token: pyrmiToken, user: email });
  if (v.verdict === 'reject') return res.status(403).json({ error: 'blocked', reasons: v.reasons });
  await db.createUser(email, { flagged: v.verdict === 'review' });
  res.json({ ok: true });
});

// A sensitive action: only an accept whose telemetry the server corroborated.
const { trusted } = require('pyrmi-server');
app.post('/claim-prize', async (req, res) => {
  const v = await pyrmi.verify({ token: req.body.pyrmiToken, user: req.user.id, score: req.body.score });
  if (!trusted(v)) return res.status(403).json({ error: 'not_verified' });
  await payPrize(req.user.id);
  res.json({ ok: true });
});
```

`verify` returns a verdict (`accept`, `review` or `reject`), a risk score from 0 to 100, `client`
(`corroborated`, `unverified` or `none`: whether the browser telemetry held up against what the server saw), and the
reasons. `trusted(v)` is true only for an `accept` with a `corroborated` client, a real key press or click seen by the
browser, and no reason other than `wrapped_runtime`, `devtools_open`, `ip_changed` or `idle_input`; the server sets
it as `v.trusted`, so it doesn't loosen when the site's thresholds are raised (an older server falls back to the same
allow-list here). Browser telemetry is advisory, so a
script that copies the real one closely enough can still pass; keep your own limits too. The
browser half is one script tag; see the [docs](https://pyrmi.com/docs/).

If the request carries a number worth capping (points, a quantity, a score), pass it as `score` and set limits on
the dashboard. If your app is deterministic (a seed plus recorded inputs always gives the same result), pass
`replay` and a `simulate(replay)` function, and Pyrmi rejects any result the inputs don't reproduce.

Options: `secretKey` (or `PYRMI_SECRET_KEY`), `endpoint` (for self-hosting), `timeoutMs`, `failOpen`.
