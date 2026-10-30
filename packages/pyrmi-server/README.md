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
```

`verify` returns a verdict (`accept`, `review` or `reject`), a risk score from 0 to 100, and the reasons. The
browser half is one script tag; see the [docs](https://pyrmi.com/docs/).

If the request carries a number worth capping (points, a quantity, a score), pass it as `score` and set limits on
the dashboard. If your app is deterministic (a seed plus recorded inputs always gives the same result), pass
`replay` and a `simulate(replay)` function, and Pyrmi rejects any result the inputs don't reproduce.

Options: `secretKey` (or `PYRMI_SECRET_KEY`), `endpoint` (for self-hosting), `timeoutMs`, `failOpen`.
