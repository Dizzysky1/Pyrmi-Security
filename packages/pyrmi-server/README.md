# pyrmi-server

Verify a web game's score on your server before you save it. Part of [Pyrmi Security](https://pyrmi.com) (MIT).

```bash
npm install pyrmi-server
```

```js
const { Pyrmi } = require('pyrmi-server');
const pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY });

app.post('/scores', async (req, res) => {
  const { token, score, durationMs, player } = req.body;
  const v = await pyrmi.verify({ token, score, durationMs, player });
  if (v.verdict === 'reject') return res.status(400).json({ error: 'score rejected', reasons: v.reasons });
  await db.saveScore(player, score, { flagged: v.verdict === 'review' });
  res.json({ ok: true });
});
```

`verify` returns a verdict (`accept`, `review` or `reject`), a risk score from 0 to 100, and the reasons. The
browser half is one script tag; see the [install guide](https://pyrmi.com/docs/).

If your game is deterministic (a seed plus recorded inputs always gives the same result), pass `replay` and a
`simulate(replay)` function. Pyrmi then rejects any run whose inputs don't reproduce the claimed score, which stops
edited scores and memory hacks cold.

Options: `secretKey` (or `PYRMI_SECRET_KEY`), `endpoint` (for self-hosting), `timeoutMs`, `failOpen`.
