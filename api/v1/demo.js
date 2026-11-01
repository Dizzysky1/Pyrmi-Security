'use strict';
// POST /api/v1/demo  { value?, visitor?, turnstile?, pyrmi: { token, ts, sig } }  -> the verdict Pyrmi gives the pyrmi.com sandbox.
// The sandbox stands in for a site's own server: it checks the action the way your server would with pyrmi-server,
// but against the demo project, so visitors can try to get flagged without keys. Nothing it sends is stored except
// the verdict on the public demo dashboard.
const core = require('../_lib/core');
const { send, fail, readJson, clientIp, handle } = require('../_lib/http');
const turnstile = require('../_lib/turnstile');

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
  const ip = clientIp(req);
  // Use the shared limiter so the window actually counts down instead of being reset on every call (F-17),
  // and pass ctx to verify so its limiter is keyed on this caller's network, not one shared 'none' bucket (F-18).
  await core.limitIp(ip, 'demo', 60, 'PYRMI_DEMO_CALLS_PER_MIN', 20, 'Slow down a little.');

  const body = await readJson(req, 8192);
  // Visitors are shown on the public dashboard, so only a random label the page made up is kept, never free text.
  const visitor = typeof body.visitor === 'string' && /^visitor-[0-9a-f]{4,8}$/.test(body.visitor) ? body.visitor : 'visitor';
  const project = await core.loadProject(core.DEMO.pid);
  // The sandbox page seals its action with Pyrmi.seal(), as a site's page should for anything that matters: the body
  // is { value, visitor, pyrmi: { token, ts, sig } }, and the signature covers everything except pyrmi. This endpoint
  // is the site's own server here, so it forwards the browser's context from its own request, as pyrmi-server does.
  const seal = body.pyrmi && typeof body.pyrmi === 'object' ? body.pyrmi : null;
  // A null-prototype copy, so every key in the body stays a field the signature covers.
  const fields = Object.create(null); for (const k of Object.keys(body)) if (k !== 'pyrmi') fields[k] = body[k];
  const client = { ua: String(req.headers['user-agent'] || ''), ip, ch: String(req.headers['sec-ch-ua'] || ''), sfs: String(req.headers['sec-fetch-site'] || '') };
  // The human check (round 12): the sandbox page runs pyrmi.com's own Turnstile widget for each session and sends its
  // token in the sealed body as `turnstile`. This endpoint plays the site's server, so it forwards the token with the
  // site's Turnstile secret key, the way pyrmi-server does with its turnstileSecret. Without the keys (a local copy or
  // a preview) there's no check, and the sandbox's best is a plain accept, as on any site without Turnstile.
  const human = typeof body.turnstile === 'string' && body.turnstile && turnstile.configured()
    ? { token: body.turnstile, secret: process.env.TURNSTILE_SECRET_KEY, action: 'sandbox' } : undefined;
  send(res, 200, await core.verify(project, {
    token: seal ? seal.token : body.token, score: body.value, player: visitor,
    request: seal && seal.sig !== undefined ? { fields, ts: seal.ts, sig: seal.sig } : undefined, client, turnstile: human,
  }, { ip }));
});
