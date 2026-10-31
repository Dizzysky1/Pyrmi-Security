'use strict';
// POST  /api/v1/project                      { name, origins?, pyrmiToken }  -> new project with keys (secret key shown once)
//       pyrmi.com protects this form with Pyrmi itself: pyrmiToken comes from the dashboard page (core.SITE), and once
//       Turnstile is set up, turnstileToken from its human check. (Calls with a secret key are server to server: no check.)
// GET   /api/v1/project   Bearer sk_...                          -> project info + settings
// PATCH /api/v1/project   Bearer sk_...      { name?, settings }  -> updated project
// POST  /api/v1/project?action=rotate  Bearer sk_...            -> new secret key (old one stops working)
const core = require('../_lib/core');
const turnstile = require('../_lib/turnstile');
const { send, fail, readJson, bearer, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  // Same-origin only: the dashboard page is the only browser client. Refuse cross-site browser calls outright.
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return fail(res, 403, 'cross_site');

  const ip = clientIp(req);
  if (req.method === 'POST' && url.searchParams.get('action') !== 'rotate') {
    const body = await readJson(req, 4096);
    await turnstile.check(body.turnstileToken, ip, 'new-project', req.headers.host);
    await core.guardSite(body.pyrmiToken, ip);
    const p = await core.createProject(body, ip);
    return send(res, 201, { ok: true, project: p });
  }
  await core.limitIp(ip, 'proj', 60, 'PYRMI_PROJECT_CALLS_PER_MIN', 30);
  const sk = bearer(req);
  const project = await core.projectForKey(sk, ip);
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  if (req.method === 'GET') return send(res, 200, { ok: true, project: core.view(project) });
  if (req.method === 'PATCH') {
    const body = await readJson(req, 8192);
    return send(res, 200, { ok: true, project: core.view(await core.updateSettings(project, { ...(body.settings || {}), ...('name' in body ? { name: body.name } : {}) })) });
  }
  if (req.method === 'POST') return send(res, 200, { ok: true, secretKey: await core.rotateSecret(project, sk) });
  fail(res, 405, 'method_not_allowed');
});
