'use strict';
// POST  /api/v1/project                      { name, origins?, pyrmiToken }  -> new project with keys (secret key shown once)
//       pyrmi.com protects this form with Pyrmi itself: pyrmiToken comes from the dashboard page (core.SITE), and once
//       Turnstile is set up, turnstileToken from its human check. (Calls with a secret key are server to server: no check.)
// GET   /api/v1/project   Bearer sk_...                          -> project info + settings
// PATCH /api/v1/project   Bearer sk_...      { name?, settings }  -> updated project
// POST  /api/v1/project?action=rotate  Bearer sk_...            -> new secret key (old one stops working)
// DELETE /api/v1/project  Bearer sk_...                           -> deletes a key-only project (one not in an account)
const core = require('../_lib/core');
const turnstile = require('../_lib/turnstile');
const { send, fail, readJson, bearer, clientIp, handle, httpError } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  // Same-origin only: the dashboard page is the only browser client. Refuse cross-site browser calls outright.
  const site = req.headers['sec-fetch-site'];
  if (site && site !== 'same-origin' && site !== 'none') return fail(res, 403, 'cross_site');

  const ip = clientIp(req);
  if (req.method === 'POST' && url.searchParams.get('action') !== 'rotate') {
    // A per-minute cap ahead of the human check and the site guard, so junk sign-ups can't run them freely (round 12).
    await core.limitIp(ip, 'projnew', 60, 'PYRMI_PROJECT_CREATES_PER_MIN', 10);
    const body = await readJson(req, 4096);
    await turnstile.check(body.turnstileToken, ip, 'new-project', req.headers.host);
    await core.guardSite(body.pyrmiToken, ip);
    const p = await core.createProject(body, ip);
    return send(res, 201, { ok: true, project: p });
  }
  // The key is checked first and the allowance is per site. A missing or malformed key costs no lookup and counts in
  // its own bucket; a well-formed wrong one counts toward the wrong-key cap (the right key always works, see projectForKey).
  const sk = bearer(req);
  if (!core.SK_RE.test(sk)) { await core.limitIp(ip, 'keyless', 60, 'PYRMI_KEYLESS_PER_MIN', 120); return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.'); }
  const project = await core.projectForKey(sk, ip);
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  await core.limitIp(ip, 'proj:' + project.pid, 60, 'PYRMI_PROJECT_CALLS_PER_MIN', 30);
  if (req.method === 'GET') return send(res, 200, { ok: true, project: core.view(project) });
  if (req.method === 'PATCH') {
    const body = await readJson(req, 8192);
    return send(res, 200, { ok: true, project: core.view(await core.updateSettings(project, { ...(body.settings || {}), ...('name' in body ? { name: body.name } : {}) })) });
  }
  if (req.method === 'POST') return send(res, 200, { ok: true, secretKey: await core.rotateSecret(project, sk) });
  if (req.method === 'DELETE') {
    // A project in an account is deleted from the signed-in dashboard (with its human check), never with the key alone.
    // Runs under the key lock, with the key and owner checked again there.
    const owned = () => httpError(403, 'owned', 'This project belongs to an account. Delete it from the dashboard while signed in.');
    if (project.owner) throw owned();
    await core.withKeyLock(project.pid, async () => {
      const now = await core.projectBySecretKey(sk);
      if (!now || now.pid !== project.pid) throw httpError(401, 'bad_secret_key', 'Missing or wrong secret key.');
      if (now.owner) throw owned();
      await core.deleteProject(now);
    });
    return send(res, 200, { ok: true });
  }
  fail(res, 405, 'method_not_allowed', undefined, { Allow: 'GET, POST, PATCH, DELETE' });
});
