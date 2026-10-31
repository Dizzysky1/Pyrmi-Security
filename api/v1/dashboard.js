'use strict';
// GET /api/v1/dashboard   Bearer sk_...   -> stats, recent verdicts, flagged players
// GET /api/v1/dashboard?demo=1            -> the same for the public sandbox demo (read only)
// GET /api/v1/dashboard?demo=site         -> pyrmi.com's own protection: who tried to get past it (read only)
const core = require('../_lib/core');
const { send, fail, bearer, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed');
  const ip = clientIp(req);
  await core.limitIp(ip, 'dash', 60, 'PYRMI_DASHBOARD_PER_MIN', 60);
  const demo = new URL(req.url, 'http://x').searchParams.get('demo');
  const project = demo ? await core.loadProject(demo === 'site' ? core.SITE.pid : core.DEMO.pid) : await core.projectForKey(bearer(req), ip);
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  send(res, 200, await core.dashboard(project));
});
