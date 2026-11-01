'use strict';
// GET /api/v1/dashboard   Bearer sk_...   -> stats, recent verdicts, flagged players
// GET /api/v1/dashboard?demo=1            -> the same for the public sandbox demo (read only)
// GET /api/v1/dashboard?demo=site         -> pyrmi.com's own protection: who tried to get past it (read only)
const core = require('../_lib/core');
const { send, fail, bearer, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
  const ip = clientIp(req);
  const demo = new URL(req.url, 'http://x').searchParams.get('demo');
  // The public demo views and the keyed dashboard count in separate buckets. The keyed dashboard checks the key first
  // and counts per site, as /project does.
  let project;
  if (demo) {
    await core.limitIp(ip, 'dashdemo', 60, 'PYRMI_DEMO_DASHBOARD_PER_MIN', 60);
    project = await core.loadProject(demo === 'site' ? core.SITE.pid : core.DEMO.pid);
  } else {
    const sk = bearer(req);
    if (!core.SK_RE.test(sk)) { await core.limitIp(ip, 'keyless', 60, 'PYRMI_KEYLESS_PER_MIN', 120); return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.'); }
    project = await core.projectForKey(sk, ip);
    if (project) await core.limitIp(ip, 'dash:' + project.pid, 60, 'PYRMI_DASHBOARD_PER_MIN', 60);
  }
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  send(res, 200, await core.dashboard(project));
});
