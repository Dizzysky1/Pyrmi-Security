'use strict';
// GET /api/v1/dashboard   Bearer sk_...   -> stats, recent verdicts, flagged players
// GET /api/v1/dashboard?demo=1            -> the same for the public sandbox demo (read only)
const core = require('../_lib/core');
const { send, fail, bearer, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed');
  const url = new URL(req.url, 'http://x');
  const project = url.searchParams.get('demo') ? await core.loadProject(core.DEMO.pid) : await core.projectBySecretKey(bearer(req));
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  send(res, 200, await core.dashboard(project));
});
