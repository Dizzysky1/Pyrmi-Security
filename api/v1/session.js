'use strict';
// POST /api/v1/session  { site: "pk_..." }  ->  { token, session, seed, expiresAt, issuedAt, bn, rk }
// Called by the browser script (sdk/pyrmi.js) when a run starts. The token proves a real page asked for it.
const core = require('../_lib/core');
const { send, fail, readJson, clientIp, cors, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method === 'OPTIONS') { cors(req, res, null); res.statusCode = 204; return res.end(); }
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST, OPTIONS' });
  const body = await readJson(req, 4096);
  const project = await core.projectByPublicKey(body.site);
  // Wrong keys are capped per network, for load.
  // The answer stays readable so a developer with a typo sees unknown_site rather than a CORS error.
  if (!project) {
    await core.limitIp(clientIp(req), 'sessmiss', 600, 'PYRMI_UNKNOWN_SITE_PER_IP', 120);
    cors(req, res, null); return fail(res, 404, 'unknown_site', 'No project has that public key.');
  }
  if (!cors(req, res, project.settings.origins)) return fail(res, 403, 'origin_not_allowed');
  const out = await core.startSession(project, { ip: clientIp(req), ua: req.headers['user-agent'], ch: String(req.headers['sec-ch-ua'] || ''), origin: String(req.headers.origin || '') }, body);
  send(res, 200, { ok: true, ...out });
});
