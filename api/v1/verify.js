'use strict';
// POST /api/v1/verify   Authorization: Bearer sk_...
//   { token, score, durationMs?, player?, replay?: { check: "match"|"mismatch"|"none", detail? } }
//   -> { verdict: "accept"|"review"|"reject", risk: 0-100, reasons: [...] }
// Called by the game's own server (see packages/pyrmi-server) before it saves a score.
const core = require('../_lib/core');
const { send, fail, readJson, bearer, fromBrowser, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed');
  if (fromBrowser(req)) return fail(res, 400, 'secret_key_in_browser', 'Call /verify from your server. A secret key in the browser can be stolen.');
  const project = await core.projectBySecretKey(bearer(req));
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  const body = await readJson(req, 16384);
  send(res, 200, await core.verify(project, body));
});
