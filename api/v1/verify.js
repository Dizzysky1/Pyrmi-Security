'use strict';
// POST /api/v1/verify   Authorization: Bearer sk_...
//   { token, score?, durationMs?, player? (or user), replay?: { check: "match"|"mismatch"|"none", detail? } }
//   -> { verdict: "accept"|"review"|"reject", risk: 0-100, reasons: [...] }
// Called by your own server (see packages/pyrmi-server) before it trusts an action from the browser.
const core = require('../_lib/core');
const { send, fail, readJson, bearer, fromBrowser, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
  if (fromBrowser(req)) return fail(res, 400, 'secret_key_in_browser', 'Call /verify from your server. A secret key in the browser can be stolen.');
  // No per-network cap on wrong keys here: customer servers often share outbound addresses (serverless), and a
  // 180-bit key can't be guessed anyway.
  const project = await core.projectBySecretKey(bearer(req));
  if (!project) return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  const body = await readJson(req, 16384);
  send(res, 200, await core.verify(project, body, { ip: clientIp(req) }));
});
