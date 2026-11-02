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
  // The right key always works. Wrong ones have a generous cap (customer servers often share outbound addresses);
  // only well-formed keys count, since only those are looked up.
  const sk = bearer(req);
  const project = await core.projectBySecretKey(sk);
  if (!project) {
    if (core.SK_RE.test(sk) && await core.verifyKeyMiss(clientIp(req))) return fail(res, 429, 'rate_limited', 'Too many wrong secret keys. Try again in a minute.', { 'Retry-After': '60' });
    return fail(res, 401, 'bad_secret_key', 'Missing or wrong secret key.');
  }
  const body = await readJson(req, 16384);
  send(res, 200, await core.verify(project, body, { ip: clientIp(req) }));
});
