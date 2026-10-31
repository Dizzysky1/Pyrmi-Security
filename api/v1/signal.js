'use strict';
// POST /api/v1/signal  { token, signals: {...} }  ->  { ok }
// Telemetry beacons from the browser script. Accepts text/plain so the beacon needs no CORS preflight.
const core = require('../_lib/core');
const { send, fail, readJson, clientIp, cors, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  cors(req, res, null); // the token is what's checked here, not the origin
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST, OPTIONS' });
  await core.limitIp(clientIp(req), 'sig', 600, 'PYRMI_SIGNALS_PER_IP', 1500);
  const body = await readJson(req, 8192);
  // Origin and Sec-Fetch-Site are set by the browser itself (page code can't change them), so they're compared with
  // the page that started the session. A script outside a browser can still fake them; see core.js corroborate().
  const out = await core.recordSignals(body, { ip: clientIp(req), ua: req.headers['user-agent'], origin: String(req.headers.origin || ''), sfs: String(req.headers['sec-fetch-site'] || '') });
  send(res, 200, out);
});
