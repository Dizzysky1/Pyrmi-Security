'use strict';
// POST /api/v1/signal  { token, <session field>: <encoded signals> }  ->  { ok }
// Telemetry beacons from the browser script. Accepts text/plain so navigator.sendBeacon works without a preflight.
const core = require('../_lib/core');
const { send, fail, readJson, clientIp, cors, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  cors(req, res, null); // the token is what's checked here, not the origin
  if (req.method === 'OPTIONS') { res.statusCode = 204; return res.end(); }
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed');
  await core.limitIp(clientIp(req), 'sig', 600, 'PYRMI_SIGNALS_PER_IP', 1500);
  const body = await readJson(req, 8192);
  const out = await core.recordSignals(body, { ip: clientIp(req), ua: req.headers['user-agent'] });
  send(res, 200, out);
});
