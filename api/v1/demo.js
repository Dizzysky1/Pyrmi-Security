'use strict';
// POST /api/v1/demo  { token, value?, visitor? }  -> the verdict Pyrmi gives the pyrmi.com sandbox.
// The sandbox stands in for a site's own server: it checks the action the way your server would with pyrmi-server,
// but against the demo project, so visitors can try to get flagged without keys. Nothing it sends is stored except
// the verdict on the public demo dashboard.
const core = require('../_lib/core');
const C = require('../_lib/crypto');
const kv = require('../_lib/kv');
const { send, fail, readJson, clientIp, handle, httpError } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed');
  const ipf = await C.fingerprint('ip', clientIp(req));
  const [n] = await kv.pipeline([['INCR', 'ps:rl:demo:' + ipf], ['EXPIRE', 'ps:rl:demo:' + ipf, 60]]);
  if (n > 20) throw httpError(429, 'rate_limited', 'Slow down a little.');

  const body = await readJson(req, 8192);
  // Visitors are shown on the public dashboard, so only a random label the page made up is kept, never free text.
  const visitor = /^visitor-[0-9a-f]{4,8}$/.test(String(body.visitor || '')) ? body.visitor : 'visitor';
  const project = await core.loadProject(core.DEMO.pid);
  send(res, 200, await core.verify(project, { token: body.token, score: body.value, player: visitor }));
});
