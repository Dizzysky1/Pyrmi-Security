'use strict';
// GET /api/v1/google           -> redirects to Google's sign-in page
// GET /api/v1/google?code=...  -> Google sends people back here; signs them in and opens their dashboard
// Needs GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET, and this address registered as a redirect URI in Google Cloud.
const accounts = require('../_lib/accounts');
const core = require('../_lib/core');
const { fail, clientIp, handle } = require('../_lib/http');

function redirect(res, location, cookies) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (cookies) res.setHeader('Set-Cookie', cookies);
  res.end();
}

module.exports = handle(async (req, res) => {
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed');
  await core.limitIp(clientIp(req), 'google', 600, 'PYRMI_SIGNINS_PER_IP', 30);
  const q = new URL(req.url, 'http://x').searchParams;
  if (!q.has('code') && !q.has('error')) {
    const s = await accounts.googleStart(req);
    return redirect(res, s.location, [s.setCookie]);
  }
  try {
    const r = await accounts.googleCallback(req, q, module.exports.exchange);
    redirect(res, '/dashboard/', r.setCookies);
  } catch (e) {
    if (!e.status) throw e;
    redirect(res, '/dashboard/?signin=' + encodeURIComponent(e.code || 'failed'), [accounts.STATE_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0']);
  }
});
module.exports.exchange = null; // tests swap in a fake Google token endpoint
