'use strict';
// Signing in.
// GET  /api/v1/auth/github | /api/v1/auth/google  -> off to GitHub or Google
// GET  /api/v1/auth/github?code=... (and google)    -> they send people back here; signs them in, opens the dashboard
// POST /api/v1/auth/email?action=start   {email, pyrmiToken, turnstileToken?}  -> emails a 6-digit code (same answer for any address)
//      turnstileToken is required once Turnstile is set up (TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY).
// POST /api/v1/auth/email?action=verify  {email, code}        -> signs in
// Each way in is off until its env vars are set (see README).
const accounts = require('../../_lib/accounts');
const core = require('../../_lib/core');
const turnstile = require('../../_lib/turnstile');
const { send, fail, readJson, clientIp, handle } = require('../../_lib/http');

function redirect(res, location, cookies) {
  res.statusCode = 302;
  res.setHeader('Location', location);
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Referrer-Policy', 'no-referrer');
  if (cookies) res.setHeader('Set-Cookie', cookies);
  res.end();
}

function providerOf(req, url) {
  const p = (req.query && req.query.provider) || (url.pathname.match(/\/auth\/([a-z]+)\/?$/) || [])[1];
  return ['email', 'github', 'google'].includes(p) ? p : null;
}

module.exports = handle(async (req, res) => {
  const url = new URL(req.url, 'http://x'), q = url.searchParams, ip = clientIp(req);
  const provider = providerOf(req, url);
  if (!provider) return fail(res, 404, 'not_found');

  if (provider === 'email') {
    if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed', 'Use POST.', { Allow: 'POST' });
    if (!accounts.emailConfigured()) return fail(res, 503, 'email_not_configured', 'Email sign-in isn\'t set up on this server yet.');
    accounts.checkCsrf(req);
    const body = await readJson(req, 4096);
    if (q.get('action') === 'start') {
      await core.limitIp(ip, 'emailcode', 600, 'PYRMI_EMAIL_CODES_PER_IP', 10, 'Too many sign-in codes from your network. Try again in a few minutes.');
      await turnstile.check(body.turnstileToken, ip, 'signin', req.headers.host);
      await core.guardSite(body.pyrmiToken, ip);
      await accounts.emailStart(body, ip, module.exports.mailer);
      return send(res, 200, { ok: true });
    }
    if (q.get('action') === 'verify') {
      await core.limitIp(ip, 'emailverify', 600, 'PYRMI_SIGNINS_PER_IP', 30);
      const r = await accounts.emailVerify(body, ip);
      return send(res, 200, { ok: true }, { 'Set-Cookie': r.setCookies });
    }
    return fail(res, 400, 'bad_action');
  }

  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed', 'Use GET.', { Allow: 'GET' });
  await core.limitIp(ip, 'oauth', 600, 'PYRMI_SIGNINS_PER_IP', 30);
  if (!q.has('code') && !q.has('error')) {
    const s = await accounts.oauthStart(req, provider);
    return redirect(res, s.location, [s.setCookie]);
  }
  try {
    const r = await accounts.oauthCallback(req, provider, q, module.exports.hooks);
    redirect(res, '/dashboard/', r.setCookies);
  } catch (e) {
    if (!e.status) throw e;
    redirect(res, '/dashboard/?signin=' + encodeURIComponent(e.code || 'failed'), [accounts.STATE_COOKIE + '=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0']);
  }
});
module.exports.hooks = null;  // tests swap in fake GitHub and Google endpoints
module.exports.mailer = null; // and a fake mailer
