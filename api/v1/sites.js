'use strict';
// The signed-in dashboard. Every call needs the session cookie; every change also needs the X-Pyrmi-CSRF header.
// POST   /api/v1/sites                       { name, origins?, pyrmiToken }  -> new site, secret key shown once
// POST   /api/v1/sites?action=claim          { secretKey }                   -> add a key-only project to this account
// Once Turnstile is set up, creating, claiming, rotating and deleting also need { turnstileToken } (a human check).
// GET    /api/v1/sites?pid=p_...                                            -> that site's dashboard and connection status
// PATCH  /api/v1/sites?pid=p_...             { name?, settings }             -> updated settings
// POST   /api/v1/sites?pid=p_...&action=rotate                              -> new secret key (old one stops working)
// DELETE /api/v1/sites?pid=p_...                                            -> deletes the site and its keys
const accounts = require('../_lib/accounts');
const core = require('../_lib/core');
const turnstile = require('../_lib/turnstile');
const C = require('../_lib/crypto');
const { send, fail, readJson, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  const ip = clientIp(req);
  // Look the session up first. A well-formed cookie that opens nothing counts in a bucket of its own, and a real one
  // counts against its account.
  const user = await accounts.currentUser(req);
  if (!user) {
    if (accounts.sessionSid(req)) await core.limitIp(ip, 'mebad', 600, 'PYRMI_BAD_SESSIONS_PER_IP', 120);
    return fail(res, 401, 'signed_out', 'Sign in to see your sites.');
  }
  await core.limitIp(ip, 'sites:' + C.sha256(user.uid).slice(0, 24), 60, 'PYRMI_ACCOUNT_CALLS_PER_MIN', 60);
  accounts.checkCsrf(req);
  const q = new URL(req.url, 'http://x').searchParams, pid = q.get('pid'), action = q.get('action');

  if (!pid && req.method === 'POST' && action === 'claim') {
    const body = await readJson(req, 4096);
    await turnstile.check(body.turnstileToken, ip, 'claim', req.headers.host);
    return send(res, 200, { ok: true, site: await accounts.claimSite(user.uid, typeof body.secretKey === 'string' ? body.secretKey.trim() : '', { keepKey: body.keepKey === true }) });
  }
  if (!pid && req.method === 'POST') {
    const body = await readJson(req, 4096);
    await turnstile.check(body.turnstileToken, ip, 'new-site', req.headers.host);
    await core.guardSite(body.pyrmiToken, ip);
    return send(res, 201, { ok: true, project: core.view(await accounts.createSite(user.uid, body, ip)) });
  }
  const p = await accounts.ownedSite(user.uid, pid);
  if (req.method === 'GET') return send(res, 200, { ...(await core.dashboard(p)), status: accounts.status(p) });
  if (req.method === 'PATCH') {
    const body = await readJson(req, 8192);
    return send(res, 200, { ok: true, project: core.view(await core.updateSettings(p, { ...(body.settings || {}), ...('name' in body ? { name: body.name } : {}) })) });
  }
  if (req.method === 'POST' && action === 'rotate') {
    if (turnstile.configured()) await turnstile.check((await readJson(req, 4096)).turnstileToken, ip, 'rotate', req.headers.host);
    return send(res, 200, { ok: true, secretKey: await core.rotateSecret(p) });
  }
  if (req.method === 'DELETE') {
    if (turnstile.configured()) await turnstile.check((await readJson(req, 4096)).turnstileToken, ip, 'delete', req.headers.host);
    await accounts.deleteSite(user.uid, p); return send(res, 200, { ok: true });
  }
  fail(res, 405, 'method_not_allowed', undefined, { Allow: 'GET, POST, PATCH, DELETE' });
});
