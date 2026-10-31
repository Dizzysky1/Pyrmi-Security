'use strict';
// GET  /api/v1/me                 -> { user, sites } when signed in; 401 { providers } when not (which ways to sign in are switched on)
// POST /api/v1/me?action=signout  -> ends the signed-in session (needs the X-Pyrmi-CSRF header)
const accounts = require('../_lib/accounts');
const core = require('../_lib/core');
const { send, fail, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  // Only spend the per-network limiter on a request that will actually touch KV: one carrying a well-formed session
  // cookie. A missing or malformed cookie makes sessionSid null and currentUser returns without a lookup, and a
  // signed-out /me just reads env (providers()), so it costs nothing. Running the limiter unconditionally let an
  // anonymous flood from a shared or spoofed network burn this bucket and lock that network's signed-in users out of
  // the dashboard's "am I signed in?" check — the same lockout sites.js already avoids for its pre-auth bucket (F-11/F-20).
  if (accounts.sessionSid(req)) await core.limitIp(clientIp(req), 'me', 60, 'PYRMI_ACCOUNT_CALLS_PER_MIN', 60);
  const action = new URL(req.url, 'http://x').searchParams.get('action');
  if (req.method === 'POST' && action === 'signout') {
    accounts.checkCsrf(req);
    return send(res, 200, { ok: true }, { 'Set-Cookie': await accounts.signOut(req) });
  }
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed');
  const user = await accounts.currentUser(req);
  if (!user) return send(res, 401, { ok: false, error: 'signed_out', providers: accounts.providers() });
  send(res, 200, { ok: true, user: { email: user.email, name: user.name }, sites: await accounts.listSites(user.uid) });
});
