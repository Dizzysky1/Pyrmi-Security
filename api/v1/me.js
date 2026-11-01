'use strict';
// GET  /api/v1/me                    -> { user, sites, turnstile } when signed in; 401 { providers, turnstile } when not
//                                       (which ways to sign in are on, and the Turnstile site key, or null while it's off)
// POST /api/v1/me?action=signout     -> ends this signed-in session (needs the X-Pyrmi-CSRF header)
// POST /api/v1/me?action=revoke-all  -> ends every session for the account, this one included (needs the X-Pyrmi-CSRF header)
const accounts = require('../_lib/accounts');
const core = require('../_lib/core');
const C = require('../_lib/crypto');
const turnstile = require('../_lib/turnstile');
const { send, fail, clientIp, handle } = require('../_lib/http');

module.exports = handle(async (req, res) => {
  // The lookup runs first: a well-formed cookie that opens nothing counts against the network (a bucket of its own),
  // and a real session counts against its own account.
  const ip = clientIp(req);
  const who = async () => {
    const u = await accounts.currentUser(req);
    if (u) await core.limitIp(ip, 'me:' + C.sha256(u.uid).slice(0, 24), 60, 'PYRMI_ACCOUNT_CALLS_PER_MIN', 60);
    else if (accounts.sessionSid(req)) await core.limitIp(ip, 'mebad', 600, 'PYRMI_BAD_SESSIONS_PER_IP', 120);
    return u;
  };
  const action = new URL(req.url, 'http://x').searchParams.get('action');
  if (req.method === 'POST' && action === 'signout') {
    accounts.checkCsrf(req);
    await who();
    return send(res, 200, { ok: true }, { 'Set-Cookie': await accounts.signOut(req) });
  }
  if (req.method === 'POST' && action === 'revoke-all') {
    accounts.checkCsrf(req);
    const u = await who();
    if (!u) return send(res, 401, { ok: false, error: 'signed_out' });
    const revoked = await accounts.revokeAllSessions(u.uid); // ends every session, this one included (Q4/Q10)
    return send(res, 200, { ok: true, revoked }, { 'Set-Cookie': await accounts.signOut(req) });
  }
  if (req.method !== 'GET') return fail(res, 405, 'method_not_allowed', 'Use GET, or POST with an action.', { Allow: 'GET, POST' });
  const user = await who();
  if (!user) return send(res, 401, { ok: false, error: 'signed_out', providers: accounts.providers(), turnstile: turnstile.siteKey() });
  send(res, 200, { ok: true, user: { email: user.email, name: user.name }, sites: await accounts.listSites(user.uid), turnstile: turnstile.siteKey() });
});
