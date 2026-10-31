'use strict';
// Makes API tests send what a real page sends. The browser script posts its page clock (`pt`) with /session and the
// full set of telemetry fields with each beacon, and the browser itself adds Origin and Sec-Fetch-Site to both. The
// server corroborates beacons against those (core.js corroborate()), so a test that leaves them out looks like a
// hand-written client, which is the round-7 finding. Tests about that case send raw requests on purpose.
const SDK = require('../api/_lib/sdk-build.json');
const C = require('../api/_lib/crypto');

const origins = new Map(); // session token -> the Origin it was started from
const sessions = new Map(); // session token -> { bn, n }: the beacon nonce and the script's beacon count

// Wraps a test file's call(method, path, body, headers): /session gets the page clock and remembers its Origin.
function wrap(call) {
  return async (method, p, body, headers) => {
    const isSession = method === 'POST' && p === '/api/v1/session' && body && typeof body === 'object';
    const r = await call(method, p, isSession && !('pt' in body) ? { pt: 0, ...body } : body, headers);
    if (isSession && r.body && r.body.token) { origins.set(r.body.token, (headers && headers.Origin) || ''); sessions.set(r.body.token, { bn: r.body.bn, n: 0 }); }
    return r;
  };
}

function signals(extra) {
  return { wd: false, hl: false, au: [], tp: [], wr: [], dt: 0, ut: 0, ih: 0, k: 5, p: 3, h: 0, pt: 1000, gt: null, sh: SDK.hash, ac: true, ...(extra || {}) };
}

// bn and n as the script sends them: the session's beacon nonce and a count that goes up with each beacon.
function order(s) {
  const o = sessions.get(s.token) || { bn: s.bn, n: 0 };
  sessions.set(s.token, o);
  o.n++;
  return { bn: o.bn, n: o.n };
}

// A beacon the way the browser script sends it (fetch, text/plain), from the page that started the session.
function beacon(call, s, extra) {
  const origin = origins.get(s.token) || '';
  const h = { 'Content-Type': 'text/plain', ...(origin ? { Origin: origin, 'Sec-Fetch-Site': 'same-site' } : {}) };
  return call('POST', '/api/v1/signal', JSON.stringify({ token: s.token, ...order(s), signals: signals(extra) }), h);
}

// What Pyrmi.seal() does in the page: sign the action with the session's request key (rk, from the /session answer).
// Returns the `request` part of a /verify call: { fields, ts, sig }.
function sign(s, fields, ts) {
  const sid = JSON.parse(Buffer.from(s.token.split('.')[0], 'base64url').toString()).s;
  const at = ts === undefined ? Date.now() : ts;
  return { fields: fields || {}, ts: at, sig: C.requestMac(s.rk, sid, at, C.canon(fields || {})) };
}

module.exports = { wrap, beacon, signals, order, sign, SDK };
