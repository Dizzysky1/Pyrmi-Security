'use strict';
// Request/response helpers shared by the /api/v1 functions.

const MAX_BODY = 256 * 1024;

function send(res, status, obj, headers) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  for (const [k, v] of Object.entries(headers || {})) res.setHeader(k, v);
  res.end(body);
}

function fail(res, status, code, message, headers) {
  send(res, status, { ok: false, error: code, message: message || code }, headers);
}

// Vercel pre-parses JSON bodies, but sendBeacon posts text/plain, and the local dev server parses nothing,
// so read the raw stream when needed and enforce a size cap either way.
async function readJson(req, max) {
  max = max || MAX_BODY;
  let raw;
  try { raw = req.body; } catch (_) { throw httpError(400, 'bad_json'); } // Vercel's body getter throws on bad JSON
  if (raw && typeof raw === 'object' && !Buffer.isBuffer(raw)) {
    if (JSON.stringify(raw).length > max) throw httpError(413, 'body_too_large');
    return raw;
  }
  if (raw === undefined || raw === null) {
    const chunks = []; let size = 0;
    for await (const ch of req) { size += ch.length; if (size > max) throw httpError(413, 'body_too_large'); chunks.push(ch); }
    raw = Buffer.concat(chunks).toString('utf8');
  } else if (Buffer.isBuffer(raw)) raw = raw.toString('utf8');
  if (raw.length > max) throw httpError(413, 'body_too_large');
  if (!raw.trim()) return {};
  try { const v = JSON.parse(raw); return v && typeof v === 'object' ? v : {}; } catch (_) { throw httpError(400, 'bad_json'); }
}

function httpError(status, code, message) { const e = new Error(message || code); e.status = status; e.code = code; return e; }

// The caller's address, which rate limits, quotas and the session's network binding are keyed on.
//   - On Vercel (VERCEL_ENV is set) the platform writes X-Forwarded-For and x-vercel-forwarded-for itself, overwriting
//     whatever the client sent, so the first entry is the client.
//   - Behind your own proxies (nginx, a load balancer), set PYRMI_PROXY_HOPS to how many there are: the address is taken
//     that many entries from the right, where your own proxy wrote it.
//   - Anywhere else, X-Forwarded-For and X-Real-IP are ignored and the socket address is used, since the client can
//     type them. PYRMI_PROXY_HOPS=0 means the same: no proxy, socket address only.
function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '').split(',').map((s) => s.trim()).filter(Boolean);
  const raw = process.env.PYRMI_PROXY_HOPS;
  const hops = parseInt(raw, 10);
  let pick = '';
  // Fewer entries than hops means the request skipped your proxies, so every entry is the caller's own: use the socket.
  if (raw !== undefined && raw !== '' && Number.isFinite(hops) && hops >= 0) pick = hops > 0 && xff.length >= hops ? xff[xff.length - hops] : '';
  else if (process.env.VERCEL_ENV) pick = String(req.headers['x-vercel-forwarded-for'] || '').split(',')[0].trim() || xff[0];
  return pick || (req.socket && req.socket.remoteAddress) || '0.0.0.0';
}

function bearer(req) {
  const h = String(req.headers.authorization || '');
  return h.toLowerCase().startsWith('bearer ') ? h.slice(7).trim() : '';
}

// Browsers send Origin on every POST and Sec-Fetch-Site on every request; server-side HTTP clients
// (Node's fetch included) send neither. Note Node's fetch does send Sec-Fetch-Mode, so that one proves nothing.
function fromBrowser(req) { return !!(req.headers.origin || req.headers['sec-fetch-site']); }

// CORS for the public (browser) endpoints. allowed = list of origins, empty = any origin.
function cors(req, res, allowed) {
  const origin = String(req.headers.origin || '');
  res.setHeader('Vary', 'Origin');
  if (!origin) return true;
  // "null" is what sandboxed iframes, data: and file: pages send. Echoing it would let any such page read the answer,
  // whoever made it, so it's never echoed.
  if (origin === 'null') return !allowed || !allowed.length;
  const ok = !allowed || !allowed.length || allowed.includes(origin);
  if (ok) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '600');
  }
  return ok;
}

// Wraps a handler: catches errors and maps them to JSON without leaking internals.
function handle(fn) {
  return async (req, res) => {
    try { await fn(req, res); } catch (e) {
      if (e && e.status) {
        // Tell a rate-limited caller when to come back, so well-behaved clients back off instead of hammering (F-23).
        const h = e.status === 429 ? { 'Retry-After': String(e.retryAfter && e.retryAfter > 0 ? Math.ceil(e.retryAfter) : 60) } : undefined;
        if (e.reasons) return send(res, e.status, { ok: false, error: e.code, message: e.message, reasons: e.reasons }, h);
        return fail(res, e.status, e.code || 'error', e.message, h);
      }
      if (e && String(e.message).startsWith('kv_not_configured')) return fail(res, 503, 'storage_not_configured', 'Pyrmi storage is not set up on this server yet.');
      console.error('[pyrmi]', e);
      fail(res, 500, 'server_error', 'Something went wrong on our side.');
    }
  };
}

module.exports = { send, fail, readJson, httpError, clientIp, bearer, fromBrowser, cors, handle };
