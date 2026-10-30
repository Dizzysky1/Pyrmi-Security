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

function clientIp(req) {
  const xff = String(req.headers['x-forwarded-for'] || '');
  return (xff.split(',')[0] || '').trim() || String(req.headers['x-real-ip'] || '') || (req.socket && req.socket.remoteAddress) || '0.0.0.0';
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
      if (e && e.status) return fail(res, e.status, e.code || 'error', e.message);
      if (e && String(e.message).startsWith('kv_not_configured')) return fail(res, 503, 'storage_not_configured', 'Pyrmi storage is not set up on this server yet.');
      console.error('[pyrmi]', e);
      fail(res, 500, 'server_error', 'Something went wrong on our side.');
    }
  };
}

module.exports = { send, fail, readJson, httpError, clientIp, bearer, fromBrowser, cors, handle };
