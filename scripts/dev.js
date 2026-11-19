'use strict';
// Local dev server: static files + the Node functions in api/v1, the way Vercel serves them.
//   PYRMI_KV=memory node scripts/dev.js        (no database needed; data lives until you stop it)
//   node scripts/dev.js                        (uses KV_REST_API_URL / KV_REST_API_TOKEN from your env)
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const ROOT_REAL = fs.realpathSync(ROOT);
const ROOT_PREFIX = ROOT_REAL.endsWith(path.sep) ? ROOT_REAL : ROOT_REAL + path.sep;
const CASE_INSENSITIVE_FS = process.platform === 'win32' || process.platform === 'darwin';
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT || 3000);
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };

// Public static allowlist matching scripts/build-cf.js (stored lowercase for case-insensitive matching).
const PUBLIC_FILES = new Set([
  'index.html',
  'site.css',
  'site.js',
  'intro.js',
  'motion.js',
  'sandbox.js',
  'apple-touch-icon.png',
  'favicon.ico',
  'favicon.svg',
  'og.png',
  'robots.txt',
  'sitemap.xml',
  'install.md',
  'llms.txt',
  'license',
  'notice',
]);
const PUBLIC_DIRS = new Set([
  '.well-known',
  'bg',
  'blog',
  'dashboard',
  'docs',
  'sdk',
  'vendor',
]);
const EXCLUDED_REL = new Set([
  'docs/hardening-todo.md',
]);

// The dev server stands in for Vercel's edge, which writes the caller's address into X-Forwarded-For. Tests send the
// address they want there, so treat this server as one trusted proxy hop unless told otherwise.
if (process.env.PYRMI_PROXY_HOPS === undefined && !process.env.VERCEL_ENV) process.env.PYRMI_PROXY_HOPS = '1';

function isAllowedRelSegments(segs, allowDirOnly) {
  if (!segs.length) return false;
  for (const s of segs) {
    if (!s || s === '.' || s === '..' || s.includes('\0')) return false;
  }
  const first = segs[0].toLowerCase();
  if (segs.length === 1) {
    return PUBLIC_FILES.has(first) || (allowDirOnly && PUBLIC_DIRS.has(first));
  }
  if (!PUBLIC_DIRS.has(first)) return false;
  for (let i = 1; i < segs.length; i++) {
    if (segs[i].startsWith('.')) return false;
  }
  const relLower = segs.map((s) => s.toLowerCase()).join('/');
  return !EXCLUDED_REL.has(relLower);
}

function notFound(res) {
  res.statusCode = 404;
  return res.end('not found');
}

function serve(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (/^\/api\/v1\/auth\/[a-z]+$/.test(url.pathname)) return require(path.join(ROOT, 'api', 'v1', 'auth', '[provider].js'))(req, res);
  const m = url.pathname.match(/^\/api\/v1\/([a-z]+)$/);
  if (m) {
    const file = path.join(ROOT, 'api', 'v1', m[1] + '.js');
    if (fs.existsSync(file)) return require(file)(req, res);
  }
  let decoded;
  try {
    decoded = decodeURIComponent(url.pathname);
  } catch (_) {
    res.statusCode = 400;
    return res.end('bad request');
  }
  if (decoded.includes('\0')) return notFound(res);
  const trimmed = decoded.replace(/^\/+|\/+$/g, '');
  const segs = trimmed ? trimmed.split(/[/\\]/) : ['index.html'];
  if (!isAllowedRelSegments(segs, true)) return notFound(res);

  let file = path.join(ROOT, ...segs);
  let stat;
  try {
    stat = fs.statSync(file);
  } catch (_) {
    return notFound(res);
  }
  if (stat.isDirectory()) {
    file = path.join(file, 'index.html');
    try {
      stat = fs.statSync(file);
    } catch (_) {
      return notFound(res);
    }
  }
  if (!stat.isFile()) return notFound(res);

  let real;
  try {
    real = fs.realpathSync(file);
  } catch (_) {
    return notFound(res);
  }
  const realCmp = CASE_INSENSITIVE_FS ? real.toLowerCase() : real;
  const prefixCmp = CASE_INSENSITIVE_FS ? ROOT_PREFIX.toLowerCase() : ROOT_PREFIX;
  if (!realCmp.startsWith(prefixCmp)) return notFound(res);
  const realRel = path.relative(ROOT_REAL, real).split(path.sep);
  if (!isAllowedRelSegments(realRel, false)) return notFound(res);

  res.setHeader('Content-Type', TYPES[path.extname(real).toLowerCase()] || 'application/octet-stream');
  const stream = fs.createReadStream(real);
  stream.on('error', () => {
    if (!res.headersSent) notFound(res);
    else res.end();
  });
  stream.pipe(res);
}

if (require.main === module) http.createServer(serve).listen(PORT, HOST, () => console.log('Pyrmi dev server on http://' + HOST + ':' + PORT));
module.exports = { serve };
