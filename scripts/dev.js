'use strict';
// Local dev server: static files + the Node functions in api/v1, the way Vercel serves them.
//   PYRMI_KV=memory node scripts/dev.js        (no database needed; data lives until you stop it)
//   node scripts/dev.js                        (uses KV_REST_API_URL / KV_REST_API_TOKEN from your env)
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const PORT = Number(process.env.PORT || 3000);
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.json': 'application/json',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.ico': 'image/x-icon', '.md': 'text/markdown; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };

// The dev server stands in for Vercel's edge, which writes the caller's address into X-Forwarded-For. Tests send the
// address they want there, so treat this server as one trusted proxy hop unless told otherwise.
if (process.env.PYRMI_PROXY_HOPS === undefined && !process.env.VERCEL_ENV) process.env.PYRMI_PROXY_HOPS = '1';

function serve(req, res) {
  const url = new URL(req.url, 'http://localhost');
  if (/^\/api\/v1\/auth\/[a-z]+$/.test(url.pathname)) return require(path.join(ROOT, 'api', 'v1', 'auth', '[provider].js'))(req, res);
  const m = url.pathname.match(/^\/api\/v1\/([a-z]+)$/);
  if (m) {
    const file = path.join(ROOT, 'api', 'v1', m[1] + '.js');
    if (fs.existsSync(file)) return require(file)(req, res);
  }
  let p = path.normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, '');
  let file = path.join(ROOT, p);
  if (!file.startsWith(ROOT) || /[/\\](api|tests|scripts|node_modules|\.git)([/\\]|$)/.test(file.slice(ROOT.length))) { res.statusCode = 404; return res.end('not found'); }
  if (fs.existsSync(file) && fs.statSync(file).isDirectory()) file = path.join(file, 'index.html');
  if (!fs.existsSync(file)) { res.statusCode = 404; return res.end('not found'); }
  res.setHeader('Content-Type', TYPES[path.extname(file)] || 'application/octet-stream');
  fs.createReadStream(file).pipe(res);
}

if (require.main === module) http.createServer(serve).listen(PORT, () => console.log('Pyrmi dev server on http://localhost:' + PORT));
module.exports = { serve };
