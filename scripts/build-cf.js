'use strict';
// Stages Pyrmi's public static assets into .cf-assets/ and translates vercel.json header rules
// into Cloudflare Workers Static Assets _headers format.
// Runs check-no-python.js and build-sdk.js --check first so every deploy enforces repo guardrails.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const OUT = path.join(ROOT, '.cf-assets');

// 1. Run repo guardrails
execFileSync(process.execPath, [path.join(__dirname, 'check-no-python.js')], { stdio: 'inherit' });
execFileSync(process.execPath, [path.join(__dirname, 'build-sdk.js'), '--check'], { stdio: 'inherit' });

// 2. Clean and stage only allowlisted public files/directories
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

const PUBLIC_FILES = [
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
  'LICENSE',
  'NOTICE',
];

const PUBLIC_DIRS = [
  '.well-known',
  'bg',
  'blog',
  'dashboard',
  'docs',
  'sdk',
  'vendor',
];

// Explicit exclusions inside allowlisted directories (matches .vercelignore)
const EXCLUDED_REL = new Set([
  'docs/HARDENING-TODO.md',
]);

for (const file of PUBLIC_FILES) {
  const src = path.join(ROOT, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, path.join(OUT, file));
  }
}

function copyDir(relDir) {
  if (relDir !== '.well-known' && path.basename(relDir).startsWith('.')) return;
  const srcDir = path.join(ROOT, relDir);
  if (!fs.existsSync(srcDir)) return;
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    if (relDir !== '.well-known' && entry.name.startsWith('.')) continue;
    if (entry.name.startsWith('.')) continue;
    const relPath = relDir + '/' + entry.name;
    if (EXCLUDED_REL.has(relPath)) continue;
    if (entry.isSymbolicLink()) continue;
    const srcPath = path.join(ROOT, relPath);
    const dstPath = path.join(OUT, relPath);
    if (entry.isDirectory()) {
      fs.mkdirSync(dstPath, { recursive: true });
      copyDir(relPath);
    } else if (entry.isFile()) {
      fs.mkdirSync(path.dirname(dstPath), { recursive: true });
      fs.copyFileSync(srcPath, dstPath);
    }
  }
}

for (const dir of PUBLIC_DIRS) copyDir(dir);

// Emit a clean minimal edge 404 page (served free at Cloudflare's edge via not_found_handling: "404-page")
const NOT_FOUND_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>404 · Pyrmi Security</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  html, body { margin: 0; min-height: 100vh; background: #0a0a0b; color: #ecebe7; font: 15px/1.6 ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; -webkit-font-smoothing: antialiased; }
  main { max-width: 520px; margin: 0 auto; padding: 20vh 24px 64px; }
  .code { font: 600 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; letter-spacing: .12em; text-transform: uppercase; color: #ff5147; margin: 0 0 12px; }
  h1 { font-size: 24px; font-weight: 600; letter-spacing: -.01em; margin: 0 0 10px; }
  p { color: #b0afa9; margin: 0 0 24px; }
  nav { display: flex; gap: 12px; padding-top: 20px; border-top: 1px solid rgba(255,255,255,.13); font: 500 13px/1 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  a { color: #ecebe7; text-decoration: none; border: 1px solid rgba(255,255,255,.24); border-radius: 3px; padding: 10px 14px; }
  a:hover { background: rgba(255,255,255,.05); border-color: #b0afa9; }
</style>
</head>
<body>
<main>
  <p class="code">404 · Not found</p>
  <h1>Nothing at this path.</h1>
  <p>The page or resource you requested does not exist on pyrmi.com.</p>
  <nav aria-label="Recovery">
    <a href="/">Home</a>
    <a href="/docs/">Documentation</a>
  </nav>
</main>
</body>
</html>
`;
fs.writeFileSync(path.join(OUT, '404.html'), NOT_FOUND_HTML, 'utf8');

// 3. Generate Cloudflare _headers from vercel.json so security/cache headers stay in sync
const vercelConfig = JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8'));
const bySource = new Map();
for (const r of vercelConfig.headers || []) {
  if (bySource.has(r.source)) {
    throw new Error('build-cf: duplicate header source in vercel.json: ' + r.source);
  }
  bySource.set(r.source, r.headers);
}

function takeRule(src) {
  const h = bySource.get(src);
  if (!h) throw new Error('build-cf: expected header rule not found in vercel.json: ' + src);
  bySource.delete(src);
  return h;
}

const globalHeaders = takeRule('/(.*)');
const isolatedHeaders = takeRule('/((?!sdk/|api/|install\\.md$|llms\\.txt$|\\.well-known/).*)');
const homeHeaders = takeRule('/');
const indexHeaders = takeRule('/index.html');
const docsRootHeaders = takeRule('/docs');
const docsSubHeaders = takeRule('/docs/(.*)');
const blogHeaders = takeRule('/blog/(.*)');
const dashHeaders = takeRule('/dashboard(.*)');
const sdkCorsHeaders = takeRule('/sdk/(.*)');
const sdkLatestCache = takeRule('/sdk/pyrmi.js');
const sdkPinnedCache = takeRule('/sdk/(\\d+\\.\\d+\\.\\d+)/pyrmi.js');
const selftestRootHeaders = takeRule('/sdk/selftest');
const selftestHtmlHeaders = takeRule('/sdk/selftest.html');
const vendorCache = takeRule('/vendor/(.*)');
const bgCache = takeRule('/bg/(.*)');

if (bySource.size !== 0) {
  throw new Error('build-cf: unconsumed header rules in vercel.json: ' + [...bySource.keys()].join(', '));
}

const blocks = [];
function addBlock(pattern, lines) {
  blocks.push(pattern + '\n' + lines.map((l) => '  ' + l).join('\n'));
}
const fmt = (arr) => arr.map((h) => `${h.key}: ${h.value}`);
const detach = (arr) => arr.map((h) => `! ${h.key}`);

// Base rule on all static assets: global headers + default same-origin isolation
addBlock('/*', [...fmt(globalHeaders), ...fmt(isolatedHeaders)]);

// Paths excluded from same-origin isolation in vercel.json's negative lookahead
for (const openPath of ['/install.md', '/llms.txt', '/.well-known/*']) {
  addBlock(openPath, detach(isolatedHeaders));
}

// Edge 404 page CSP & framing guard
addBlock('/404.html', [
  "Content-Security-Policy: default-src 'none'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; object-src 'none'; upgrade-insecure-requests",
  'X-Frame-Options: DENY',
  'X-Robots-Tag: noindex',
]);

// Page-specific CSP & X-Frame-Options
addBlock('/', fmt(homeHeaders));
addBlock('/index.html', fmt(indexHeaders));
addBlock('/docs', fmt(docsRootHeaders));
addBlock('/docs/*', fmt(docsSubHeaders));
addBlock('/blog', fmt(blogHeaders));
addBlock('/blog/*', fmt(blogHeaders));
addBlock('/dashboard', fmt(dashHeaders));
addBlock('/dashboard/*', fmt(dashHeaders));

// Only the embeddable browser SDK scripts opt into cross-origin loading; /sdk/selftest* stays same-origin isolated
addBlock('/sdk/pyrmi.js', [...detach(isolatedHeaders), ...fmt(sdkCorsHeaders), '! Cache-Control', ...fmt(sdkLatestCache)]);
addBlock('/sdk/:version/pyrmi.js', [...detach(isolatedHeaders), ...fmt(sdkCorsHeaders), '! Cache-Control', ...fmt(sdkPinnedCache)]);

// /sdk/selftest loads selftest.html?case=... in a same-origin iframe, so SAMEORIGIN + frame-ancestors 'self' is required
addBlock('/sdk/selftest', [...detach(isolatedHeaders), ...fmt(selftestRootHeaders)]);
addBlock('/sdk/selftest.html', [...detach(isolatedHeaders), ...fmt(selftestHtmlHeaders)]);

// Cache-Control overrides (detach default Cache-Control first so Cloudflare replaces rather than comma-joins)
addBlock('/vendor/*', ['! Cache-Control', ...fmt(vendorCache)]);
addBlock('/bg/*', ['! Cache-Control', ...fmt(bgCache)]);

// Prevent workers.dev preview/default URLs from competing with pyrmi.com in search engines
addBlock('https://:subdomain.workers.dev/*', ['X-Robots-Tag: noindex']);
addBlock('https://:worker.:subdomain.workers.dev/*', ['X-Robots-Tag: noindex']);

const headersContent = '# Generated by scripts/build-cf.js from vercel.json — do not edit by hand.\n\n' + blocks.join('\n\n') + '\n';
fs.writeFileSync(path.join(OUT, '_headers'), headersContent, 'utf8');

console.log('build-cf: staged static assets, 404.html, and _headers into .cf-assets/');
