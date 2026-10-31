'use strict';
// Build/CI guardrail: fail if any Python file is committed under api/.
//
// Pyrmi's API is Node-only (api/v1/*.js, api/_lib/*.js). Two leftover Python files once reached production deployment
// trees here before anyone caught them: a copied third-party Discord image-logger (api/hi.py) and a hidden "knock"
// endpoint. Neither belonged in a Node project, and this check would have failed the build on both. There is no
// legitimate api/**/*.py, so any match is a hard stop.
//
// Usage: `node scripts/check-no-python.js` — exits non-zero (and lists the offenders) if any api/**/*.py exists.

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const apiDir = path.join(repoRoot, 'api');
const offenders = [];

(function walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.py$/i.test(e.name)) offenders.push(path.relative(repoRoot, p));
  }
})(apiDir);

if (offenders.length) {
  console.error('Build refused: Python files are not allowed under api/. Pyrmi runs Node-only functions.');
  for (const f of offenders) console.error('  ' + f);
  console.error('If a .py file is genuinely needed, move it out of api/ and document why.');
  process.exit(1);
}
console.log('check-no-python: ok (no api/**/*.py)');
