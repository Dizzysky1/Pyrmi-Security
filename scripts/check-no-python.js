'use strict';
// Build/CI guardrail: enforce strict file allowlists and reject symbolic links under api/ and worker/.
//
// Pyrmi's API is Node-only (api/v1/*.js, api/_lib/*.js, api/_lib/sdk-build.json). Two leftover Python files once
// reached production deployment trees here before anyone caught them: a copied third-party Discord image-logger
// (api/hi.py) and a hidden "knock" endpoint. Neither belonged in a Node project, and symbolic links or unexpected
// file types under api/ or worker/ could expose unintended endpoints or traverse outside the directory.
//
// Usage: `node scripts/check-no-python.js` — exits non-zero (and lists the offenders) on any violation.

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const apiDir = path.join(repoRoot, 'api');
const workerDir = path.join(repoRoot, 'worker');
const offenders = [];

const toPosix = (p) => path.relative(repoRoot, p).split(path.sep).join('/');

function checkRootDir(dir) {
  let st;
  try { st = fs.lstatSync(dir); } catch (_) { return false; }
  if (st.isSymbolicLink()) {
    offenders.push(toPosix(dir) + ' (symbolic link)');
    return false;
  }
  return st.isDirectory();
}

function walkApi(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    const rel = toPosix(p);
    const lstat = fs.lstatSync(p);
    if (e.isSymbolicLink() || lstat.isSymbolicLink()) {
      offenders.push(rel + ' (symbolic link)');
      continue;
    }
    if (lstat.isDirectory()) {
      walkApi(p);
      continue;
    }
    const allowed = lstat.isFile() && (
      e.name.endsWith('.js') ||
      e.name === '.gitkeep' ||
      rel === 'api/_lib/sdk-build.json'
    );
    if (!allowed) offenders.push(rel);
  }
}

function walkWorker(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    const rel = toPosix(p);
    const lstat = fs.lstatSync(p);
    if (e.isSymbolicLink() || lstat.isSymbolicLink()) {
      offenders.push(rel + ' (symbolic link)');
      continue;
    }
    if (lstat.isDirectory()) {
      walkWorker(p);
      continue;
    }
    const allowed = lstat.isFile() && (
      e.name.endsWith('.js') ||
      e.name.endsWith('.mjs') ||
      e.name === '.gitkeep'
    );
    if (!allowed) offenders.push(rel);
  }
}

if (checkRootDir(apiDir)) walkApi(apiDir);
if (checkRootDir(workerDir)) walkWorker(workerDir);

if (offenders.length) {
  console.error('Build refused: disallowed files or symbolic links under api/ or worker/.');
  for (const f of offenders) console.error('  ' + f);
  console.error('Only .js files (plus api/_lib/sdk-build.json and .gitkeep) are allowed under api/, and symbolic links are forbidden under api/ and worker/.');
  process.exit(1);
}
console.log('check-no-python: ok (api/ allowlist and api/, worker/ symlink checks passed)');
