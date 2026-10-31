'use strict';
// Builds the browser script pyrmi.com serves (sdk/pyrmi.js) from the readable source (src/sdk/pyrmi.js):
//   node scripts/build-sdk.js           write sdk/pyrmi.js and api/_lib/sdk-build.json
//   node scripts/build-sdk.js --check   fail if the committed build is out of date (used by the tests)
//
// No dependencies, so it only understands the plain ES5-style JavaScript the source is written in (semicolons
// everywhere, no template literals, no shorthand properties, no labels). What it does:
//   - mangles every local name to a short look-alike (lIl1I...), seeded from the source so builds are reproducible
//   - moves strings, property names, regexes and browser globals into one XOR-encoded table decoded at start-up
//   - strips comments and whitespace
//   - records a fingerprint of the built function so the server can spot an edited copy (see core.js)
// It makes the script slower to read and to hook, not impossible: the real check is still the server's verdict.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src/sdk/pyrmi.js');
const OUT = path.join(ROOT, 'sdk/pyrmi.js');
const META = path.join(ROOT, 'api/_lib/sdk-build.json');

const KEYWORDS = new Set(('break case catch class const continue debugger default delete do else export extends false finally for function if ' +
  'import in instanceof let new null return super switch this throw true try typeof undefined var void while with yield of arguments').split(' '));
// Browser globals read as plain names. They're rewritten to window[...] lookups so they don't show up as text.
const GLOBALS = new Set(['Date', 'Math', 'JSON', 'String', 'Promise', 'Blob', 'URL', 'EventTarget', 'Function', 'Error', 'setTimeout',
  'setInterval', 'clearTimeout', 'clearInterval', 'isFinite', 'location', 'fetch', 'atob', 'btoa']);
const PUNCT = ['>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '=>', '==', '!=', '<=', '>=', '&&', '||', '??', '?.', '++', '--', '+=',
  '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>', '**'];
const REGEX_AFTER = new Set(['(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '<', '>', '~', '^', '&&', '||',
  '==', '===', '!=', '!==', '=>', 'return', 'typeof', 'case', 'do', 'else', 'in', 'of', 'new', 'delete', 'void', 'throw']);

function fnv(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return ('0000000' + h.toString(16)).slice(-8);
}

function tokenize(src) {
  const out = [];
  let i = 0;
  const last = () => { for (let j = out.length - 1; j >= 0; j--) if (out[j].t !== 'ws' && out[j].t !== 'com') return out[j]; return null; };
  while (i < src.length) {
    const c = src[i], rest = src.slice(i);
    let m;
    if ((m = /^\s+/.exec(rest))) { out.push({ t: 'ws', v: m[0] }); i += m[0].length; continue; }
    if (rest.startsWith('//')) { const e = src.indexOf('\n', i); const v = src.slice(i, e < 0 ? src.length : e); out.push({ t: 'com', v }); i += v.length; continue; }
    if (rest.startsWith('/*')) { const e = src.indexOf('*/', i + 2); const v = src.slice(i, e + 2); out.push({ t: 'com', v }); i += v.length; continue; }
    if (c === '`') throw new Error('build-sdk: template literals are not supported');
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (src[j] !== c) { if (src[j] === '\\') j++; if (src[j] === '\n' || j >= src.length) throw new Error('build-sdk: unterminated string at ' + i); j++; }
      const raw = src.slice(i, j + 1);
      out.push({ t: 'str', v: raw, s: Function('"use strict";return ' + raw)() });
      i = j + 1; continue;
    }
    if ((m = /^(0[xX][\da-fA-F]+|(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?)/.exec(rest)) && !/^\.[^\d]/.test(rest)) { out.push({ t: 'num', v: m[0] }); i += m[0].length; continue; }
    if ((m = /^[A-Za-z_$][\w$]*/.exec(rest))) { out.push({ t: 'id', v: m[0] }); i += m[0].length; continue; }
    if (c === '/') {
      const p = last();
      if (!p || (p.t === 'punc' && REGEX_AFTER.has(p.v)) || (p.t === 'id' && REGEX_AFTER.has(p.v))) {
        let j = i + 1, cls = false;
        while (true) {
          const ch = src[j];
          if (ch === undefined || ch === '\n') throw new Error('build-sdk: unterminated regex at ' + i);
          if (ch === '\\') { j += 2; continue; }
          if (ch === '[') cls = true; else if (ch === ']') cls = false; else if (ch === '/' && !cls) break;
          j++;
        }
        const body = src.slice(i + 1, j);
        const fl = /^[a-z]*/.exec(src.slice(j + 1))[0];
        out.push({ t: 're', v: src.slice(i, j + 1 + fl.length), body, flags: fl });
        i = j + 1 + fl.length; continue;
      }
    }
    const p = PUNCT.find((x) => rest.startsWith(x));
    out.push({ t: 'punc', v: p || c }); i += (p || c).length;
  }
  return out;
}

// Seeded PRNG so the same source always builds to the same file.
function rng(seed) {
  let s = parseInt(seed.slice(0, 8), 16) || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
}

function build(source) {
  // The banner comment stays; everything up to the opening "(function" is the banner.
  const start = source.indexOf('(function pyrmiMain');
  const banner = '/*! Pyrmi Security browser script v' + /version:\s*'([\d.]+)'/.exec(source)[1] + ' - MIT License - https://pyrmi.com - built from src/sdk/pyrmi.js */';
  const fnEnd = source.lastIndexOf('})(window, document);');
  const fnSrc = source.slice(start + 1, fnEnd + 1); // "function pyrmiMain(w, d) { ... }"
  const sourceHash = fnv(fnSrc);
  const all = tokenize(fnSrc).filter((t) => t.t !== 'ws' && t.t !== 'com');
  const rand = rng(crypto.createHash('sha256').update(source).digest('hex'));

  // 1) local names: var lists, function names and parameters, catch parameters
  const declared = new Set();
  for (let i = 0; i < all.length; i++) {
    const t = all[i];
    if (t.t !== 'id') continue;
    if (t.v === 'function') {
      let j = i + 1;
      if (all[j].t === 'id') declared.add(all[j++].v);
      if (all[j].v === '(') { for (j++; all[j].v !== ')'; j++) if (all[j].t === 'id') declared.add(all[j].v); }
    } else if (t.v === 'catch' && all[i + 1].v === '(') declared.add(all[i + 2].v);
    else if (t.v === 'var') {
      let depth = 0, expectName = true;
      for (let j = i + 1; j < all.length; j++) {
        const v = all[j].v;
        if (expectName && all[j].t === 'id') { declared.add(v); expectName = false; continue; }
        if ('([{'.includes(v)) depth++;
        else if (')]}'.includes(v)) { if (depth === 0) break; depth--; }
        else if (depth === 0 && v === ',') expectName = true;
        else if (depth === 0 && v === ';') break;
      }
    }
  }
  for (const k of KEYWORDS) declared.delete(k);

  const used = new Set(all.filter((t) => t.t === 'id').map((t) => t.v));
  const names = new Map(), taken = new Set();
  const fresh = () => {
    for (;;) {
      const len = 3 + Math.floor(rand() * 3);
      let n = rand() < 0.5 ? 'l' : 'I';
      for (let k = 1; k < len; k++) n += 'Il1'[Math.floor(rand() * 3)];
      if (!taken.has(n) && !used.has(n) && !KEYWORDS.has(n)) { taken.add(n); return n; }
    }
  };
  for (const n of declared) names.set(n, fresh());
  const TABLE = fresh(), WIN = names.get('w');
  if (!WIN) throw new Error('build-sdk: expected the main function to take (w, d)');

  // 2) strings table
  const table = [], index = new Map();
  const ref = (s) => { if (!index.has(s)) { index.set(s, table.length); table.push(s); } return TABLE + '[' + index.get(s) + ']'; };

  const out = [];
  for (let i = 0; i < all.length; i++) {
    const t = all[i], prev = all[i - 1], next = all[i + 1];
    const isKey = next && next.v === ':' && prev && (prev.v === '{' || prev.v === ',') && (t.t === 'id' || t.t === 'str');
    if (isKey) { out.push('[' + ref(t.t === 'str' ? t.s : t.v) + ']'); continue; }
    if (t.t === 'str') {
      if (t.s === 'use strict' && prev && prev.v === '{') { out.push("'use strict'"); continue; }
      out.push(ref(t.s)); continue;
    }
    if (t.t === 're') { out.push('(new ' + WIN + '[' + ref('RegExp') + '](' + ref(t.body) + ',' + ref(t.flags) + '))'); continue; }
    if (t.t === 'punc' && (t.v === '.' || t.v === '?.') && next && next.t === 'id') {
      out.push((t.v === '?.' ? '?.' : '') + '[' + ref(next.v) + ']'); i++; continue;
    }
    if (t.t === 'id') {
      const afterDot = prev && (prev.v === '.' || prev.v === '?.');
      if (!afterDot && names.has(t.v)) { out.push(names.get(t.v)); continue; }
      if (!afterDot && GLOBALS.has(t.v) && !declared.has(t.v)) { out.push(WIN + '[' + ref(t.v) + ']'); continue; }
    }
    out.push(t.v);
  }
  // after "use strict";, decode the table: base64, then XOR with a build key
  const key = crypto.createHash('sha256').update('pyrmi-sdk:' + source).digest('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 13);
  for (const s of table) if (/[^\x00-\x7f]/.test(s)) throw new Error('build-sdk: non-ASCII string in source: ' + s);
  const enc = table.map((s) => Buffer.from([...s].map((ch, i) => ch.charCodeAt(0) ^ key.charCodeAt(i % key.length))).toString('base64'));
  const [a, b, c, e, k] = [fresh(), fresh(), fresh(), fresh(), fresh()];
  const decoder = 'var ' + TABLE + '=(function(' + k + ',' + a + '){return ' + a + '.map(function(' + b + '){var ' + c + '=atob(' + b + '),' + e + "='';" +
    'for(var i=0;i<' + c + '.length;i++)' + e + '+=String.fromCharCode(' + c + '.charCodeAt(i)^' + k + '.charCodeAt(i%' + k + '.length));return ' + e + ';});})(' +
    JSON.stringify(key) + ',' + JSON.stringify(enc) + ');';
  const strictAt = out.indexOf("'use strict'");
  out.splice(strictAt + 2, 0, decoder); // after 'use strict' and its ;

  // 3) join with the fewest spaces that keep tokens apart
  let code = '';
  for (const piece of out) {
    const lc = code.slice(-1), fc = piece[0];
    if ((/[\w$]/.test(lc) && /[\w$]/.test(fc)) || (lc === '+' && fc === '+') || (lc === '-' && fc === '-')) code += ' ';
    code += piece;
  }
  return { file: banner + '\n(' + code + ')(window,document);\n', hash: fnv(code), sourceHash };
}

function main() {
  const source = fs.readFileSync(SRC, 'utf8');
  const version = /version:\s*'([\d.]+)'/.exec(source)[1];
  const b = build(source);
  let meta = { version: null, hash: null, sourceHash: null, previous: [] };
  try { meta = JSON.parse(fs.readFileSync(META, 'utf8')); } catch (_) { /* first build */ }
  if (process.argv.includes('--check')) {
    const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
    if (cur !== b.file || meta.hash !== b.hash || meta.sourceHash !== b.sourceHash) { console.error('sdk/pyrmi.js is out of date: run node scripts/build-sdk.js'); process.exit(1); }
    console.log('sdk/pyrmi.js is up to date (' + b.file.length + ' bytes, fingerprint ' + b.hash + ')');
    return;
  }
  // Keep a few earlier fingerprints so pages still holding the last build (CDN and browser caches) aren't flagged.
  const previous = [meta.hash, ...(meta.previous || [])].filter((h) => h && h !== b.hash).slice(0, 5);
  fs.writeFileSync(OUT, b.file);
  fs.writeFileSync(META, JSON.stringify({ version, hash: b.hash, sourceHash: b.sourceHash, previous }, null, 2) + '\n');
  console.log('built sdk/pyrmi.js: ' + b.file.length + ' bytes (source ' + source.length + '), fingerprint ' + b.hash);
}

if (require.main === module) main();
module.exports = { build, fnv, tokenize };
