'use strict';
// Tiny Redis client for the Upstash REST API (what Vercel's "Upstash for Redis" integration sets up).
// No dependencies. Set PYRMI_KV=memory to use an in-process store instead (local dev and tests only:
// on Vercel every function instance would get its own empty store).

const PAIRS = [
  ['KV_REST_API_URL', 'KV_REST_API_TOKEN'],
  ['UPSTASH_REDIS_REST_URL', 'UPSTASH_REDIS_REST_TOKEN'],
  ['STORAGE_REST_API_URL', 'STORAGE_REST_API_TOKEN'],
];

function creds() {
  for (const [u, t] of PAIRS) {
    if (process.env[u] && process.env[t]) return { url: process.env[u].replace(/\/+$/, ''), token: process.env[t] };
  }
  return null;
}

function useMemory() { return process.env.PYRMI_KV === 'memory'; }

// Every key is namespaced by Vercel environment, so a preview that does reach the same Redis never mixes with
// pyrmi.com's keys. A prefix is not a permission, though: give previews their own store (pyrmi.com runs them on
// PYRMI_KV=memory). Every command used in this project takes its key as the first argument.
function prefix() {
  if (process.env.PYRMI_KV_PREFIX !== undefined) return process.env.PYRMI_KV_PREFIX;
  const env = process.env.PYRMI_ENV || process.env.VERCEL_ENV;
  return env === 'production' ? 'live:' : env ? env + ':' : '';
}
function ready() { return useMemory() || !!creds(); }

const INTERNAL_EVAL = Symbol('kv.eval');

const SCRIPT_HIT = [
  "local n = redis.call('INCR', KEYS[1])",
  "if n == 1 or redis.call('TTL', KEYS[1]) == -1 then",
  "  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))",
  'end',
  'return n',
].join('\n');

const SCRIPT_UNLOCK = [
  "if redis.call('GET', KEYS[1]) == ARGV[1] then",
  "  return redis.call('DEL', KEYS[1])",
  'end',
  'return 0',
].join('\n');

const SCRIPT_RECORD_SIGNALS = [
  'local k = KEYS[1]',
  "if not redis.call('HGET', k, 'p') then return 'expired' end",
  'local maxB = tonumber(ARGV[2])',
  "local b = tonumber(redis.call('HGET', k, 'b') or '0') or 0",
  "if b >= maxB then return 'capped' end",
  "local curN = tonumber(redis.call('HGET', k, 'n') or '0') or 0",
  'local nStr = ARGV[1]',
  "if nStr ~= '' then",
  '  local n = tonumber(nStr)',
  "  if not n or n < 1 or n <= curN then return 'stale' end",
  "  if n > curN + maxB then return 'out_of_order' end",
  'elseif curN > 0 then',
  "  return 'wrong_session'",
  'end',
  'local cur = cjson.decode(ARGV[3])',
  "local prevRaw = redis.call('HGET', k, 'sig')",
  'local prev = {}',
  "if prevRaw and prevRaw ~= '' then",
  '  local ok, decoded = pcall(cjson.decode, prevRaw)',
  "  if ok and type(decoded) == 'table' then prev = decoded end",
  'end',
  'local counters = cjson.decode(ARGV[6])',
  "local sv = tonumber(redis.call('HGET', k, 'sv') or '0') or 0",
  "local prevLcRaw = redis.call('HGET', k, 'lc')",
  'local counterRegressed = false',
  "if sv ~= 0 and prevLcRaw and prevLcRaw ~= '' then",
  '  local ok, prevLc = pcall(cjson.decode, prevLcRaw)',
  "  if ok and type(prevLc) == 'table' then",
  "    for _, cf in ipairs({'k', 'p', 'ut', 'ih', 'h', 'dt'}) do",
  '      local nv = tonumber(counters[cf])',
  '      local ov = tonumber(prevLc[cf]) or 0',
  '      if nv and nv < ov then counterRegressed = true; break end',
  '    end',
  '  end',
  'end',
  'local function uniq(a, b2)',
  '  local out, seen = {}, {}',
  "  if type(a) == 'table' then",
  '    for _, v in ipairs(a) do',
  '      if not seen[v] and #out < 10 then seen[v] = true; out[#out + 1] = v end',
  '    end',
  '  end',
  "  if type(b2) == 'table' then",
  '    for _, v in ipairs(b2) do',
  '      if not seen[v] and #out < 10 then seen[v] = true; out[#out + 1] = v end',
  '    end',
  '  end',
  '  return out',
  'end',
  'local uv = uniq(prev.uv, cur.uv)',
  "if counterRegressed then uv = uniq(uv, {'counters'}) end",
  'local merged = {',
  '  wd = (prev.wd == true) or (cur.wd == true),',
  '  hl = (prev.hl == true) or (cur.hl == true),',
  '  au = uniq(prev.au, cur.au),',
  '  tp = uniq(prev.tp, cur.tp),',
  '  wr = uniq(prev.wr, cur.wr),',
  '  dt = math.max(tonumber(prev.dt) or 0, tonumber(cur.dt) or 0),',
  '  ut = math.max(tonumber(prev.ut) or 0, tonumber(cur.ut) or 0),',
  '  ih = math.max(tonumber(prev.ih) or 0, tonumber(cur.ih) or 0),',
  '  k = math.max(tonumber(prev.k) or 0, tonumber(cur.k) or 0),',
  '  p = math.max(tonumber(prev.p) or 0, tonumber(cur.p) or 0),',
  '  h = math.max(tonumber(prev.h) or 0, tonumber(cur.h) or 0),',
  '  uac = (prev.uac == true) or (cur.uac == true),',
  '  ipc = (prev.ipc == true) or (cur.ipc == true),',
  '  uv = uv,',
  '  ac = (prev.ac == true) or (cur.ac == true),',
  '}',
  'local function encArr(a)',
  "  if #a == 0 then return '[]' end",
  '  return cjson.encode(a)',
  'end',
  'local function encNum(v)',
  '  local x = tonumber(v) or 0',
  '  if x ~= x or x < 0 then x = 0 elseif x > 1e6 then x = 1e6 end',
  "  return string.format('%.0f', math.floor(x))",
  'end',
  "local encoded = '{'",
  "  .. '\"wd\":' .. (merged.wd and 'true' or 'false')",
  "  .. ',\"hl\":' .. (merged.hl and 'true' or 'false')",
  "  .. ',\"au\":' .. encArr(merged.au)",
  "  .. ',\"tp\":' .. encArr(merged.tp)",
  "  .. ',\"wr\":' .. encArr(merged.wr)",
  "  .. ',\"dt\":' .. encNum(merged.dt)",
  "  .. ',\"ut\":' .. encNum(merged.ut)",
  "  .. ',\"ih\":' .. encNum(merged.ih)",
  "  .. ',\"k\":' .. encNum(merged.k)",
  "  .. ',\"p\":' .. encNum(merged.p)",
  "  .. ',\"h\":' .. encNum(merged.h)",
  "  .. ',\"uac\":' .. (merged.uac and 'true' or 'false')",
  "  .. ',\"ipc\":' .. (merged.ipc and 'true' or 'false')",
  "  .. ',\"uv\":' .. encArr(merged.uv)",
  "  .. ',\"ac\":' .. (merged.ac and 'true' or 'false')",
  "  .. '}'",
  "if nStr ~= '' then",
  "  redis.call('HSET', k, 'sig', encoded, 'l', ARGV[4], 'lc', ARGV[6], 'n', nStr)",
  'else',
  "  redis.call('HSET', k, 'sig', encoded, 'l', ARGV[4], 'lc', ARGV[6])",
  'end',
  "redis.call('HSETNX', k, 'f', ARGV[4])",
  "if ARGV[5] == '1' then redis.call('HSETNX', k, 'g', ARGV[4]) end",
  "redis.call('HINCRBY', k, 'b', 1)",
  "return 'ok'",
].join('\n');

const ALLOWED_EVAL = new Set([SCRIPT_HIT, SCRIPT_UNLOCK, SCRIPT_RECORD_SIGNALS]);

function evalCmd(script, keys, args) {
  const c = ['EVAL', script, keys.length, ...keys, ...args];
  c[INTERNAL_EVAL] = true;
  return c;
}
function hitCmd(key, ttl) { return evalCmd(SCRIPT_HIT, [key], [ttl]); }
async function hit(key, ttl) { return Number((await pipeline([hitCmd(key, ttl)]))[0]); }
function unlockCmd(key, token) { return evalCmd(SCRIPT_UNLOCK, [key], [token]); }
async function unlock(key, token) { return Number((await pipeline([unlockCmd(key, token)]))[0]); }
function recordSignalsCmd(key, nStr, maxBeacons, sigJson, markJson, hasGt, countersJson) {
  return evalCmd(SCRIPT_RECORD_SIGNALS, [key], [nStr, maxBeacons, sigJson, markJson, hasGt, countersJson]);
}

async function pipeline(cmds) {
  if (!cmds.length) return [];
  const pre = prefix();
  // Commands whose arguments are ALL keys (not key + values) must have every key prefixed, not just the first, or a
  // multi-key DEL in production (prefix "live:") would delete only its first key and silently no-op the rest (F-13).
  // ALL_KEYS lists commands whose every argument is a key; prefix() gives each of them the prefix. A command with a
  // different key layout (RENAME, COPY, MSET, EVAL, ...) isn't here and is refused below, so a new one can't skip
  // the prefix by accident. Internal allowlisted EVAL helpers carry INTERNAL_EVAL and have their numkeys keys prefixed.
  const ALL_KEYS = new Set(['DEL', 'UNLINK', 'EXISTS', 'MGET', 'TOUCH', 'WATCH']);
  const OTHER_LAYOUT = /^(RENAME|RENAMENX|COPY|MSET|MSETNX|EVAL|EVALSHA|FCALL|SMOVE|LMOVE|BLMOVE|RPOPLPUSH|SINTERSTORE|SUNIONSTORE|SDIFFSTORE|ZUNIONSTORE|ZINTERSTORE|ZDIFFSTORE|ZRANGESTORE|BITOP|PFMERGE|GEORADIUS|SORT|OBJECT|MIGRATE)$/;
  for (const c of cmds) {
    const op = String(c[0]).toUpperCase();
    if (op === 'EVAL' && c[INTERNAL_EVAL] === true && ALLOWED_EVAL.has(c[1])) continue;
    if (OTHER_LAYOUT.test(op)) throw new Error('kv: ' + c[0] + ' needs its own key prefixing (see ALL_KEYS)');
  }
  if (pre) cmds = cmds.map((c) => {
    if (c.length <= 1) return c;
    const op = String(c[0]).toUpperCase();
    if (op === 'EVAL' && c[INTERNAL_EVAL] === true) {
      const nk = Number(c[2]) || 0;
      return [c[0], c[1], c[2], ...c.slice(3, 3 + nk).map((k) => pre + k), ...c.slice(3 + nk)];
    }
    if (ALL_KEYS.has(op)) return [c[0], ...c.slice(1).map((k) => pre + k)];
    return [c[0], pre + c[1], ...c.slice(2)];
  });
  if (useMemory()) return cmds.map((c) => mem.run(c.map(String)));
  const c = creds();
  if (!c) throw new Error('kv_not_configured');
  const resp = await fetch(c.url + '/pipeline', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + c.token, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmds.map((x) => x.map(String))),
    signal: AbortSignal.timeout(8000),
  });
  if (!resp.ok) throw new Error('kv_http_' + resp.status);
  const out = await resp.json();
  return out.map((r) => {
    if (r.error) throw new Error('kv_error: ' + r.error);
    return r.result;
  });
}

async function cmd(...args) { return (await pipeline([args]))[0]; }

// Redis replies HGETALL as a flat [k, v, k, v] array; this turns it into an object.
function pairs(arr) {
  // Null prototype: a field named "__proto__" (a player label, say) is kept as a field instead of vanishing (round 12).
  const o = Object.create(null);
  if (!Array.isArray(arr)) return o;
  for (let i = 0; i + 1 < arr.length; i += 2) o[arr[i]] = arr[i + 1];
  return o;
}

// ---- in-memory store: just enough Redis for this project -------------------------------------------------------
const mem = {
  data: new Map(), exp: new Map(),
  alive(k) {
    const e = this.exp.get(k);
    if (e && e <= Date.now()) { this.data.delete(k); this.exp.delete(k); }
    return this.data.has(k);
  },
  get(k) { return this.alive(k) ? this.data.get(k) : undefined; },
  ensure(k, make) { let v = this.get(k); if (v === undefined) { v = make(); this.data.set(k, v); } return v; },
  zsorted(z) { return [...z.entries()].sort((a, b) => a[1] - b[1] || (a[0] < b[0] ? -1 : 1)); },
  range(len, rawStart, rawEnd) {
    let s = Number(rawStart), e = Number(rawEnd);
    if (s < 0) s = len + s;
    if (e < 0) e = len + e;
    if (s < 0) s = 0;
    if (e >= len) e = len - 1;
    if (s > e || s >= len || e < 0) return null;
    return [s, e];
  },
  run(c) {
    if (this.exp.size > 5000) {
      const now = Date.now();
      for (const [ek, until] of this.exp) if (until <= now) { this.data.delete(ek); this.exp.delete(ek); }
    }
    const op = c[0].toUpperCase(), k = c[1];
    switch (op) {
      case 'EVAL': {
        const script = c[1], nk = Number(c[2]);
        if (!Number.isInteger(nk) || nk < 0 || c.length < 3 + nk) throw new Error('memory kv: bad EVAL');
        const keys = c.slice(3, 3 + nk), argv = c.slice(3 + nk);
        if (script === SCRIPT_HIT && nk === 1) {
          const hk = keys[0];
          const n = Number(this.get(hk) || 0) + 1;
          this.data.set(hk, String(n));
          const e = this.exp.get(hk);
          if (n === 1 || !e) this.exp.set(hk, Date.now() + Number(argv[0]) * 1000);
          return n;
        }
        if (script === SCRIPT_UNLOCK && nk === 1) {
          const uk = keys[0];
          if (this.get(uk) === argv[0]) { this.data.delete(uk); this.exp.delete(uk); return 1; }
          return 0;
        }
        if (script === SCRIPT_RECORD_SIGNALS && nk === 1) {
          const sk = keys[0];
          const h = this.get(sk);
          if (!h || !h.has('p')) return 'expired';
          const maxB = Number(argv[1]);
          const b = Number(h.get('b') || 0) || 0;
          if (b >= maxB) return 'capped';
          const curN = Number(h.get('n') || 0) || 0;
          const nStr = argv[0];
          if (nStr !== '') {
            const n = Number(nStr);
            if (!Number.isFinite(n) || n < 1 || n <= curN) return 'stale';
            if (n > curN + maxB) return 'out_of_order';
          } else if (curN > 0) {
            return 'wrong_session';
          }
          const cur = JSON.parse(argv[2]);
          let prev = {};
          const prevRaw = h.get('sig');
          if (prevRaw) { try { const d = JSON.parse(prevRaw); if (d && typeof d === 'object') prev = d; } catch (_) {} }
          const counters = JSON.parse(argv[5]);
          const sv = Number(h.get('sv') || 0) || 0;
          let counterRegressed = false;
          const prevLcRaw = h.get('lc');
          if (sv !== 0 && prevLcRaw) {
            try {
              const prevLc = JSON.parse(prevLcRaw);
              if (prevLc && typeof prevLc === 'object') {
                for (const cf of ['k', 'p', 'ut', 'ih', 'h', 'dt']) {
                  const nv = Number(counters[cf]), ov = Number(prevLc[cf]) || 0;
                  if (Number.isFinite(nv) && nv < ov) { counterRegressed = true; break; }
                }
              }
            } catch (_) {}
          }
          const uniq = (a, b2) => [...new Set([...(Array.isArray(a) ? a : []), ...(Array.isArray(b2) ? b2 : [])])].slice(0, 10);
          let uv = uniq(prev.uv, cur.uv);
          if (counterRegressed) uv = uniq(uv, ['counters']);
          const merged = {
            wd: !!(prev.wd || cur.wd), hl: !!(prev.hl || cur.hl),
            au: uniq(prev.au, cur.au), tp: uniq(prev.tp, cur.tp), wr: uniq(prev.wr, cur.wr),
            dt: Math.max(Number(prev.dt) || 0, Number(cur.dt) || 0),
            ut: Math.max(Number(prev.ut) || 0, Number(cur.ut) || 0),
            ih: Math.max(Number(prev.ih) || 0, Number(cur.ih) || 0),
            k: Math.max(Number(prev.k) || 0, Number(cur.k) || 0),
            p: Math.max(Number(prev.p) || 0, Number(cur.p) || 0),
            h: Math.max(Number(prev.h) || 0, Number(cur.h) || 0),
            uac: !!(prev.uac || cur.uac), ipc: !!(prev.ipc || cur.ipc),
            uv, ac: !!(prev.ac || cur.ac),
          };
          h.set('sig', JSON.stringify(merged));
          h.set('l', argv[3]);
          h.set('lc', argv[5]);
          if (nStr !== '') h.set('n', nStr);
          if (!h.has('f')) h.set('f', argv[3]);
          if (argv[4] === '1' && !h.has('g')) h.set('g', argv[3]);
          h.set('b', String(b + 1));
          return 'ok';
        }
        throw new Error('memory kv: unsupported EVAL');
      }
      case 'GET': { const v = this.get(k); return v === undefined ? null : v; }
      case 'SET': {
        const flags = c.slice(3).map((s) => s.toUpperCase());
        if (flags.includes('NX') && this.alive(k)) return null;
        this.data.set(k, c[2]); this.exp.delete(k);
        const ex = flags.indexOf('EX'); if (ex >= 0) this.exp.set(k, Date.now() + Number(c[3 + ex + 1]) * 1000);
        return 'OK';
      }
      case 'DEL': { let n = 0; for (const x of c.slice(1)) { if (this.alive(x)) { this.data.delete(x); this.exp.delete(x); n++; } } return n; }
      case 'EXISTS': return this.alive(k) ? 1 : 0;
      case 'INCR': case 'INCRBY': { const n = Number(this.get(k) || 0) + (op === 'INCR' ? 1 : Number(c[2])); this.data.set(k, String(n)); return n; }
      case 'DECR': case 'DECRBY': { const n = Number(this.get(k) || 0) - (op === 'DECR' ? 1 : Number(c[2])); this.data.set(k, String(n)); return n; }
      case 'EXPIRE': if (!this.alive(k)) return 0; this.exp.set(k, Date.now() + Number(c[2]) * 1000); return 1;
      case 'TTL': { if (!this.alive(k)) return -2; const e = this.exp.get(k); return e ? Math.ceil((e - Date.now()) / 1000) : -1; }
      case 'HSET': { const h = this.ensure(k, () => new Map()); let n = 0; for (let i = 2; i + 1 < c.length; i += 2) { if (!h.has(c[i])) n++; h.set(c[i], c[i + 1]); } return n; }
      case 'HSETNX': { const h = this.ensure(k, () => new Map()); if (h.has(c[2])) return 0; h.set(c[2], c[3]); return 1; }
      case 'HDEL': { const h = this.get(k); let n = 0; if (h) for (const f of c.slice(2)) if (h.delete(f)) n++; return n; }
      case 'HGET': { const h = this.get(k); return h && h.has(c[2]) ? h.get(c[2]) : null; }
      case 'HMGET': { const h = this.get(k); return c.slice(2).map((f) => (h && h.has(f) ? h.get(f) : null)); }
      case 'HGETALL': { const h = this.get(k); return h ? [...h.entries()].flat() : []; }
      case 'HINCRBY': { const h = this.ensure(k, () => new Map()); const n = Number(h.get(c[2]) || 0) + Number(c[3]); h.set(c[2], String(n)); return n; }
      case 'LPUSH': { const l = this.ensure(k, () => []); for (const v of c.slice(2)) l.unshift(v); return l.length; }
      case 'LTRIM': { const l = this.get(k); if (!l) return 'OK'; const r = this.range(l.length, c[2], c[3]); this.data.set(k, r ? l.slice(r[0], r[1] + 1) : []); return 'OK'; }
      case 'LRANGE': { const l = this.get(k) || []; const r = this.range(l.length, c[2], c[3]); return r ? l.slice(r[0], r[1] + 1) : []; }
      case 'ZADD': {
        const z = this.ensure(k, () => new Map()); let i = 2; const fl = [];
        while (['GT', 'LT', 'NX', 'XX'].includes(String(c[i]).toUpperCase())) fl.push(String(c[i++]).toUpperCase());
        let n = 0;
        for (; i + 1 < c.length; i += 2) {
          const sc = Number(c[i]), m = c[i + 1], had = z.has(m), old = z.get(m);
          if (fl.includes('NX') && had) continue;
          if (fl.includes('GT') && had && !(sc > old)) continue;
          if (fl.includes('LT') && had && !(sc < old)) continue;
          z.set(m, sc); if (!had) n++;
        }
        return n;
      }
      case 'ZINCRBY': { const z = this.ensure(k, () => new Map()); const n = (z.get(c[3]) || 0) + Number(c[2]); z.set(c[3], n); return String(n); }
      case 'ZREM': { const z = this.get(k); let n = 0; if (z) for (const m of c.slice(2)) if (z.delete(m)) n++; return n; }
      case 'ZSCORE': { const z = this.get(k); return z && z.has(c[2]) ? String(z.get(c[2])) : null; }
      case 'ZCARD': { const z = this.get(k); return z ? z.size : 0; }
      case 'ZREVRANK': { const z = this.get(k); if (!z || !z.has(c[2])) return null; return this.zsorted(z).reverse().findIndex((e) => e[0] === c[2]); }
      case 'ZREVRANGE': {
        const z = this.get(k); if (!z) return [];
        const all = this.zsorted(z).reverse(); const r = this.range(all.length, c[2], c[3]);
        const part = r ? all.slice(r[0], r[1] + 1) : [];
        return String(c[4] || '').toUpperCase() === 'WITHSCORES' ? part.flatMap(([m, sc]) => [m, String(sc)]) : part.map((x) => x[0]);
      }
      case 'ZRANGE': {
        const z = this.get(k); if (!z) return [];
        const all = this.zsorted(z); const r = this.range(all.length, c[2], c[3]);
        const part = r ? all.slice(r[0], r[1] + 1) : [];
        return String(c[4] || '').toUpperCase() === 'WITHSCORES' ? part.flatMap(([m, sc]) => [m, String(sc)]) : part.map((x) => x[0]);
      }
      case 'ZREMRANGEBYRANK': {
        const z = this.get(k); if (!z) return 0; const all = this.zsorted(z); const r = this.range(all.length, c[2], c[3]);
        if (!r) return 0;
        let n = 0; for (const [m] of all.slice(r[0], r[1] + 1)) { z.delete(m); n++; } return n;
      }
      case 'SADD': { const st = this.ensure(k, () => new Set()); let n = 0; for (const v of c.slice(2)) if (!st.has(v)) { st.add(v); n++; } return n; }
      case 'SCARD': { const st = this.get(k); return st ? st.size : 0; }
      default: throw new Error('memory kv: unsupported ' + op);
    }
  },
};

module.exports = { ready, pipeline, cmd, pairs, hitCmd, hit, unlockCmd, unlock, recordSignalsCmd, _mem: mem };
