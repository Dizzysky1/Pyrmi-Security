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
  const env = process.env.VERCEL_ENV;
  return env === 'production' ? 'live:' : env ? env + ':' : '';
}
function ready() { return useMemory() || !!creds(); }

async function pipeline(cmds) {
  if (!cmds.length) return [];
  const pre = prefix();
  // Commands whose arguments are ALL keys (not key + values) must have every key prefixed, not just the first, or a
  // multi-key DEL in production (prefix "live:") would delete only its first key and silently no-op the rest (F-13).
  const ALL_KEYS = new Set(['DEL', 'UNLINK', 'EXISTS', 'MGET', 'TOUCH', 'WATCH']);
  if (pre) cmds = cmds.map((c) => {
    if (c.length <= 1) return c;
    if (ALL_KEYS.has(String(c[0]).toUpperCase())) return [c[0], ...c.slice(1).map((k) => pre + k)];
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
  const o = {};
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
  run(c) {
    const op = c[0].toUpperCase(), k = c[1];
    switch (op) {
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
      case 'HGETALL': { const h = this.get(k); return h ? [...h.entries()].flat() : []; }
      case 'HINCRBY': { const h = this.ensure(k, () => new Map()); const n = Number(h.get(c[2]) || 0) + Number(c[3]); h.set(c[2], String(n)); return n; }
      case 'LPUSH': { const l = this.ensure(k, () => []); for (const v of c.slice(2)) l.unshift(v); return l.length; }
      case 'LTRIM': { const l = this.get(k); if (!l) return 'OK'; const s = Number(c[2]), e = Number(c[3]); const end = e < 0 ? l.length + e : e; this.data.set(k, l.slice(s, end + 1)); return 'OK'; }
      case 'LRANGE': { const l = this.get(k) || []; const s = Number(c[2]), e = Number(c[3]); const end = e < 0 ? l.length + e : e; return l.slice(s, end + 1); }
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
        const s = Number(c[2]), e = Number(c[3]); const all = this.zsorted(z).reverse(); const end = e < 0 ? all.length + e : e;
        const part = all.slice(s, end + 1);
        return String(c[4] || '').toUpperCase() === 'WITHSCORES' ? part.flatMap(([m, sc]) => [m, String(sc)]) : part.map((x) => x[0]);
      }
      case 'ZRANGE': {
        const z = this.get(k); if (!z) return [];
        const s = Number(c[2]), e = Number(c[3]); const all = this.zsorted(z); const end = e < 0 ? all.length + e : e;
        const part = all.slice(s, end + 1);
        return String(c[4] || '').toUpperCase() === 'WITHSCORES' ? part.flatMap(([m, sc]) => [m, String(sc)]) : part.map((x) => x[0]);
      }
      case 'ZREMRANGEBYRANK': {
        const z = this.get(k); if (!z) return 0; const all = this.zsorted(z); const s = Number(c[2]), e = Number(c[3]);
        const end = e < 0 ? all.length + e : e; let n = 0; for (const [m] of all.slice(s, end + 1)) { z.delete(m); n++; } return n;
      }
      case 'SADD': { const st = this.ensure(k, () => new Set()); let n = 0; for (const v of c.slice(2)) if (!st.has(v)) { st.add(v); n++; } return n; }
      case 'SCARD': { const st = this.get(k); return st ? st.size : 0; }
      default: throw new Error('memory kv: unsupported ' + op);
    }
  },
};

module.exports = { ready, pipeline, cmd, pairs, _mem: mem };
