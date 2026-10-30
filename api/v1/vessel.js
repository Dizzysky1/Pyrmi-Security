'use strict';
// The Vessel's own game server: the live demo of Pyrmi Security protecting a real leaderboard.
// GET  /api/v1/vessel                                   -> this week's board + all-time top
// POST /api/v1/vessel  { token, name, ticks, replay }   -> replays the run, asks Pyrmi for a verdict, saves if allowed
const core = require('../_lib/core');
const C = require('../_lib/crypto');
const kv = require('../_lib/kv');
const Engine = require('../../vessel/engine.js');
const { send, fail, readJson, clientIp, handle, httpError } = require('../_lib/http');

function week(t) {
  const d = new Date(t); d.setUTCHours(0, 0, 0, 0);
  d.setUTCDate(d.getUTCDate() + 3 - ((d.getUTCDay() + 6) % 7)); // Thursday of this ISO week
  const y = d.getUTCFullYear(), w1 = new Date(Date.UTC(y, 0, 4));
  const n = 1 + Math.round(((d - w1) / 864e5 - 3 + ((w1.getUTCDay() + 6) % 7)) / 7);
  return y + '-W' + String(n).padStart(2, '0');
}

function cleanName(s) {
  const v = String(s || '').replace(/[^A-Za-z0-9_ .-]/g, '').trim().slice(0, 16);
  return v.length >= 2 ? v : null;
}

async function boards() {
  const wk = week(Date.now());
  const [a, b] = await kv.pipeline([
    ['ZREVRANGE', 'vessel:board:' + wk, 0, 9, 'WITHSCORES'],
    ['ZREVRANGE', 'vessel:board:all', 0, 9, 'WITHSCORES'],
  ]);
  const rows = (arr) => { const o = []; for (let i = 0; i + 1 < (arr || []).length; i += 2) o.push({ name: arr[i], seconds: Number(arr[i + 1]) }); return o; };
  return { week: wk, board: rows(a), allTime: rows(b) };
}

module.exports = handle(async (req, res) => {
  if (req.method === 'GET') {
    res.setHeader('Cache-Control', 'public, max-age=5');
    return send(res, 200, { ok: true, ...(await boards()) }, { 'Cache-Control': 'public, max-age=5, s-maxage=5' });
  }
  if (req.method !== 'POST') return fail(res, 405, 'method_not_allowed');
  const ipf = await C.fingerprint('ip', clientIp(req));
  const [n] = await kv.pipeline([['INCR', 'vessel:rl:' + ipf], ['EXPIRE', 'vessel:rl:' + ipf, 60]]);
  if (n > 20) throw httpError(429, 'rate_limited', 'Slow down a little.');

  const body = await readJson(req, 2 * 1024 * 1024);
  const name = cleanName(body.name);
  if (!name) return fail(res, 400, 'bad_name', 'Pick a name of 2 to 16 letters or numbers.');
  const ticks = Number(body.ticks);
  if (!Number.isInteger(ticks) || ticks < 1 || ticks > Engine.MAX_TICKS) return fail(res, 400, 'bad_score');

  // Replay the run on the server from the seed baked into the signed session token.
  const t = await C.readToken(body.token);
  let replay = { check: 'mismatch', detail: 'no valid session' };
  if (t && ticks * 1000 / 60 > Date.now() - t.i + 2000) {
    replay = { check: 'mismatch', detail: 'not replayed: the run is longer than its session' };
  } else if (t) {
    const sim = Engine.simulate(t.seed, body.replay, ticks + 1);
    if (!sim.ok) replay = { check: 'mismatch', detail: sim.error };
    else if (!sim.dead) replay = { check: 'mismatch', detail: 'the recorded inputs survive past ' + (sim.ticks / 60).toFixed(1) + 's; the soul never died' };
    else if (sim.ticks !== ticks) replay = { check: 'mismatch', detail: 'inputs die at ' + (sim.ticks / 60).toFixed(2) + 's, claimed ' + (ticks / 60).toFixed(2) + 's' };
    else replay = { check: 'match' };
  }

  const seconds = Math.round(ticks / 60 * 100) / 100;
  const project = await core.loadProject(core.DEMO.pid);
  const v = await core.verify(project, { token: body.token, score: seconds, durationMs: Math.round(ticks * 1000 / 60), player: name, replay });

  let rank = null;
  if (v.verdict !== 'reject') {
    const wk = week(Date.now());
    const out = await kv.pipeline([
      ['ZADD', 'vessel:board:' + wk, 'GT', seconds, name], ['EXPIRE', 'vessel:board:' + wk, 60 * 864e2],
      ['ZADD', 'vessel:board:all', 'GT', seconds, name], ['ZREMRANGEBYRANK', 'vessel:board:all', 0, -501],
      ['ZREVRANK', 'vessel:board:' + wk, name],
    ]);
    rank = out[4] === null ? null : Number(out[4]) + 1;
  }
  send(res, 200, { ...v, seconds, rank, ...(await boards()) });
});
