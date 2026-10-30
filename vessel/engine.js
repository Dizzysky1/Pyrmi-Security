/* THE VESSEL: deterministic engine (original game).
   The same file runs in the browser (window.VesselEngine) and on the server (require), so the server can replay a
   run's recorded inputs and check the result. Everything here is integer ticks, a seeded RNG and plain + - * / sqrt,
   which give identical results in every JavaScript engine. Math.sin/cos/atan2 can differ in the last bit between
   browsers, so they're replaced with small polynomial versions below. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.VesselEngine = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';
  var W = 640, H = 420, HZ = 60;
  var SOUL_R = 6, SOUL_SPEED = 3.4;
  var Q = 16;                 // inputs are recorded in 1/16 px per tick
  var MAX_Q = 88;             // fastest legal move per tick (drag cap 1.6x keyboard speed), in Q units
  var MAX_TICKS = HZ * 3600;  // one hour
  var PI = 3.141592653589793, TAU = 6.283185307179586;

  function rng(seed) {
    var a = seed >>> 0;
    return function () {
      a = (a + 0x6D2B79F5) >>> 0;
      var t = a;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  function dsin(x) {
    x = x - TAU * Math.round(x / TAU);
    if (x > PI / 2) x = PI - x; else if (x < -PI / 2) x = -PI - x;
    var x2 = x * x;
    return x * (1 - x2 / 6 * (1 - x2 / 20 * (1 - x2 / 42 * (1 - x2 / 72 * (1 - x2 / 110 * (1 - x2 / 156))))));
  }
  function dcos(x) { return dsin(x + PI / 2); }
  function datan(z) { // |z| <= 1
    var z2 = z * z;
    return z * (0.9998660 + z2 * (-0.3302995 + z2 * (0.1801410 + z2 * (-0.0851330 + z2 * 0.0208351))));
  }
  function datan2(y, x) {
    if (x === 0 && y === 0) return 0;
    var ax = x < 0 ? -x : x, ay = y < 0 ? -y : y, a;
    a = ax >= ay ? datan(ay / ax) : PI / 2 - datan(ax / ay);
    if (x < 0) a = PI - a;
    return y < 0 ? -a : a;
  }

  function create(seed) {
    return {
      seed: seed >>> 0, rnd: rng(seed), tick: 0, stage: 1, dead: false, stageUp: false,
      soul: { x: W / 2, y: H * 0.72, r: SOUL_R },
      boss: { x: W / 2, y: 70, phase: 0, timer: 0 },
      bullets: [],
    };
  }

  // One 1/60 s step. qx, qy = this tick's movement in 1/16 px (integers). Returns false for an illegal input.
  function step(s, qx, qy) {
    if (s.dead) return true;
    if ((qx | 0) !== qx || (qy | 0) !== qy || qx * qx + qy * qy > MAX_Q * MAX_Q) return false;
    s.tick++;
    var t = s.tick / HZ;
    var ns = 1 + Math.floor(s.tick / (12 * HZ));
    s.stageUp = ns > s.stage; s.stage = ns;
    var sp = 1.6 + s.stage * 0.25, soul = s.soul, boss = s.boss, b = s.bullets, R = s.rnd, i, n, a;

    soul.x = Math.max(SOUL_R, Math.min(W - SOUL_R, soul.x + qx / Q));
    soul.y = Math.max(SOUL_R, Math.min(H - SOUL_R, soul.y + qy / Q));
    boss.x = W / 2 + dsin(t * 0.8) * W * 0.28;

    function ring(count, speed, off) {
      for (var k = 0; k < count; k++) { var ang = off + k / count * TAU; b.push({ x: boss.x, y: boss.y, vx: dcos(ang) * speed, vy: dsin(ang) * speed, r: 5, k: 0 }); }
    }
    function rain() { b.push({ x: R() * W, y: -6, vx: (R() - 0.5) * 0.6, vy: 2.4 + R() * 1.2, r: 4, k: 2 }); }

    boss.timer++;
    if (boss.timer > Math.max(33 - s.stage * 2, 13)) {
      boss.timer = 0; boss.phase++;
      var p = boss.phase % 4;
      if (p === 0) ring(8 + s.stage, sp, boss.phase * 0.3);
      else if (p === 1) {
        var a0 = datan2(soul.y - boss.y, soul.x - boss.x), m = 3 + Math.min(s.stage, 5);
        for (i = 0; i < m; i++) { a = a0 + (i - (m - 1) / 2) * 0.28; b.push({ x: boss.x, y: boss.y, vx: dcos(a) * (sp + 0.8), vy: dsin(a) * (sp + 0.8), r: 5, k: 1 }); }
      } else if (p === 2) { n = 2 + Math.min(s.stage, 4); for (i = 0; i < n; i++) rain(); }
      else ring(12 + s.stage * 2, sp * 0.9, R() * 6.28);
    }
    if (s.stage >= 3 && R() < 0.2) rain();

    for (i = b.length - 1; i >= 0; i--) {
      var o = b[i];
      o.x += o.vx; o.y += o.vy;
      if (o.x < -20 || o.x > W + 20 || o.y < -20 || o.y > H + 20) { b.splice(i, 1); continue; }
      var dx = o.x - soul.x, dy = o.y - soul.y, rr = o.r + SOUL_R;
      if (dx * dx + dy * dy < rr * rr) { s.dead = true; break; }
    }
    return true;
  }

  // Turns a float movement (px) into the recorded integer input.
  function quantize(mx, my) {
    var qx = Math.round(mx * Q), qy = Math.round(my * Q), l2 = qx * qx + qy * qy;
    if (l2 > MAX_Q * MAX_Q) { var k = MAX_Q / Math.sqrt(l2); qx = Math.trunc(qx * k); qy = Math.trunc(qy * k); }
    return [qx, qy];
  }

  // Replay = flat run-length list [count, qx, qy, count, qx, qy, ...]. Runs it from the seed until the soul dies,
  // or until `limit` ticks (the server passes the claimed length + 1, so a fake run can't make it simulate for long).
  function simulate(seed, replay, limit) {
    if (!Array.isArray(replay) || replay.length % 3 !== 0 || replay.length > MAX_TICKS * 3) return { ok: false, error: 'bad replay format' };
    var s = create(seed), total = 0, cap = Math.min(MAX_TICKS, limit || MAX_TICKS);
    for (var i = 0; i < replay.length && !s.dead; i += 3) {
      var c = replay[i], qx = replay[i + 1], qy = replay[i + 2];
      if ((c | 0) !== c || c < 1) return { ok: false, error: 'bad replay entry' };
      total += c;
      if (total > MAX_TICKS) return { ok: false, error: 'replay too long' };
      for (var j = 0; j < c && !s.dead; j++) {
        if (s.tick >= cap) return { ok: true, dead: false, ticks: s.tick };
        if (!step(s, qx, qy)) return { ok: false, error: 'illegal move at tick ' + (s.tick + 1) };
      }
    }
    return { ok: true, dead: s.dead, ticks: s.tick };
  }

  // Records inputs as they happen, already run-length encoded.
  function recorder() {
    var out = [], last = null;
    return {
      push: function (qx, qy) {
        if (last && last[1] === qx && last[2] === qy) { out[out.length - 3]++; return; }
        out.push(1, qx, qy); last = [1, qx, qy];
      },
      data: function () { return out.slice(); },
    };
  }

  return { W: W, H: H, HZ: HZ, SOUL_SPEED: SOUL_SPEED, MAX_TICKS: MAX_TICKS, create: create, step: step, quantize: quantize, simulate: simulate, recorder: recorder, rng: rng };
});
