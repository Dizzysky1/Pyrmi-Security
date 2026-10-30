/* THE VESSEL: browser player for vessel/engine.js (original game).
   mountVessel(canvas, hooks) runs fixed 60 Hz ticks, records every input for the server-side replay, and draws.
   hooks: getSeed() -> Promise<{seed, ranked}>, onTick(state), onStage(n), onEnd({ticks, replay, seed, forfeit}) */
(function () {
  'use strict';
  var E = window.VesselEngine;
  var COLORS = ['#8a5cff', '#36e0d0', '#ff3b4e'];

  window.mountVessel = function (cv, hooks) {
    hooks = hooks || {};
    var g = cv.getContext('2d'), W = E.W, H = E.H;
    var keys = {}, pointer = null, s = E.create(1), rec = null, seed = 1;
    var phase = 'idle'; // idle | loading | playing | over
    var shake = 0, banner = 0, msg = null, acc = 0;

    cv.addEventListener('keydown', function (e) {
      if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', ' ', 'w', 'a', 's', 'd'].indexOf(e.key) >= 0) { keys[e.key] = true; e.preventDefault(); }
    });
    cv.addEventListener('keyup', function (e) { keys[e.key] = false; });
    cv.addEventListener('blur', function () { for (var k in keys) keys[k] = false; });
    function pt(e) { var r = cv.getBoundingClientRect(); return { x: (e.clientX - r.left) * (W / r.width), y: (e.clientY - r.top) * (H / r.height) }; }
    // relative drag: slide anywhere and the soul follows the motion, so your finger never covers it
    cv.addEventListener('pointerdown', function (e) { var p = pt(e); pointer = { x: p.x, y: p.y, px: 0, py: 0 }; try { cv.setPointerCapture(e.pointerId); } catch (_) {} });
    cv.addEventListener('pointermove', function (e) {
      if (!pointer) return; var p = pt(e);
      pointer.px += p.x - pointer.x; pointer.py += p.y - pointer.y; pointer.x = p.x; pointer.y = p.y;
      var l = Math.hypot(pointer.px, pointer.py); if (l > 60) { pointer.px *= 60 / l; pointer.py *= 60 / l; }
    });
    addEventListener('pointerup', function () { pointer = null; });
    addEventListener('pointercancel', function () { pointer = null; });

    function input() {
      var dx = 0, dy = 0, mx = 0, my = 0, sp = E.SOUL_SPEED;
      if (keys.ArrowLeft || keys.a) dx--; if (keys.ArrowRight || keys.d) dx++;
      if (keys.ArrowUp || keys.w) dy--; if (keys.ArrowDown || keys.s) dy++;
      if (dx || dy) { var d = Math.hypot(dx, dy); mx = dx / d * sp; my = dy / d * sp; }
      if (pointer) { var pl = Math.hypot(pointer.px, pointer.py); if (pl > 0) { var k = Math.min(1, sp * 1.6 / pl); mx = pointer.px * k; my = pointer.py * k; } }
      var q = E.quantize(mx, my);
      if (pointer) { pointer.px -= q[0] / 16; pointer.py -= q[1] / 16; }
      return q;
    }

    function begin() {
      if (phase === 'playing' || phase === 'loading') return;
      phase = 'loading'; msg = null;
      Promise.resolve(hooks.getSeed ? hooks.getSeed() : { seed: (Math.random() * 4294967296) >>> 0 }).then(function (r) {
        seed = r.seed >>> 0; s = E.create(seed); rec = E.recorder(); acc = 0; banner = 0;
        phase = 'playing'; if (window.PyrmiSFX) PyrmiSFX.start();
        if (hooks.onStart) hooks.onStart(r);
      }, function () { phase = 'idle'; });
    }
    function end(forfeit) {
      phase = 'over'; shake = forfeit ? 0 : 14;
      if (!forfeit && window.PyrmiSFX) PyrmiSFX.death();
      if (hooks.onEnd) hooks.onEnd({ ticks: s.tick, replay: rec.data(), seed: seed, forfeit: !!forfeit });
    }
    // a ranked run can't pause: leaving the tab ends it
    document.addEventListener('visibilitychange', function () { if (document.hidden && phase === 'playing') { msg = 'run ended: you left the tab'; end(true); } });

    function tick() {
      var q = input(); rec.push(q[0], q[1]); E.step(s, q[0], q[1]);
      if (s.stageUp) { banner = 1.3; if (window.PyrmiSFX) PyrmiSFX.stage(); if (hooks.onStage) hooks.onStage(s.stage); }
      if (hooks.onTick) hooks.onTick(s);
      if (s.dead) end(false);
    }

    function heart(cx, cy, r) {
      g.beginPath(); g.moveTo(cx, cy + r * 0.9);
      g.bezierCurveTo(cx + r * 1.3, cy - r * 0.4, cx + r * 0.5, cy - r * 1.3, cx, cy - r * 0.4);
      g.bezierCurveTo(cx - r * 0.5, cy - r * 1.3, cx - r * 1.3, cy - r * 0.4, cx, cy + r * 0.9);
      g.closePath(); g.fill();
    }
    function overlay(a, b) {
      g.fillStyle = 'rgba(0,0,0,.55)'; g.fillRect(0, 0, W, H);
      g.textAlign = 'center'; g.fillStyle = '#fff'; g.font = '20px "Press Start 2P",monospace'; g.fillText(a, W / 2, H / 2 - 6);
      g.fillStyle = '#9aa0c4'; g.font = '12px "Press Start 2P",monospace'; g.fillText(b, W / 2, H / 2 + 26);
    }
    function draw() {
      var t = s.tick / 60;
      g.save();
      if (shake > 0) { g.translate((Math.random() - .5) * shake, (Math.random() - .5) * shake); shake *= .85; if (shake < .4) shake = 0; }
      g.clearRect(-20, -20, W + 40, H + 40);
      g.strokeStyle = 'rgba(138,92,255,.08)'; g.lineWidth = 1;
      for (var i = 0; i <= W; i += 32) { g.beginPath(); g.moveTo(i, 0); g.lineTo(i, H); g.stroke(); }
      for (var j = 0; j <= H; j += 32) { g.beginPath(); g.moveTo(0, j); g.lineTo(W, j); g.stroke(); }
      var pr = 18 + Math.sin(t * 4) * 3;
      g.save(); g.translate(s.boss.x, s.boss.y); g.rotate(t * 0.6);
      g.strokeStyle = '#8a5cff'; g.lineWidth = 2; g.beginPath();
      for (var k = 0; k < 6; k++) { var a = k / 6 * 6.28; g.lineTo(Math.cos(a) * pr, Math.sin(a) * pr); }
      g.closePath(); g.stroke();
      g.fillStyle = 'rgba(54,224,208,.9)'; g.beginPath(); g.arc(0, 0, 5, 0, 6.28); g.fill(); g.restore();
      for (var n = 0; n < s.bullets.length; n++) {
        var b = s.bullets[n]; g.fillStyle = COLORS[b.k];
        g.beginPath(); g.arc(b.x, b.y, b.r, 0, 6.28); g.fill();
        g.globalAlpha = .3; g.beginPath(); g.arc(b.x, b.y, b.r + 2, 0, 6.28); g.fill(); g.globalAlpha = 1;
      }
      g.fillStyle = s.dead ? '#555' : '#ff3b4e'; heart(s.soul.x, s.soul.y, s.soul.r);
      g.restore();
      if (banner > 0 && phase === 'playing') {
        g.save(); g.globalAlpha = Math.min(1, banner / 0.4); g.textAlign = 'center'; g.fillStyle = '#ffe14d';
        g.font = '22px "Press Start 2P",monospace'; g.fillText('STAGE ' + s.stage, W / 2, H * 0.42); g.restore();
      }
      var how = document.activeElement === cv ? 'press any key or click' : 'click or tap';
      if (phase === 'idle') overlay('THE VESSEL', how + ' to begin');
      else if (phase === 'loading') overlay('THE VESSEL', 'connecting...');
      else if (phase === 'over') overlay(msg ? 'FORFEIT' : 'SHATTERED', msg || ('survived ' + t.toFixed(1) + 's  ·  ' + (document.activeElement === cv ? 'any key' : 'tap') + ' to retry'));
    }

    cv.addEventListener('pointerdown', function () { cv.focus({ preventScroll: true }); begin(); });
    cv.addEventListener('keydown', function (e) { if (e.key === 'Tab' || e.key === 'Shift' || e.metaKey || e.ctrlKey || e.altKey) return; if (phase !== 'playing') begin(); });
    var onScreen = true;
    if ('IntersectionObserver' in window) new IntersectionObserver(function (es) { onScreen = es[0].isIntersecting; }).observe(cv);

    // fixed 60 Hz simulation, drawn at whatever rate the screen runs (120 Hz screens no longer play faster)
    var last = performance.now();
    (function loop(now) {
      var dt = Math.min((now - last) / 1000, 0.25); last = now;
      if (phase === 'playing') { acc += dt; while (acc >= 1 / 60 && phase === 'playing') { acc -= 1 / 60; tick(); } if (banner > 0) banner -= dt; }
      if (onScreen || phase === 'playing') draw();
      requestAnimationFrame(loop);
    })(last);

    return { begin: begin, state: function () { return s; }, phase: function () { return phase; } };
  };
})();
