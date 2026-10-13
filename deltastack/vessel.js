/* THE VESSEL engine (original). createVessel(canvas, {auto, onTime, onDeath}) runs one fight on a canvas.
   auto:true = attract mode: an autopilot soul dodges forever (used as the blurred page background). */
(function () {
  function createVessel(cv, opts) {
    opts = opts || {};
    const g = cv.getContext('2d');
    let W = cv.width, H = cv.height;
    const auto = !!opts.auto;
    const soul = { x: W / 2, y: H * 0.72, r: 6, speed: 3.4 };
    const boss = { x: W / 2, y: 70, phase: 0, timer: 0 };
    const keys = {};
    let pointer = null, bullets = [], t = 0, stage = 1, dead = false, started = auto, shake = 0, running = true;

    function reset() { bullets = []; t = 0; stage = 1; dead = false; soul.x = W / 2; soul.y = H * 0.72; boss.timer = 0; boss.phase = 0; }

    function ring(n, sp, off) { for (let i = 0; i < n; i++) { const a = off + i / n * Math.PI * 2;
      bullets.push({ x: boss.x, y: boss.y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, r: 5, c: '#8a5cff' }); } }
    function aimed(sp, spread, n) { const a0 = Math.atan2(soul.y - boss.y, soul.x - boss.x);
      for (let i = 0; i < n; i++) { const a = a0 + (i - (n - 1) / 2) * spread;
        bullets.push({ x: boss.x, y: boss.y, vx: Math.cos(a) * sp, vy: Math.sin(a) * sp, r: 5, c: '#36e0d0' }); } }
    function rain() { bullets.push({ x: Math.random() * W, y: -6, vx: (Math.random() - .5) * .6, vy: 2.4 + Math.random() * 1.2, r: 4, c: '#ff3b4e' }); }

    // autopilot: steer away from nearby bullets, drift back toward a home spot
    function autoSteer() {
      let fx = (W / 2 - soul.x) * 0.002, fy = (H * 0.72 - soul.y) * 0.004;
      for (const b of bullets) {
        const dx = soul.x - b.x, dy = soul.y - b.y, d2 = dx * dx + dy * dy;
        if (d2 < 70 * 70 && d2 > 0.01) { const f = 60 / d2; fx += dx * f; fy += dy * f; }
      }
      const d = Math.hypot(fx, fy);
      return d > 0.05 ? [fx / d, fy / d] : [0, 0];
    }

    function step(dt) {
      if (dead || !started) return;
      t += dt; stage = 1 + Math.floor(t / 12);
      const sp = 1.6 + Math.min(stage, auto ? 3 : 99) * 0.25;
      let dx = 0, dy = 0;
      if (auto) { [dx, dy] = autoSteer(); }
      else {
        if (keys.ArrowLeft || keys.a) dx--; if (keys.ArrowRight || keys.d) dx++;
        if (keys.ArrowUp || keys.w) dy--; if (keys.ArrowDown || keys.s) dy++;
        if (pointer) { const mx = pointer.x - soul.x, my = pointer.y - soul.y, d = Math.hypot(mx, my) || 1; if (d > 2) { dx = mx / d; dy = my / d; } }
        else if (dx || dy) { const d = Math.hypot(dx, dy); dx /= d; dy /= d; }
      }
      soul.x = Math.max(soul.r, Math.min(W - soul.r, soul.x + dx * soul.speed));
      soul.y = Math.max(soul.r, Math.min(H - soul.r, soul.y + dy * soul.speed));
      boss.x = W / 2 + Math.sin(t * 0.8) * W * 0.28;
      boss.timer += dt;
      const every = Math.max(0.55 - stage * 0.03, auto ? 0.4 : 0.22);
      if (boss.timer > every) { boss.timer = 0; boss.phase++;
        const p = boss.phase % 4;
        if (p === 0) ring(8 + Math.min(stage, 4), sp, boss.phase * 0.3);
        else if (p === 1) aimed(sp + 0.8, 0.28, 3 + Math.min(stage, 5));
        else if (p === 2) { for (let k = 0; k < 2 + Math.min(stage, 4); k++) rain(); }
        else ring(12 + Math.min(stage, 4) * 2, sp * 0.9, Math.random() * 6.28);
      }
      if (stage >= 3 && Math.random() < (auto ? 0.08 : 0.2)) rain();
      for (let i = bullets.length - 1; i >= 0; i--) { const b = bullets[i];
        b.x += b.vx; b.y += b.vy;
        if (b.x < -20 || b.x > W + 20 || b.y < -20 || b.y > H + 20) { bullets.splice(i, 1); continue; }
        if ((b.x - soul.x) ** 2 + (b.y - soul.y) ** 2 < (b.r + soul.r) ** 2) {
          if (auto) { shake = 8; reset(); break; } // attract mode just restarts
          dead = true; shake = 14; opts.onDeath && opts.onDeath(t); break;
        }
      }
      opts.onTime && opts.onTime(t, stage);
    }

    function heart(cx, cy, r) { g.beginPath(); g.moveTo(cx, cy + r * 0.9);
      g.bezierCurveTo(cx + r * 1.3, cy - r * 0.4, cx + r * 0.5, cy - r * 1.3, cx, cy - r * 0.4);
      g.bezierCurveTo(cx - r * 0.5, cy - r * 1.3, cx - r * 1.3, cy - r * 0.4, cx, cy + r * 0.9); g.closePath(); g.fill(); }
    function overlay(a, b) { g.fillStyle = 'rgba(0,0,0,.55)'; g.fillRect(0, 0, W, H); g.textAlign = 'center';
      g.fillStyle = '#fff'; g.font = '30px "VT323",monospace'; g.fillText(a, W / 2, H / 2 - 4);
      g.fillStyle = '#9aa0c4'; g.font = '20px "VT323",monospace'; g.fillText(b, W / 2, H / 2 + 24); }

    function draw() {
      g.save();
      if (shake > 0) { g.translate((Math.random() - .5) * shake, (Math.random() - .5) * shake); shake *= .85; if (shake < .4) shake = 0; }
      g.clearRect(-20, -20, W + 40, H + 40);
      g.strokeStyle = 'rgba(138,92,255,.08)'; g.lineWidth = 1;
      for (let i = 0; i <= W; i += 32) { g.beginPath(); g.moveTo(i, 0); g.lineTo(i, H); g.stroke(); }
      for (let j = 0; j <= H; j += 32) { g.beginPath(); g.moveTo(0, j); g.lineTo(W, j); g.stroke(); }
      const pr = 18 + Math.sin(t * 4) * 3;
      g.save(); g.translate(boss.x, boss.y); g.rotate(t * 0.6); g.strokeStyle = '#8a5cff'; g.lineWidth = 2;
      g.beginPath(); for (let i = 0; i < 6; i++) { const a = i / 6 * 6.28; g.lineTo(Math.cos(a) * pr, Math.sin(a) * pr); } g.closePath(); g.stroke();
      g.fillStyle = 'rgba(54,224,208,.9)'; g.beginPath(); g.arc(0, 0, 5, 0, 6.28); g.fill(); g.restore();
      for (const b of bullets) { g.fillStyle = b.c; g.beginPath(); g.arc(b.x, b.y, b.r, 0, 6.28); g.fill();
        g.globalAlpha = .3; g.beginPath(); g.arc(b.x, b.y, b.r + 2, 0, 6.28); g.fill(); g.globalAlpha = 1; }
      g.fillStyle = dead ? '#555' : '#ff3b4e'; heart(soul.x, soul.y, soul.r);
      g.restore();
      if (!auto) { if (!started) overlay('THE VESSEL', 'click or press a key to begin');
        else if (dead) overlay('SHATTERED', 'survived ' + t.toFixed(1) + 's  ·  click to retry'); }
    }

    if (!auto) {
      const pt = e => { const r = cv.getBoundingClientRect(); return { x: (e.clientX - r.left) * (W / r.width), y: (e.clientY - r.top) * (H / r.height) }; };
      const begin = () => { if (!started || dead) { reset(); started = true; dead = false; opts.onStart && opts.onStart(); } };
      cv.addEventListener('pointerdown', e => { pointer = pt(e); begin(); });
      cv.addEventListener('pointermove', e => { if (pointer) pointer = pt(e); });
      addEventListener('pointerup', () => { pointer = null; });
      cv.addEventListener('keydown', e => {
        if (['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight', ' ', 'w', 'a', 's', 'd'].includes(e.key)) { keys[e.key] = true; e.preventDefault(); }
        begin();
      });
      cv.addEventListener('keyup', e => { keys[e.key] = false; });
      cv.addEventListener('blur', () => { for (const k in keys) keys[k] = false; });
    }

    let last = performance.now();
    (function loop(now) { if (!running) return; const dt = Math.min((now - last) / 1000, 0.05); last = now; step(dt); draw(); requestAnimationFrame(loop); })(last);
    return { stop() { running = false; } };
  }
  window.createVessel = createVessel;
})();
