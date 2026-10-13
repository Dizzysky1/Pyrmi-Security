/* PULSE: an original timing minigame. A ring closes in on the target ring; hit when they line up.
   createPulse(canvas, {onScore(score, best)}) — tap/click the canvas, or Space/Enter while it's focused. */
(function () {
  const SCALE = [262, 294, 330, 392, 440, 523, 587, 659, 784, 880]; // pentatonic steps for hit notes

  function createPulse(cv, opts) {
    opts = opts || {};
    const g = cv.getContext('2d'), W = cv.width, H = cv.height, CX = W / 2, CY = H / 2;
    const TARGET = Math.min(W, H) * 0.22, START = Math.hypot(W, H) * 0.55;
    let best = 0; try { best = parseInt(localStorage.getItem('pyrmi_pulse_best') || '0', 10) || 0; } catch (e) {}
    let state = 'idle', r = START, speed = 0, score = 0, combo = 0, lives = 3, flash = null, parts = [], t = 0;

    const sfx = (fn, ...a) => window.PyrmiSFX && PyrmiSFX[fn] && PyrmiSFX[fn](...a);

    function newRing() { r = START; speed = 150 + Math.min(score, 40) * 9; }
    function start() { state = 'play'; score = 0; combo = 0; lives = 3; parts = []; newRing(); sfx('start'); report(); }
    function report() { opts.onScore && opts.onScore(score, best); }

    function burst(color) {
      for (let i = 0; i < 18; i++) { const a = Math.random() * 6.28, v = 60 + Math.random() * 140;
        parts.push({ x: CX + Math.cos(a) * TARGET, y: CY + Math.sin(a) * TARGET, vx: Math.cos(a) * v, vy: Math.sin(a) * v, life: 0.6, c: color }); }
    }

    function miss(label) {
      lives--; combo = 0; flash = { text: label, c: '#ff2a3d', life: 0.7 };
      if (lives <= 0) { state = 'over'; sfx('death');
        if (score > best) { best = score; try { localStorage.setItem('pyrmi_pulse_best', String(best)); } catch (e) {} }
      } else { sfx('note', 110, 0.18); newRing(); }
      report();
    }

    function press() {
      if (state !== 'play') { start(); return; }
      const d = Math.abs(r - TARGET), tol = Math.max(7, 16 - score * 0.15);
      if (d <= tol) {
        const perfect = d <= tol * 0.4;
        combo++; score += perfect ? 2 : 1;
        flash = { text: perfect ? 'PERFECT' : 'GOOD', c: perfect ? '#ffe14d' : '#3fd8ff', life: 0.6 };
        burst(perfect ? '#ffe14d' : '#3fd8ff');
        sfx('note', SCALE[Math.min(combo - 1, SCALE.length - 1)], 0.16);
        newRing(); report();
      } else miss(r > TARGET ? 'TOO EARLY' : 'TOO LATE');
    }

    function step(dt) {
      t += dt;
      if (state === 'play') { r -= speed * dt; if (r < TARGET - 22) miss('TOO LATE'); }
      for (let i = parts.length - 1; i >= 0; i--) { const p = parts[i]; p.x += p.vx * dt; p.y += p.vy * dt; p.life -= dt; if (p.life <= 0) parts.splice(i, 1); }
      if (flash) { flash.life -= dt; if (flash.life <= 0) flash = null; }
    }

    function heart(x, y, s, fill) { g.fillStyle = fill; g.beginPath(); g.moveTo(x, y + s * 0.9);
      g.bezierCurveTo(x + s * 1.3, y - s * 0.4, x + s * 0.5, y - s * 1.3, x, y - s * 0.4);
      g.bezierCurveTo(x - s * 0.5, y - s * 1.3, x - s * 1.3, y - s * 0.4, x, y + s * 0.9); g.fill(); }

    function draw() {
      g.clearRect(0, 0, W, H);
      g.strokeStyle = 'rgba(155,107,255,.08)'; g.lineWidth = 1;
      for (let i = 0; i <= W; i += 32) { g.beginPath(); g.moveTo(i, 0); g.lineTo(i, H); g.stroke(); }
      for (let j = 0; j <= H; j += 32) { g.beginPath(); g.moveTo(0, j); g.lineTo(W, j); g.stroke(); }

      // target: rotating dashed gold ring with a soul at the center
      g.save(); g.translate(CX, CY); g.rotate(t * 0.5);
      g.setLineDash([10, 8]); g.strokeStyle = '#ffe14d'; g.lineWidth = 4;
      g.beginPath(); g.arc(0, 0, TARGET, 0, 6.28); g.stroke(); g.setLineDash([]); g.restore();
      heart(CX, CY + 2, 10 + Math.sin(t * 6) * 1.2, '#ff2a3d');

      if (state === 'play') {
        const close = Math.max(0, 1 - Math.abs(r - TARGET) / 60);
        g.strokeStyle = `rgba(63,216,255,${0.55 + close * 0.45})`; g.lineWidth = 3 + close * 3;
        g.beginPath(); g.arc(CX, CY, Math.max(r, 1), 0, 6.28); g.stroke();
      }

      for (const p of parts) { g.globalAlpha = Math.max(p.life / 0.6, 0); g.fillStyle = p.c;
        g.save(); g.translate(p.x, p.y); g.rotate(0.785); g.fillRect(-3, -3, 6, 6); g.restore(); }
      g.globalAlpha = 1;

      g.textAlign = 'left'; g.fillStyle = '#f2f3ff'; g.font = '22px "VT323",monospace';
      g.fillText('SCORE ' + score, 14, 26); g.fillStyle = '#a3a8cc'; g.fillText('BEST ' + best, 14, 48);
      for (let i = 0; i < 3; i++) heart(W - 24 - i * 22, 20, 7, i < lives ? '#ff2a3d' : '#333');

      if (flash) { g.textAlign = 'center'; g.globalAlpha = Math.min(flash.life / 0.3, 1); g.fillStyle = flash.c;
        g.font = '30px "VT323",monospace'; g.fillText(flash.text, CX, CY - TARGET - 18); g.globalAlpha = 1; }

      if (state !== 'play') {
        g.fillStyle = 'rgba(0,0,0,.6)'; g.fillRect(0, 0, W, H); g.textAlign = 'center';
        g.fillStyle = '#fff'; g.font = '32px "VT323",monospace';
        g.fillText(state === 'over' ? 'OUT OF HEARTS · ' + score : 'PULSE', CX, CY - 6);
        g.fillStyle = '#a3a8cc'; g.font = '20px "VT323",monospace';
        g.fillText(state === 'over' ? 'tap or press space to go again' : 'tap or press space when the rings line up', CX, CY + 22);
      }
    }

    cv.addEventListener('pointerdown', e => { e.preventDefault(); cv.focus({ preventScroll: true }); press(); });
    cv.addEventListener('keydown', e => { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) press(); } });

    let onScreen = true;
    if ('IntersectionObserver' in window) new IntersectionObserver(es => { onScreen = es[0].isIntersecting; }).observe(cv);
    let last = performance.now();
    (function loop(now) { const dt = Math.min((now - last) / 1000, 0.05); last = now; if (onScreen) { step(dt); draw(); } requestAnimationFrame(loop); })(last);
    report();
  }
  window.createPulse = createPulse;
})();
