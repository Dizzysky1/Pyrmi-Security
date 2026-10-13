/* PYRMI synth SFX (original, generated live with WebAudio; no audio files).
   PyrmiSFX.start() / .stage() / .death(). Any button with [data-sfx-mute] becomes a mute toggle.
   Mute choice is remembered in this browser only. */
(function () {
  let ctx = null, master = null, muted = false;
  try { muted = localStorage.getItem('pyrmi_mute') === '1'; } catch (e) {}

  function ac() {
    if (!ctx) {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) return null;
      ctx = new AC(); master = ctx.createGain(); master.gain.value = 0.18; master.connect(ctx.destination);
    }
    if (ctx.state === 'suspended') ctx.resume();
    return ctx;
  }

  function tone(freq, start, dur, type, endFreq, vol) {
    const c = ac(); if (!c || muted) return;
    const t0 = c.currentTime + start, o = c.createOscillator(), g = c.createGain();
    o.type = type || 'square';
    o.frequency.setValueAtTime(freq, t0);
    if (endFreq) o.frequency.exponentialRampToValueAtTime(endFreq, t0 + dur);
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(vol || 1, t0 + 0.01);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    o.connect(g); g.connect(master); o.start(t0); o.stop(t0 + dur + 0.02);
  }

  function noise(start, dur, vol) {
    const c = ac(); if (!c || muted) return;
    const len = Math.floor(c.sampleRate * dur), buf = c.createBuffer(1, len, c.sampleRate), d = buf.getChannelData(0);
    for (let i = 0; i < len; i++) d[i] = (Math.random() * 2 - 1) * (1 - i / len);
    const s = c.createBufferSource(), g = c.createGain(), f = c.createBiquadFilter();
    f.type = 'lowpass'; f.frequency.value = 1400; g.gain.value = vol || 0.8;
    s.buffer = buf; s.connect(f); f.connect(g); g.connect(master); s.start(c.currentTime + start);
  }

  const SFX = {
    start() { tone(330, 0, 0.08, 'square'); tone(495, 0.07, 0.12, 'square'); },
    stage() { [523, 659, 784, 1047].forEach((f, i) => tone(f, i * 0.06, 0.1, 'triangle', null, 0.8)); },
    death() { tone(440, 0, 0.55, 'sawtooth', 55, 0.9); noise(0, 0.35, 0.6); tone(110, 0.05, 0.4, 'square', 40, 0.5); },
    get muted() { return muted; },
    setMuted(m) {
      muted = !!m; try { localStorage.setItem('pyrmi_mute', muted ? '1' : '0'); } catch (e) {}
      document.querySelectorAll('[data-sfx-mute]').forEach(paint);
    }
  };

  function paint(b) { b.textContent = muted ? '♪ off' : '♪ on'; b.setAttribute('aria-pressed', String(muted));
    b.setAttribute('aria-label', muted ? 'Sound off. Click to turn sound on' : 'Sound on. Click to mute'); }

  function wire() {
    document.querySelectorAll('[data-sfx-mute]').forEach(b => {
      paint(b);
      b.addEventListener('click', () => { SFX.setMuted(!muted); if (!muted) SFX.start(); });
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
  window.PyrmiSFX = SFX;
})();
