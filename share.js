/* "Share your time": any button with [data-share="/path/"] shares a short brag with your best Vessel time.
   Uses the phone's share sheet when there is one, otherwise copies the text. Reads only this browser's best time. */
(function () {
  function bestTime() {
    try { return parseFloat(localStorage.getItem('pyrmi_best') || '0') || 0; } catch (e) { return 0; }
  }
  function text(url) {
    const b = bestTime();
    return b > 0
      ? 'I survived The Vessel for ' + b.toFixed(1) + 's on PYRMI ♥ can you last longer? ' + url
      : 'Can you survive The Vessel? A little bullet-dodging boss fight on PYRMI ♥ ' + url;
  }
  function copyFallback(s) {
    const ta = document.createElement('textarea');
    ta.value = s; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    let ok = false; try { ok = document.execCommand('copy'); } catch (e) {}
    ta.remove(); return ok;
  }
  function say(btn, msg) {
    const orig = btn.dataset.label || btn.textContent;
    btn.dataset.label = orig; btn.textContent = msg;
    clearTimeout(btn._t); btn._t = setTimeout(() => { btn.textContent = orig; }, 1800);
  }
  async function share(btn) {
    const url = 'https://pyrmi.com' + (btn.getAttribute('data-share') || '/');
    const s = text(url);
    if (navigator.share && matchMedia('(pointer: coarse)').matches) {
      try { await navigator.share({ text: s }); return; } catch (e) { if (e && e.name === 'AbortError') return; }
    }
    try { await navigator.clipboard.writeText(s); say(btn, 'copied!'); }
    catch (e) { say(btn, copyFallback(s) ? 'copied!' : 'copy failed'); }
  }
  function wire() {
    document.querySelectorAll('[data-share]').forEach(b => b.addEventListener('click', () => share(b)));
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire); else wire();
  window.PyrmiShare = { text };
})();
