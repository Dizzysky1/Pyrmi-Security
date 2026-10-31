/* Runs in <head> on the landing page, before anything paints, so the page never flashes before its intro.
   Decides how the page arrives: the full intro once per browser session, a quick fade-in after that, and nothing
   at all for reduced motion. motion.js does the rest; if it never runs, a timer shows the page anyway. */
(function () {
  var root = document.documentElement;
  if (matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  root.classList.add('motion');
  var seen = false;
  try { seen = sessionStorage.getItem('pyrmi_intro') === '1'; sessionStorage.setItem('pyrmi_intro', '1'); } catch (e) { /* storage off: play it */ }
  if (/[?&]intro=1\b/.test(location.search)) seen = false; // ?intro=1 replays it
  if (!seen) { root.classList.add('intro'); window.__pyrmiIntroAt = performance.now(); }
  setTimeout(function () { root.classList.add('shown'); }, 5000);
})();
