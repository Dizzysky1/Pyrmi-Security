/* Runs in <head> on the landing page, before anything paints. There is no intro screen: the page is readable on the
   first frame. This only marks html.motion when the visitor hasn't asked for reduced motion, so motion.js can add its
   small scroll reveals without a flash of hidden content, and everything stays still otherwise. */
(function () {
  try { if (!matchMedia('(prefers-reduced-motion: reduce)').matches) document.documentElement.classList.add('motion'); } catch (e) { /* old browser: no motion */ }
})();
