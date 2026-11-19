/* Landing page motion, kept small on purpose: sections below the fold ease in as they reach the screen, a beat apart
   within each group. Nothing above the fold animates, nothing blocks reading, and with reduced motion (no html.motion,
   see intro.js) this does nothing at all. */
(function () {
  var root = document.documentElement;
  if (!root.classList.contains('motion') || !('IntersectionObserver' in window)) return;
  var items = document.querySelectorAll('.sec .sec-h, .cells > *, .code-pair .code, .ledger > div, .callout, .console, #agents .code');
  var io = new IntersectionObserver(function (entries) {
    entries.forEach(function (en) {
      if (!en.isIntersecting) return;
      en.target.classList.add('in'); io.unobserve(en.target);
    });
  }, { rootMargin: '0px 0px -6% 0px', threshold: 0.08 });
  var fold = innerHeight;
  Array.prototype.forEach.call(items, function (el) {
    if (el.getBoundingClientRect().top < fold) return; // already on screen: leave it alone
    var sib = Array.prototype.indexOf.call(el.parentNode.children, el);
    el.classList.add('rv', 'rv-d' + Math.min(sib, 5));
    io.observe(el);
  });
})();
