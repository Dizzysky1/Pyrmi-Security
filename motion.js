/* Landing page motion: the intro (wordmark, then the singularity pulls itself together and the headline comes in),
   section reveals as you scroll, and a soft light that follows the pointer on cards. The particle side of the intro
   is in /bg/singularity.js and keys off the same start time. Any key, click, scroll or the skip button ends it. */
(function () {
  var root = document.documentElement;
  if (!root.classList.contains('motion')) return;
  var hero = document.querySelector('.hero');

  // Headline words come in one at a time, so wrap each one (the <br> and the coloured span stay as they are).
  var h1 = hero && hero.querySelector('h1');
  if (h1) {
    var i = 0;
    (function wrap(node) {
      Array.prototype.slice.call(node.childNodes).forEach(function (n) {
        if (n.nodeType === 3) {
          var frag = document.createDocumentFragment();
          n.textContent.split(/(\s+)/).forEach(function (part) {
            if (!part) return;
            if (/^\s+$/.test(part)) { frag.appendChild(document.createTextNode(part)); return; }
            var s = document.createElement('span'); s.className = 'w'; s.style.setProperty('--i', i++); s.textContent = part; frag.appendChild(s);
          });
          node.replaceChild(frag, n);
        } else if (n.nodeType === 1 && n.tagName !== 'BR') wrap(n);
      });
    })(h1);
    h1.style.setProperty('--n', i);
  }

  var intro = document.getElementById('intro');
  function heroIn() { root.classList.add('hero-in'); }
  function done() {
    root.classList.remove('intro'); root.classList.add('shown');
    if (intro && intro.parentNode) intro.parentNode.removeChild(intro);
    ['keydown', 'wheel', 'touchstart', 'pointerdown'].forEach(function (ev) { removeEventListener(ev, skip, true); });
  }
  var timers = [];
  function skip(e) {
    if (e && e.type === 'keydown' && (e.metaKey || e.ctrlKey || e.altKey)) return;
    timers.forEach(clearTimeout);
    root.classList.add('intro-skip');
    dispatchEvent(new Event('pyrmi:intro-skip'));
    heroIn(); setTimeout(done, 350);
  }

  if (root.classList.contains('intro') && intro) {
    var at = window.__pyrmiIntroAt || performance.now(), since = performance.now() - at;
    timers.push(setTimeout(function () { root.classList.add('intro-out'); }, Math.max(0, 1000 - since)));
    timers.push(setTimeout(heroIn, Math.max(0, 1450 - since)));
    timers.push(setTimeout(done, Math.max(0, 2900 - since)));
    ['keydown', 'wheel', 'touchstart', 'pointerdown'].forEach(function (ev) { addEventListener(ev, skip, { capture: true, passive: true }); });
  } else {
    if (intro) intro.parentNode.removeChild(intro);
    requestAnimationFrame(heroIn);
  }

  // Sections and cards rise in as they reach the screen, a beat apart within each group.
  var items = document.querySelectorAll('section:not(.hero) h2.sec, section .lead, .steps .card, .code-pair .code, .grid3 .mini, .grid2 .card, .demo > *, #agents .code');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) {
        if (!en.isIntersecting) return;
        en.target.classList.add('in'); io.unobserve(en.target);
      });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.12 });
    Array.prototype.forEach.call(items, function (el) {
      var sib = Array.prototype.indexOf.call(el.parentNode.children, el);
      el.classList.add('rv'); el.style.setProperty('--d', Math.min(sib, 8) * 70 + 'ms');
      io.observe(el);
    });
  }

  // A soft light under the pointer on cards (mouse only).
  if (matchMedia('(hover: hover)').matches) {
    document.addEventListener('pointermove', function (e) {
      var c = e.target.closest && e.target.closest('.card,.mini,.panel,.code');
      if (!c) return;
      var r = c.getBoundingClientRect();
      c.style.setProperty('--mx', (e.clientX - r.left) + 'px'); c.style.setProperty('--my', (e.clientY - r.top) + 'px');
    }, { passive: true });
  }
})();
