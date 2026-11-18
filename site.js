/* Shared page bits: copy buttons, and marking the current page in the top bar. The homepage backdrop lives in
   /bg/singularity.js. */
(function () {
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.getAttribute('data-copy'));
    if (!el) return;
    var text = 'value' in el ? el.value : el.textContent;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(function () {
      if (b.getAttribute('data-copied')) return;
      var old = b.textContent; b.textContent = 'copied'; b.setAttribute('data-copied', '1');
      setTimeout(function () { b.textContent = old; b.removeAttribute('data-copied'); }, 1400);
    }, function () { var r = document.createRange(); r.selectNodeContents(el); var s = getSelection(); s.removeAllRanges(); s.addRange(r); });
  });
  var here = location.pathname.replace(/index\.html$/, '');
  Array.prototype.forEach.call(document.querySelectorAll('header.top nav a[href^="/"]'), function (a) {
    var p = a.getAttribute('href');
    if (p !== '/' && here.indexOf(p) === 0) a.setAttribute('aria-current', 'page');
  });
})();
