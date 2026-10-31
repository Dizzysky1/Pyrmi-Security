/* Shared page bits: copy buttons. The animated backdrop lives in /bg/singularity.js. */
(function () {
  document.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy]');
    if (!b) return;
    var el = document.getElementById(b.getAttribute('data-copy'));
    if (!el) return;
    var text = 'value' in el ? el.value : el.textContent;
    (navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject()).then(function () {
      var old = b.textContent; b.textContent = 'copied'; setTimeout(function () { b.textContent = old; }, 1400);
    }, function () { var r = document.createRange(); r.selectNodeContents(el); var s = getSelection(); s.removeAllRanges(); s.addRange(r); });
  });
})();
