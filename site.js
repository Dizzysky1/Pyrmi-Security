/* Shared page bits: starfield backdrop and copy buttons. */
(function () {
  var c = document.getElementById('stars');
  if (c && !matchMedia('(prefers-reduced-motion: reduce)').matches) {
    var x = c.getContext('2d'), w, h, stars;
    var rs = function () { w = c.width = innerWidth; h = c.height = innerHeight; stars = Array.from({ length: 90 }, function () { return { x: Math.random() * w, y: Math.random() * h, z: Math.random() * .8 + .2 }; }); };
    rs(); addEventListener('resize', rs);
    (function loop() {
      x.clearRect(0, 0, w, h);
      for (var i = 0; i < stars.length; i++) { var s = stars[i]; s.y += s.z * .3; if (s.y > h) s.y = 0; x.globalAlpha = s.z; x.fillStyle = '#b9c0ff'; x.fillRect(s.x, s.y, s.z * 2, s.z * 2); }
      x.globalAlpha = 1; requestAnimationFrame(loop);
    })();
  }
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
