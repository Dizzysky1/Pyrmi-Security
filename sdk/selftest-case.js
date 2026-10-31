/* Pyrmi Security: in-browser self-test cases for the replaced built-ins check (see selftest.html). MIT License.
 * In a case frame (selftest.html?case=<id>) this file runs before pyrmi.js, so "before" cases install their trick
 * ahead of the script; selftest.js runs "after" cases once it has loaded. The same tricks as tests/sdk-tamper.test.js. */
(function () {
  'use strict';
  var W = ['setTimeout', 'setInterval', 'requestAnimationFrame', 'fetch', 'XMLHttpRequest.send', 'addEventListener', 'Function.toString'];
  function bindNow() { performance.now = (function () { return 0; }).bind(window); }
  function sentry() {
    function fill(obj, name, make) { var orig = obj[name]; var w = make(orig); w.__sentry_original__ = orig; obj[name] = w; }
    fill(window, 'setTimeout', function (orig) { return function (fn, ms) { return orig.call(this, function () { return fn.apply(this, arguments); }, ms); }; });
    fill(window, 'setInterval', function (orig) { return function (fn, ms) { return orig.call(this, function () { return fn.apply(this, arguments); }, ms); }; });
    fill(window, 'requestAnimationFrame', function (orig) { return function (fn) { return orig.call(this, fn); }; });
    fill(window, 'fetch', function (orig) { return function () { return orig.apply(window, arguments); }; });
    fill(XMLHttpRequest.prototype, 'send', function (orig) { return function () { return orig.apply(this, arguments); }; });
    fill(EventTarget.prototype, 'addEventListener', function (orig) { return function (t, fn, o) { return orig.call(this, t, fn, o); }; });
    var ts = Function.prototype.toString;
    Function.prototype.toString = function () { var f = (this && this.__sentry_original__) || this; return ts.apply(f, arguments); };
  }
  function zone() {
    function patch(obj, name) { var orig = obj[name]; obj['__zone_symbol__' + name] = orig; obj[name] = function () { return orig.apply(this, arguments); }; obj[name].__zone_symbol__OriginalDelegate = orig; }
    ['setTimeout', 'setInterval', 'requestAnimationFrame', 'fetch'].forEach(function (n) { patch(window, n); });
    patch(XMLHttpRequest.prototype, 'send'); patch(EventTarget.prototype, 'addEventListener');
    var ts = Function.prototype.toString;
    Function.prototype.toString = function () { var d = this && this.__zone_symbol__OriginalDelegate; return ts.call(d || this); };
  }
  function bound(get, set) { return function () { set(get().bind(null)); }; }
  // tp / wr: labels that must be listed; [] means that list must be empty; null means don't care.
  var C = [
    { id: 'clean', desc: 'nothing changed', when: 'after', run: function () {}, tp: [], wr: [] },
    { id: 'bind-after', desc: 'performance.now = (() => 0).bind(window), after load (the report)', when: 'after', run: bindNow, tp: ['performance.now'] },
    { id: 'bind-before', desc: 'the same, before the script loads', when: 'before', run: bindNow, tp: ['performance.now'] },
    { id: 'proto-bind-before', desc: 'Performance.prototype.now bound, before load', when: 'before', run: function () { Performance.prototype.now = (function () { return 0; }).bind(null); }, tp: ['performance.now'] },
    { id: 'renamed-bound', desc: 'bound function renamed to "now"', when: 'after', run: function () { var f = (function () { return 0; }).bind(window); Object.defineProperty(f, 'name', { value: 'now' }); performance.now = f; }, tp: ['performance.now'] },
    { id: 'proxy-after', desc: 'Proxy around performance.now, after load', when: 'after', run: function () { performance.now = new Proxy(performance.now, { apply: function () { return 0; } }); }, tp: ['performance.now'] },
    { id: 'proxy-before', desc: 'Proxy around performance.now, before load', when: 'before', run: function () { performance.now = new Proxy(performance.now, { apply: function () { return 0; } }); }, tp: ['performance.now'] },
    { id: 'getter', desc: 'performance.now as a getter', when: 'after', run: function () { Object.defineProperty(performance, 'now', { get: function () { return function () { return 0; }; }, configurable: true }); }, tp: ['performance.now'] },
    { id: 'native-moved', desc: 'a real native (Date.now) put on the instance, before load', when: 'before', run: function () { Object.defineProperty(performance, 'now', { value: Date.now, writable: true, configurable: true }); }, tp: ['performance.now'] },
    { id: 'tostring-lie', desc: 'toString patched to vouch for a fake clock, before load', when: 'before', run: function () { Function.prototype.toString = function toString() { return 'function now() { [native code] }'; }; performance.now = function () { return 0; }; }, tp: ['performance.now'], wr: ['Function.toString'] },
    { id: 'webdriver-stealth', desc: 'navigator.webdriver hidden with a getter, before load', when: 'before', run: function () { Object.defineProperty(navigator, 'webdriver', { get: function () { return false; }, configurable: true }); }, tp: ['navigator.webdriver'] },
    { id: 'ua-spoof', desc: 'navigator.userAgent replaced with a getter', when: 'after', run: function () { Object.defineProperty(navigator, 'userAgent', { get: function () { return 'Mozilla/5.0 Firefox/120'; }, configurable: true }); }, tp: ['navigator.userAgent'] },
    { id: 'date-now', desc: 'Date.now bound', when: 'after', run: bound(function () { return function () { return 0; }; }, function (f) { Date.now = f; }), tp: ['Date.now'] },
    { id: 'math-random', desc: 'Math.random bound', when: 'after', run: bound(function () { return function () { return 0.5; }; }, function (f) { Math.random = f; }), tp: ['Math.random'] },
    { id: 'fn-call', desc: 'Function.prototype.call bound', when: 'after', run: function () { Function.prototype.call = Function.prototype.call.bind(Function.prototype.call); }, tp: ['Function.call'] },
    { id: 'fn-apply', desc: 'Function.prototype.apply bound', when: 'after', run: function () { Function.prototype.apply = (function () {}).bind(null); }, tp: ['Function.apply'] },
    { id: 'fn-bind', desc: 'Function.prototype.bind bound', when: 'after', run: function () { Function.prototype.bind = Function.prototype.bind.bind(Function.prototype.bind); }, tp: ['Function.bind'] },
    { id: 'gopd', desc: 'Object.getOwnPropertyDescriptor bound', when: 'after', run: function () { Object.getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor.bind(Object); }, tp: ['Object.descriptor'] },
    { id: 'gpo', desc: 'Object.getPrototypeOf bound', when: 'after', run: function () { Object.getPrototypeOf = Object.getPrototypeOf.bind(Object); }, tp: ['Object.getPrototypeOf'] },
    { id: 'create-element', desc: 'document.createElement bound', when: 'after', run: function () { document.createElement = document.createElement.bind(document); }, tp: ['document.createElement'] },
    { id: 'content-window', desc: 'iframe contentWindow getter replaced', when: 'after', run: function () { Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', { get: (function () { return null; }).bind(null), configurable: true }); }, tp: ['iframe.contentWindow'] },
    { id: 'timers-bound', desc: 'setTimeout, setInterval, rAF and fetch bound', when: 'after', run: function () { window.setTimeout = setTimeout.bind(window); window.setInterval = setInterval.bind(window); window.requestAnimationFrame = requestAnimationFrame.bind(window); window.fetch = fetch.bind(window); }, tp: [], wr: ['setTimeout', 'setInterval', 'requestAnimationFrame', 'fetch'] },
    { id: 'xhr-listen-bound', desc: 'XHR send and addEventListener bound', when: 'after', run: function () { XMLHttpRequest.prototype.send = (function () {}).bind(null); EventTarget.prototype.addEventListener = (function () {}).bind(null); }, tp: [], wr: ['XMLHttpRequest.send', 'addEventListener'] },
    { id: 'sentry-before', desc: 'Sentry-style wrappers, loaded before the script', when: 'before', run: sentry, tp: [], wr: W },
    { id: 'sentry-after', desc: 'Sentry-style wrappers, loaded after the script', when: 'after', run: sentry, tp: [], wr: W },
    { id: 'zone-before', desc: 'zone.js-style patches, loaded before the script', when: 'before', run: zone, tp: [], wr: W },
    { id: 'zone-after', desc: 'zone.js-style patches, loaded after the script', when: 'after', run: zone, tp: [], wr: W },
    { id: 'sentry-plus-bind', desc: 'Sentry on the page, then the bind() bypass', when: 'after', run: function () { sentry(); bindNow(); }, tp: ['performance.now'] },
    { id: 'fake-sentry-marker', desc: 'a fake clock carrying a __sentry_original__ marker', when: 'after', run: function () { var f = function () { return 0; }; f.__sentry_original__ = performance.now; performance.now = f; }, tp: ['performance.now'] },
  ];
  window.PYRMI_SELFTEST = C;
  var m = /[?&]case=([\w-]+)/.exec(location.search);
  if (!m) return;
  for (var i = 0; i < C.length; i++) {
    if (C[i].id === m[1] && C[i].when === 'before') { try { C[i].run(); } catch (e) { window.PYRMI_SELFTEST_ERROR = String(e); } }
  }
})();
