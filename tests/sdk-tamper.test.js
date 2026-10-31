'use strict';
// The browser script's "replaced built-ins" check, run against real JavaScript realms: node --test tests/*.test.js
//
// Each page is a fresh vm context (its own Function, Object, Date, Math...), and the script's hidden iframe is a second
// one, so the check sees the same engine behaviour it sees in Chrome (V8 in both). The real built-ins here are real
// natives: performance.now is Date.now, which V8 prints as "function now() { [native code] }". Browser APIs a vm
// context doesn't have (timers, fetch, EventTarget...) are stand-ins written with identical source in both realms, so
// they look "clean" to the comparison the way the real ones do in a browser.
//
// The first tests are the round-6 report: `performance.now = (() => 0).bind(window)` printed as [native code], so the
// old check reported "replaced built-ins: clear" and the server answered accept, risk 0.
// PYRMI_SDK_FILE=<path> runs the same tests against another copy of the script (e.g. main's, to watch them fail).
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const http = require('http');
const { serve } = require('../scripts/dev.js');

const FILES = process.env.PYRMI_SDK_FILE ? [process.env.PYRMI_SDK_FILE]
  : [path.join(__dirname, '../src/sdk/pyrmi.js'), path.join(__dirname, '../sdk/pyrmi.js')];

let base, server;
test.before(async () => { server = http.createServer(serve); await new Promise((r) => server.listen(0, r)); base = 'http://127.0.0.1:' + server.address().port; });
test.after(() => server.close());
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

// Runs in every realm, word for word, so the stand-ins print the same in the page and in its iframe.
const SETUP = `(function () {
  var H = __host;
  function Performance() {}
  Object.defineProperty(Performance.prototype, 'now', { value: Date.now, writable: true, enumerable: true, configurable: true });
  globalThis.Performance = Performance;
  globalThis.performance = Object.create(Performance.prototype);
  function Navigator() {}
  Navigator.prototype.webdriver = H.webdriver;
  Navigator.prototype.userAgent = H.userAgent;
  Navigator.prototype.languages = ['en'];
  globalThis.Navigator = Navigator;
  globalThis.navigator = Object.create(Navigator.prototype);
  var doc = { hidden: false, currentScript: H.script, documentElement: {
    getAttribute: function () { return null; },
    appendChild: function (f) { f.__cw = H.frameWindow ? H.frameWindow() : null; },
    removeChild: function (f) { f.__cw = null; } } };
  if (H.shims) {
    globalThis.setTimeout = function setTimeout(f, ms) { return H.setTimeout(f, ms); };
    globalThis.setInterval = function setInterval(f, ms) { return H.setInterval(f, ms); };
    globalThis.clearTimeout = function clearTimeout(t) { return H.clearTimeout(t); };
    globalThis.clearInterval = function clearInterval(t) { return H.clearInterval(t); };
    globalThis.requestAnimationFrame = function requestAnimationFrame(f) { return H.setTimeout(f, 16); };
    globalThis.fetch = function fetch(u, o) { return H.fetch(u, o); };
    function XMLHttpRequest() {}
    XMLHttpRequest.prototype.send = function send() {};
    globalThis.XMLHttpRequest = XMLHttpRequest;
    function EventTarget() {}
    EventTarget.prototype.addEventListener = function addEventListener(t, f, o) { H.listen(this, t, f, o); };
    globalThis.EventTarget = EventTarget;
    globalThis.addEventListener = EventTarget.prototype.addEventListener;
    doc.addEventListener = EventTarget.prototype.addEventListener;
    function HTMLIFrameElement() {}
    Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', { get: function () { return this.__cw || null; }, enumerable: true, configurable: true });
    globalThis.HTMLIFrameElement = HTMLIFrameElement;
    if (H.iframe) doc.createElement = function createElement(tag) { var f = Object.create(HTMLIFrameElement.prototype); f.style = {}; f.setAttribute = function () {}; return f; };
  }
  globalThis.window = globalThis;
  globalThis.document = doc;
  globalThis.location = H.location;
  globalThis.URL = H.URL; globalThis.Blob = H.Blob; globalThis.atob = H.atob; globalThis.btoa = H.btoa;
  globalThis.outerWidth = 0; globalThis.innerWidth = 0; globalThis.outerHeight = 0; globalThis.innerHeight = 0;
})();`;

// A page with the script on it. `prelude` runs before the script loads (code that got there first).
function page(file, opts) {
  opts = opts || {};
  const shims = opts.shims !== false, iframe = shims && opts.iframe !== false;
  const flags = { shims, iframe, webdriver: !!opts.webdriver, userAgent: 'Mozilla/5.0 Chrome/120', location: { href: (base || 'http://x') + '/', origin: base || 'http://x' },
    URL, Blob, atob, btoa, setTimeout, setInterval, clearTimeout, clearInterval,
    fetch: (u, o) => fetch(u, { ...o, headers: { ...(o && o.headers), 'User-Agent': 'test-ua' } }), listen: () => {},
    script: { getAttribute: (n) => (n === 'data-site' ? 'pk_demo_sandbox' : null), src: (base || 'http://x') + '/sdk/pyrmi.js' } };
  const frameHost = { ...flags, frameWindow: null };
  const mainHost = { ...flags, frameWindow: () => { const c = vm.createContext({ __host: frameHost }); vm.runInContext(SETUP, c); return vm.runInContext('globalThis', c); } };
  const ctx = vm.createContext({ __host: mainHost });
  vm.runInContext(SETUP, ctx);
  if (opts.prelude) vm.runInContext(opts.prelude, ctx);
  vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  const run = (code) => vm.runInContext(code, ctx);
  return { run, Pyrmi: run('window.Pyrmi'), tp: () => Array.from(run('window.Pyrmi.report().tp')), wr: () => Array.from(run('window.Pyrmi.report().wr || []')) };
}

const BIND = 'performance.now = (() => 0).bind(window);';
// Built-ins that error trackers and frameworks wrap on ordinary sites: reported as "wrapped" (low risk), not "tampered".
const WRAPPABLE = ['setTimeout', 'setInterval', 'requestAnimationFrame', 'fetch', 'XMLHttpRequest.send', 'addEventListener', 'Function.toString'];

// What Sentry's browser SDK does (helpers.ts fill() + the FunctionToString integration): plain wrapper functions that
// call the original, an __sentry_original__ back-pointer, and a toString patched to print the original for them.
const SENTRY = `(function () {
  function fill(obj, name, make) { var orig = obj[name]; var w = make(orig); w.__sentry_original__ = orig; obj[name] = w; }
  fill(window, 'setTimeout', function (orig) { return function (fn, ms) { return orig.call(this, function () { return fn.apply(this, arguments); }, ms); }; });
  fill(window, 'setInterval', function (orig) { return function (fn, ms) { return orig.call(this, function () { return fn.apply(this, arguments); }, ms); }; });
  fill(window, 'requestAnimationFrame', function (orig) { return function (fn) { return orig.call(this, fn); }; });
  fill(window, 'fetch', function (orig) { return function () { return orig.apply(window, arguments); }; });
  fill(XMLHttpRequest.prototype, 'send', function (orig) { return function () { return orig.apply(this, arguments); }; });
  fill(EventTarget.prototype, 'addEventListener', function (orig) { return function (t, fn, o) { return orig.call(this, t, fn, o); }; });
  var ts = Function.prototype.toString;
  Function.prototype.toString = function () { var f = this && this.__sentry_original__ || this; return ts.apply(f, arguments); };
  window.__SENTRY__ = { version: '8' };
})();`;
// What zone.js (Angular) does: patches timers, rAF, listeners, fetch, XHR and toString, with __zone_symbol__ originals.
const ZONE = `(function () {
  function patch(obj, name) { var orig = obj[name]; obj['__zone_symbol__' + name] = orig; obj[name] = function () { return orig.apply(this, arguments); }; obj[name].__zone_symbol__OriginalDelegate = orig; }
  ['setTimeout', 'setInterval', 'requestAnimationFrame', 'fetch'].forEach(function (n) { patch(window, n); });
  patch(XMLHttpRequest.prototype, 'send'); patch(EventTarget.prototype, 'addEventListener');
  var ts = Function.prototype.toString;
  Function.prototype.toString = function () { var d = this && this.__zone_symbol__OriginalDelegate; return ts.call(d || this); };
  window.Zone = { __symbol__: function (n) { return '__zone_symbol__' + n; } };
})();`;

for (const file of FILES) {
  const which = path.relative(path.join(__dirname, '..'), file);

  test(which + ': a clean page reports no replaced built-ins (with and without the iframe)', () => {
    assert.deepEqual(page(file).tp(), []);
    // no iframe and no stand-ins: only real natives are on the page, so the name check alone must pass them
    assert.deepEqual(page(file, { shims: false }).tp(), []);
  });

  test(which + ': the reported bind() bypass is caught (performance.now = (() => 0).bind(window))', () => {
    for (const opts of [{}, { iframe: false }, { shims: false }]) {
      const p = page(file, opts);
      p.run(BIND);
      assert.equal(p.run('performance.now()'), 0, 'the hijack itself works');
      assert.ok(p.tp().includes('performance.now'), JSON.stringify(opts) + ' -> ' + JSON.stringify(p.tp()));
    }
  });

  test(which + ': a bound replacement made before the script loaded is caught', () => {
    for (const prelude of [BIND, 'Performance.prototype.now = (() => 0).bind(null);']) {
      for (const opts of [{}, { shims: false }]) {
        const p = page(file, { ...opts, prelude });
        assert.ok(p.tp().includes('performance.now'), prelude + ' ' + JSON.stringify(opts) + ' -> ' + JSON.stringify(p.tp()));
      }
    }
  });

  test(which + ': renaming the bound function, a Proxy, or a getter does not hide the replacement', () => {
    const tricks = [
      "var f = (() => 0).bind(window); Object.defineProperty(f, 'name', { value: 'now' }); performance.now = f;",
      'performance.now = new Proxy(performance.now, { apply: () => 0 });',
      "Object.defineProperty(performance, 'now', { get: () => () => 0, configurable: true });",
      "Object.defineProperty(performance, 'now', { value: Date.now, writable: true, configurable: true });", // a real native, wrong place
    ];
    for (const t of tricks) {
      for (const when of ['after', 'before']) {
        const p = page(file, when === 'before' ? { prelude: t } : {});
        if (when === 'after') p.run(t);
        assert.ok(p.tp().includes('performance.now'), when + ': ' + t + ' -> ' + JSON.stringify(p.tp()));
      }
    }
  });

  test(which + ': a hijacked Function.prototype.toString cannot vouch for a fake', () => {
    const lie = "Function.prototype.toString = function toString() { return 'function now() { [native code] }'; };";
    const fake = 'performance.now = function () { return 0; };';
    const before = page(file, { prelude: lie + fake });
    // the replaced toString is noted (as "wrapped": error trackers patch it too), and it can't hide the fake clock
    assert.ok(before.wr().includes('Function.toString'), JSON.stringify(before.wr()));
    assert.ok(before.tp().includes('performance.now'), JSON.stringify(before.tp()));
    const after = page(file);
    after.run(lie + fake);
    assert.ok(after.wr().includes('Function.toString') && after.tp().includes('performance.now'), JSON.stringify([after.tp(), after.wr()]));
    // and with .bind() on toString itself (it then prints [native code] too)
    const bound = page(file);
    bound.run('Function.prototype.toString = Function.prototype.toString.bind(Date.now);');
    assert.ok(bound.wr().includes('Function.toString'), JSON.stringify(bound.wr()));
  });

  test(which + ': every watched built-in is caught when bound-replaced after load', () => {
    const cases = {
      'performance.now': BIND, 'Date.now': 'Date.now = (() => 0).bind(null);', 'Math.random': 'Math.random = (() => 0.5).bind(null);',
      setTimeout: 'window.setTimeout = setTimeout.bind(window);', setInterval: 'window.setInterval = setInterval.bind(window);',
      requestAnimationFrame: 'window.requestAnimationFrame = requestAnimationFrame.bind(window);', fetch: 'window.fetch = fetch.bind(window);',
      'XMLHttpRequest.send': 'XMLHttpRequest.prototype.send = (() => {}).bind(null);',
      addEventListener: 'EventTarget.prototype.addEventListener = (() => {}).bind(null);',
      'Function.call': 'Function.prototype.call = Function.prototype.call.bind(Function.prototype.call);',
      'Function.apply': 'Function.prototype.apply = (() => {}).bind(null);', 'Function.bind': 'Function.prototype.bind = (() => {}).bind(null);',
      'Object.descriptor': 'Object.getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor.bind(Object);',
      'Object.getPrototypeOf': 'Object.getPrototypeOf = Object.getPrototypeOf.bind(Object);',
      'document.createElement': 'document.createElement = (() => null).bind(null);',
      'iframe.contentWindow': "Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', { get: (() => null).bind(null), configurable: true });",
    };
    for (const label of Object.keys(cases)) {
      const p = page(file);
      p.run(cases[label]);
      const list = WRAPPABLE.includes(label) ? p.wr() : p.tp();
      assert.ok(list.includes(label), label + ' -> ' + JSON.stringify([p.tp(), p.wr()]));
    }
  });

  test(which + ': a stealth patch that hides navigator.webdriver is reported, and webdriver still reads true', () => {
    const p = page(file, { webdriver: true, prelude: "Object.defineProperty(navigator, 'webdriver', { get: () => false, configurable: true });" });
    const r = p.run('window.Pyrmi.report()');
    assert.equal(r.wd, true, 'the clean iframe still says webdriver');
    assert.ok(Array.from(r.tp).includes('navigator.webdriver'), JSON.stringify(r.tp));
    const ua = page(file, { prelude: "Object.defineProperty(navigator, 'userAgent', { get: () => 'Mozilla/5.0 Firefox/120', configurable: true });" });
    assert.ok(ua.tp().includes('navigator.userAgent'), JSON.stringify(ua.tp()));
  });

  test(which + ': the script keeps working through later hooks, and its API cannot be swapped', async () => {
    const p = page(file);
    await p.Pyrmi.start();
    // a later script breaks fetch and timers and tries to replace flush() with a no-op
    p.run('window.fetch = function () { return Promise.reject(new Error("blocked")); }; window.setInterval = function () {};');
    try { p.run('window.Pyrmi.flush = function () { return Promise.resolve(); };'); } catch (_) { /* frozen */ }
    assert.notEqual(p.run('String(window.Pyrmi.flush)'), 'function () { return Promise.resolve(); }', 'flush() was replaced');
    const r = await p.Pyrmi.flush();
    p.Pyrmi.stop();
    assert.ok(r && r.ok, 'the beacon still got through: ' + JSON.stringify(r));
    assert.ok(p.wr().includes('fetch') && p.wr().includes('setInterval'), JSON.stringify(p.wr()));
  });

  test(which + ': Sentry- and zone.js-style wrappers are "wrapped", not "tampered", loaded before or after the script', () => {
    for (const [name, lib] of [['sentry', SENTRY], ['zone', ZONE]]) {
      for (const when of ['before', 'after']) {
        const p = page(file, when === 'before' ? { prelude: lib } : {});
        if (when === 'after') p.run(lib);
        assert.deepEqual(p.tp(), [], name + ' ' + when + ' -> tampered: ' + JSON.stringify(p.tp()));
        for (const label of WRAPPABLE) assert.ok(p.wr().includes(label), name + ' ' + when + ' should list ' + label + ': ' + JSON.stringify(p.wr()));
      }
    }
  });

  test(which + ': a wrapper library on the page does not make the bind() bypass, or a fake dressed as Sentry, look benign', () => {
    const tricks = [
      BIND,
      'var f = function () { return 0; }; f.__sentry_original__ = performance.now; performance.now = f;',
      'var g = (() => 0.5).bind(null); g.__zone_symbol__OriginalDelegate = Math.random; Math.random = g;',
    ];
    for (const [name, lib] of [['sentry', SENTRY], ['zone', ZONE]]) {
      for (const t of tricks) {
        const p = page(file, { prelude: lib });
        p.run(t);
        const label = /Math\.random/.test(t) ? 'Math.random' : 'performance.now';
        assert.ok(p.tp().includes(label), name + ': ' + t + ' -> ' + JSON.stringify(p.tp()));
      }
    }
  });

  test(which + ': at the server, a Sentry-wrapped page stays a low-risk accept and the bypass still costs +30', async () => {
    const run = async (prelude, hijack, visitor) => {
      const p = page(file, { prelude });
      const s = await p.Pyrmi.start();
      if (hijack) p.run(hijack);
      await wait(1600);
      await p.Pyrmi.flush();
      p.Pyrmi.stop();
      const r = await fetch(base + '/api/v1/demo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua' },
        body: JSON.stringify({ token: s.token, value: 5, visitor }) });
      return r.json();
    };
    const benign = await run(SENTRY, null, 'visitor-5e0001');
    assert.ok(!benign.reasons.some((r) => r.code === 'tampered_runtime'), JSON.stringify(benign.reasons));
    const w = benign.reasons.find((r) => r.code === 'wrapped_runtime');
    assert.ok(w && w.weight <= 5, JSON.stringify(benign.reasons));
    assert.equal(benign.verdict, 'accept');
    const attacked = await run(SENTRY, BIND, 'visitor-5e0002');
    const t = attacked.reasons.find((r) => r.code === 'tampered_runtime');
    assert.ok(t && t.weight === 30 && /performance\.now/.test(t.detail), JSON.stringify(attacked.reasons));
  });

  test(which + ': end to end, the bind() bypass now costs risk at the server instead of a clean accept', async () => {
    const verdict = async (hijack) => {
      const p = page(file);
      const s = await p.Pyrmi.start();
      if (hijack) p.run(BIND);
      await wait(1600);
      await p.Pyrmi.flush();
      p.Pyrmi.stop();
      const r = await fetch(base + '/api/v1/demo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua' },
        body: JSON.stringify({ token: s.token, value: 5, visitor: 'visitor-' + (hijack ? 'bad0' : '0c00') }) });
      return r.json();
    };
    const clean = await verdict(false);
    assert.ok(!clean.reasons.some((r) => r.code === 'tampered_runtime'), JSON.stringify(clean.reasons));
    const hijacked = await verdict(true);
    const t = hijacked.reasons.find((r) => r.code === 'tampered_runtime');
    assert.ok(t && /performance\.now/.test(t.detail), JSON.stringify(hijacked.reasons));
    assert.ok(hijacked.risk >= clean.risk + 30, 'risk ' + clean.risk + ' -> ' + hijacked.risk);
  });
}
