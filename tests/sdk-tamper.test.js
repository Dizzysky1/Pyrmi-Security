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
  // window sizes: real accessors (as in a browser) when a test sets H.sizes, plain zeros otherwise
  ['outerWidth', 'innerWidth', 'outerHeight', 'innerHeight'].forEach(function (k) {
    if (H.sizes) Object.defineProperty(globalThis, k, { get: function () { return H.sizes[k]; }, set: function (v) {}, enumerable: true, configurable: true });
    else globalThis[k] = 0;
  });
  // navigator.userActivation, the browser's own "a person has pressed or clicked" flag, when a test sets H.activation
  if (H.activation) {
    var UserActivation = function UserActivation() {};
    Object.defineProperty(UserActivation.prototype, 'hasBeenActive', { get: function hasBeenActive() { return H.activation.active; }, enumerable: true, configurable: true });
    globalThis.UserActivation = UserActivation;
    var uact = Object.create(UserActivation.prototype);
    Object.defineProperty(Navigator.prototype, 'userActivation', { get: function userActivation() { return uact; }, enumerable: true, configurable: true });
  }
})();`;

// A page with the script on it. `prelude` runs before the script loads (code that got there first).
function page(file, opts) {
  opts = opts || {};
  const shims = opts.shims !== false, iframe = shims && opts.iframe !== false;
  const flags = { shims, iframe, webdriver: !!opts.webdriver, userAgent: 'Mozilla/5.0 Chrome/120', location: { href: (base || 'http://x') + '/', origin: base || 'http://x' },
    URL, Blob, atob, btoa, setTimeout, setInterval, clearTimeout, clearInterval,
    // a browser adds Origin and Sec-Fetch-Site to every request the page makes; the server corroborates beacons with them
    fetch: (u, o) => fetch(u, { ...o, headers: { ...(o && o.headers), 'User-Agent': opts.ua || 'test-ua', Origin: base || 'http://x', 'Sec-Fetch-Site': 'same-origin' } }),
    listen: opts.listen || (() => {}), sizes: opts.sizes || null, activation: opts.activation || null,
    script: { getAttribute: (n) => (n === 'data-site' ? 'pk_demo_sandbox' : null), src: (base || 'http://x') + '/sdk/pyrmi.js' } };
  const frameHost = { ...flags, frameWindow: null };
  const mainHost = { ...flags, frameWindow: () => { const c = vm.createContext({ __host: frameHost }); vm.runInContext(SETUP, c); return vm.runInContext('globalThis', c); } };
  const ctx = vm.createContext({ __host: mainHost });
  vm.runInContext(SETUP, ctx);
  if (opts.prelude) vm.runInContext(opts.prelude, ctx);
  vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
  if (opts.twice) vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
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

  test(which + ': at the server, a Sentry-wrapped page stays a low-risk accept and the bypass still costs +40', async () => {
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
    assert.equal(benign.verdict, 'accept', JSON.stringify(benign.reasons));
    const attacked = await run(SENTRY, BIND, 'visitor-5e0002');
    const t = attacked.reasons.find((r) => r.code === 'tampered_runtime');
    assert.ok(t && t.weight === 40 && /performance\.now/.test(t.detail), JSON.stringify(attacked.reasons));
  });

  // sdk/selftest.html runs these same tricks in a real browser (open it in Safari or Firefox to check those engines).
  // Here they run in V8 realms, so a wrong expectation in the page would show up before anyone opens it.
  test(which + ': every case on the in-browser self-test page passes in this engine', () => {
    const casesSrc = fs.readFileSync(path.join(__dirname, '../sdk/selftest-case.js'), 'utf8');
    const ids = Array.from(page(file, { prelude: casesSrc }).run('window.PYRMI_SELFTEST.map(function (c) { return c.id; })'));
    assert.ok(ids.length >= 25, 'cases: ' + ids.length);
    const has = (got, exp) => !exp || (exp.length ? exp.every((x) => got.includes(x)) : got.length === 0);
    for (const id of ids) {
      const p = page(file, { prelude: 'window.PYRMI_SELFTEST_CASE = ' + JSON.stringify(id) + ';\n' + casesSrc });
      p.run('(function () { var c = window.PYRMI_SELFTEST.filter(function (x) { return x.id === ' + JSON.stringify(id) + '; })[0]; if (c.when === "after") c.run(); })()');
      const exp = p.run('window.PYRMI_SELFTEST.filter(function (x) { return x.id === ' + JSON.stringify(id) + '; })[0]');
      assert.equal(p.run('window.PYRMI_SELFTEST_ERROR || null'), null, id);
      assert.ok(has(p.tp(), exp.tp) && has(p.wr(), exp.wr), id + ' -> tampered ' + JSON.stringify(p.tp()) + ' wrapped ' + JSON.stringify(p.wr()));
    }
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

// ---- round 7: the three parked backlog items, and the second tester's write-up ----
const SDKMETA = require('../api/_lib/sdk-build.json');
for (const file of FILES) {
  const which = path.relative(path.join(__dirname, '..'), file);
  const expectHash = /src[\\/]sdk/.test(which) ? SDKMETA.sourceHash : SDKMETA.hash;

  test(which + ': a fake window.Pyrmi planted before the script loads is replaced and reported', () => {
    // The old double-load guard returned early whenever window.Pyrmi.version existed, so this switched the script off.
    const p = page(file, { prelude: "window.Pyrmi = { version: '9.9.9', start: function () { return Promise.resolve({ token: 'fake' }); }, flush: function () {} };" });
    assert.equal(p.run('window.Pyrmi.version'), '1.3.0');
    assert.ok(p.tp().includes('window.Pyrmi'), JSON.stringify(p.tp()));
    // ...also when the fake is a getter
    const g = page(file, { prelude: "Object.defineProperty(window, 'Pyrmi', { get: function () { return { version: '1.3.0' }; }, configurable: true });" });
    assert.ok(g.tp().includes('window.Pyrmi'), JSON.stringify(g.tp()));
  });

  test(which + ': the same script included twice keeps the first copy and flags nothing', () => {
    const p = page(file, { twice: true });
    assert.equal(p.run('window.Pyrmi'), p.Pyrmi);
    assert.deepEqual(p.tp(), []);
  });

  test(which + ': a fake that can\'t be replaced (non-configurable) leaves the page without the script, without errors', () => {
    const p = page(file, { prelude: "Object.defineProperty(window, 'Pyrmi', { value: Object.freeze({ version: '1.3.0', start: function () {} }) });" });
    assert.equal(typeof p.run('window.Pyrmi.report'), 'undefined'); // still the fake: the server sees no telemetry (no_client)
  });

  test(which + ': spoofing the window sizes to hide docked devtools is caught, and the hint still reads the real sizes', () => {
    const sizes = { outerWidth: 1400, innerWidth: 1000, outerHeight: 900, innerHeight: 860 }; // a 400 px docked panel
    const p = page(file, { sizes });
    assert.ok(p.run('Pyrmi.report().dt') > 0, 'devtools hint seen');
    const q = page(file, { sizes });
    q.run("Object.defineProperty(window, 'outerWidth', { get: function () { return window.innerWidth; }, configurable: true });");
    assert.ok(q.run('Pyrmi.report().dt') > 0, 'the spoof must not hide the hint');
    assert.ok(q.tp().includes('outerWidth'), JSON.stringify(q.tp()));
  });

  test(which + ': input hidden from the script (stopped before its listener) is caught through the browser\'s activation flag', async () => {
    const listeners = [];
    const activation = { active: false };
    const p = page(file, { activation, listen: (t, type, fn) => listeners.push({ type, fn }) });
    // The person clicks, but a capture listener that ran first stops the event: the browser marks the page activated,
    // our listener never runs.
    activation.active = true;
    p.run('Pyrmi.report()');
    await wait(200);
    assert.ok(p.tp().includes('input.hidden'), JSON.stringify(p.tp()));
    // The same click reaching our listener is fine.
    const seen = [], act2 = { active: false };
    const q = page(file, { activation: act2, listen: (t, type, fn) => seen.push({ type, fn }) });
    act2.active = true;
    for (const l of seen) if (l.type === 'pointerdown') l.fn({ isTrusted: true, type: 'pointerdown' });
    q.run('Pyrmi.report()');
    await wait(200);
    assert.ok(!q.tp().includes('input.hidden'), JSON.stringify(q.tp()));
    // A page that was already activated before the script loaded (script loaded after a click) isn't flagged.
    const r = page(file, { activation: { active: true } });
    r.run('Pyrmi.report()'); await wait(200);
    assert.ok(!r.tp().includes('input.hidden'), JSON.stringify(r.tp()));
  });

  test(which + ': scripted keyup / pointerup / mouseup / touchend count as synthetic input', () => {
    const listeners = [];
    const p = page(file, { listen: (t, type, fn) => listeners.push({ type, fn }) });
    for (const type of ['keyup', 'pointerup', 'mouseup', 'touchend']) {
      const l = listeners.find((x) => x.type === type);
      assert.ok(l, 'listens for ' + type);
      l.fn({ isTrusted: false, type });
    }
    assert.equal(p.run('Pyrmi.report().ut'), 4);
    // form events from password managers are not counted
    assert.ok(!listeners.some((x) => x.type === 'input' || x.type === 'change'));
  });

  test(which + ': a page that wraps fetch (or loads Sentry / zone.js) before the script keeps the known fingerprint', () => {
    // Reported against the pre-round-6 build, which hashed itself through the page's own toString.
    for (const prelude of ['var f0 = window.fetch; window.fetch = function (u, o) { return f0(u, o); };', SENTRY, ZONE]) {
      const p = page(file, { prelude });
      assert.equal(p.run('Pyrmi.report().sh'), expectHash);
    }
  });

  test(which + ': the script sends its start clock and ties beacons to the session (end to end: corroborated accept)', async () => {
    const p = page(file);
    const s = await p.Pyrmi.start();
    await wait(1600);
    await p.Pyrmi.flush();
    p.Pyrmi.stop();
    const r = await fetch(base + '/api/v1/demo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': 'test-ua' },
      body: JSON.stringify({ token: s.token, value: 5, visitor: 'visitor-7c01' }) });
    const v = await r.json();
    assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
    assert.equal(v.client, 'corroborated');
    assert.equal(v.risk, 0, JSON.stringify(v.reasons));
  });

  // Round 8: on a browser that has navigator.userActivation the server now expects a true/false answer. The real
  // script gives one, so a real Chrome visit that hasn't clicked yet must still be a clean, corroborated accept.
  test(which + ': end to end in a Chrome with userActivation (not yet activated): still a corroborated accept at risk 0', async () => {
    const ua = 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0 Safari/537.36';
    const p = page(file, { ua, activation: { active: false } });
    const s = await p.Pyrmi.start();
    await wait(1600);
    await p.Pyrmi.flush();
    p.Pyrmi.stop();
    const r = await fetch(base + '/api/v1/demo', { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': ua },
      body: JSON.stringify({ token: s.token, value: 5, visitor: 'visitor-8c01' }) });
    const v = await r.json();
    assert.equal(v.verdict, 'accept', JSON.stringify(v.reasons));
    assert.equal(v.client, 'corroborated');
    assert.equal(v.risk, 0, JSON.stringify(v.reasons));
  });
}
