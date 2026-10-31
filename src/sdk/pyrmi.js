/*! Pyrmi Security browser script · MIT License · https://pyrmi.com
 *
 *   <script src="https://pyrmi.com/sdk/pyrmi.js" data-site="pk_..."></script>
 *
 *   const s = await Pyrmi.start();     // when the page or a session begins: { token, seed, ... }
 *   Pyrmi.mark(appSeconds);            // optional, for apps with their own clock (games, timers): spots speed hacks
 *   await Pyrmi.flush();               // before you send s.token with the action to YOUR server
 *
 * This script can't stop someone who controls their own browser, and it doesn't try to: anything it "blocks" can be
 * switched off from devtools. It watches for bots, tampering and devtools and reports them, and your server asks
 * Pyrmi for a verdict before it trusts the action. That's where the real protection is.
 *
 * This is the readable source. pyrmi.com serves a minified build of it (node scripts/build-sdk.js) with a fingerprint
 * of its own code that the server checks. The telemetry it sends is advisory: your server still asks Pyrmi for a
 * verdict, and the real protection is the signed, single-use session token checked there, not anything in this file.
 */
(function pyrmiMain(w, d) {
  'use strict';
  if (w.Pyrmi && w.Pyrmi.version) return;

  // ---- trusted references, taken before any later page code can run ----
  // Everything this script calls for itself is captured here, once. run(fn, thisArg, a, b) calls fn through a bound
  // copy of the built-in call, so there's no property lookup at call time for a later hook (on .call, .apply,
  // .toString or the function itself) to step into. Code that ran before this script is caught by the checks below.
  var O = Object, FP = Function.prototype;
  var callFn = FP.call, bindFn = FP.bind, nativeToString = FP.toString;
  var run = bindFn.call(callFn, callFn);
  var gopd = O.getOwnPropertyDescriptor, gpo = O.getPrototypeOf, freeze = O.freeze, defineProp = O.defineProperty;
  var stringify = JSON.stringify, dateNow = Date.now;
  var script = d.currentScript;
  var cfg = {
    site: script && script.getAttribute('data-site'),
    api: (script && script.getAttribute('data-api')) || (script && script.src ? new URL(script.src, location.href).origin : location.origin) + '/api/v1',
  };
  var nav = w.navigator || {};
  var perf = w.performance;
  var perfNow = perf && perf.now, fetchFn = w.fetch, sendBeaconFn = nav.sendBeacon;
  var setTimeoutFn = w.setTimeout, setIntervalFn = w.setInterval, clearTimeoutFn = w.clearTimeout, clearIntervalFn = w.clearInterval;
  var listenW = w.addEventListener, listenD = d.addEventListener;
  function clock() { return typeof perfNow === 'function' ? run(perfNow, perf) : run(dateNow, Date); }
  function wallNow() { return run(dateNow, Date); }

  // FNV-1a over a string, as 8 hex digits. Used for this script's own fingerprint.
  function fnv(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }

  // ---- where a built-in lives, and what it is ----
  // Built-ins that speed hacks, cheat scripts and bot "stealth" kits like to replace. Each is a path from the window.
  var WATCH = [
    ['performance.now', ['performance', 'now']], ['Date.now', ['Date', 'now']], ['requestAnimationFrame', ['requestAnimationFrame']],
    ['setTimeout', ['setTimeout']], ['setInterval', ['setInterval']], ['Math.random', ['Math', 'random']], ['fetch', ['fetch']],
    ['XMLHttpRequest.send', ['XMLHttpRequest', 'prototype', 'send']], ['addEventListener', ['EventTarget', 'prototype', 'addEventListener']],
    ['Function.toString', ['Function', 'prototype', 'toString']], ['Function.call', ['Function', 'prototype', 'call']],
    ['Function.apply', ['Function', 'prototype', 'apply']], ['Function.bind', ['Function', 'prototype', 'bind']],
    ['Object.descriptor', ['Object', 'getOwnPropertyDescriptor']], ['Object.getPrototypeOf', ['Object', 'getPrototypeOf']],
    ['document.createElement', ['document', 'createElement']], ['iframe.contentWindow', ['HTMLIFrameElement', 'prototype', 'contentWindow']],
    ['navigator.webdriver', ['navigator', 'webdriver']], ['navigator.userAgent', ['navigator', 'userAgent']], ['navigator.languages', ['navigator', 'languages']],
  ];
  var WD = 17, UA = 18, LANGS = 19; // indexes into WATCH
  // Finds the object that really holds the property (the instance or something up its prototype chain) and how it's
  // defined there. A replacement shows up as a different function, a different place (an own property shadowing the
  // prototype's), or a different kind (a getter where a plain value belongs), even when its toString looks native.
  function locate(root, path) {
    var o = root, i, depth = 0, desc = null, p;
    for (i = 0; i < path.length - 1; i++) { if (o === null || o === undefined) return null; o = o[path[i]]; }
    if (o === null || (typeof o !== 'object' && typeof o !== 'function')) return null;
    for (p = o; p !== null && depth < 8; p = gpo(p)) { desc = gopd(p, path[path.length - 1]); if (desc) break; depth++; }
    if (!desc) return null;
    var acc = 'get' in desc || 'set' in desc, fn = acc ? desc.get : desc.value;
    return { base: o, acc: acc, fn: typeof fn === 'function' ? fn : null, value: acc ? undefined : desc.value,
      sig: depth + (acc ? 'a' : 'd') + (desc.enumerable ? 'e' : '') + (desc.configurable ? 'c' : '') + (!acc && desc.writable ? 'w' : '') };
  }
  // A real built-in prints as "function now() { [native code] }": the spec makes it carry its own name. A bound
  // function or a Proxy also prints [native code], but without the name ("function () { [native code] }"), which is
  // exactly the hole that matching [native code] alone left open.
  function nativeNamed(str, name) {
    var s = typeof str === 'string' ? str.replace(/\s+/g, '') : '';
    return s === 'function' + name + '(){[nativecode]}' || s === 'functionget' + name + '(){[nativecode]}';
  }
  function boundName(fn) {
    try { var n = gopd(fn, 'name'); return !!n && typeof n.value === 'string' && n.value.indexOf('bound ') === 0; } catch (_) { return true; }
  }

  // ---- a clean copy of the built-ins, from a fresh iframe ----
  // A same-origin about:blank iframe gets its own untouched set of built-ins. We keep, for each watched one, how the
  // fresh copy prints and where it lives, then let the iframe go. Comparing against that is engine-exact (no guessing
  // at whitespace) and catches a replacement made before this script loaded, which load-time capture alone can't.
  var fresh = null;
  try {
    var host = d.documentElement || d.head || d.body;
    if (host && typeof d.createElement === 'function') {
      var frame = d.createElement('iframe');
      if (frame.style) frame.style.display = 'none';
      if (frame.setAttribute) frame.setAttribute('aria-hidden', 'true');
      host.appendChild(frame);
      var iw = frame.contentWindow;
      if (iw && iw !== w && iw.Function && iw.Function !== w.Function) {
        var iStr = iw.Function.prototype.toString, base = [];
        for (var bi = 0; bi < WATCH.length; bi++) {
          var bl = null;
          try { bl = locate(iw, WATCH[bi][1]); } catch (_) { bl = null; }
          base.push(bl ? { sig: bl.sig, str: bl.fn ? run(iStr, bl.fn) : null } : null);
        }
        var inav = iw.navigator || {};
        fresh = { toStr: iStr, base: base, wd: inav.webdriver === true, ua: String(inav.userAgent || '') };
      }
      host.removeChild(frame);
    }
  } catch (_) { fresh = null; }

  // The toString we trust: the one captured above, unless the fresh realm says it was already replaced.
  var toStr = nativeToString, toStrReplaced = false;
  try {
    if (fresh) toStrReplaced = run(fresh.toStr, nativeToString) !== run(fresh.toStr, fresh.toStr);
    else toStrReplaced = !nativeNamed(run(nativeToString, nativeToString), 'toString');
    if (toStrReplaced && fresh) toStr = fresh.toStr;
  } catch (_) { toStrReplaced = true; }
  function strOf(f) {
    try { return run(toStr, f); } catch (_) { try { return run(nativeToString, f); } catch (e) { return null; } }
  }
  var loaded = [];
  for (var li = 0; li < WATCH.length; li++) { try { loaded.push(locate(w, WATCH[li][1])); } catch (_) { loaded.push(null); } }
  // Reads a navigator property through the getter captured at load, not whatever a later script put in its place.
  function navRead(i) {
    var l = loaded[i];
    if (!l) return undefined;
    try { return l.acc ? (l.fn ? run(l.fn, nav) : undefined) : nav[WATCH[i][1][1]]; } catch (_) { return undefined; }
  }
  function tampered(i) {
    var e = WATCH[i], now = locate(w, e[1]), was = loaded[i], b = fresh ? fresh.base[i] : null;
    if (!now) return !!was; // deleted since load
    if (was && (now.fn !== was.fn || now.sig !== was.sig || now.base !== was.base)) return true; // replaced since load
    if (b && now.sig !== b.sig) return true; // lives somewhere a clean copy doesn't (e.g. an own property shadowing it)
    if (!now.fn) return false;
    if (boundName(now.fn)) return true; // cheap stopgap: bound functions are named "bound <name>"
    var s = strOf(now.fn);
    if (b && b.str !== null) return s !== b.str; // prints differently from the clean copy
    return !nativeNamed(s, e[1][e[1].length - 1]);
  }

  var selfHash = null;
  try { selfHash = fnv(strOf(pyrmiMain)); } catch (_) { selfHash = 'unreadable'; }

  // ---- environment checks (once, plus re-checks on a timer) ----
  var env = { wd: false, hl: false, au: [], tp: [], dt: 0 };
  function addOnce(list, v) { if (list.indexOf(v) < 0) list.push(v); }
  function checkEnv() {
    try {
      if (navRead(WD) === true || (fresh && fresh.wd)) env.wd = true;
      var ua = String(navRead(UA) || ''), langs = navRead(LANGS);
      if (/HeadlessChrome|PhantomJS|SlimerJS/i.test(ua) || (fresh && /HeadlessChrome/i.test(fresh.ua))) env.hl = true;
      if (/Chrome\//.test(ua) && !/Mobile|Android/.test(ua) && langs && langs.length === 0) env.hl = true;
      if (fresh && fresh.ua && ua && ua !== fresh.ua) addOnce(env.tp, 'navigator.userAgent');
      var marks = { __playwright__binding__: 'playwright', __pwInitScripts: 'playwright', _phantom: 'phantom', callPhantom: 'phantom',
        __nightmare: 'nightmare', domAutomation: 'chromedriver', domAutomationController: 'chromedriver', _selenium: 'selenium',
        __webdriver_evaluate: 'selenium', __selenium_unwrapped: 'selenium', __lastWatirAlert: 'watir', Cypress: 'cypress', __puppeteer_evaluation_script__: 'puppeteer' };
      for (var k in marks) if (k in w) addOnce(env.au, marks[k]);
      if (d.documentElement && (d.documentElement.getAttribute('webdriver') || d.documentElement.getAttribute('selenium'))) addOnce(env.au, 'selenium');
    } catch (_) { /* never break the page */ }
    if (toStrReplaced) addOnce(env.tp, 'Function.toString');
    for (var i = 0; i < WATCH.length; i++) {
      try { if (tampered(i)) addOnce(env.tp, WATCH[i][0]); } catch (_) { addOnce(env.tp, WATCH[i][0]); }
    }
    // devtools: a docked panel shrinks the page well below the window. A rough hint, so it only adds a little risk.
    try {
      var gw = w.outerWidth - w.innerWidth, gh = w.outerHeight - w.innerHeight;
      if (w.outerWidth && (gw > 200 || gh > 260) && !/Mobile|Android/.test(String(navRead(UA) || ''))) env.dt++;
    } catch (_) { /* ignore */ }
  }

  // ---- input watching (per session) ----
  var inp;
  function resetInput() { inp = { ut: 0, ih: 0, k: 0, p: 0, h: 0, lastKey: 0, gaps: [], win: [] }; }
  resetInput();
  function onInput(e) {
    if (!e.isTrusted) { inp.ut++; return; }
    var now = clock();
    if (e.type === 'keydown') {
      if (e.repeat) return;
      inp.k++;
      if (inp.lastKey) { inp.gaps.push(now - inp.lastKey); if (inp.gaps.length > 40) inp.gaps.shift(); }
      inp.lastKey = now;
      // perfectly even key timing over many presses is a macro or bot, not a hand
      if (inp.gaps.length >= 40) {
        var m = 0, v = 0, i;
        for (i = 0; i < inp.gaps.length; i++) m += inp.gaps[i];
        m /= inp.gaps.length;
        for (i = 0; i < inp.gaps.length; i++) v += (inp.gaps[i] - m) * (inp.gaps[i] - m);
        if (Math.sqrt(v / inp.gaps.length) < 1.5 && m < 400) { inp.ih++; inp.gaps = []; }
      }
    } else inp.p++;
    if (e.type === 'keydown' || e.type === 'pointerdown' || e.type === 'mousedown' || e.type === 'touchstart') {
      inp.win.push(now);
      while (inp.win.length && now - inp.win[0] > 1000) inp.win.shift();
      if (inp.win.length > 25) { inp.ih++; inp.win = []; } // 25+ distinct presses in one second
    }
  }
  ['keydown', 'pointerdown', 'mousedown', 'touchstart', 'click'].forEach(function (t) {
    try { run(listenW, w, t, onInput, { capture: true, passive: true }); } catch (_) { /* no input stats then */ }
  });
  try { run(listenD, d, 'visibilitychange', function () { if (d.hidden) inp.h++; }); } catch (_) { /* ignore */ }

  // ---- session + beacons ----
  var session = null, gameTime = null, timer = null, firstBeacon = null;
  // The page clock is read live on purpose: if something has warped performance.now, the server should see the warp
  // (speed_hack) as well as the replacement (tampered_runtime). Everything else here uses the references taken at load.
  function pageClock() { try { return perf ? Math.round(perf.now()) : null; } catch (_) { return null; } }
  function signals() {
    return { wd: env.wd, hl: env.hl, au: env.au, tp: env.tp, dt: env.dt, ut: inp.ut, ih: inp.ih, k: inp.k, p: inp.p, h: inp.h,
      pt: pageClock(), gt: gameTime, sh: selfHash };
  }
  // Telemetry is sent in the clear under `signals`. It's advisory only: the server treats it as hints that can raise
  // risk, never as proof, because any client can send whatever it likes. (We used to XOR it with a per-session key,
  // but that key was handed to the browser, so it protected nothing and only made the wire format look clever.)
  function payload() {
    return { token: session.token, signals: signals() };
  }
  function post(path, body, beacon) {
    var json = stringify(body);
    if (beacon && typeof sendBeaconFn === 'function') {
      try { if (run(sendBeaconFn, nav, cfg.api + path, new Blob([json], { type: 'text/plain' }))) return Promise.resolve({ ok: true }); } catch (_) { /* fall through */ }
    }
    return run(fetchFn, w, cfg.api + path, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: json, keepalive: json.length < 60000, credentials: 'omit' })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'bad_response' }; }).then(function (j) { if (!r.ok && !j.error) j.error = 'http_' + r.status; return j; }); });
  }
  function beacon(useBeacon, force) {
    if (!session) return Promise.resolve();
    if (wallNow() > session.expiresAt) { api.stop(); return Promise.resolve(); }
    if (!force && d.hidden) return Promise.resolve(); // nothing to report from a background tab
    checkEnv();
    return post('/signal', payload(), useBeacon).catch(function () { /* offline: the verdict will say so */ });
  }

  var api = {
    version: '1.2.0',
    config: cfg,
    // Starts a new session (on page load, or when a protected flow begins). Resolves to { token, seed, session, expiresAt }.
    start: function (opts) {
      opts = opts || {};
      var site = opts.site || cfg.site;
      if (!site) return Promise.reject(new Error('Pyrmi: add data-site="pk_..." to the script tag'));
      checkEnv();
      return run(fetchFn, w, cfg.api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: stringify({ site: site }), credentials: 'omit' })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok || !j.ok) throw new Error('Pyrmi: ' + (j.message || j.error || r.status)); return j; }); })
        .then(function (j) {
          session = j; gameTime = null; resetInput();
          if (timer) run(clearIntervalFn, w, timer);
          if (firstBeacon) run(clearTimeoutFn, w, firstBeacon);
          firstBeacon = run(setTimeoutFn, w, function () { beacon(true); }, 1500);
          timer = run(setIntervalFn, w, function () { beacon(true); }, 10000);
          return { token: j.token, seed: j.seed, session: j.session, expiresAt: j.expiresAt };
        });
    },
    // Optional: report your app's own clock (seconds), e.g. a game or a timed quiz. The server compares it with real time.
    mark: function (seconds) { if (typeof seconds === 'number' && isFinite(seconds) && seconds >= 0) gameTime = seconds; },
    // Sends a last beacon and waits for it. Call before sending the action to your server.
    flush: function () { return beacon(false, true); },
    // Ends the session's beacons (e.g. back to the menu).
    stop: function () { if (timer) run(clearIntervalFn, w, timer); if (firstBeacon) run(clearTimeoutFn, w, firstBeacon); timer = firstBeacon = null; },
    token: function () { return session ? session.token : null; },
    // What this script has noticed so far, for showing players what's being checked.
    report: function () { checkEnv(); var s = signals(); delete s.pt; return s; },
  };
  checkEnv();
  // Frozen and read-only, so a later script can't swap out flush() or point cfg.api somewhere else.
  freeze(cfg);
  try { defineProp(w, 'Pyrmi', { value: freeze(api), enumerable: true }); } catch (_) { w.Pyrmi = api; }
})(window, document);
