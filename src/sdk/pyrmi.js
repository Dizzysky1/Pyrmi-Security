/*! Pyrmi Security browser script · MIT License · https://pyrmi.com
 *
 *   <script src="https://pyrmi.com/sdk/pyrmi.js" data-site="pk_..."></script>
 *
 *   const s = await Pyrmi.start();     // when the page or a session begins: { token, seed, ... }
 *   Pyrmi.mark(appSeconds);            // optional, for apps with their own clock (games, timers): spots speed hacks
 *   await Pyrmi.flush();               // before you send the action to YOUR server
 *   const body = await Pyrmi.seal({ score: 42 }); // the action, signed: POST it to your server as JSON, unchanged
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

  // ---- trusted references, taken before any later page code can run ----
  // Everything this script calls for itself is captured here, once. run(fn, thisArg, a, b) calls fn through a bound
  // copy of the built-in call, so there's no property lookup at call time for a later hook (on .call, .apply,
  // .toString or the function itself) to step into. Code that ran before this script is caught by the checks below.
  var O = Object, FP = Function.prototype;
  var callFn = FP.call, bindFn = FP.bind, nativeToString = FP.toString;
  var run = bindFn.call(callFn, callFn);
  var gopd = O.getOwnPropertyDescriptor, gpo = O.getPrototypeOf, freeze = O.freeze, isFrozen = O.isFrozen, defineProp = O.defineProperty;
  // Whatever already sits at window.Pyrmi. The script used to skip itself whenever window.Pyrmi.version existed, so a
  // fake planted before it loaded switched it off. It's checked properly further down, once a trusted toString exists.
  var prior = null;
  try { prior = gopd(w, 'Pyrmi') || null; } catch (_) { prior = { configurable: false }; }
  var stringify = JSON.stringify, parse = JSON.parse, dateNow = Date.now, isArray = Array.isArray, objKeys = O.keys, fromCC = String.fromCharCode;
  // For signing actions (seal/sign): Web Crypto's HMAC, taken here like everything else.
  var wcrypto = w.crypto, subtle = wcrypto && wcrypto.subtle, U8 = w.Uint8Array, TE = w.TextEncoder;
  var importKeyFn = subtle && subtle.importKey, signFn = subtle && subtle.sign, encodeFn = TE && TE.prototype.encode;
  var atobFn = w.atob, btoaFn = w.btoa;
  var script = d.currentScript;
  var cfg = {
    site: script && script.getAttribute('data-site'),
    api: (script && script.getAttribute('data-api')) || (script && script.src ? new URL(script.src, location.href).origin : location.origin) + '/api/v1',
  };
  var nav = w.navigator || {};
  var perf = w.performance;
  var perfNow = perf && perf.now, fetchFn = w.fetch;
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
  // A third entry of 1 marks the ones that error trackers and frameworks (Sentry, zone.js/Angular, Datadog, New Relic)
  // wrap on ordinary sites: timers, fetch/XHR, event listeners and toString. Replacing those is reported apart, as a
  // "wrapped" built-in that adds little risk. The clocks, Math.random, call/apply/bind, the descriptor lookups and the
  // navigator getters aren't wrapped by those tools, so replacing them stays a "tampered" built-in at full weight.
  var WATCH = [
    ['performance.now', ['performance', 'now']], ['Date.now', ['Date', 'now']], ['requestAnimationFrame', ['requestAnimationFrame'], 1],
    ['setTimeout', ['setTimeout'], 1], ['setInterval', ['setInterval'], 1], ['Math.random', ['Math', 'random']], ['fetch', ['fetch'], 1],
    ['XMLHttpRequest.send', ['XMLHttpRequest', 'prototype', 'send'], 1], ['addEventListener', ['EventTarget', 'prototype', 'addEventListener'], 1],
    ['Function.toString', ['Function', 'prototype', 'toString'], 1], ['Function.call', ['Function', 'prototype', 'call']],
    ['Function.apply', ['Function', 'prototype', 'apply']], ['Function.bind', ['Function', 'prototype', 'bind']],
    ['Object.descriptor', ['Object', 'getOwnPropertyDescriptor']], ['Object.getPrototypeOf', ['Object', 'getPrototypeOf']],
    ['document.createElement', ['document', 'createElement']], ['iframe.contentWindow', ['HTMLIFrameElement', 'prototype', 'contentWindow']],
    ['navigator.webdriver', ['navigator', 'webdriver']], ['navigator.userAgent', ['navigator', 'userAgent']], ['navigator.languages', ['navigator', 'languages']],
    // The browser's own record of a real key press or click (can't be set by script), and the window sizes the devtools
    // hint reads. Replacing these to hide input or devtools is tampering in its own right.
    ['navigator.userActivation', ['navigator', 'userActivation']], ['UserActivation.hasBeenActive', ['UserActivation', 'prototype', 'hasBeenActive']],
    ['outerWidth', ['outerWidth']], ['innerWidth', ['innerWidth']], ['outerHeight', ['outerHeight']], ['innerHeight', ['innerHeight']],
  ];
  var WD = 17, UA = 18, LANGS = 19, UACT = 20, UHBA = 21, OW = 22, IW = 23, OH = 24, IH = 25; // indexes into WATCH
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
  // ---- a window.Pyrmi that was there before us ----
  // Our own copy (the same script included twice) is a frozen, read-only, non-configurable object whose methods are
  // text out of this very function. Anything else was planted: replace it if we can and report it. If it can't be
  // replaced (defined non-configurable by code that ran first), the page talks to the fake and nothing reaches the
  // server from us, which the server reads as no telemetry (or, if the fake makes some up, as unverified telemetry).
  function ours(desc) {
    try {
      if (!desc || !('value' in desc) || desc.writable || desc.configurable) return false;
      var v = desc.value, me = strOf(pyrmiMain), names = ['start', 'flush', 'mark', 'stop', 'token', 'report', 'sign', 'seal'];
      if (!v || typeof v !== 'object' || !isFrozen(v) || !me) return false;
      for (var ni = 0; ni < names.length; ni++) {
        var dv = gopd(v, names[ni]), src = dv && typeof dv.value === 'function' ? strOf(dv.value) : null;
        if (!src || src.length < 24 || me.indexOf(src) < 0) return false;
      }
      return true;
    } catch (_) { return false; }
  }
  var planted = false;
  if (prior) {
    if (ours(prior)) return; // already running
    if (!prior.configurable) return; // can't take the name back; see above
    planted = true;
  }

  var loaded = [];
  for (var li = 0; li < WATCH.length; li++) { try { loaded.push(locate(w, WATCH[li][1])); } catch (_) { loaded.push(null); } }
  // Reads a navigator property through the getter captured at load, not whatever a later script put in its place.
  function navRead(i) {
    var l = loaded[i];
    if (!l) return undefined;
    try { return l.acc ? (l.fn ? run(l.fn, nav) : undefined) : nav[WATCH[i][1][1]]; } catch (_) { return undefined; }
  }
  // Window sizes through the getters captured at load, so a later spoof of outerWidth/innerWidth doesn't change the reading.
  function winRead(i) {
    var l = loaded[i];
    if (!l) return 0;
    try { return Number(l.acc ? (l.fn ? run(l.fn, w) : 0) : w[WATCH[i][1][0]]) || 0; } catch (_) { return 0; }
  }
  // navigator.userActivation.hasBeenActive through the load-time getters: true once the person has really pressed a key
  // or clicked, whatever any script does with events. null where the browser doesn't have it.
  function activation() {
    var l = loaded[UACT], g = loaded[UHBA], o;
    if (!l) return null;
    try {
      o = l.acc ? (l.fn ? run(l.fn, nav) : null) : nav.userActivation;
      if (!o) return null;
      if (g && g.acc && g.fn) return run(g.fn, o) === true;
      return o.hasBeenActive === true;
    } catch (_) { return null; }
  }
  var activeAtLoad = activation();

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
  var env = { wd: false, hl: false, au: [], tp: [], wr: [], dt: 0 };
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
    if (planted) addOnce(env.tp, 'window.Pyrmi');
    // Input hidden from us: the browser says the person pressed or clicked since we loaded, but none of it reached our
    // listeners (a capture listener that ran first and stopped it). Checked again a moment later, so a beacon sent from
    // inside the very first event's dispatch, before our listener's turn, isn't mistaken for it.
    var act = activation();
    if (act === true && activeAtLoad === false && inputSeen === 0) {
      if (!hidePending) { hidePending = clock() || 1; try { run(setTimeoutFn, w, checkEnv, 150); } catch (_) { /* next beacon */ } }
      else if (clock() - hidePending > 100) addOnce(env.tp, 'input.hidden');
    }
    // Our own checks never rely on the page's toString, so a replaced one (Sentry and zone.js both patch it) is only "wrapped".
    if (toStrReplaced) addOnce(env.wr, 'Function.toString');
    for (var i = 0; i < WATCH.length; i++) {
      var hit;
      try { hit = tampered(i); } catch (_) { hit = true; }
      if (hit) addOnce(WATCH[i][2] ? env.wr : env.tp, WATCH[i][0]);
    }
    // devtools: a docked panel shrinks the page well below the window. A rough hint, so it only adds a little risk.
    try {
      var gw = winRead(OW) - winRead(IW), gh = winRead(OH) - winRead(IH);
      if (winRead(OW) && (gw > 200 || gh > 260) && !/Mobile|Android/.test(String(navRead(UA) || ''))) env.dt++;
    } catch (_) { /* ignore */ }
  }

  // ---- input watching (per session) ----
  var inp, inputSeen = 0, hidePending = 0; // inputSeen: real input events we've seen since load (never reset)
  function resetInput() { inp = { ut: 0, ih: 0, k: 0, p: 0, h: 0, lastKey: 0, gaps: [], win: [] }; }
  resetInput();
  function onInput(e) {
    if (!e.isTrusted) { inp.ut++; return; }
    inputSeen++;
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
  // The other halves of presses and clicks: scripted ones count as synthetic too (a bot that only fakes keyup or
  // pointerup used to go unseen). Form events (input, change) are left alone: password managers fire those by script.
  function onOther(e) { if (!e.isTrusted) inp.ut++; else inputSeen++; }
  ['keyup', 'keypress', 'pointerup', 'mouseup', 'touchend', 'dblclick', 'contextmenu', 'wheel'].forEach(function (t) {
    try { run(listenW, w, t, onOther, { capture: true, passive: true }); } catch (_) { /* no input stats then */ }
  });
  try { run(listenD, d, 'visibilitychange', function () { if (d.hidden) inp.h++; }); } catch (_) { /* ignore */ }

  // ---- session + beacons ----
  var session = null, gameTime = null, timer = null, firstBeacon = null, seq = 0, skew = 0;
  // The page clock is read live on purpose: if something has warped performance.now, the server should see the warp
  // (speed_hack) as well as the replacement (tampered_runtime). Everything else here uses the references taken at load.
  function pageClock() { try { return perf ? Math.round(perf.now()) : null; } catch (_) { return null; } }
  function signals() {
    return { wd: env.wd, hl: env.hl, au: env.au, tp: env.tp, wr: env.wr, dt: env.dt, ut: inp.ut, ih: inp.ih, k: inp.k, p: inp.p, h: inp.h,
      pt: pageClock(), gt: gameTime, sh: selfHash, ac: activation() };
  }
  // Telemetry is sent in the clear under `signals`. It's advisory only: the server treats it as hints that can raise
  // risk, never as proof, because any client can send whatever it likes. (We used to XOR it with a per-session key,
  // but that key was handed to the browser, so it protected nothing and only made the wire format look clever.)
  // bn and n tie each beacon to this session and put them in order, so a beacon copied from another session, or sent
  // twice, is refused. They're not a secret (this script holds them), so they don't make a beacon trustworthy.
  function payload() {
    seq++;
    return { token: session.token, bn: session.bn, n: seq, signals: signals() };
  }
  function post(path, body, beacon) {
    // Always fetch (keepalive), never sendBeacon: sendBeacon goes out in no-cors mode, where a site's Referrer-Policy can
    // turn the Origin header into "null" while /session (cors) carried the real one, and the server compares the two.
    var json = stringify(body);
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

  // ---- signed actions ----
  // The server hands each session a request key (rk) that only this script holds: it's not in the token, and start()
  // doesn't return it. sign() uses it to sign the action the page is about to send, so the server can tell the action
  // arrived exactly as the page built it: a value rewritten on the wire (a proxy, a debugger's Fetch interception) or a
  // token lifted out of a request and replayed with other fields fails. It does not stop code running in this page from
  // asking for a signature on whatever it likes; that is what the server's own limits are for.
  // The signed form is JSON with sorted keys at every level (canon), the same one the server rebuilds from the JSON it
  // received, and the timestamp is on the server's clock (the offset learned at start), so a wrong device clock is fine.
  function canon(v) {
    var i, out = [], keys;
    if (isArray(v)) {
      for (i = 0; i < v.length; i++) out.push(v[i] === undefined ? 'null' : canon(v[i]));
      return '[' + out.join(',') + ']';
    }
    if (v && typeof v === 'object') {
      keys = objKeys(v).sort();
      for (i = 0; i < keys.length; i++) if (v[keys[i]] !== undefined) out.push(stringify(keys[i]) + ':' + canon(v[keys[i]]));
      return '{' + out.join(',') + '}';
    }
    var j = stringify(v);
    return j === undefined ? 'null' : j;
  }
  function fromB64u(s) {
    var b = run(atobFn, w, s.replace(new RegExp('-', 'g'), '+').replace(new RegExp('_', 'g'), '/') + '===='.slice(0, (4 - s.length % 4) % 4));
    var u = new U8(b.length);
    for (var bi = 0; bi < b.length; bi++) u[bi] = b.charCodeAt(bi);
    return u;
  }
  function toB64u(buf) {
    var u = new U8(buf), str = '';
    for (var ui = 0; ui < u.length; ui++) str += run(fromCC, String, u[ui]);
    return run(btoaFn, w, str).replace(new RegExp('[+]', 'g'), '-').replace(new RegExp('/', 'g'), '_').replace(new RegExp('=+$'), '');
  }
  // The action as the server will see it: plain JSON (a Date becomes its string, undefined goes away).
  function plainObject(fields) {
    var plain = parse(stringify(fields === undefined ? {} : fields));
    if (!plain || typeof plain !== 'object' || isArray(plain)) throw new Error('Pyrmi: sign an object, like { score: 42 }');
    return plain;
  }
  function signPlain(plain) {
    if (!session || !session.rk) return Promise.reject(new Error('Pyrmi: call start() before signing'));
    if (!subtle || !importKeyFn || !signFn || !TE || !U8) return Promise.reject(new Error('Pyrmi: signing needs a secure (https) page'));
    var s = session, ts = Math.round(wallNow() + skew);
    var msg = 'pyrmi.req.v1\n' + s.session + '\n' + ts + '\n' + canon(plain);
    return run(importKeyFn, subtle, 'raw', fromB64u(s.rk), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
      .then(function (key) { return run(signFn, subtle, 'HMAC', key, run(encodeFn, new TE(), msg)); })
      .then(function (mac) { return { token: s.token, ts: ts, sig: toB64u(mac) }; });
  }

  // beacon protocol: 3 (what the beacons carry; scripts/build-sdk.js reads this. Bump it when the server starts
  // needing something older builds don't send.)
  var api = {
    version: '1.4.0',
    config: cfg,
    // Starts a new session (on page load, or when a protected flow begins). Resolves to { token, seed, session, expiresAt }.
    start: function (opts) {
      opts = opts || {};
      var site = opts.site || cfg.site;
      if (!site) return Promise.reject(new Error('Pyrmi: add data-site="pk_..." to the script tag'));
      checkEnv();
      return run(fetchFn, w, cfg.api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: stringify({ site: site, pt: Math.floor(clock()) }), credentials: 'omit' })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok || !j.ok) throw new Error('Pyrmi: ' + (j.message || j.error || r.status)); return j; }); })
        .then(function (j) {
          session = j; gameTime = null; seq = 0; resetInput();
          skew = Number(j.issuedAt) > 0 ? Number(j.issuedAt) - wallNow() : 0;
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
    // Signs an action for this session: resolves to { token, ts, sig } over exactly these fields. Send all three with
    // the fields, and have your server pass them to Pyrmi (pyrmi-server does it from a sealed body). Most pages want seal().
    sign: function (fields) {
      try { var plain = plainObject(fields); if ('pyrmi' in plain) throw new Error('Pyrmi: "pyrmi" is reserved for the signature'); return signPlain(plain); } catch (e) { return Promise.reject(e); }
    },
    // Seals an action: resolves to a copy of it with pyrmi: { token, ts, sig } added. POST that as JSON to your server
    // as it is; if anything in it changes on the way, the verdict is reject (bad_signature).
    seal: function (fields) {
      try {
        var plain = plainObject(fields);
        delete plain.pyrmi;
        return signPlain(plain).then(function (p) { plain.pyrmi = p; return plain; });
      } catch (e) { return Promise.reject(e); }
    },
    // What this script has noticed so far, for showing players what's being checked.
    report: function () { checkEnv(); var s = signals(); delete s.pt; return s; },
  };
  checkEnv();
  // Frozen and read-only, so a later script can't swap out flush() or point cfg.api somewhere else.
  freeze(cfg);
  try { defineProp(w, 'Pyrmi', { value: freeze(api), enumerable: true }); } catch (_) { w.Pyrmi = api; }
})(window, document);
