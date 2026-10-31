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

  var script = d.currentScript;
  var cfg = {
    site: script && script.getAttribute('data-site'),
    api: (script && script.getAttribute('data-api')) || (script && script.src ? new URL(script.src, location.href).origin : location.origin) + '/api/v1',
  };
  var nav = w.navigator || {};
  var perf = w.performance;

  // FNV-1a over a string, as 8 hex digits. Used for this script's own fingerprint.
  function fnv(str) {
    var h = 0x811c9dc5;
    for (var i = 0; i < str.length; i++) { h ^= str.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  }
  var selfHash = null;
  try { selfHash = fnv(String(pyrmiMain)); } catch (_) { selfHash = 'unreadable'; }

  // ---- environment checks (once, plus re-checks on a timer) ----
  var env = { wd: false, hl: false, au: [], tp: [], dt: 0 };
  function addOnce(list, v) { if (list.indexOf(v) < 0) list.push(v); }
  function checkEnv() {
    try {
      if (nav.webdriver) env.wd = true;
      var ua = String(nav.userAgent || '');
      if (/HeadlessChrome|PhantomJS|SlimerJS/i.test(ua)) env.hl = true;
      if (/Chrome\//.test(ua) && !/Mobile|Android/.test(ua) && nav.languages && nav.languages.length === 0) env.hl = true;
      var marks = { __playwright__binding__: 'playwright', __pwInitScripts: 'playwright', _phantom: 'phantom', callPhantom: 'phantom',
        __nightmare: 'nightmare', domAutomation: 'chromedriver', domAutomationController: 'chromedriver', _selenium: 'selenium',
        __webdriver_evaluate: 'selenium', __selenium_unwrapped: 'selenium', __lastWatirAlert: 'watir', Cypress: 'cypress', __puppeteer_evaluation_script__: 'puppeteer' };
      for (var k in marks) if (k in w) addOnce(env.au, marks[k]);
      if (d.documentElement && (d.documentElement.getAttribute('webdriver') || d.documentElement.getAttribute('selenium'))) addOnce(env.au, 'selenium');
    } catch (_) { /* never break the page */ }
    // built-ins that speed hacks and cheat scripts like to replace
    var natives = [
      ['performance.now', perf && perf.now], ['Date.now', Date.now], ['requestAnimationFrame', w.requestAnimationFrame],
      ['setTimeout', w.setTimeout], ['setInterval', w.setInterval], ['Math.random', Math.random], ['fetch', w.fetch],
      ['XMLHttpRequest.send', w.XMLHttpRequest && w.XMLHttpRequest.prototype.send], ['addEventListener', EventTarget.prototype.addEventListener],
    ];
    var toStr = Function.prototype.toString;
    try { if (!/\[native code\]\s*\}\s*$/.test(toStr.call(toStr))) addOnce(env.tp, 'Function.toString'); } catch (_) { addOnce(env.tp, 'Function.toString'); }
    for (var i = 0; i < natives.length; i++) {
      var f = natives[i][1];
      if (typeof f !== 'function') continue;
      try { if (!/\[native code\]\s*\}\s*$/.test(toStr.call(f))) addOnce(env.tp, natives[i][0]); } catch (_) { addOnce(env.tp, natives[i][0]); }
    }
    // devtools: a docked panel shrinks the page well below the window. A rough hint, so it only adds a little risk.
    try {
      var gw = w.outerWidth - w.innerWidth, gh = w.outerHeight - w.innerHeight;
      if (w.outerWidth && (gw > 200 || gh > 260) && !/Mobile|Android/.test(nav.userAgent)) env.dt++;
    } catch (_) { /* ignore */ }
  }

  // ---- input watching (per session) ----
  var inp;
  function resetInput() { inp = { ut: 0, ih: 0, k: 0, p: 0, h: 0, lastKey: 0, gaps: [], win: [] }; }
  resetInput();
  function onInput(e) {
    if (!e.isTrusted) { inp.ut++; return; }
    var now = perf ? perf.now() : Date.now();
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
    w.addEventListener(t, onInput, { capture: true, passive: true });
  });
  d.addEventListener('visibilitychange', function () { if (d.hidden) inp.h++; });

  // ---- session + beacons ----
  var session = null, gameTime = null, timer = null, firstBeacon = null;
  function signals() {
    return { wd: env.wd, hl: env.hl, au: env.au, tp: env.tp, dt: env.dt, ut: inp.ut, ih: inp.ih, k: inp.k, p: inp.p, h: inp.h,
      pt: perf ? Math.round(perf.now()) : null, gt: gameTime, sh: selfHash };
  }
  // Telemetry is sent in the clear under `signals`. It's advisory only: the server treats it as hints that can raise
  // risk, never as proof, because any client can send whatever it likes. (We used to XOR it with a per-session key,
  // but that key was handed to the browser, so it protected nothing and only made the wire format look clever.)
  function payload() {
    return { token: session.token, signals: signals() };
  }
  function post(path, body, beacon) {
    var json = JSON.stringify(body);
    if (beacon && nav.sendBeacon) {
      try { if (nav.sendBeacon(cfg.api + path, new Blob([json], { type: 'text/plain' }))) return Promise.resolve({ ok: true }); } catch (_) { /* fall through */ }
    }
    return fetch(cfg.api + path, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: json, keepalive: json.length < 60000, credentials: 'omit' })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'bad_response' }; }).then(function (j) { if (!r.ok && !j.error) j.error = 'http_' + r.status; return j; }); });
  }
  function beacon(useBeacon, force) {
    if (!session) return Promise.resolve();
    if (Date.now() > session.expiresAt) { api.stop(); return Promise.resolve(); }
    if (!force && d.hidden) return Promise.resolve(); // nothing to report from a background tab
    checkEnv();
    return post('/signal', payload(), useBeacon).catch(function () { /* offline: the verdict will say so */ });
  }

  var api = {
    version: '1.1.0',
    config: cfg,
    // Starts a new session (on page load, or when a protected flow begins). Resolves to { token, seed, session, expiresAt }.
    start: function (opts) {
      opts = opts || {};
      var site = opts.site || cfg.site;
      if (!site) return Promise.reject(new Error('Pyrmi: add data-site="pk_..." to the script tag'));
      checkEnv();
      return fetch(cfg.api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: JSON.stringify({ site: site }), credentials: 'omit' })
        .then(function (r) { return r.json().then(function (j) { if (!r.ok || !j.ok) throw new Error('Pyrmi: ' + (j.message || j.error || r.status)); return j; }); })
        .then(function (j) {
          session = j; gameTime = null; resetInput();
          if (timer) clearInterval(timer);
          if (firstBeacon) clearTimeout(firstBeacon);
          firstBeacon = setTimeout(function () { beacon(true); }, 1500);
          timer = setInterval(function () { beacon(true); }, 10000);
          return { token: j.token, seed: j.seed, session: j.session, expiresAt: j.expiresAt };
        });
    },
    // Optional: report your app's own clock (seconds), e.g. a game or a timed quiz. The server compares it with real time.
    mark: function (seconds) { if (typeof seconds === 'number' && isFinite(seconds) && seconds >= 0) gameTime = seconds; },
    // Sends a last beacon and waits for it. Call before sending the action to your server.
    flush: function () { return beacon(false, true); },
    // Ends the session's beacons (e.g. back to the menu).
    stop: function () { if (timer) clearInterval(timer); if (firstBeacon) clearTimeout(firstBeacon); timer = firstBeacon = null; },
    token: function () { return session ? session.token : null; },
    // What this script has noticed so far, for showing players what's being checked.
    report: function () { checkEnv(); var s = signals(); delete s.pt; return s; },
  };
  checkEnv();
  w.Pyrmi = api;
})(window, document);
