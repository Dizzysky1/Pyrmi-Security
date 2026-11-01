/* The sandbox on the Pyrmi Security homepage: send a protected action the honest way or try one of the usual cheats,
   and see the verdict your server would get. Each button really does what it says; nothing is faked on the page. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var SITE = 'pk_demo_sandbox';
  var api = (window.Pyrmi && document.querySelector('script[data-site]') && document.querySelector('script[data-site]').getAttribute('data-api')) || '/api/v1';
  var visitor = 'visitor-' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
  try { visitor = localStorage.getItem('pyrmi_visitor') || visitor; localStorage.setItem('pyrmi_visitor', visitor); } catch (e) { /* private mode */ }

  var current = null, last = null, busy = false;
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  function fresh() {
    current = null;
    if (!window.Pyrmi) return Promise.resolve(null);
    return Pyrmi.start().then(function (s) { current = s; return s; }, function () { return null; });
  }

  function show(chip, label, risk, lines) {
    $('verdict').hidden = false;
    var c = $('v-chip'); c.className = 'chip ' + chip; c.textContent = label;
    $('v-risk-n').textContent = risk == null ? '' : 'risk ' + risk;
    $('v-risk').style.width = (risk == null ? 0 : risk) + '%';
    $('v-reasons').innerHTML = lines.map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('');
  }

  // The sandbox project has requireHumanCheck on, so `trusted` needs a human check Pyrmi confirms with Cloudflare itself,
  // solved for this session on this page. The honest button runs it the way a site should: a Turnstile widget rendered with cdata set to the session
  // id, its token sealed with the action. When the server has no Turnstile key (GET /me says), the check is skipped and
  // the verdict says trusted is false. The cheat buttons skip it, as a script would.
  var tsKey = null, tsLoad = null;
  var tsInfo = fetch(api + '/me', { credentials: 'omit' }).then(function (r) { return r.json(); })
    .then(function (j) { tsKey = (j && j.turnstile) || null; }, function () { tsKey = null; });
  function turnstileReady() {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (!tsLoad) tsLoad = new Promise(function (resolve, reject) {
      var sc = document.createElement('script');
      sc.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; sc.async = true;
      sc.onload = function () { if (window.turnstile) resolve(window.turnstile); else reject(new Error('The human check didn\'t load.')); };
      sc.onerror = function () { tsLoad = null; reject(new Error('The human check didn\'t load.')); };
      document.head.appendChild(sc);
    });
    return tsLoad;
  }
  function humanCheck() {
    return tsInfo.then(function () {
      if (!tsKey || !current || !current.session) return undefined;
      return turnstileReady().then(function (ts) {
        return new Promise(function (resolve, reject) {
          var el = $('sb-ts'), old = el.getAttribute('data-wid');
          if (old) { try { ts.remove(old); } catch (e) { /* already gone */ } }
          var fail = function () { reject(new Error('The human check didn\'t finish. Try again.')); };
          el.setAttribute('data-wid', ts.render(el, { sitekey: tsKey, action: 'sandbox', cData: current.session, appearance: 'interaction-only',
            callback: resolve, 'error-callback': fail, 'timeout-callback': fail }));
        });
      });
    });
  }

  // The action is sealed by the browser script (Pyrmi.seal), the way a site's page should send anything that matters:
  // { value, visitor, turnstile?, pyrmi: { token, ts, sig } }. Change any of it after sealing and the signature stops
  // matching.
  function seal(value, turnstile) {
    return Pyrmi.flush().then(function () {
      var action = { value: value, visitor: visitor };
      if (turnstile) action.turnstile = turnstile;
      return Pyrmi.seal(action);
    });
  }
  function post(body) {
    return fetch(api + '/demo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit', body: JSON.stringify(body) })
      .then(function (r) { return r.json(); });
  }

  function report(what, v) {
    if (!v || !v.ok) { show('info', 'error', null, [(v && (v.message || v.error)) || 'Couldn\'t reach the server.']); return; }
    var label = { accept: 'accepted', review: 'flagged', reject: 'rejected' }[v.verdict];
    var lines = v.reasons.map(function (r) { return r.text + (r.detail ? ' (' + r.detail + ')' : ''); });
    if (!lines.length) lines.push('No warning signs. Your server would go ahead.');
    if (v.client) lines.push(v.trusted === true
      ? 'The action was signed by this browser and the human check passed for this session: trusted(v) is true, so a sensitive action (a prize, a payout) would go ahead too.'
      : 'trusted(v) is false: a sensitive action (a prize, a payout) would be refused.' + (v.verdict === 'accept' && v.human !== 'ok' ? ' Without a passed human check, an accept is the best a verdict gets.' : ''));
    lines.unshift(what);
    show(v.verdict, label, v.risk, lines);
  }

  function value() { var n = Number($('value').value); return $('value').value === '' ? null : n; }

  var ACTIONS = {
    honest: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['The browser script didn\'t load, so there\'s no session to send.']));
      return humanCheck().then(function (t) { return seal(value(), t); }).then(function (b) { last = b; return post(b); })
        .then(function (v) { report(tsKey ? 'Sent like a normal page would, with the human check.' : 'Sent like a normal page would (the human check isn\'t set up on this server).', v); });
    },
    replay: function () {
      if (!last) return Promise.resolve(show('info', 'nothing yet', null, ['Send one normally first, then replay it.']));
      return post(last).then(function (v) { report('Sent the exact same request again.', v); });
    },
    edit: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['No session to edit.']));
      var parts = current.token.split('.'), body = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      body.i -= 3600 * 1000; // pretend the session started an hour ago
      var forged = btoa(JSON.stringify(body)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') + '.' + parts[1];
      return seal(value()).then(function (b) { b.pyrmi = { token: forged, ts: b.pyrmi.ts, sig: b.pyrmi.sig }; return post(b); })
        .then(function (v) { report('Edited the session token to look an hour old.', v); });
    },
    big: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['No session to send with.']));
      return seal(999999).then(function (b) { last = b; return post(b); }).then(function (v) { report('Sent 999999 where the limit is 1000.', v); });
    },
    rewrite: function () {
      // what a proxy or a debugger on the wire does: the page signs one value, and a different one goes out
      if (!current) return Promise.resolve(show('info', 'offline', null, ['No session to send with.']));
      var asked = value() === null ? 1 : value();
      return seal(asked).then(function (b) { b.value = asked + 33; last = b; return post(b); })
        .then(function (v) { report('The page signed ' + asked + ', then ' + (asked + 33) + ' was sent instead.', v); });
    },
    direct: function () {
      // what a scraper or a script does: grab a session straight from the API and use it at once, no page involved
      return fetch(api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, credentials: 'omit', body: JSON.stringify({ site: SITE }) })
        .then(function (r) { return r.json(); })
        .then(function (s) { if (!s.ok) throw new Error(s.message || s.error); return post({ value: value(), visitor: visitor, pyrmi: { token: s.token } }); })
        .then(function (v) { report('Called the API directly, with no page behind it.', v); });
    },
  };

  Array.prototype.forEach.call(document.querySelectorAll('[data-act]'), function (b) {
    b.addEventListener('click', function () {
      if (busy) return;
      busy = true; show('info', 'checking…', null, ['Asking Pyrmi for a verdict…']);
      Promise.resolve().then(ACTIONS[b.getAttribute('data-act')])
        .catch(function (e) { show('info', 'error', null, [String(e && e.message || 'Something went wrong.')]); })
        .then(function () { return b.getAttribute('data-act') === 'replay' ? null : fresh(); }) // tokens are single use
        .then(function () { busy = false; });
    });
  });

  // live view of the signals the browser script reports
  var LIVE = [
    ['automation', function (r) { return r.wd || r.hl || r.au.length ? (r.au.join(', ') || (r.wd ? 'webdriver' : 'headless')) : ''; }],
    ['devtools', function (r) { return r.dt ? 'probably open' : ''; }],
    ['replaced built-ins', function (r) { return r.tp.length ? r.tp.join(', ') : ''; }],
    ['wrapped built-ins', function (r) { return r.wr && r.wr.length ? r.wr.join(', ') : ''; }],
    ['scripted input', function (r) { return r.ut ? r.ut + ' events' : ''; }],
    ['inhuman input', function (r) { return r.ih ? r.ih + ' bursts' : ''; }],
  ];
  function live() {
    if (!window.Pyrmi) { $('live').innerHTML = '<li>script blocked or not loaded</li>'; return; }
    var r = Pyrmi.report();
    $('live').innerHTML = LIVE.map(function (x) { var v = x[1](r); return '<li><span>' + x[0] + '</span><span class="' + (v ? 'on' : 'off') + '">' + esc(v || 'clear') + '</span></li>'; }).join('');
  }
  live(); setInterval(live, 2000);
  fresh();
})();
