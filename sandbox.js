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

  function post(token, value) {
    return fetch(api + '/demo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit',
      body: JSON.stringify({ token: token, value: value, visitor: visitor }) })
      .then(function (r) { return r.json(); });
  }

  function report(what, v) {
    if (!v || !v.ok) { show('info', 'error', null, [(v && (v.message || v.error)) || 'Couldn\'t reach the server.']); return; }
    var label = { accept: 'accepted', review: 'flagged', reject: 'rejected' }[v.verdict];
    var lines = v.reasons.map(function (r) { return r.text + (r.detail ? ' (' + r.detail + ')' : ''); });
    if (!lines.length) lines.push('No warning signs. Your server would go ahead.');
    lines.unshift(what);
    show(v.verdict, label, v.risk, lines);
  }

  function value() { var n = Number($('value').value); return $('value').value === '' ? null : n; }

  var ACTIONS = {
    honest: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['The browser script didn\'t load, so there\'s no session to send.']));
      var s = current;
      return Pyrmi.flush().then(function () { return post(s.token, value()); }).then(function (v) {
        last = s.token; report('Sent like a normal page would.', v);
      });
    },
    replay: function () {
      if (!last) return Promise.resolve(show('info', 'nothing yet', null, ['Send one normally first, then replay it.']));
      return post(last, value()).then(function (v) { report('Sent the exact same request again.', v); });
    },
    edit: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['No session to edit.']));
      var parts = current.token.split('.'), body = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      body.i -= 3600 * 1000; // pretend the session started an hour ago
      var forged = btoa(JSON.stringify(body)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') + '.' + parts[1];
      return Pyrmi.flush().then(function () { return post(forged, value()); }).then(function (v) { report('Edited the session token to look an hour old.', v); });
    },
    big: function () {
      if (!current) return Promise.resolve(show('info', 'offline', null, ['No session to send with.']));
      var s = current;
      return Pyrmi.flush().then(function () { return post(s.token, 999999); }).then(function (v) { last = s.token; report('Sent 999999 where the limit is 1000.', v); });
    },
    direct: function () {
      // what a scraper or a script does: grab a session straight from the API and use it at once, no page involved
      return fetch(api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, credentials: 'omit', body: JSON.stringify({ site: SITE }) })
        .then(function (r) { return r.json(); })
        .then(function (s) { if (!s.ok) throw new Error(s.message || s.error); return post(s.token, value()); })
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
