/* The sandbox on the Pyrmi Security homepage: send a protected action the honest way or try one of the usual cheats,
   and see the request that went out and the verdict your server would get. Each button really does what it says;
   nothing is faked on the page. Everything shown that came from the server or the page is set with textContent. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var SITE = 'pk_demo_sandbox';
  var api = (window.Pyrmi && document.querySelector('script[data-site]') && document.querySelector('script[data-site]').getAttribute('data-api')) || '/api/v1';
  var visitor = 'visitor-' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
  try { visitor = localStorage.getItem('pyrmi_visitor') || visitor; localStorage.setItem('pyrmi_visitor', visitor); } catch (e) { /* private mode */ }

  var current = null, last = null, lastN = 0, busy = false, sent = 0;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = String(text);
    return n;
  }
  function clear(n) { while (n.firstChild) n.removeChild(n.firstChild); return n; }
  function has(o, k) { return o != null && Object.prototype.hasOwnProperty.call(o, k); }
  function short(s) { s = String(s); return s.length > 30 ? s.slice(0, 16) + '…' + s.slice(-8) : s; }

  function fresh() {
    current = null; sid();
    if (!window.Pyrmi) return Promise.resolve(null);
    return Pyrmi.start().then(function (s) { current = s; sid(); return s; }, function () { sid(); return null; });
  }
  function sid() {
    var s = $('sb-sid'); if (!s) return;
    s.textContent = current && current.session ? short(current.session) : window.Pyrmi ? 'starting…' : 'none (script blocked)';
  }
  function state(cls, text) { var c = $('sb-state'); c.className = 'con-state chip ' + cls; c.textContent = text; }

  // ---- the request pane: the body as it went out, with whatever was tampered marked on its line ----
  // marks: { field: { cls: 'bad' | 'warn', note } }, for value, visitor, turnstile, token, ts, sig.
  function wire(body, marks, banner, note) {
    var pre = clear($('sb-req')); marks = marks || {};
    function line(depth, key, val, mark, comma) {
      var ln = el('span', 'ln' + (mark ? ' ' + mark.cls : ''));
      ln.appendChild(document.createTextNode('  '.repeat(depth)));
      ln.appendChild(el('span', 'key', JSON.stringify(key) + ': '));
      ln.appendChild(el('span', 'val', typeof val === 'string' ? JSON.stringify(short(val)) : JSON.stringify(val)));
      if (comma) ln.appendChild(document.createTextNode(','));
      if (mark && mark.note) ln.appendChild(el('span', 'wn', mark.note));
      pre.appendChild(ln);
    }
    function raw(text, cls) { pre.appendChild(el('span', 'ln' + (cls ? ' ' + cls : ''), text)); }
    raw('POST ' + api + '/demo', 'hd');
    raw('Content-Type: application/json', 'key');
    raw(' ');
    raw('{');
    var keys = Object.keys(body).filter(function (k) { return k !== 'pyrmi'; });
    keys.forEach(function (k, i) { line(1, k, body[k], has(marks, k) ? marks[k] : null, i < keys.length - 1 || !!body.pyrmi); });
    if (body.pyrmi) {
      raw('  "pyrmi": {');
      var pk = Object.keys(body.pyrmi);
      pk.forEach(function (k, i) { line(2, k, body.pyrmi[k], has(marks, k) ? marks[k] : null, i < pk.length - 1); });
      if (!('sig' in body.pyrmi)) raw('    // no ts, no sig: nothing on a page sealed this', 'miss');
      raw('  }');
    }
    raw('}');
    var b = $('sb-banner'); b.textContent = banner || ''; b.className = 'wire-banner' + (banner ? ' on' : '');
    $('sb-req-note').textContent = note || '';
  }

  // ---- the verdict pane ----
  // A verdict from the server is used as a class name or a lookup key only if it's one of the three known words.
  var WORD = { accept: 'accepted', review: 'flagged', reject: 'rejected' };
  function vk(v) { return has(WORD, v) ? v : 'info'; }
  function fact(i, text, cls) { var dd = $('v-facts').querySelectorAll('dd')[i]; dd.textContent = text; dd.className = cls || 'meh'; }
  function facts(v, ms) {
    if (!v) { for (var i = 0; i < 6; i++) fact(i, '–'); return; }
    fact(0, v.trusted === true ? 'true' : 'false', v.trusted === true ? 'blue' : 'meh');
    fact(1, v.client || '–', v.client === 'corroborated' ? 'yes' : v.client ? 'no' : 'meh');
    fact(2, v.signed === 'ok' ? 'valid' : v.signed === 'bad' ? 'broken' : v.signed || '–', v.signed === 'ok' ? 'yes' : v.signed === 'bad' ? 'no' : 'meh');
    fact(3, v.bound === true ? 'yes' : v.bound === false ? 'no' : '–', v.bound === true ? 'yes' : 'meh');
    fact(4, v.human === 'ok' ? 'passed' : v.human || '–', v.human === 'ok' ? 'yes' : v.human === 'failed' ? 'no' : 'meh');
    fact(5, ms == null ? '–' : Math.round(ms) + ' ms', 'meh');
  }
  function summary(lines) {
    var p = $('v-sum'); clear(p); p.hidden = !lines.length;
    lines.forEach(function (t, i) { if (i) p.appendChild(document.createTextNode(' ')); p.appendChild(i === 0 ? el('b', null, t) : document.createTextNode(t)); });
  }

  // An info state: an error, an empty precondition, or "checking…".
  function show(chip, label, risk, lines) {
    var box = $('verdict'); box.setAttribute('data-v', 'info'); box.removeAttribute('data-trusted');
    $('v-word').textContent = label;
    var c = $('v-chip'); c.className = 'chip ' + chip + (label === 'checking…' ? ' busy' : ''); c.textContent = chip === 'info' ? (label === 'checking…' ? 'pending' : 'no verdict') : chip;
    $('v-trust').hidden = true;
    $('v-risk-n').textContent = risk == null ? '–' : risk;
    $('v-risk').value = risk == null ? 0 : risk;
    facts(null);
    summary(lines);
    clear($('v-reasons'));
  }

  function verdict(what, v, ms) {
    var k = vk(v.verdict);
    var box = $('verdict'); box.setAttribute('data-v', k);
    box.setAttribute('data-trusted', v.trusted === true ? 'yes' : 'no');
    $('v-word').textContent = k === 'info' ? String(v.verdict) : WORD[k];
    var c = $('v-chip'); c.className = 'chip ' + k; c.textContent = String(v.verdict);
    var t = $('v-trust'); t.hidden = false;
    t.className = 'chip ' + (v.trusted === true ? 'trusted' : 'untrusted'); t.textContent = v.trusted === true ? 'trusted' : 'not trusted';
    var risk = Math.max(0, Math.min(100, Number(v.risk) || 0));
    $('v-risk-n').textContent = risk;
    $('v-risk').value = risk;
    facts(v, ms);
    var lines = [what];
    if (!v.reasons.length) lines.push('No warning signs. Your server would go ahead.');
    if (v.client) lines.push(v.trusted === true
      ? 'The action was signed by this browser and the human check passed for this session: trusted(v) is true, so a sensitive action (a prize, a payout) would go ahead too.'
      : 'trusted(v) is false: a sensitive action (a prize, a payout) would be refused.' + (v.verdict === 'accept' && v.human !== 'ok' ? ' Without a passed human check, an accept is the best a verdict gets.' : ''));
    summary(lines);
    var ul = clear($('v-reasons'));
    if (!v.reasons.length) { ul.appendChild(el('li', 'clean', 'No reasons fired.')); }
    v.reasons.forEach(function (r) {
      var li = el('li');
      li.appendChild(el('code', null, r.code));
      li.appendChild(el('span', 'txt', (r.text || r.code) + (r.detail ? ' (' + r.detail + ')' : '')));
      var w = Number(r.weight), hard = w >= 100;
      var ws = el('span', 'w' + (hard ? ' hard' : ''), hard ? 'hard' : Number.isFinite(w) ? '+' + w : '');
      li.appendChild(ws);
      ul.appendChild(li);
    });
  }

  // ---- the log: one line per request on this page, newest first ----
  var NAMES = { honest: 'sent normally', replay: 'replayed', edit: 'edited token', big: 'impossible value', rewrite: 'changed on the wire', direct: 'direct API call' };
  function log(act, v) {
    var ol = $('sb-log'), empty = ol.querySelector('.empty');
    if (empty) ol.removeChild(empty);
    var li = el('li'), d = new Date();
    li.appendChild(el('span', 't', [d.getHours(), d.getMinutes(), d.getSeconds()].map(function (x) { return String(x).padStart(2, '0'); }).join(':')));
    li.appendChild(el('span', null, '#' + sent + ' ' + (has(NAMES, act) ? NAMES[act] : act)));
    var ok = v && v.ok && vk(v.verdict) !== 'info';
    li.appendChild(el('span', 'chip ' + (ok ? vk(v.verdict) : 'info'), ok ? v.verdict : 'error'));
    li.appendChild(el('span', 'r', ok ? Number(v.risk) || 0 : '–'));
    ol.insertBefore(li, ol.firstChild);
    while (ol.children.length > 8) ol.removeChild(ol.lastChild);
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
          var box = $('sb-ts'), old = box.getAttribute('data-wid');
          if (old) { try { ts.remove(old); } catch (e) { /* already gone */ } }
          var fail = function () { reject(new Error('The human check didn\'t finish. Try again.')); };
          box.setAttribute('data-wid', ts.render(box, { sitekey: tsKey, action: 'sandbox', cData: current.session, appearance: 'interaction-only',
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
  var lastMs = null;
  function post(body) {
    var t0 = performance.now();
    return fetch(api + '/demo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'omit', body: JSON.stringify(body) })
      .then(function (r) { return r.json(); })
      .then(function (j) { lastMs = performance.now() - t0; return j; });
  }

  function report(what, v) {
    if (!v || !v.ok) { show('info', 'error', null, [(v && (v.message || v.error)) || 'Couldn\'t reach the server.']); return v; }
    verdict(what, v, lastMs);
    return v;
  }

  function value() { var n = Number($('value').value); return $('value').value === '' ? null : n; }
  function offline(msg) { return Promise.resolve(show('info', 'offline', null, [msg])); }

  var ACTIONS = {
    honest: function () {
      if (!current) return offline('The browser script didn\'t load, so there\'s no session to send.');
      return humanCheck().then(function (t) { return seal(value(), t); }).then(function (b) {
        last = b; lastN = sent; wire(b, null, '', 'sealed by Pyrmi.seal()'); return post(b);
      }).then(function (v) { return report(tsKey ? 'Sent like a normal page would, with the human check.' : 'Sent like a normal page would (the human check isn\'t set up on this server).', v); });
    },
    replay: function () {
      if (!last) return offline('Send one normally first, then replay it.');
      wire(last, { token: { cls: 'warn', note: 'already used' } }, 'Byte-for-byte copy of request #' + lastN + ', sent again.', 'replayed');
      return post(last).then(function (v) { return report('Sent the exact same request again.', v); });
    },
    edit: function () {
      if (!current) return offline('No session to edit.');
      var parts = current.token.split('.'), body = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      body.i -= 3600 * 1000; // pretend the session started an hour ago
      var forged = btoa(JSON.stringify(body)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') + '.' + parts[1];
      return seal(value()).then(function (b) {
        b.pyrmi = { token: forged, ts: b.pyrmi.ts, sig: b.pyrmi.sig };
        wire(b, { token: { cls: 'bad', note: 'edited: issued 1 h earlier' } }, '', 'token forged'); return post(b);
      }).then(function (v) { return report('Edited the session token to look an hour old.', v); });
    },
    big: function () {
      if (!current) return offline('No session to send with.');
      return seal(999999).then(function (b) {
        last = b; lastN = sent; wire(b, { value: { cls: 'warn', note: 'limit is 1000' } }, '', 'sealed, value out of range'); return post(b);
      }).then(function (v) { return report('Sent 999999 where the limit is 1000.', v); });
    },
    rewrite: function () {
      // what a proxy or a debugger on the wire does: the page signs one value, and a different one goes out
      if (!current) return offline('No session to send with.');
      var asked = value() === null ? 1 : value();
      return seal(asked).then(function (b) {
        b.value = asked + 33; last = b; lastN = sent;
        wire(b, { value: { cls: 'bad', note: 'page signed ' + asked }, sig: { cls: 'warn', note: 'covers the old value' } }, '', 'changed after sealing'); return post(b);
      }).then(function (v) { return report('The page signed ' + asked + ', then ' + (asked + 33) + ' was sent instead.', v); });
    },
    direct: function () {
      // what a scraper or a script does: grab a session straight from the API and use it at once, no page involved
      return fetch(api + '/session', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, credentials: 'omit', body: JSON.stringify({ site: SITE }) })
        .then(function (r) { return r.json(); })
        .then(function (s) {
          if (!s.ok) throw new Error(s.message || s.error);
          var b = { value: value(), visitor: visitor, pyrmi: { token: s.token } };
          wire(b, { token: { cls: 'warn', note: 'from POST /session, no page' } }, '', 'unsealed'); return post(b);
        })
        .then(function (v) { return report('Called the API directly, with no page behind it.', v); });
    },
  };

  var buttons = document.querySelectorAll('[data-act]');
  Array.prototype.forEach.call(buttons, function (b) {
    b.addEventListener('click', function () {
      if (busy) return;
      var act = b.getAttribute('data-act');
      if (!has(ACTIONS, act)) return;
      busy = true; sent++; lastMs = null;
      b.classList.add('running');
      state('info busy', 'checking');
      show('info', 'checking…', null, ['Asking Pyrmi for a verdict…']);
      // Stacked layout (phones, narrow windows): bring the verdict into view, since it sits below the buttons.
      if (matchMedia('(max-width: 940px)').matches) {
        ($('verdict').previousElementSibling || $('verdict')).scrollIntoView({ block: 'start', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
      }
      Promise.resolve().then(ACTIONS[act])
        .then(function (v) { if (v && typeof v === 'object') log(act, v); else sent--; },
          function (e) { log(act, null); show('info', 'error', null, [String(e && e.message || 'Something went wrong.')]); })
        .then(function () { return act === 'replay' ? null : fresh(); }) // tokens are single use
        .then(function () { busy = false; b.classList.remove('running'); state('info', 'ready'); });
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
    var ul = clear($('live'));
    if (!window.Pyrmi) { ul.appendChild(el('li', null, 'script blocked or not loaded')); return; }
    var r = Pyrmi.report();
    LIVE.forEach(function (x) {
      var v = x[1](r), li = el('li');
      li.appendChild(el('span', null, x[0]));
      li.appendChild(el('span', v ? 'on' : 'off', v || 'clear'));
      ul.appendChild(li);
    });
  }
  live(); setInterval(live, 2000);
  fresh();
})();
