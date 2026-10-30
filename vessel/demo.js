/* The Vessel on the Pyrmi Security homepage: ranked runs protected by Pyrmi, the weekly board, and a live view of
   what the browser script sees. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var tEl = $('t'), bestEl = $('best'), stEl = $('stage'), nameEl = $('name');
  var best = 0; try { best = parseFloat(localStorage.getItem('pyrmi_best') || '0') || 0; } catch (e) { /* private mode */ }
  bestEl.textContent = best.toFixed(1);
  try { nameEl.value = localStorage.getItem('pyrmi_name') || ''; } catch (e) { /* ignore */ }
  nameEl.addEventListener('change', function () { try { localStorage.setItem('pyrmi_name', nameEl.value.trim()); } catch (e) { /* ignore */ } });

  var ranked = !!window.Pyrmi, current = null;
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  function drawBoard(d, me) {
    $('week').textContent = d.week ? d.week.replace('-W', ' wk ') : '';
    var rows = d.board || [];
    $('board').innerHTML = rows.length ? rows.map(function (r) {
      return '<li' + (r.name === me ? ' class="me"' : '') + '>' + esc(r.name) + ' <span>' + Number(r.seconds).toFixed(2) + 's</span></li>';
    }).join('') : '<li class="muted">no verified runs yet. be first.</li>';
  }
  function loadBoard() {
    fetch('/api/v1/vessel').then(function (r) { return r.json(); }).then(function (d) { if (d.ok) drawBoard(d); else $('board').innerHTML = '<li class="muted">board offline</li>'; })
      .catch(function () { $('board').innerHTML = '<li class="muted">board offline</li>'; });
  }

  function showVerdict(chip, label, time, risk, reasons) {
    $('verdict').hidden = false;
    var c = $('v-chip'); c.className = 'chip ' + chip; c.textContent = label;
    $('v-time').textContent = time;
    $('v-risk').style.width = (risk == null ? 0 : risk) + '%';
    $('v-reasons').innerHTML = reasons.length ? reasons.map(function (r) { return '<li>' + esc(r) + '</li>'; }).join('') : '<li>No warning signs. Clean run.</li>';
  }

  var game = window.mountVessel($('game'), {
    getSeed: function () {
      // a fresh signed session per run: its seed decides every bullet, so nobody can practise a run in advance
      var offline = function () { current = null; return { seed: (Math.random() * 4294967296) >>> 0 }; };
      if (!ranked) return offline();
      return Pyrmi.start().then(function (s) { current = s; return { seed: s.seed }; }, offline);
    },
    onStart: function () { stEl.textContent = '1'; },
    onTick: function (s) { if (s.tick % 6 === 0) tEl.textContent = (s.tick / 60).toFixed(1); if (window.Pyrmi && s.tick % 30 === 0) Pyrmi.mark(s.tick / 60); },
    onStage: function (n) { stEl.textContent = n; },
    onEnd: function (run) {
      var secs = run.ticks / 60;
      tEl.textContent = secs.toFixed(1);
      if (!run.forfeit && secs > best) { best = secs; try { localStorage.setItem('pyrmi_best', best.toFixed(2)); } catch (e) { /* ignore */ } bestEl.textContent = best.toFixed(1); }
      var session = current; current = null;
      if (run.forfeit) { showVerdict('info', 'not sent', secs.toFixed(2) + 's', 0, ['Ranked runs can\'t pause, so leaving the tab ends the run without sending it.']); return; }
      if (!session) { showVerdict('info', 'offline', secs.toFixed(2) + 's', 0, ['Couldn\'t reach the Pyrmi server, so this run is unranked.']); return; }
      if (window.Pyrmi) Pyrmi.stop();
      var name = nameEl.value.trim();
      if (name.replace(/[^A-Za-z0-9_ .-]/g, '').length < 2) {
        name = 'anon-' + (Math.random() * 9000 + 1000 | 0); nameEl.value = name;
        try { localStorage.setItem('pyrmi_name', name); } catch (e) { /* ignore */ }
      }
      showVerdict('info', 'verifying…', secs.toFixed(2) + 's', 0, ['Replaying your run on the server…']);
      (window.Pyrmi ? Pyrmi.flush() : Promise.resolve()).then(function () {
        return fetch('/api/v1/vessel', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: session.token, name: name, ticks: run.ticks, replay: run.replay }) });
      }).then(function (r) { return r.json(); }).then(function (v) {
        if (!v.ok) { showVerdict('info', 'not ranked', secs.toFixed(2) + 's', 0, [v.message || v.error || 'Something went wrong.']); return; }
        var label = { accept: 'verified', review: 'flagged', reject: 'rejected' }[v.verdict];
        var lines = v.reasons.map(function (r) { return r.text + (r.detail ? ' (' + r.detail + ')' : ''); });
        if (v.verdict === 'accept') lines.unshift('Server replay matched your inputs' + (v.rank ? '. You\'re #' + v.rank + ' this week.' : '.'));
        if (v.verdict === 'review') lines.unshift('Counted, but flagged on the dashboard' + (v.rank ? '. #' + v.rank + ' this week.' : '.'));
        showVerdict(v.verdict, label, secs.toFixed(2) + 's · risk ' + v.risk, v.risk, lines);
        drawBoard(v, name);
      }).catch(function () { showVerdict('info', 'offline', secs.toFixed(2) + 's', 0, ['Couldn\'t reach the server to verify this run.']); });
    },
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
  loadBoard();
  void game;
})();
