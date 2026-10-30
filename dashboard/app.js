/* Pyrmi Security dashboard. The secret key lives in sessionStorage (or localStorage if "remember" is ticked) and is
   only ever sent to this site's own API. Everything shown is escaped: player names come from players. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  var demo = new URLSearchParams(location.search).has('demo');
  var KEY = 'pyrmi_sk', sk = null, timer = null, lastLoad = 0, data = null;
  try { sk = sessionStorage.getItem(KEY) || localStorage.getItem(KEY); } catch (e) { /* storage blocked */ }

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  function show(id) { ['gate', 'keys', 'dash'].forEach(function (x) { $(x).hidden = x !== id; }); }
  function api(method, path, body) {
    var h = { 'Content-Type': 'application/json' };
    if (sk && !demo) h.Authorization = 'Bearer ' + sk;
    return fetch('/api/v1/' + path, { method: method, headers: h, body: body ? JSON.stringify(body) : undefined, credentials: 'omit' })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'http_' + r.status }; }).then(function (j) { j._status = r.status; return j; }); });
  }
  function ago(t) {
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return Math.floor(s) + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
  }
  function save(k, remember) {
    try { sessionStorage.setItem(KEY, k); if (remember) localStorage.setItem(KEY, k); else localStorage.removeItem(KEY); } catch (e) { /* ignore */ }
  }
  function forget() { try { sessionStorage.removeItem(KEY); localStorage.removeItem(KEY); } catch (e) { /* ignore */ } sk = null; }
  function lines(v) { return String(v || '').split(/[\s,]+/).filter(Boolean); }

  // ---- signed out ----
  $('create').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, btn = f.querySelector('button');
    btn.disabled = true; $('create-err').textContent = '';
    api('POST', 'project', { name: f.name.value, origins: lines(f.origins.value) }).then(function (r) {
      btn.disabled = false;
      if (!r.ok) { $('create-err').textContent = r.message || r.error; return; }
      $('k-pk').textContent = r.project.publicKey; $('k-sk').textContent = r.project.secretKey;
      sk = r.project.secretKey; save(sk, false); show('keys');
    }, function () { btn.disabled = false; $('create-err').textContent = 'Could not reach the server.'; });
  });
  $('k-saved').addEventListener('change', function () { $('k-go').disabled = !this.checked; });
  $('k-go').addEventListener('click', function () { $('k-sk').textContent = ''; load(true); });
  $('login').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target; sk = f.sk.value.trim(); $('login-err').textContent = '';
    api('GET', 'project').then(function (r) {
      if (!r.ok) { $('login-err').textContent = r._status === 401 ? 'That key didn\'t work.' : (r.message || r.error); sk = null; return; }
      save(sk, f.remember.checked); f.sk.value = ''; load(true);
    });
  });
  $('signout').addEventListener('click', function () { if (demo) { location.href = '/dashboard/'; return; } forget(); clearInterval(timer); show('gate'); });

  // ---- dashboard ----
  function chart(days) {
    var W = 560, H = 180, pad = 22, n = days.length, bw = (W - pad) / n;
    var max = Math.max(1, Math.max.apply(null, days.map(function (d) { return d.accept + d.review + d.reject; })));
    var out = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">';
    out += '<line x1="' + pad + '" y1="' + (H - 18) + '" x2="' + W + '" y2="' + (H - 18) + '" stroke="rgba(255,255,255,.12)"/>';
    out += '<text x="0" y="12" fill="#9aa0c4" font-size="10">' + max + '</text>';
    days.forEach(function (d, i) {
      var x = pad + i * bw + 3, w = Math.max(2, bw - 6), y = H - 18, scale = (H - 34) / max;
      [['accept', '#3ddc84'], ['review', '#ffb020'], ['reject', '#ff4d5e']].forEach(function (p) {
        var h = d[p[0]] * scale; if (h <= 0) return; y -= h;
        out += '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="2" fill="' + p[1] + '"><title>' + d.day + ' ' + p[0] + ': ' + d[p[0]] + '</title></rect>';
      });
      if (i % 2 === 0 || n < 8) out += '<text x="' + (x + w / 2) + '" y="' + (H - 4) + '" fill="#9aa0c4" font-size="10" text-anchor="middle">' + d.day.slice(6) + '</text>';
    });
    return out + '</svg>';
  }

  function render(d) {
    data = d; var p = d.project;
    $('d-name').textContent = p.name; $('d-pk').textContent = p.publicKey; $('d-demo').hidden = !p.demo;
    $('owner-only').hidden = !!p.demo;
    var tot = { sessions: 0, accept: 0, review: 0, reject: 0 }, reasons = {};
    d.days.forEach(function (x) { tot.sessions += x.sessions; tot.accept += x.accept; tot.review += x.review; tot.reject += x.reject;
      for (var k in x.reasons) reasons[k] = (reasons[k] || 0) + x.reasons[k]; });
    $('s-sessions').textContent = tot.sessions; $('s-accept').textContent = tot.accept; $('s-review').textContent = tot.review; $('s-reject').textContent = tot.reject;
    var all = tot.accept + tot.review + tot.reject;
    $('s-rate').textContent = all ? Math.round(tot.reject / all * 100) + '% of all scores' : 'of all scores';
    $('chart').innerHTML = chart(d.days);

    var rs = Object.keys(reasons).sort(function (a, b) { return reasons[b] - reasons[a]; }).slice(0, 8);
    var rmax = rs.length ? reasons[rs[0]] : 1;
    $('why').innerHTML = rs.length ? rs.map(function (k) {
      return '<li><div class="row"><b>' + esc(d.reasonText[k] || k) + '</b><span class="num">' + reasons[k] + '</span></div><div class="bar"><i style="width:' + (reasons[k] / rmax * 100) + '%"></i></div></li>';
    }).join('') : '<li class="empty">Nothing flagged yet. Reasons show up here as scores come in.</li>';

    var label = { accept: 'verified', review: 'flagged', reject: 'rejected' };
    $('events').tBodies[0].innerHTML = d.events.length ? d.events.map(function (e, i) {
      var top = e.reasons[0];
      return '<tr class="ev" data-i="' + i + '"><td class="num">' + ago(e.t) + '</td><td>' + esc(e.player) + '</td><td class="num">' + esc(e.score) + '</td><td><span class="chip ' + e.verdict + '">' + label[e.verdict] + '</span></td><td class="num">' + e.risk + '</td><td>' + esc(top ? (d.reasonText[top.code] || top.code) : 'clean') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">No scores yet. Once your server calls verify, every verdict lands here.</td></tr>';

    $('p-count').textContent = d.playerCount ? d.playerCount + ' seen in 30 days' : '';
    $('players').tBodies[0].innerHTML = d.players.length ? d.players.map(function (x) {
      return '<tr><td>' + esc(x.player) + '</td><td class="num">' + x.accept + '</td><td class="num">' + x.review + '</td><td class="num">' + x.reject + '</td><td class="num">' + x.lastRisk + '</td><td>' + esc(x.topReason ? (d.reasonText[x.topReason] || x.topReason) : '') + '</td><td class="num">' + (x.lastSeen ? ago(x.lastSeen) : '') + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="empty">No players yet.</td></tr>';

    if (!p.demo) {
      var f = $('settings'), s = p.settings;
      if (document.activeElement.form !== f) {
        f.name.value = p.name; f.maxScore.value = s.maxScore == null ? '' : s.maxScore; f.maxScorePerSec.value = s.maxScorePerSec == null ? '' : s.maxScorePerSec;
        f.minDurationMs.value = s.minDurationMs; f.reviewAt.value = s.reviewAt; f.rejectAt.value = s.rejectAt;
        f.origins.value = (s.origins || []).join('\n'); f.strictClock.checked = !!s.strictClock;
      }
      $('i-snippet').textContent = '<script src="' + location.origin + '/sdk/pyrmi.js" data-site="' + p.publicKey + '"></script>';
    }
    lastLoad = Date.now(); tick();
  }
  function tick() { if (lastLoad) $('d-updated').textContent = 'updated ' + ago(lastLoad); }

  $('events').addEventListener('click', function (e) {
    var tr = e.target.closest('tr.ev'); if (!tr || !data) return;
    var next = tr.nextElementSibling;
    if (next && next.classList.contains('detail')) { next.remove(); return; }
    var ev = data.events[Number(tr.getAttribute('data-i'))];
    var items = ev.reasons.length ? ev.reasons.map(function (r) { return '<li>' + esc(data.reasonText[r.code] || r.code) + (r.detail ? ' <span class="mono">(' + esc(r.detail) + ')</span>' : '') + '</li>'; }).join('') : '<li>No warning signs.</li>';
    var extra = [ev.durationMs != null ? 'run ' + (ev.durationMs / 1000).toFixed(1) + 's' : null, 'replay ' + esc(ev.replay || 'none'), ev.sid ? 'session ' + esc(ev.sid) : null, new Date(ev.t).toLocaleString()].filter(Boolean).join(' · ');
    tr.insertAdjacentHTML('afterend', '<tr class="detail"><td colspan="6"><ul>' + items + '</ul>' + extra + '</td></tr>');
  });

  $('settings').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, msg = $('settings-msg');
    msg.className = 'err'; msg.textContent = 'saving…';
    api('PATCH', 'project', { name: f.name.value, settings: {
      maxScore: f.maxScore.value.trim(), maxScorePerSec: f.maxScorePerSec.value.trim(), minDurationMs: f.minDurationMs.value.trim(),
      reviewAt: f.reviewAt.value.trim(), rejectAt: f.rejectAt.value.trim(), origins: lines(f.origins.value), strictClock: f.strictClock.checked } })
      .then(function (r) { if (!r.ok) { msg.textContent = r.message || r.error; return; } msg.className = 'err good'; msg.textContent = 'saved'; document.activeElement.blur(); load(); });
  });
  $('rotate').addEventListener('click', function () { $('rotate-confirm').hidden = false; });
  $('rotate-no').addEventListener('click', function () { $('rotate-confirm').hidden = true; });
  $('rotate-yes').addEventListener('click', function () {
    api('POST', 'project?action=rotate', {}).then(function (r) {
      $('rotate-confirm').hidden = true;
      if (!r.ok) return;
      sk = r.secretKey; var remembered = false; try { remembered = !!localStorage.getItem(KEY); } catch (e) { /* ignore */ }
      save(sk, remembered); $('r-sk').textContent = sk; $('rotate-out').hidden = false;
    });
  });

  function load(first) {
    return api('GET', demo ? 'dashboard?demo=1' : 'dashboard').then(function (r) {
      if (!r.ok) {
        if (r._status === 401 && !demo) { forget(); show('gate'); return; }
        if (first) { show(demo ? 'dash' : 'gate'); $(demo ? 'd-name' : 'login-err').textContent = r.message || 'Could not load the dashboard.'; }
        return;
      }
      show('dash'); render(r);
      if (!timer) timer = setInterval(function () { if (!document.hidden) load(); tick(); }, 15000);
    }, function () { if (first) { show(demo ? 'dash' : 'gate'); } });
  }

  if (demo || sk) load(true); else show('gate');
})();
