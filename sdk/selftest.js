/* Pyrmi Security: runs the self-test cases (selftest-case.js) in fresh frames and shows what this browser reports. */
(function () {
  'use strict';
  var C = window.PYRMI_SELFTEST || [];
  var m = /[?&]case=([\w-]+)/.exec(location.search);
  if (m) { // a case frame: run an "after" trick, then report to the parent page
    var c = null, i;
    for (i = 0; i < C.length; i++) if (C[i].id === m[1]) c = C[i];
    var out = { pyrmiSelftest: true, id: m[1], error: window.PYRMI_SELFTEST_ERROR || null };
    try {
      if (c && c.when === 'after') c.run();
      var r = window.Pyrmi.report();
      out.tp = r.tp.slice(); out.wr = (r.wr || []).slice(); out.wd = r.wd;
    } catch (e) { out.error = String(e); }
    parent.postMessage(out, location.origin);
    return;
  }
  var $ = function (id) { return document.getElementById(id); };
  $('ua').textContent = navigator.userAgent;
  var rows = $('rows'), pass = 0, done = 0, results = [];
  function check(exp, got) {
    if (exp === null || exp === undefined) return true;
    if (!exp.length) return got.length === 0;
    for (var i = 0; i < exp.length; i++) if (got.indexOf(exp[i]) < 0) return false;
    return true;
  }
  function row(c, res) {
    var ok = !res.error && check(c.tp, res.tp || []) && check(c.wr, res.wr || []);
    if (ok) pass++;
    done++;
    results.push({ id: c.id, ok: ok, tp: res.tp, wr: res.wr, error: res.error });
    var tr = document.createElement('tr');
    [ok ? 'pass' : 'FAIL', c.desc, (res.tp || []).join(', ') || '-', (res.wr || []).join(', ') || '-', res.error || ''].forEach(function (v, k) {
      var td = document.createElement('td'); td.textContent = v; if (k === 0) td.className = ok ? 'ok' : 'bad'; tr.appendChild(td);
    });
    rows.appendChild(tr);
    $('summary').textContent = pass + ' of ' + done + ' passed' + (done < C.length ? ' (running...)' : '');
    $('summary').className = pass === done ? 'ok' : 'bad';
    window.PYRMI_SELFTEST_RESULTS = { pass: pass, total: C.length, done: done, results: results };
  }
  var idx = 0;
  function next() {
    if (idx >= C.length) return;
    var c = C[idx++], f = document.createElement('iframe'), timer;
    function onMsg(ev) {
      if (ev.source !== f.contentWindow || !ev.data || !ev.data.pyrmiSelftest || ev.data.id !== c.id) return;
      window.removeEventListener('message', onMsg); clearTimeout(timer); f.remove(); row(c, ev.data); next();
    }
    window.addEventListener('message', onMsg);
    timer = setTimeout(function () { window.removeEventListener('message', onMsg); f.remove(); row(c, { error: 'timed out' }); next(); }, 8000);
    f.className = 'case'; f.src = 'selftest.html?case=' + encodeURIComponent(c.id);
    document.body.appendChild(f);
  }
  next();
})();
