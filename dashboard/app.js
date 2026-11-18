/* Pyrmi Security dashboard. Two ways in: signed in (by email code, GitHub or Google; a session cookie this script never sees; every change
   also sends X-Pyrmi-CSRF), or with a project's secret key, which lives in this tab's sessionStorage only
   (round 12: never localStorage) and is only ever sent to this site's own API. Everything shown is escaped: user names come
   from your users. */
(function () {
  'use strict';
  var $ = function (id) { return document.getElementById(id); };
  // The browser script to tell people to use: a fixed version with its integrity hash (scripts/build-sdk.js keeps this
  // line up to date). That file never changes, so a page that pins it can't be handed a different script.
  var SDK_PATH = '/sdk/1.4.1/pyrmi.js', SDK_SRI = 'sha384-D04YwtCEA1kV3ku22rSlK5QI7BBEb3SkSvSIJGz5i1ololjoYjDLgdbcf8dsuvN8';
  var sdkTag = function (origin, pk) { return '<script src="' + origin + SDK_PATH + '" integrity="' + SDK_SRI + '" crossorigin="anonymous" data-site="' + pk + '"></script>'; };
  var q = new URLSearchParams(location.search);
  var demo = q.has('demo') ? (q.get('demo') === 'site' ? 'site' : '1') : null;
  // pyrmi.com protects its own "new project" form with Pyrmi: start a session now, send its token with the form.
  var guard = null;
  function guardStart() { if (window.Pyrmi && !demo) Pyrmi.start().then(function (s) { guard = s; }, function () { guard = null; }); }
  guardStart();
  var KEY = 'pyrmi_sk', sk = null, timer = null, lastLoad = 0, data = null;
  var me = null, pid = null; // signed in: the account, and the site being looked at
  // Cloudflare Turnstile, once the server has a site key for it (GET /api/v1/me says): a human check on sign-in codes,
  // new projects and sites, and account changes. Each form gets a fresh token; Cloudflare accepts a token once.
  var tsKey = null, tsLoad = null, HUMAN_ERR = 'The human check didn\'t finish. Try again.';
  function turnstileReady() {
    if (window.turnstile) return Promise.resolve(window.turnstile);
    if (!tsLoad) tsLoad = new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'; s.async = true;
      s.onload = function () { if (window.turnstile) resolve(window.turnstile); else reject(new Error('human_check')); };
      s.onerror = function () { tsLoad = null; reject(new Error('human_check')); };
      document.head.appendChild(s);
    });
    return tsLoad;
  }
  function human(action, box) {
    if (!tsKey) return Promise.resolve(undefined);
    return turnstileReady().then(function (ts) {
      return new Promise(function (resolve, reject) {
        var el = $(box), old = el.getAttribute('data-wid');
        if (old) { try { ts.remove(old); } catch (e) { /* already gone */ } }
        el.hidden = false;
        var fail = function () { reject(new Error('human_check')); };
        el.setAttribute('data-wid', ts.render(el, { sitekey: tsKey, action: action, appearance: 'interaction-only',
          callback: resolve, 'error-callback': fail, 'timeout-callback': fail }));
      });
    });
  }
  function whyFailed(e) { return e && e.message === 'human_check' ? HUMAN_ERR : 'Could not reach the server.'; }
  try { sk = sessionStorage.getItem(KEY); localStorage.removeItem(KEY); } catch (e) { /* storage blocked */ }

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }
  // Lookups keyed by anything from a URL or the API go through has(), so "toString" or "constructor" never resolve to
  // Object.prototype.
  function has(o, k) { return o != null && Object.prototype.hasOwnProperty.call(o, k); }
  // Secret keys on screen (a new key after creating, claiming or rotating) never outlive the view they were shown in:
  // leaving the keys view clears the shown key, and leaving or switching a project clears a rotated one.
  function clearShownKey() { $('k-sk').textContent = ''; $('k-saved').checked = false; $('k-go').disabled = true; }
  function clearProject() {
    $('r-sk').textContent = ''; $('rotate-out').hidden = true; $('rotate-confirm').hidden = true; $('rotate-err').textContent = '';
    $('delete-confirm').hidden = true; $('delete-err').textContent = ''; $('settings-msg').textContent = ''; $('settings-msg').className = 'err';
  }
  function show(id) {
    if (id !== 'keys') clearShownKey();
    if (id !== 'dash') clearProject();
    ['gate', 'keys', 'dash', 'account'].forEach(function (x) { $(x).hidden = x !== id; });
  }
  function api(method, path, body) {
    var h = { 'Content-Type': 'application/json' };
    if (sk && !demo && !me) h.Authorization = 'Bearer ' + sk;
    var own = me || path === 'me' || path.indexOf('auth/') === 0;
    if (own) h['X-Pyrmi-CSRF'] = '1';
    return fetch('/api/v1/' + path, { method: method, headers: h, body: body ? JSON.stringify(body) : undefined, credentials: own ? 'same-origin' : 'omit' })
      .then(function (r) { return r.json().catch(function () { return { ok: false, error: 'http_' + r.status }; }).then(function (j) { j._status = r.status; return j; }); });
  }
  function ago(t) {
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 60) return Math.floor(s) + 's ago'; if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago'; return Math.floor(s / 86400) + 'd ago';
  }
  // The key lives in this tab's sessionStorage only, never localStorage, so it doesn't outlive the tab; a copy saved by
  // an older version is removed.
  function save(k) {
    try { sessionStorage.setItem(KEY, k); localStorage.removeItem(KEY); } catch (e) { /* ignore */ }
  }
  function forget() { try { sessionStorage.removeItem(KEY); localStorage.removeItem(KEY); } catch (e) { /* ignore */ } sk = null; }
  function lines(v) { return String(v || '').split(/[\s,]+/).filter(Boolean); }

  // ---- signed out ----
  $('create').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, btn = f.querySelector('button');
    btn.disabled = true; $('create-err').textContent = '';
    var human1;
    human('new-project', 'ts-create').then(function (t) { human1 = t; return window.Pyrmi ? Pyrmi.flush() : null; }).then(function () {
      var token = guard && guard.token; guard = null;
      return api('POST', 'project', { name: f.name.value, origins: lines(f.origins.value), pyrmiToken: token, turnstileToken: human1 });
    }).then(function (r) {
      btn.disabled = false;
      guardStart(); // tokens are single use
      if (!r.ok) { $('create-err').textContent = r.message || r.error; return; }
      $('k-pk').textContent = r.project.publicKey; $('k-title').textContent = 'Project created'; $('k-sk').textContent = r.project.secretKey;
      sk = r.project.secretKey; save(sk); show('keys');
    }, function (e) { btn.disabled = false; $('create-err').textContent = whyFailed(e); });
  });
  $('k-saved').addEventListener('change', function () { $('k-go').disabled = !this.checked; });
  $('k-go').addEventListener('click', function () { $('k-sk').textContent = ''; $('k-saved').checked = false; $('k-go').disabled = true; if (me) location.hash = 'site=' + pid; else load(true); });
  $('login').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target; sk = f.sk.value.trim(); $('login-err').textContent = '';
    api('GET', 'project').then(function (r) {
      if (!r.ok) { $('login-err').textContent = r._status === 401 ? 'That key didn\'t work.' : (r.message || r.error); sk = null; return; }
      save(sk); f.sk.value = ''; load(true);
    });
  });
  $('signout').addEventListener('click', function () {
    if (demo) { location.href = '/dashboard/'; return; }
    if (me) { signOut(); return; }
    forget(); clearInterval(timer); timer = null; data = null; show('gate');
  });

  // ---- signing in ----
  var SIGNIN_ERR = { cancelled: 'Sign-in was cancelled.', bad_state: 'That sign-in link expired. Try again.',
    bad_id_token: 'Google didn\'t confirm a verified email for that account.', exchange_failed: 'The sign-in didn\'t go through. Try again.',
    no_verified_email: 'Your GitHub account has no verified primary email. Verify one on GitHub and try again.',
    github_not_configured: 'Sign in with GitHub isn\'t set up on this server yet.', google_not_configured: 'Sign in with Google isn\'t set up on this server yet.' };
  var signinErr = q.get('signin');
  if (signinErr) $('signin-err').textContent = has(SIGNIN_ERR, signinErr) ? SIGNIN_ERR[signinErr] : 'Sign-in didn\'t work. Try again.';
  var codeEmail = '';
  function codeStep(on) { $('email-form').hidden = on; $('code-form').hidden = !on; if (on) $('code-form').code.focus(); }
  $('email-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, btn = f.querySelector('button');
    btn.disabled = true; $('signin-err').textContent = '';
    var human1;
    human('signin', 'ts-signin').then(function (t) { human1 = t; return window.Pyrmi ? Pyrmi.flush() : null; }).then(function () {
      var token = guard && guard.token; guard = null;
      codeEmail = f.email.value.trim();
      return api('POST', 'auth/email?action=start', { email: codeEmail, pyrmiToken: token, turnstileToken: human1 });
    }).then(function (r) {
      btn.disabled = false; guardStart();
      if (!r.ok) { $('signin-err').textContent = r.message || r.error; return; }
      $('code-to').textContent = codeEmail; codeStep(true);
    }, function (e) { btn.disabled = false; $('signin-err').textContent = whyFailed(e); });
  });
  $('code-form').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, btn = f.querySelector('button');
    btn.disabled = true; $('signin-err').textContent = '';
    api('POST', 'auth/email?action=verify', { email: codeEmail, code: f.code.value }).then(function (r) {
      btn.disabled = false;
      if (!r.ok) { $('signin-err').textContent = r.message || r.error; if (r.error === 'too_many_tries') codeStep(false); return; }
      f.reset(); codeStep(false); boot();
    }, function () { btn.disabled = false; $('signin-err').textContent = 'Could not reach the server.'; });
  });
  $('code-back').addEventListener('click', function () { $('signin-err').textContent = ''; codeStep(false); });
  function signOut() {
    forget(); // a key saved from key-only mode goes too
    api('POST', 'me?action=signout', {}).then(function () { me = null; pid = null; data = null; clearInterval(timer); timer = null; clearProject(); clearShownKey(); history.replaceState(null, '', '/dashboard/'); boot(); });
  }
  $('a-signout').addEventListener('click', signOut);
  $('back').addEventListener('click', function () { location.hash = ''; });
  function dot(on, label) { return '<span class="' + (on ? 'on' : '') + '">' + label + (on ? ' connected' : ' waiting') + '</span>'; }
  function sites() {
    clearInterval(timer); timer = null; pid = null; data = null; clearProject();
    return api('GET', 'me').then(function (r) {
      if (!r.ok) { me = null; return boot(); }
      me = r.user; tsKey = r.turnstile || null; $('a-email').textContent = me.email; show('account');
      $('sites').innerHTML = r.sites.length ? r.sites.map(function (x) {
        return '<button class="card site" type="button" data-pid="' + esc(x.pid) + '"><b>' + esc(x.name) + '</b><code>' + esc(x.publicKey) + '</code>' +
          '<span class="dots">' + dot(x.status && x.status.page, 'page') + dot(x.status && x.status.server, 'server') + '</span><span class="go">open dashboard →</span></button>';
      }).join('') : '<p class="empty">No sites yet. Add your first one below.</p>';
    });
  }
  $('sites').addEventListener('click', function (e) { var b = e.target.closest('[data-pid]'); if (b) location.hash = 'site=' + b.getAttribute('data-pid'); });
  $('add-site').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, btn = f.querySelector('button');
    btn.disabled = true; $('add-err').textContent = '';
    var human1;
    human('new-site', 'ts-add').then(function (t) { human1 = t; return window.Pyrmi ? Pyrmi.flush() : null; }).then(function () {
      var token = guard && guard.token; guard = null;
      return api('POST', 'sites', { name: f.name.value, origins: lines(f.origins.value), pyrmiToken: token, turnstileToken: human1 });
    }).then(function (r) {
      btn.disabled = false; guardStart();
      if (!r.ok) { $('add-err').textContent = r.message || r.error; return; }
      f.reset(); pid = r.project.pid;
      $('k-pk').textContent = r.project.publicKey; $('k-title').textContent = 'Project created'; $('k-sk').textContent = r.project.secretKey; show('keys');
    }, function (e) { btn.disabled = false; $('add-err').textContent = whyFailed(e); });
  });
  $('claim').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target; $('claim-err').textContent = '';
    human('claim', 'ts-claim').then(function (t) { return api('POST', 'sites?action=claim', { secretKey: f.sk.value.trim(), keepKey: f.keep.checked, turnstileToken: t }); }).then(function (r) {
      if (!r.ok) { $('claim-err').textContent = r.message || r.error; return; }
      f.reset();
      if (!r.site.secretKey) { location.hash = 'site=' + r.site.pid; return; }
      pid = r.site.pid; $('k-title').textContent = 'Project added: new secret key';
      $('k-pk').textContent = r.site.publicKey; $('k-sk').textContent = r.site.secretKey; show('keys');
    }, function (e) { $('claim-err').textContent = whyFailed(e); });
  });
  $('g-check').addEventListener('click', function () { $('g-note').textContent = 'checking…'; load().then(function () { $('g-note').textContent = 'checked ' + new Date().toLocaleTimeString(); }); });
  function guide(d) {
    var p = d.project, st = d.status, origin = location.origin;
    $('guide').hidden = false;
    $('g1').textContent = sdkTag(origin, p.publicKey) + '\n<script>\n  let pyrmi = null;\n  Pyrmi.start().then((s) => { pyrmi = s; });\n  // right before a protected request (sign-up, vote, checkout...):\n  //   await Pyrmi.flush(); const body = await Pyrmi.seal({ ...yourFields });\n  //   POST body as JSON, unchanged, then call Pyrmi.start() again for the next one\n</script>';
    $('g2').textContent = "// npm install pyrmi-server\nconst { Pyrmi } = require('pyrmi-server');\nconst pyrmi = new Pyrmi({ secretKey: process.env.PYRMI_SECRET_KEY" + (origin === 'https://pyrmi.com' ? '' : ", endpoint: '" + origin + "/api/v1'") + " });\n\n// req.body: what the page sent from Pyrmi.seal(); req: this request (checks it's the same browser)\n// user: from your own sign-in, never from req.body. A sealed `score` is checked against your caps; a value under\n// another name, pass as score: too.\nconst v = await pyrmi.verify({ sealed: req.body, req, user: userId });\nif (v.verdict === 'reject') return res.status(403).json({ error: 'blocked' });\n\n// Payouts, prizes, leaderboards: use trusted(v). For a stronger trusted, add a Turnstile pass (install.md, requireHumanCheck).\n// Behind Vercel, Netlify or Cloudflare add trustProxyHops: 1 to new Pyrmi({...}).";
    $('g3').textContent = 'Read ' + origin + '/install.md and add Pyrmi Security to this site. My public key is ' + p.publicKey + ' and my secret key is in the PYRMI_SECRET_KEY environment variable (don\'t write it into any file). Protect the requests worth protecting (sign-ups, logins, votes, checkouts, scores) and tell me which files you changed.';
    $('g-page').className = st.page ? 'done' : ''; $('g-server').className = st.server ? 'done' : '';
    var c = $('g-state');
    c.className = 'chip ' + (st.connected ? 'accept' : st.page || st.server ? 'review' : 'info');
    c.textContent = st.connected ? 'connected' : st.page ? 'page connected, waiting for your server' : st.server ? 'server connected, waiting for your page' : 'not connected yet';
  }
  function route() {
    var m = /site=(p_[\w-]+)/.exec(location.hash);
    if (me && m) { pid = m[1]; $('guide').hidden = true; return load(true); }
    if (me) return sites();
  }
  addEventListener('hashchange', route);

  // ---- dashboard ----
  // Stacked bars per day. Every number goes through Number() and every label through esc(), even though they come
  // from this site's own API; colours come from the stylesheet (b-accept, b-review, b-reject).
  function chart(days) {
    // Drawn at the box's own width, so bars stretch and the axis labels don't.
    var W = Math.max(300, Math.round($('chart').clientWidth || 560)), H = 190, pad = 28, n = days.length || 1, bw = (W - pad) / n, base = H - 20, top = 12;
    var max = Math.max(1, Math.max.apply(null, days.map(function (d) { return (Number(d.accept) || 0) + (Number(d.review) || 0) + (Number(d.reject) || 0); })));
    var out = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">';
    out += '<line class="gl2" x1="' + pad + '" y1="' + top + '" x2="' + W + '" y2="' + top + '"/>';
    out += '<line class="gl2" x1="' + pad + '" y1="' + ((base + top) / 2) + '" x2="' + W + '" y2="' + ((base + top) / 2) + '"/>';
    out += '<line class="gl" x1="' + pad + '" y1="' + base + '" x2="' + W + '" y2="' + base + '"/>';
    out += '<text class="ax" x="0" y="' + (top + 4) + '">' + esc(max) + '</text><text class="ax" x="0" y="' + (base + 3) + '">0</text>';
    days.forEach(function (d, i) {
      var x = pad + i * bw + 3, w = Math.max(2, bw - 6), y = base, scale = (base - top) / max, day = String(d.day);
      var iso = day.length === 8 ? day.slice(0, 4) + '-' + day.slice(4, 6) + '-' + day.slice(6) : day;
      ['accept', 'review', 'reject'].forEach(function (k) {
        var c = Number(d[k]) || 0, h = c * scale; if (h <= 0) return; y -= h;
        out += '<rect class="b-' + k + '" x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '"><title>' + esc(iso) + ' ' + k + ': ' + esc(c) + '</title></rect>';
      });
      if (i % 2 === 0 || n < 8) out += '<text class="ax" x="' + (x + w / 2) + '" y="' + (H - 4) + '" text-anchor="middle">' + esc(day.slice(6)) + '</text>';
    });
    return out + '</svg>';
  }

  // A reason's readable text, looked up as an own key only (a code of "constructor" shows as the code).
  function rt(code) { return data && has(data.reasonText, code) ? data.reasonText[code] : code; }
  // A verdict is one of three known words; anything else is shown as plain text, never as a class name.
  var VERDICT = { accept: 'verified', review: 'flagged', reject: 'rejected' };
  function vk(v) { return has(VERDICT, v) ? v : 'info'; }

  function render(d) {
    data = d; var p = d.project;
    $('d-name').textContent = p.name; $('d-pk').textContent = p.publicKey; $('d-demo').hidden = !p.demo;
    $('owner-only').hidden = !!p.demo; $('signout').textContent = p.demo ? 'Exit demo' : 'Sign out';
    $('delete').textContent = me ? 'Delete this site' : 'Delete this project';
    var w = d.warnings || [];
    $('warns').hidden = !w.length;
    $('warn-list').innerHTML = w.map(function (x) { return '<li>' + esc(x.text) + '</li>'; }).join('');
    var tot = { sessions: 0, accept: 0, review: 0, reject: 0 }, reasons = Object.create(null);
    var n = function (v) { return Number(v) || 0; };
    d.days.forEach(function (x) { tot.sessions += n(x.sessions); tot.accept += n(x.accept); tot.review += n(x.review); tot.reject += n(x.reject);
      for (var k in x.reasons) if (has(x.reasons, k)) reasons[k] = (reasons[k] || 0) + n(x.reasons[k]); });
    $('s-sessions').textContent = tot.sessions; $('s-accept').textContent = tot.accept; $('s-review').textContent = tot.review; $('s-reject').textContent = tot.reject;
    var all = tot.accept + tot.review + tot.reject;
    $('s-rate').textContent = all ? Math.round(tot.reject / all * 100) + '% of all checks' : 'of all checks';
    $('chart').innerHTML = chart(d.days);

    var rs = Object.keys(reasons).sort(function (a, b) { return reasons[b] - reasons[a]; }).slice(0, 8);
    var rmax = rs.length ? reasons[rs[0]] : 1;
    $('why').innerHTML = rs.length ? rs.map(function (k) {
      var c = reasons[k];
      return '<li><div class="row"><b>' + esc(rt(k)) + '</b><span class="num">' + esc(c) + '</span></div><div class="bar"><i style="width:' + esc(c / (rmax || 1) * 100) + '%"></i></div></li>';
    }).join('') : '<li class="empty">Nothing flagged yet. Reasons show up here as checks come in.</li>';

    $('events').tBodies[0].innerHTML = d.events.length ? d.events.map(function (e, i) {
      var top = e.reasons && e.reasons[0], v = vk(e.verdict);
      return '<tr class="ev v-' + v + '" data-i="' + i + '" tabindex="0"><td class="num">' + esc(ago(e.t)) + '</td><td class="u">' + esc(e.player) + '</td><td class="num r">' + (e.score == null ? '·' : esc(e.score)) + '</td><td><span class="chip ' + v + '">' + esc(v === 'info' ? e.verdict : VERDICT[v]) + '</span></td><td class="num r rk ' + v + '">' + esc(e.risk) + '</td><td>' + esc(top ? rt(top.code) : 'clean') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="empty">Nothing checked yet. Once your server calls verify, every verdict lands here.</td></tr>';

    $('p-count').textContent = d.playerCount ? '· ' + d.playerCount + ' seen in 30 days' : '';
    $('players').tBodies[0].innerHTML = d.players.length ? d.players.map(function (x) {
      return '<tr><td class="u">' + esc(x.player) + '</td><td class="num r">' + esc(x.accept) + '</td><td class="num r">' + esc(x.review) + '</td><td class="num r">' + esc(x.reject) + '</td><td class="num r">' + esc(x.lastRisk) + '</td><td>' + esc(x.topReason ? rt(x.topReason) : '') + '</td><td class="num r">' + (x.lastSeen ? esc(ago(x.lastSeen)) : '') + '</td></tr>';
    }).join('') : '<tr><td colspan="7" class="empty">No users yet.</td></tr>';

    if (!p.demo) {
      var f = $('settings'), s = p.settings;
      if (document.activeElement.form !== f) {
        f.name.value = p.name; f.maxScore.value = s.maxScore == null ? '' : s.maxScore; f.maxScorePerSec.value = s.maxScorePerSec == null ? '' : s.maxScorePerSec;
        f.minDurationMs.value = s.minDurationMs; f.reviewAt.value = s.reviewAt; f.rejectAt.value = s.rejectAt;
        f.origins.value = (s.origins || []).join('\n'); f.strictClock.checked = !!s.strictClock; f.requireSignedRequests.checked = !!s.requireSignedRequests; f.requireHumanCheck.checked = !!s.requireHumanCheck;
      }
      $('i-snippet').textContent = sdkTag(location.origin, p.publicKey);
    }
    lastLoad = Date.now(); tick();
  }
  function tick() { if (lastLoad) $('d-updated').textContent = 'updated ' + ago(lastLoad); }
  var resizeT = 0;
  addEventListener('resize', function () {
    clearTimeout(resizeT);
    resizeT = setTimeout(function () { if (data && !$('dash').hidden) $('chart').innerHTML = chart(data.days); }, 150);
  });

  function toggleEvent(tr) {
    if (!tr || !data) return;
    var next = tr.nextElementSibling;
    if (next && next.classList.contains('detail')) { next.remove(); tr.classList.remove('open'); return; }
    var ev = data.events[Number(tr.getAttribute('data-i'))]; if (!ev) return;
    var rs = ev.reasons || [];
    var items = rs.length ? rs.map(function (r) { return '<li>' + esc(rt(r.code)) + ' <span class="mono">' + esc(r.code) + (r.detail ? ' · ' + esc(r.detail) : '') + '</span></li>'; }).join('') : '<li>No warning signs.</li>';
    var extra = [ev.durationMs != null ? 'run ' + esc((Number(ev.durationMs) / 1000).toFixed(1)) + 's' : null, 'replay ' + esc(ev.replay || 'none'), ev.sid ? 'session ' + esc(ev.sid) : null, esc(new Date(ev.t).toLocaleString())].filter(Boolean).join(' · ');
    tr.classList.add('open');
    tr.insertAdjacentHTML('afterend', '<tr class="detail"><td colspan="6"><ul>' + items + '</ul><div class="ex">' + extra + '</div></td></tr>');
  }
  $('events').addEventListener('click', function (e) { toggleEvent(e.target.closest('tr.ev')); });
  $('events').addEventListener('keydown', function (e) {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var tr = e.target.closest('tr.ev'); if (!tr) return;
    e.preventDefault(); toggleEvent(tr);
  });

  $('settings').addEventListener('submit', function (e) {
    e.preventDefault();
    var f = e.target, msg = $('settings-msg');
    msg.className = 'err'; msg.textContent = 'saving…';
    api('PATCH', me ? 'sites?pid=' + encodeURIComponent(pid) : 'project', { name: f.name.value, settings: {
      maxScore: f.maxScore.value.trim(), maxScorePerSec: f.maxScorePerSec.value.trim(), minDurationMs: f.minDurationMs.value.trim(),
      reviewAt: f.reviewAt.value.trim(), rejectAt: f.rejectAt.value.trim(), origins: lines(f.origins.value), strictClock: f.strictClock.checked, requireSignedRequests: f.requireSignedRequests.checked, requireHumanCheck: f.requireHumanCheck.checked } })
      .then(function (r) { if (!r.ok) { msg.textContent = r.message || r.error; return; } msg.className = 'err good'; msg.textContent = 'saved'; document.activeElement.blur(); load(); });
  });
  $('rotate').addEventListener('click', function () { $('rotate-confirm').hidden = false; });
  $('rotate-no').addEventListener('click', function () { $('rotate-confirm').hidden = true; $('rotate-err').textContent = ''; });
  $('rotate-yes').addEventListener('click', function () {
    $('rotate-err').textContent = '';
    (me ? human('rotate', 'ts-rotate') : Promise.resolve(undefined)).then(function (t) {
      return api('POST', me ? 'sites?pid=' + encodeURIComponent(pid) + '&action=rotate' : 'project?action=rotate', me ? { turnstileToken: t } : {});
    }).then(function (r) {
      if (!r.ok) { $('rotate-err').textContent = r.message || r.error; return; }
      $('rotate-confirm').hidden = true;
      if (me) { $('r-sk').textContent = r.secretKey; $('rotate-out').hidden = false; return; }
      sk = r.secretKey; save(sk); $('r-sk').textContent = sk; $('rotate-out').hidden = false;
    }, function (e) { $('rotate-err').textContent = whyFailed(e); });
  });
  // Deleting: a signed-in site goes through DELETE /sites with the human check (action "delete"); a key-only project
  // through DELETE /project with its key (the API refuses that for a project that belongs to an account).
  $('delete').addEventListener('click', function () { $('delete-confirm').hidden = false; });
  $('delete-no').addEventListener('click', function () { $('delete-confirm').hidden = true; $('delete-err').textContent = ''; });
  $('delete-yes').addEventListener('click', function () {
    var btn = $('delete-yes'); btn.disabled = true; $('delete-err').textContent = '';
    (me ? human('delete', 'ts-delete') : Promise.resolve(undefined)).then(function (t) {
      return api('DELETE', me ? 'sites?pid=' + encodeURIComponent(pid) : 'project', me ? { turnstileToken: t } : undefined);
    }).then(function (r) {
      btn.disabled = false;
      if (!r.ok) { $('delete-err').textContent = r.message || r.error; return; }
      clearInterval(timer); timer = null; data = null; clearProject();
      if (me) { if (location.hash.replace('#', '')) location.hash = ''; else sites(); return; }
      forget(); show('gate');
    }, function (e) { btn.disabled = false; $('delete-err').textContent = whyFailed(e); });
  });

  function load(first) {
    if (first) clearProject(); // a different project (or the same one, fresh): nothing from the last one stays on screen
    return api('GET', demo ? 'dashboard?demo=' + demo : me ? 'sites?pid=' + encodeURIComponent(pid) : 'dashboard').then(function (r) {
      if (!r.ok) {
        if (me) { if (first) { location.hash = ''; } return; }
        if (r._status === 401 && !demo) { forget(); show('gate'); return; }
        if (first) { show(demo ? 'dash' : 'gate'); $(demo ? 'd-name' : 'login-err').textContent = r.message || 'Could not load the dashboard.'; }
        return;
      }
      show('dash'); render(r);
      $('back').hidden = !me; $('signout').hidden = !!me;
      if (me) guide(r); else $('guide').hidden = true;
      if (!timer) timer = setInterval(function () { if (!document.hidden) load(); tick(); }, 15000);
    }, function () { if (first) { show(demo ? 'dash' : 'gate'); } });
  }

  function boot() {
    if (demo) return load(true);
    return api('GET', 'me').then(function (r) {
      tsKey = r.turnstile || null;
      if (r.ok) { me = r.user; return route(); }
      var p = r.providers || {}, any = p.email || p.github || p.google;
      $('signin-card').hidden = !any; $('skip-acct').hidden = !any;
      $('github-btn').hidden = !p.github; $('google-btn').hidden = !p.google;
      if (!p.email) { $('email-form').hidden = true; $('code-form').hidden = true; } else if ($('code-form').hidden) $('email-form').hidden = false;
      if (sk) load(true); else show('gate');
    }, function () { if (sk) load(true); else show('gate'); });
  }
  boot();
})();
