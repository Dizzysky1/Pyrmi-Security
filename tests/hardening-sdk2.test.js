'use strict';
// Regression tests for pyrmi-server 0.3.4, browser SDK 1.4.2 (src/sdk/pyrmi.js + sdk/pyrmi.js), and scripts/build-sdk.js.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';
process.env.TURNSTILE_SITE_KEY = 'test-site-key';
process.env.TURNSTILE_SECRET_KEY = '0x-test-turnstile-secret';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const vm = require('node:vm');
const util = require('node:util');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const { Pyrmi, trusted } = require('../packages/pyrmi-server');
const serverPkg = require('../packages/pyrmi-server/package.json');
const sdkMeta = require('../api/_lib/sdk-build.json');
const core = require('../api/_lib/core');
const B = require('./_browser');
const { serve } = require('../scripts/dev');

const SK = 'sk_' + 's'.repeat(30);
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const validTok = b64u({ v: 1, p: 'p_1', s: 'sess_1', seed: 42, i: 1, e: 9e12 }) + '.mac_part';

let apiSrv, apiBase;
test.before(async () => {
  await B.fakeTurnstile();
  apiSrv = http.createServer(serve);
  await new Promise((r) => apiSrv.listen(0, '127.0.0.1', r));
  apiBase = 'http://127.0.0.1:' + apiSrv.address().port;
});
test.after(() => apiSrv.close());

// Helper to load src/sdk/pyrmi.js or sdk/pyrmi.js in a realistic browser-like VM realm with Document, HTMLScriptElement, Response, etc.
function makeBrowserRealm(sdkPath, opts) {
  opts = opts || {};
  const src = fs.readFileSync(sdkPath, 'utf8');
  let appended = 0, removed = 0;
  let styleTouched = false;
  const setupRealm = (isFrame) => {
    const ctx = vm.createContext({});
    vm.runInContext(`(function (H) {
      function Performance() {}
      Object.defineProperty(Performance.prototype, 'now', { value: Date.now, writable: true, enumerable: true, configurable: true });
      globalThis.Performance = Performance;
      globalThis.performance = Object.create(Performance.prototype);
      function Navigator() {}
      Object.defineProperty(Navigator.prototype, 'webdriver', { get: function webdriver() { return H.webdriver; }, enumerable: true, configurable: true });
      Object.defineProperty(Navigator.prototype, 'userAgent', { get: function userAgent() { return 'Mozilla/5.0 Chrome/156.0'; }, enumerable: true, configurable: true });
      Object.defineProperty(Navigator.prototype, 'languages', { get: function languages() { return ['en']; }, enumerable: true, configurable: true });
      globalThis.Navigator = Navigator;
      globalThis.navigator = Object.create(Navigator.prototype);
      globalThis.setTimeout = H.setTimeout;
      globalThis.setInterval = H.setInterval;
      globalThis.clearTimeout = H.clearTimeout;
      globalThis.clearInterval = H.clearInterval;
      globalThis.requestAnimationFrame = function requestAnimationFrame(f) { return H.setTimeout(f, 16); };
      globalThis.fetch = H.fetch;
      if (H.Response) globalThis.Response = H.Response;
      function XMLHttpRequest() {}
      XMLHttpRequest.prototype.send = function send() {};
      globalThis.XMLHttpRequest = XMLHttpRequest;
      function EventTarget() {}
      EventTarget.prototype.addEventListener = function addEventListener() {};
      globalThis.EventTarget = EventTarget;
      globalThis.addEventListener = EventTarget.prototype.addEventListener;
      function Element() {}
      Element.prototype.getAttribute = function getAttribute(n) { return this.__attrs && n in this.__attrs ? this.__attrs[n] : null; };
      Element.prototype.setAttribute = function setAttribute(n, v) { if (!this.__attrs) this.__attrs = {}; this.__attrs[n] = String(v); };
      globalThis.Element = Element;
      function HTMLScriptElement() {}
      HTMLScriptElement.prototype = Object.create(Element.prototype);
      HTMLScriptElement.prototype.constructor = HTMLScriptElement;
      Object.defineProperty(HTMLScriptElement.prototype, 'src', {
        get: function src() { return this.__src || ''; },
        enumerable: true, configurable: true,
      });
      globalThis.HTMLScriptElement = HTMLScriptElement;
      function HTMLIFrameElement() {}
      HTMLIFrameElement.prototype = Object.create(Element.prototype);
      HTMLIFrameElement.prototype.constructor = HTMLIFrameElement;
      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
        get: function contentWindow() {
          if (H.frameMode === 'throw') throw new Error('SecurityError');
          if (H.frameMode === 'null') return null;
          if (H.frameMode === 'self') return globalThis;
          if (H.frameMode === 'fake') return { Function: globalThis.Function };
          return this.__cw || null;
        },
        enumerable: true, configurable: true,
      });
      globalThis.HTMLIFrameElement = HTMLIFrameElement;
      function Document() {}
      var realScript = Object.create(HTMLScriptElement.prototype);
      realScript.__attrs = H.scriptAttrs || { 'data-site': 'pk_demo_sandbox' };
      realScript.__src = H.scriptSrc !== undefined ? H.scriptSrc : ((H.origin === 'null' ? 'https://pyrmi.com' : H.origin) + '/sdk/pyrmi.js');
      var realDocEl = Object.create(Element.prototype);
      realDocEl.__attrs = {};
      realDocEl.appendChild = function (f) { H.onAppend(); f.__cw = H.makeFrame ? H.makeFrame() : null; };
      realDocEl.removeChild = function (f) { H.onRemove(); f.__cw = null; };
      Object.defineProperty(Document.prototype, 'currentScript', {
        get: function currentScript() { return H.realScriptNull ? null : realScript; },
        enumerable: true, configurable: true,
      });
      Object.defineProperty(Document.prototype, 'documentElement', {
        get: function documentElement() { return realDocEl; },
        enumerable: true, configurable: true,
      });
      Document.prototype.createElement = function createElement() {
        var f = Object.create(HTMLIFrameElement.prototype);
        f.__attrs = {};
        Object.defineProperty(f, 'style', {
          get: function () { H.onStyle(); return {}; },
          configurable: true,
        });
        return f;
      };
      Document.prototype.addEventListener = EventTarget.prototype.addEventListener;
      globalThis.Document = Document;
      var doc = Object.create(Document.prototype);
      doc.hidden = false;
      globalThis.window = globalThis;
      globalThis.document = doc;
      globalThis.location = { href: (H.origin === 'null' ? 'about:blank' : H.origin + '/'), origin: H.origin };
      globalThis.URL = H.URL;
      globalThis.Blob = H.Blob;
      globalThis.atob = H.atob;
      globalThis.btoa = H.btoa;
      globalThis.crypto = H.crypto;
      globalThis.TextEncoder = H.TextEncoder;
      ['outerWidth', 'innerWidth', 'outerHeight', 'innerHeight'].forEach(function (k) {
        Object.defineProperty(globalThis, k, { get: function () { return 0; }, set: function () {}, enumerable: true, configurable: true });
      });
    })`, ctx)({
      webdriver: !!opts.webdriver,
      origin: opts.origin !== undefined ? opts.origin : apiBase,
      frameMode: isFrame ? 'ok' : (opts.frameMode || 'ok'),
      realScriptNull: !isFrame && !!opts.realScriptNull,
      scriptAttrs: opts.scriptAttrs,
      scriptSrc: opts.scriptSrc,
      onAppend: () => { if (!isFrame) appended++; },
      onRemove: () => { if (!isFrame) removed++; },
      onStyle: () => { if (!isFrame) styleTouched = true; },
      makeFrame: isFrame || opts.noIframe ? null : () => setupRealm(true).win,
      setTimeout, setInterval, clearTimeout, clearInterval, URL, Blob, atob, btoa,
      Response: opts.noResponse ? undefined : globalThis.Response,
      crypto: opts.crypto || globalThis.crypto,
      TextEncoder,
      fetch: opts.fetch || ((u, o) => fetch(u, { ...o, headers: { ...(o && o.headers), 'User-Agent': 'Mozilla/5.0 Chrome/156.0', Origin: apiBase, 'Sec-Fetch-Site': 'same-origin' } })),
    });
    return { ctx, win: vm.runInContext('globalThis', ctx) };
  };
  const { ctx, win } = setupRealm(false);
  if (opts.prelude) vm.runInContext(opts.prelude, ctx);
  vm.runInContext(src, ctx);
  return {
    ctx, win, Pyrmi: win.Pyrmi,
    stats: () => ({ appended, removed, styleTouched }),
    tp: () => Array.from(win.Pyrmi.report().tp),
    au: () => Array.from(win.Pyrmi.report().au),
    wr: () => Array.from(win.Pyrmi.report().wr),
  };
}

test('1. High #3: pyrmi-server forwards turnstile fail-closed on empty/null/non-string tokens and missing turnstileSecret', async () => {
  const sent = [];
  const saved = global.fetch;
  global.fetch = async (u, init) => {
    sent.push(JSON.parse(init.body));
    return new Response(JSON.stringify({ ok: true, verdict: 'accept', risk: 0, client: 'corroborated', trusted: true, reasons: [] }), { status: 200 });
  };
  try {
    const withSec = new Pyrmi({ secretKey: SK, turnstileSecret: 'ts_sec_abc' });
    const noSec = new Pyrmi({ secretKey: SK, turnstileSecret: null });
    const sealedWith = (val) => ({ score: 1, turnstile: val, pyrmi: { token: validTok, ts: Date.now(), sig: 'A'.repeat(43) } });

    // Omitting turnstile everywhere leaves turnstile absent from payload
    await withSec.verify({ token: validTok });
    assert.equal(Object.prototype.hasOwnProperty.call(sent.at(-1), 'turnstile'), false);
    await withSec.verify({ sealed: { score: 1, pyrmi: { token: validTok, ts: Date.now(), sig: 'A'.repeat(43) } } });
    assert.equal(Object.prototype.hasOwnProperty.call(sent.at(-1), 'turnstile'), false);

    // Presence on input.turnstile (even empty, null, undefined, non-string, or bad object) ALWAYS forwards turnstile
    for (const bad of ['', null, undefined, 123, false, [], {}, { token: '' }, { token: null, action: 'payout' }, { token: 99, action: 'payout' }]) {
      await withSec.verify({ token: validTok, turnstile: bad });
      const ts = sent.at(-1).turnstile;
      assert.ok(ts && typeof ts === 'object', 'must include turnstile for ' + String(bad));
      assert.equal(ts.token, '');
      assert.equal(ts.secret, 'ts_sec_abc');
    }
    // Action is preserved on object form even when token is missing
    assert.equal(sent.at(-1).turnstile.action, 'payout');

    // Presence on sealed.turnstile (empty, null, non-string, object) ALWAYS forwards turnstile
    for (const bad of ['', null, 123, false, [], { token: 'x' }]) {
      await withSec.verify({ sealed: sealedWith(bad) });
      const ts = sent.at(-1).turnstile;
      assert.ok(ts && typeof ts === 'object', 'must include turnstile for sealed ' + JSON.stringify(bad));
      assert.equal(ts.token, '');
      assert.equal(ts.secret, 'ts_sec_abc');
    }

    // Missing turnstileSecret ALWAYS forwards secret: '' so core.js:checkHuman() fails closed
    await noSec.verify({ token: validTok, turnstile: 'valid_tok' });
    assert.deepEqual(sent.at(-1).turnstile, { token: 'valid_tok', secret: '' });
    await noSec.verify({ sealed: sealedWith('valid_tok') });
    assert.deepEqual(sent.at(-1).turnstile, { token: 'valid_tok', secret: '' });
  } finally {
    global.fetch = saved;
  }

  // End-to-end against core.verify() with requireHumanCheck: false — bad turnstile MUST fail closed (human_check_failed, trusted: false)
  const ip = '198.51.100.77', UA = 'Mozilla/5.0 Chrome/156.0', CH = '"Chromium";v="156"';
  const p = await core.createProject({ name: 'H3', origins: ['https://shop.example'] }, ip, 'owner-h3');
  const project = await core.updateSettings(await core.loadProject(p.pid), { minDurationMs: 0, maxScore: 1000, requireHumanCheck: false });
  const runCase = async (makeCall) => {
    const s = await core.startSession(project, { ip, ua: UA, origin: 'https://shop.example', ch: CH }, { pt: 0 });
    await core.recordSignals({ token: s.token, ...B.order(s), signals: B.signals({ pt: 0 }) }, { ip, ua: UA, origin: 'https://shop.example', sfs: 'same-site' });
    const client = { ua: UA, ip, ch: CH, sfs: 'same-site' };
    const savedF = global.fetch;
    global.fetch = async (u, o) => new Response(JSON.stringify(await core.verify(project, JSON.parse(o.body), { ip })), { status: 200 });
    try { return await makeCall(s, client); } finally { global.fetch = savedF; }
  };

  const withSec = new Pyrmi({ secretKey: p.secretKey, endpoint: 'http://local.invalid/api/v1', turnstileSecret: B.TS_SECRET });
  const noSec = new Pyrmi({ secretKey: p.secretKey, endpoint: 'http://local.invalid/api/v1', turnstileSecret: null });

  const vEmpty = await runCase((s, client) => withSec.verify({
    sealed: { ...B.sign(s, { score: 10 }).fields, pyrmi: { token: s.token, ts: B.sign(s, { score: 10 }).ts, sig: B.sign(s, { score: 10 }).sig } },
    client, turnstile: { token: '', action: 'payout' },
  }));
  assert.equal(vEmpty.human, 'failed');
  assert.equal(vEmpty.trusted, false);
  assert.equal(trusted(vEmpty), false);
  assert.ok(vEmpty.reasons.some((r) => r.code === 'human_check_failed'));

  const vNoSec = await runCase((s, client) => {
    const q = B.sign(s, { score: 10, turnstile: B.human(s, 'shop.example').token });
    return noSec.verify({ sealed: { ...q.fields, pyrmi: { token: s.token, ts: q.ts, sig: q.sig } }, client });
  });
  assert.equal(vNoSec.human, 'failed');
  assert.equal(vNoSec.trusted, false);
  assert.ok(vNoSec.reasons.some((r) => r.code === 'human_check_failed' && /no secret key/.test(r.detail || '')));
});

test('2. Low pyrmi-server 0.3.4: private #secretKey/#turnstileSecret fields and verifyTurnstile res.ok, case-insensitive hostname, cdata', async () => {
  assert.equal(serverPkg.version, '0.3.4');
  const p = new Pyrmi({ secretKey: SK, turnstileSecret: '0x_my_ts_secret' });
  assert.equal(p.secretKey, undefined);
  assert.equal(p.turnstileSecret, undefined);
  assert.ok(!Object.keys(p).includes('secretKey'));
  assert.ok(!Object.keys(p).includes('turnstileSecret'));
  assert.ok(!Object.getOwnPropertyNames(p).includes('secretKey'));
  assert.ok(!Object.getOwnPropertyNames(p).includes('turnstileSecret'));
  assert.ok(!JSON.stringify(p).includes(SK));
  assert.ok(!JSON.stringify(p).includes('0x_my_ts_secret'));
  assert.ok(!util.inspect(p).includes(SK));
  assert.ok(!util.inspect(p).includes('0x_my_ts_secret'));

  // Mock Turnstile endpoint to test res.ok, case-insensitive hostname, and cdata
  let respStatus = 200;
  let respBody = { success: true, hostname: 'Pyrmi.COM', action: 'payout', cdata: 'sess_abc123' };
  const srv = http.createServer((req, res) => {
    req.resume();
    res.writeHead(respStatus, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(respBody));
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const tsUrl = 'http://127.0.0.1:' + srv.address().port + '/siteverify';
  try {
    const cli = new Pyrmi({ secretKey: SK, turnstileSecret: '0x_ts', turnstileEndpoint: tsUrl });

    // Case-insensitive hostname + matching cdata succeeds
    const ok = await cli.verifyTurnstile('tok_1', { hostname: 'pyrmi.com', action: 'payout', cdata: 'sess_abc123' });
    assert.equal(ok.success, true);
    assert.equal(ok.cdata, 'sess_abc123');
    const okUpper = await cli.verifyTurnstile('tok_2', { hostname: 'PYRMI.COM', cdata: 'sess_abc123' });
    assert.equal(okUpper.success, true);

    // cdata mismatch fails closed
    const badCdata = await cli.verifyTurnstile('tok_3', { hostname: 'pyrmi.com', cdata: 'sess_other' });
    assert.equal(badCdata.success, false);
    assert.deepEqual(badCdata.errorCodes, ['cdata-mismatch']);

    // Missing cdata in Cloudflare response when opts.cdata is requested fails closed
    respBody = { success: true, hostname: 'pyrmi.com', action: 'payout' };
    const missingCdata = await cli.verifyTurnstile('tok_4', { hostname: 'pyrmi.com', cdata: 'sess_abc123' });
    assert.equal(missingCdata.success, false);
    assert.deepEqual(missingCdata.errorCodes, ['cdata-mismatch']);
    // Omitting opts.cdata still passes
    assert.equal((await cli.verifyTurnstile('tok_5', { hostname: 'pyrmi.com' })).success, true);

    // Non-2xx status even with { success: true } body MUST fail closed (res.ok check)
    respStatus = 500;
    respBody = { success: true, hostname: 'pyrmi.com', action: 'payout', cdata: 'sess_abc123' };
    const http500 = await cli.verifyTurnstile('tok_6', { hostname: 'pyrmi.com', cdata: 'sess_abc123' });
    assert.equal(http500.success, false);
    assert.deepEqual(http500.errorCodes, ['turnstile-unreachable']);

    respStatus = 403;
    const http403 = await cli.verifyTurnstile('tok_7', { hostname: 'pyrmi.com' });
    assert.equal(http403.success, false);
    assert.deepEqual(http403.errorCodes, ['turnstile-unreachable']);
  } finally {
    srv.close();
  }
});

for (const rel of ['src/sdk/pyrmi.js', 'sdk/pyrmi.js']) {
  const sdkFile = path.join(ROOT, rel);

  test('3. ' + rel + ': High #4 setter-only accessor and non-function watched method are caught (before/after load, with/without iframe)', () => {
    const cases = [
      ["Object.defineProperty(Navigator.prototype, 'webdriver', { set: function () {}, enumerable: true, configurable: true });", 'navigator.webdriver'],
      ["Object.defineProperty(navigator, 'webdriver', { set: function () {}, enumerable: true, configurable: true });", 'navigator.webdriver'],
      ["Object.defineProperty(Navigator.prototype, 'webdriver', { get: undefined, set: undefined, enumerable: true, configurable: true });", 'navigator.webdriver'],
      ["Object.defineProperty(Performance.prototype, 'now', { set: function () {}, enumerable: true, configurable: true });", 'performance.now'],
      ["Object.defineProperty(window, 'outerWidth', { set: function () {}, enumerable: true, configurable: true });", 'outerWidth'],
      ["Object.defineProperty(Performance.prototype, 'now', { value: 123, writable: true, enumerable: true, configurable: true });", 'performance.now'],
    ];
    for (const [trick, label] of cases) {
      // Before load with clean iframe
      const pBefore = makeBrowserRealm(sdkFile, { prelude: trick });
      assert.ok(pBefore.tp().includes(label), 'before+iframe ' + label + ' -> ' + JSON.stringify(pBefore.tp()));
      // Before load WITHOUT clean iframe (e.g. opaque origin)
      const pNoFrame = makeBrowserRealm(sdkFile, { prelude: trick, origin: 'null', frameMode: 'null' });
      assert.ok(pNoFrame.tp().includes(label), 'before+no-iframe ' + label + ' -> ' + JSON.stringify(pNoFrame.tp()));
      // After load
      const pAfter = makeBrowserRealm(sdkFile);
      vm.runInContext(trick, pAfter.ctx);
      assert.ok(pAfter.tp().includes(label), 'after ' + label + ' -> ' + JSON.stringify(pAfter.tp()));
    }
  });

  test('4. ' + rel + ': High #4 blocked probe iframe records iframe.contentWindow (except opaque origin null) with zero .style writes', () => {
    // Clean page: no tamper, zero .style writes
    const clean = makeBrowserRealm(sdkFile);
    assert.deepEqual(clean.tp(), []);
    assert.deepEqual(clean.stats(), { appended: 1, removed: 1, styleTouched: false });

    // Blocked iframe on normal origin: records iframe.contentWindow
    for (const mode of ['null', 'self', 'fake', 'throw']) {
      const p = makeBrowserRealm(sdkFile, { frameMode: mode });
      assert.ok(p.tp().includes('iframe.contentWindow'), mode + ' -> ' + JSON.stringify(p.tp()));
      assert.equal(p.stats().appended, 1);
      assert.equal(p.stats().removed, 1);
      assert.equal(p.stats().styleTouched, false);
    }

    // Opaque origin ('null') where browser built-ins are native (no fresh iframe available):
    // does NOT false-positive iframe.contentWindow!
    const opaque = makeBrowserRealm(sdkFile, {
      origin: 'null',
      frameMode: 'null',
      prelude: `
        var origToStr = Function.prototype.toString;
        var cwGetter = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
        Function.prototype.toString = function toString() {
          if (this === cwGetter) return 'function get contentWindow() { [native code] }';
          if (this === Function.prototype.toString) return 'function toString() { [native code] }';
          return origToStr.call(this);
        };
      `,
    });
    assert.ok(!opaque.tp().includes('iframe.contentWindow'), 'opaque origin -> ' + JSON.stringify(opaque.tp()));
    // Same native-looking contentWindow on a normal origin MUST record iframe.contentWindow when probe iframe fails!
    const normalBlocked = makeBrowserRealm(sdkFile, {
      frameMode: 'null',
      prelude: `
        var origToStr = Function.prototype.toString;
        var cwGetter = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow').get;
        Function.prototype.toString = function toString() {
          if (this === cwGetter) return 'function get contentWindow() { [native code] }';
          if (this === Function.prototype.toString) return 'function toString() { [native code] }';
          return origToStr.call(this);
        };
      `,
    });
    assert.ok(normalBlocked.tp().includes('iframe.contentWindow'), 'normal origin blocked iframe -> ' + JSON.stringify(normalBlocked.tp()));
  });

  test('5. ' + rel + ': Medium #11 DOM clobbering on document.currentScript / documentElement / createElement cannot hijack config', () => {
    // Clobber document.currentScript with a fake non-HTMLScriptElement object (simulating <img name="currentScript">)
    const clobbered = makeBrowserRealm(sdkFile, {
      prelude: `
        Object.defineProperty(document, 'currentScript', {
          value: { getAttribute: function (n) { return n === 'data-api' ? 'https://evil.example/api/v1' : 'pk_evil'; }, src: 'https://evil.example/sdk/pyrmi.js' },
          configurable: true,
        });
        Object.defineProperty(document, 'documentElement', {
          value: { getAttribute: function () { return '1'; }, appendChild: function () {}, removeChild: function () {} },
          configurable: true,
        });
      `,
    });
    // Document.prototype.currentScript returned the real HTMLScriptElement, ignoring own clobbered property
    assert.equal(clobbered.Pyrmi.config.site, 'pk_demo_sandbox');
    assert.equal(clobbered.Pyrmi.config.api, apiBase + '/api/v1');
    assert.deepEqual(clobbered.au(), []);

    // Even if Document.prototype.currentScript getter itself returns a non-HTMLScriptElement (e.g. an <img>), instanceof HTMLScriptElement rejects it
    const fakeElem = makeBrowserRealm(sdkFile, {
      prelude: `
        Object.defineProperty(Document.prototype, 'currentScript', {
          get: function () { return { getAttribute: function (n) { return n === 'data-api' ? 'https://evil.example/api/v1' : 'pk_evil'; }, src: 'https://evil.example/sdk/pyrmi.js' }; },
          configurable: true,
        });
      `,
    });
    assert.equal(fakeElem.Pyrmi.config.site, null);
    assert.equal(fakeElem.Pyrmi.config.api, apiBase + '/api/v1');
  });

  test('6. ' + rel + ': Medium #11 report() and signals() clone env.tp, env.au, env.wr so page code cannot mutate internal arrays', () => {
    const p = makeBrowserRealm(sdkFile, { prelude: 'window.__playwright__binding__ = true; window.fetch = window.fetch.bind(window); performance.now = (() => 0).bind(window);' });
    const r1 = p.Pyrmi.report();
    assert.ok(r1.tp.includes('performance.now'));
    assert.ok(r1.au.includes('playwright'));
    assert.ok(r1.wr.includes('fetch'));

    // Page code mutates every array returned by report()
    r1.tp.length = 0;
    r1.tp.push('fake_tp');
    r1.au.length = 0;
    r1.wr.length = 0;

    // Subsequent report() still has the original untouched entries (and not 'fake_tp')
    const r2 = p.Pyrmi.report();
    assert.notEqual(r2.tp, r1.tp);
    assert.notEqual(r2.au, r1.au);
    assert.notEqual(r2.wr, r1.wr);
    assert.ok(r2.tp.includes('performance.now') && !r2.tp.includes('fake_tp'));
    assert.ok(r2.au.includes('playwright'));
    assert.ok(r2.wr.includes('fetch'));
  });

  test('7. ' + rel + ': immediate non-extractable CryptoKey import and survival against Response/Promise/String/RegExp post-load poisoning', async () => {
    let importCalls = 0, lastExtractable = null, lastUsages = null;
    const realSubtle = globalThis.crypto.subtle;
    const wrappedCrypto = {
      subtle: {
        importKey: function (fmt, keyData, alg, extractable, usages) {
          importCalls++;
          lastExtractable = extractable;
          lastUsages = usages;
          return realSubtle.importKey(fmt, keyData, alg, extractable, usages);
        },
        sign: function (alg, key, data) {
          return realSubtle.sign(alg, key, data);
        },
      },
    };
    const p = makeBrowserRealm(sdkFile, { crypto: wrappedCrypto });

    // Save host Response.prototype methods since globalThis.Response is shared with the VM context.
    const savedRespJson = globalThis.Response.prototype.json;
    const savedRespText = globalThis.Response.prototype.text;
    try {
      // Poison Response.prototype.json/text, Promise.prototype.then, String.prototype.replace, RegExp, RegExp.prototype.test AFTER load
      vm.runInContext(`
        Response.prototype.json = function () { throw new Error('json poisoned'); };
        Response.prototype.text = function () { throw new Error('text poisoned'); };
        Promise.prototype.then = function () { throw new Error('then poisoned'); };
        String.prototype.replace = function () { throw new Error('replace poisoned'); };
        window.RegExp = function () { throw new Error('RegExp poisoned'); };
        RegExp.prototype.test = function () { throw new Error('reTest poisoned'); };
      `, p.ctx);

      // Note: use captured Promise.prototype.then from host realm to await the returned promise cleanly
      const s = await new Promise((res, rej) => Promise.prototype.then.call(p.Pyrmi.start(), res, rej));
      assert.ok(s.token);
      assert.equal(importCalls, 1, 'j.rk must be imported immediately during start()');
      assert.equal(lastExtractable, false, 'CryptoKey must be non-extractable');
      assert.deepEqual(Array.from(lastUsages), ['sign']);

      // Even if subtle.importKey is sabotaged after start(), seal() still signs using the cached non-extractable CryptoKey!
      wrappedCrypto.subtle.importKey = () => { throw new Error('importKey must not be called during seal'); };
      const sealed1 = await new Promise((res, rej) => Promise.prototype.then.call(p.Pyrmi.seal({ value: 42, visitor: 'v1' }), res, rej));
      assert.equal(sealed1.value, 42);
      assert.ok(sealed1.pyrmi && typeof sealed1.pyrmi.sig === 'string' && sealed1.pyrmi.sig.length >= 40);
      assert.equal(importCalls, 1, 'seal() must reuse the imported CryptoKey');

      const flushed = await new Promise((res, rej) => Promise.prototype.then.call(p.Pyrmi.flush(), res, rej));
      p.Pyrmi.stop();
      assert.ok(flushed && flushed.ok, 'flush() succeeded despite poisoned Response/Promise/String/RegExp');
      const rep = p.Pyrmi.report();
      assert.equal(typeof rep.sh, 'string');
    } finally {
      globalThis.Response.prototype.json = savedRespJson;
      globalThis.Response.prototype.text = savedRespText;
    }
  });

  test('8. ' + rel + ': beacon() uses wallNow() + skew so a fast client clock does not stop beacons early', async () => {
    const beacons = [];
    const realNow = Date.now();
    const fastOffset = 3600 * 1000; // client clock is 1 hour ahead of server!
    let clockNow = realNow + fastOffset;
    const p = makeBrowserRealm(sdkFile, {
      prelude: `Date.now = function now() { return ${clockNow}; };`,
      fetch: async (u, o) => {
        if (String(u).endsWith('/session')) {
          return new Response(JSON.stringify({
            ok: true, token: validTok, session: 'sess_skew', seed: 1, bn: 'bn_skew',
            issuedAt: realNow, expiresAt: realNow + 1800 * 1000, rk: b64u({ k: 1 }),
          }), { status: 200 });
        }
        beacons.push(JSON.parse(o.body));
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      },
    });
    await p.Pyrmi.start();
    // Without skew adjustment, wallNow() (realNow + 3600s) > expiresAt (realNow + 1800s) would have stopped beacons!
    await p.Pyrmi.flush();
    p.Pyrmi.stop();
    assert.equal(beacons.length, 1, 'beacon must still be sent when client clock is fast');
    assert.equal(beacons[0].n, 1);
  });
}

test('9. scripts/build-sdk.js captures RegExp once at load time (never w["RegExp"] per regex) and preserves 1.3.0/1.4.0/1.4.1', () => {
  const built = fs.readFileSync(path.join(ROOT, 'sdk/pyrmi.js'), 'utf8');
  assert.equal(sdkMeta.version, '1.4.2');
  assert.equal(sdkMeta.protocol, 3);
  assert.equal(sdkMeta.supported.a854eb80, '1.3.0');
  assert.equal(sdkMeta.supported['0a0d2f04'], '1.4.0');
  assert.equal(sdkMeta.supported['3d5b0ed0'], '1.4.1');
  // Decoder captures RegExp once (`var <REGEXP>=<WIN>[<TABLE>[0]];`), and regexes instantiate `(new <REGEXP>(...))`
  const cap = /;var ([Il1]+)=([Il1]+)\[([Il1]+\[0\])\];/.exec(built);
  assert.ok(cap, 'built SDK must capture RegExp at load time');
  const [, regVar, winVar, reRef] = cap;
  assert.ok(built.includes('(new ' + regVar + '('), 'compiled regexes must use captured RegExp variable');
  assert.ok(!built.includes('new ' + winVar + '[' + reRef + ']'), 'built SDK must not read mutable window["RegExp"] per regex');
  // Immutable published SDK versions must retain exact hashes
  const v140 = fs.readFileSync(path.join(ROOT, 'sdk/1.4.0/pyrmi.js'));
  const v141 = fs.readFileSync(path.join(ROOT, 'sdk/1.4.1/pyrmi.js'));
  assert.equal('sha384-' + crypto.createHash('sha384').update(v140).digest('base64'), 'sha384-Ntb/iXRb7fGCpY1n/1u3hP1GrS8Dh64H7f3TD3wgzmH971YaAL8VZ7efcqfvv/uQ');
  assert.equal('sha384-' + crypto.createHash('sha384').update(v141).digest('base64'), 'sha384-D04YwtCEA1kV3ku22rSlK5QI7BBEb3SkSvSIJGz5i1ololjoYjDLgdbcf8dsuvN8');
  assert.ok(fs.existsSync(path.join(ROOT, 'sdk/1.4.2/pyrmi.js')));
});
