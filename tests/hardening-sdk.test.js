'use strict';
// Regression tests for pyrmi-server 0.3.3, browser SDK 1.4.1 (src/sdk/pyrmi.js + sdk/pyrmi.js) and scripts/build-sdk.js.
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN ||= '100000';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const vm = require('node:vm');
const crypto = require('node:crypto');

const ROOT = path.resolve(__dirname, '..');
const { Pyrmi, trusted, clientOf } = require('../packages/pyrmi-server');
const serverPkg = require('../packages/pyrmi-server/package.json');
const buildSdk = require('../scripts/build-sdk');
const sdkMeta = require('../api/_lib/sdk-build.json');
const { serve } = require('../scripts/dev');

const SK = 'sk_' + 'k'.repeat(30);
const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const validTok = b64u({ v: 1, p: 'p_1', s: 'sess_1', seed: 42, i: 1, e: 9e12 }) + '.mac_part';

let apiSrv, apiBase;
test.before(async () => {
  apiSrv = http.createServer(serve);
  await new Promise((r) => apiSrv.listen(0, '127.0.0.1', r));
  apiBase = 'http://127.0.0.1:' + apiSrv.address().port;
});
test.after(() => apiSrv.close());

test('1. pyrmi-server version is 0.3.4 and SDK metadata preserves 1.3.0 + 1.4.0 + 1.4.1 in supported', () => {
  assert.equal(serverPkg.version, '0.3.4');
  assert.equal(sdkMeta.version, '1.4.2');
  assert.equal(sdkMeta.protocol, 3);
  assert.equal(sdkMeta.supported.a854eb80, '1.3.0');
  assert.equal(sdkMeta.supported['0a0d2f04'], '1.4.0');
  assert.equal(sdkMeta.supported['3d5b0ed0'], '1.4.1');
  // Immutable published SDK files must never change bytes.
  const v140 = fs.readFileSync(path.join(ROOT, 'sdk/1.4.0/pyrmi.js'));
  assert.equal(
    'sha384-' + crypto.createHash('sha384').update(v140).digest('base64'),
    'sha384-Ntb/iXRb7fGCpY1n/1u3hP1GrS8Dh64H7f3TD3wgzmH971YaAL8VZ7efcqfvv/uQ'
  );
  const v141 = fs.readFileSync(path.join(ROOT, 'sdk/1.4.1/pyrmi.js'));
  assert.equal(
    'sha384-' + crypto.createHash('sha384').update(v141).digest('base64'),
    'sha384-D04YwtCEA1kV3ku22rSlK5QI7BBEb3SkSvSIJGz5i1ololjoYjDLgdbcf8dsuvN8'
  );
  assert.ok(fs.existsSync(path.join(ROOT, 'sdk/1.3.0/pyrmi.js')));
  assert.ok(fs.existsSync(path.join(ROOT, 'sdk/1.4.1/pyrmi.js')));
  assert.ok(fs.existsSync(path.join(ROOT, 'sdk/1.4.2/pyrmi.js')));
});

test('2. pyrmi-server refuses stripped or malformed sealed envelopes instead of downgrading to unsigned', async () => {
  const saved = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls++;
    return new Response(JSON.stringify({ ok: true, verdict: 'accept', risk: 0, client: 'corroborated', trusted: true, reasons: [] }), { status: 200 });
  };
  try {
    const pyrmi = new Pyrmi({ secretKey: SK, failOpen: true });
    const badInputs = [
      { sealed: null },
      { sealed: [] },
      { sealed: 'not-an-object' },
      { sealed: 123 },
      { sealed: { email: 'a@b.co' } },
      { sealed: { email: 'a@b.co', pyrmi: null } },
      { sealed: { email: 'a@b.co', pyrmi: [] } },
      { sealed: { email: 'a@b.co', pyrmi: { token: validTok } } }, // stripped ts + sig
      { sealed: { email: 'a@b.co', pyrmi: { token: validTok, ts: Date.now() } } }, // stripped sig
      { sealed: { email: 'a@b.co', pyrmi: { token: validTok, ts: Date.now(), sig: '' } } },
      { sealed: { email: 'a@b.co', pyrmi: { token: validTok, ts: NaN, sig: 'abc' } } },
      { sealed: { email: 'a@b.co', pyrmi: { token: validTok, ts: '123', sig: 'abc' } } },
      { sealed: { email: 'a@b.co', pyrmi: { token: '', ts: 1, sig: 'abc' } } },
      { token: validTok, sealed: { email: 'a@b.co', pyrmi: { token: validTok } } }, // token alongside stripped seal
      { sealed: Object.create({ pyrmi: { token: validTok, ts: 1, sig: 'abc' } }) }, // inherited pyrmi
    ];
    for (const input of badInputs) {
      const v = await pyrmi.verify(input);
      assert.equal(v.verdict, 'reject');
      assert.equal(v.ok, false);
      assert.equal(v.trusted, false);
      assert.equal(v.client, 'none');
      assert.equal(v.signed, 'bad');
      assert.equal(trusted(v), false);
      const codes = v.reasons.map((r) => r.code);
      assert.ok(codes.includes('pyrmi_refused') && codes.includes('bad_signature'), JSON.stringify(v));
    }
    assert.equal(calls, 0, 'malformed sealed input must be refused before any network request');
  } finally {
    global.fetch = saved;
  }
});

test('3. pyrmi-server joins multi-header X-Forwarded-For, validates trustProxyHops and supports trustedIpHeader', async () => {
  // Array X-Forwarded-For values (multiple headers): join(', ') rather than v[0].
  const multi = {
    headers: { 'x-forwarded-for': ['6.6.6.6', '198.51.100.4'], 'user-agent': 'UA', 'sec-ch-ua': 'CH', 'sec-fetch-site': 'same-origin' },
    socket: { remoteAddress: '10.0.0.2' },
  };
  assert.equal(clientOf(multi, 0).ip, '10.0.0.2');
  assert.equal(clientOf(multi, 1).ip, '198.51.100.4');
  assert.equal(clientOf(multi, 2).ip, '6.6.6.6');

  const cfToVercel = {
    headers: { 'x-forwarded-for': ['6.6.6.6, 203.0.113.55', '172.68.1.9'], 'user-agent': 'UA' },
    socket: { remoteAddress: '10.0.0.2' },
  };
  assert.equal(clientOf(cfToVercel, 2).ip, '203.0.113.55');

  // Direct Cloudflare Worker: trustedIpHeader: 'cf-connecting-ip'
  const workerReq = {
    headers: new Headers({ 'cf-connecting-ip': '203.0.113.77', 'x-forwarded-for': '1.2.3.4', 'user-agent': 'W-UA', 'sec-fetch-site': 'same-origin' }),
  };
  assert.equal(clientOf(workerReq, 0, 'cf-connecting-ip').ip, '203.0.113.77');
  assert.equal(clientOf(workerReq, { trustedIpHeader: 'CF-Connecting-IP' }).ip, '203.0.113.77');
  // Comma-stuffed single-IP header is ignored rather than trusting the first entry.
  const stuffed = { headers: { 'cf-connecting-ip': ['1.1.1.1', '2.2.2.2'] }, socket: { remoteAddress: '10.0.0.9' } };
  assert.equal(clientOf(stuffed, 0, 'cf-connecting-ip').ip, '10.0.0.9');

  // Verify Pyrmi forwards trustedIpHeader in verify({ req })
  const saved = global.fetch;
  let sent = null;
  global.fetch = async (u, init) => {
    sent = JSON.parse(init.body);
    return new Response(JSON.stringify({ ok: true, verdict: 'accept', risk: 0, client: 'corroborated', trusted: true, reasons: [] }), { status: 200 });
  };
  try {
    const p = new Pyrmi({ secretKey: SK, trustedIpHeader: 'cf-connecting-ip' });
    await p.verify({ token: validTok, req: workerReq });
    assert.equal(sent.client.ip, '203.0.113.77');
  } finally {
    global.fetch = saved;
  }

  for (const badHops of [-1, 1.5, NaN, Infinity, '1', true, null]) {
    assert.throws(() => new Pyrmi({ secretKey: SK, trustProxyHops: badHops }), /trustProxyHops/, String(badHops));
  }
  for (const badHdr of ['', '   ', 'x-forwarded-for', 'X-Forwarded-For', 'forwarded', 'bad header', 123]) {
    assert.throws(() => new Pyrmi({ secretKey: SK, trustedIpHeader: badHdr }), /trustedIpHeader/, String(badHdr));
  }
});

test('4. pyrmi-server validates endpoint, turnstileEndpoint and timeoutMs in constructor', () => {
  for (const okUrl of [
    'https://pyrmi.com/api/v1',
    'https://self.example:8443/api/v1/',
    'http://localhost:3000/api/v1',
    'http://127.0.0.1:8787/api/v1',
    'http://[::1]:8787/api/v1',
  ]) {
    const p = new Pyrmi({ secretKey: SK, endpoint: okUrl, turnstileEndpoint: okUrl });
    assert.ok(p.endpoint.length > 0);
  }

  for (const badUrl of [
    '',
    'not-a-url',
    'http://pyrmi.com/api/v1',
    'http://evil.example/api/v1',
    'http://127.0.0.2/api/v1',
    'http://10.0.0.1/api/v1',
    'http://169.254.169.254/latest/meta-data',
    'http://0x7f000001/api/v1',
    'ftp://pyrmi.com/api/v1',
    'javascript:alert(1)',
    'https://user:pass@pyrmi.com/api/v1',
    'https://user@pyrmi.com/api/v1',
    'https://@pyrmi.com/api/v1',
    'https://pyrmi.com/api/v1?leak=1',
    'https://pyrmi.com/api/v1?',
    'https://pyrmi.com/api/v1#frag',
    'https://pyrmi.com/api/v1#',
    'https://pyrmi.com\\@evil.example/api/v1',
    123,
    null,
  ]) {
    assert.throws(() => new Pyrmi({ secretKey: SK, endpoint: badUrl }), /endpoint/, String(badUrl));
    assert.throws(() => new Pyrmi({ secretKey: SK, turnstileEndpoint: badUrl }), /turnstileEndpoint/, String(badUrl));
  }

  for (const badTimeout of [0, -1, -500, NaN, Infinity, '8000', null, false]) {
    assert.throws(() => new Pyrmi({ secretKey: SK, timeoutMs: badTimeout }), /timeoutMs/, String(badTimeout));
  }
});

test('5. pyrmi-server refuses HTTP redirects (307/308) and caps response bodies at 64 KB', async () => {
  let leakedAuth = null, leakedTurnstileBody = null;
  const sink = http.createServer((req, res) => {
    leakedAuth = req.headers.authorization || null;
    let b = '';
    req.on('data', (c) => { b += c; });
    req.on('end', () => {
      leakedTurnstileBody = b;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, success: true, verdict: 'accept', risk: 0, reasons: [] }));
    });
  });
  await new Promise((r) => sink.listen(0, '127.0.0.1', r));
  const sinkUrl = 'http://127.0.0.1:' + sink.address().port;

  let mode = '307';
  const upstream = http.createServer((req, res) => {
    req.resume();
    if (mode === '307' || mode === '308') {
      res.writeHead(Number(mode), { Location: sinkUrl + req.url });
      res.end();
      return;
    }
    if (mode === 'big200') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end('{"ok":true,"verdict":"accept","reasons":[],"pad":"' + 'x'.repeat(70 * 1024) + '"}');
      return;
    }
    if (mode === 'big400') {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end('{"error":"bad_request","pad":"' + 'y'.repeat(70 * 1024) + '"}');
      return;
    }
  });
  await new Promise((r) => upstream.listen(0, '127.0.0.1', r));
  const upUrl = 'http://127.0.0.1:' + upstream.address().port;

  try {
    const pClosed = new Pyrmi({ secretKey: SK, endpoint: upUrl, turnstileSecret: 'ts_sec_123', turnstileEndpoint: upUrl + '/siteverify' });
    const pOpen = new Pyrmi({ secretKey: SK, endpoint: upUrl, failOpen: true });

    for (const code of ['307', '308']) {
      mode = code;
      const v = await pClosed.verify({ token: validTok });
      assert.equal(v.verdict, 'reject');
      assert.equal(v.trusted, false);
      assert.equal(v.client, 'none');
      const vo = await pOpen.verify({ token: validTok });
      assert.equal(vo.verdict, 'accept');
      assert.equal(vo.trusted, false);
      assert.equal(vo.client, 'none');
      assert.equal(trusted(vo), false);
      const t = await pClosed.verifyTurnstile('tok_123');
      assert.equal(t.success, false);
      assert.deepEqual(t.errorCodes, ['turnstile-unreachable']);
      assert.equal(leakedAuth, null, 'secretKey must never follow ' + code + ' redirect');
      assert.equal(leakedTurnstileBody, null, 'turnstileSecret must never follow ' + code + ' redirect');
    }

    mode = 'big200';
    const bigV = await pClosed.verify({ token: validTok });
    assert.equal(bigV.verdict, 'reject');
    assert.equal(bigV.trusted, false);
    assert.equal(bigV.client, 'none');
    const bigT = await pClosed.verifyTurnstile('tok_123');
    assert.equal(bigT.success, false);
    assert.deepEqual(bigT.errorCodes, ['turnstile-unreachable']);

    mode = 'big400';
    const big400 = await pOpen.verify({ token: validTok });
    assert.equal(big400.verdict, 'reject', '4xx with >64KB body must still refuse even under failOpen');
    assert.equal(big400.trusted, false);
    assert.equal(big400.client, 'none');
  } finally {
    upstream.close();
    sink.close();
  }
});

test('6. pyrmi-server simulate() & replay hardening: no null->0 coercion, token shape before stringify, failOpen respects mismatch', async () => {
  const saved = global.fetch;
  try {
    global.fetch = async () => new Response(
      JSON.stringify({ ok: true, verdict: 'accept', risk: 0, client: 'corroborated', trusted: true, seed: 7, session: 'sess_1', reasons: [] }),
      { status: 200 }
    );
    const p = new Pyrmi({ secretKey: SK });

    // { score: null }, false, '', [], '0', NaN must NEVER coerce to 0!
    for (const fake of [{ score: null }, { score: false }, { score: '' }, { score: [] }, { score: '0' }, { score: NaN }, { score: Infinity }, null, undefined]) {
      const v = await p.verify({ token: validTok, score: 0, replay: [1], simulate: () => fake });
      assert.equal(v.verdict, 'reject', JSON.stringify(fake));
      assert.equal(v.replay, 'mismatch');
      assert.equal(v.trusted, false);
    }

    // Non-null r.durationMs must be a finite number even when caller omitted durationMs.
    for (const badDur of [NaN, Infinity, -Infinity, '100', true, {}]) {
      const v = await p.verify({ token: validTok, score: 0, replay: [1], simulate: () => ({ score: 0, durationMs: badDur }) });
      assert.equal(v.verdict, 'reject', String(badDur));
      assert.equal(v.replay, 'mismatch');
    }

    // Honest numeric 0 and matching finite durationMs pass.
    const okZero = await p.verify({ token: validTok, score: 0, durationMs: 1000, replay: [1], simulate: () => ({ score: 0, durationMs: 1030 }) });
    assert.equal(okZero.verdict, 'accept');
    assert.equal(okZero.replay, 'match');

    // Token shape validated BEFORE JSON.stringify(replay).
    let serialized = 0;
    const bomb = { toJSON() { serialized++; return [1, 2, 3]; } };
    for (const badToken of [undefined, '', 'no-dot', '.onlymac', 'onlybody.', 'bad space.mac', 123, null]) {
      const v = await p.verify({ token: badToken, score: 1, replay: bomb, simulate: () => ({ score: 1 }) });
      assert.equal(v.verdict, 'reject');
      assert.equal(v.trusted, false);
      assert.equal(v.client, 'none');
    }
    assert.equal(serialized, 0, 'replay must never be serialized when token shape is invalid');

    // Local replayCheck mismatch (> maxReplayBytes or circular) is NEVER overridden to accept by failOpen: true when unreachable.
    global.fetch = async () => { throw new Error('ECONNREFUSED'); };
    const pOpen = new Pyrmi({ secretKey: SK, failOpen: true, maxReplayBytes: 64 });
    const over = await pOpen.verify({ token: validTok, score: 1, replay: 'x'.repeat(200), simulate: () => ({ score: 1 }) });
    assert.equal(over.verdict, 'reject');
    assert.equal(over.replay, 'mismatch');
    assert.equal(over.trusted, false);
    assert.equal(over.client, 'none');
    assert.equal(trusted(over), false);

    const cyc = {};
    cyc.self = cyc;
    const cycRes = await pOpen.verify({ token: validTok, score: 1, replay: cyc, simulate: () => ({ score: 1 }) });
    assert.equal(cycRes.verdict, 'reject');
    assert.equal(cycRes.replay, 'mismatch');
    assert.equal(cycRes.trusted, false);
    assert.equal(cycRes.client, 'none');
  } finally {
    global.fetch = saved;
  }
});

// Helper to load browser SDK (source and built) in an isolated realm with configurable iframe / prototype hooks.
function makeSdkPage(sdkPath, opts) {
  opts = opts || {};
  const src = fs.readFileSync(sdkPath, 'utf8');
  let appended = 0, removed = 0;
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
      function XMLHttpRequest() {}
      XMLHttpRequest.prototype.send = function send() {};
      globalThis.XMLHttpRequest = XMLHttpRequest;
      function EventTarget() {}
      EventTarget.prototype.addEventListener = function addEventListener() {};
      globalThis.EventTarget = EventTarget;
      globalThis.addEventListener = EventTarget.prototype.addEventListener;
      function HTMLIFrameElement() {}
      Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {
        get: function contentWindow() {
          if (H.throwFrameSecurityError) throw new Error('SecurityError: Blocked a frame from accessing a cross-origin frame.');
          return this.__cw || null;
        },
        enumerable: true,
        configurable: true,
      });
      globalThis.HTMLIFrameElement = HTMLIFrameElement;
      var doc = {
        hidden: false,
        currentScript: { getAttribute: function (n) { return n === 'data-site' ? 'pk_demo_sandbox' : null; }, src: H.origin + '/sdk/pyrmi.js' },
        addEventListener: EventTarget.prototype.addEventListener,
        createElement: function createElement() { var f = Object.create(HTMLIFrameElement.prototype); f.style = {}; f.setAttribute = function () {}; return f; },
        documentElement: {
          getAttribute: function () { return null; },
          appendChild: function (f) { H.onAppend(); f.__cw = H.makeFrame ? H.makeFrame() : null; },
          removeChild: function (f) { H.onRemove(); f.__cw = null; },
        },
      };
      globalThis.window = globalThis;
      globalThis.document = doc;
      globalThis.location = { href: H.origin + '/', origin: H.origin };
      globalThis.URL = H.URL;
      globalThis.Blob = H.Blob;
      globalThis.atob = H.atob;
      globalThis.btoa = H.btoa;
      globalThis.crypto = H.crypto;
      globalThis.TextEncoder = H.TextEncoder;
      globalThis.outerWidth = 0; globalThis.innerWidth = 0; globalThis.outerHeight = 0; globalThis.innerHeight = 0;
    })`, ctx)({
      webdriver: !!opts.webdriver,
      origin: apiBase,
      throwFrameSecurityError: !isFrame && !!opts.throwFrameSecurityError,
      onAppend: () => { if (!isFrame) appended++; },
      onRemove: () => { if (!isFrame) removed++; },
      makeFrame: isFrame ? null : () => setupRealm(true).win,
      setTimeout, setInterval, clearTimeout, clearInterval, URL, Blob, atob, btoa, crypto: globalThis.crypto, TextEncoder,
      fetch: (u, o) => fetch(u, { ...o, headers: { ...(o && o.headers), 'User-Agent': 'Mozilla/5.0 Chrome/156.0', Origin: apiBase, 'Sec-Fetch-Site': 'same-origin' } }),
    });
    return { ctx, win: vm.runInContext('globalThis', ctx) };
  };
  const { ctx, win } = setupRealm(false);
  if (opts.prelude) vm.runInContext(opts.prelude, ctx);
  vm.runInContext(src, ctx);
  return { ctx, win, Pyrmi: win.Pyrmi, stats: () => ({ appended, removed }) };
}

for (const rel of ['src/sdk/pyrmi.js', 'sdk/pyrmi.js']) {
  const sdkFile = path.join(ROOT, rel);

  test('7. ' + rel + ': catches pre-load delete of Navigator.prototype.webdriver and Performance.prototype.now', () => {
    const p = makeSdkPage(sdkFile, {
      webdriver: true,
      prelude: 'delete Navigator.prototype.webdriver; delete Performance.prototype.now;',
    });
    const rep = p.Pyrmi.report();
    const tp = Array.from(rep.tp);
    assert.equal(rep.wd, true, 'clean iframe still detects webdriver');
    assert.ok(tp.includes('navigator.webdriver'), 'pre-load delete of webdriver caught: ' + JSON.stringify(tp));
    assert.ok(tp.includes('performance.now'), 'pre-load delete of performance.now caught: ' + JSON.stringify(tp));
  });

  test('8. ' + rel + ': removes probe iframe in finally even when contentWindow throws SecurityError', () => {
    const p = makeSdkPage(sdkFile, { throwFrameSecurityError: true });
    assert.equal(p.Pyrmi.version, sdkMeta.version);
    assert.deepEqual(p.stats(), { appended: 1, removed: 1 });
  });

  test('9. ' + rel + ': seal() and sign() enforce server canon() limits (unsafe ints, -0, NaN/Inf, __proto__, depth > 64, > 8192 bytes)', async () => {
    const p = makeSdkPage(sdkFile);
    const s = await p.Pyrmi.start();
    p.Pyrmi.stop();
    assert.ok(s.token);

    const makeDeep = (n) => {
      let cur = { leaf: 1 };
      for (let i = 1; i < n; i++) cur = { a: cur };
      return cur;
    };

    const badPayloads = [
      '({ n: 9007199254740992 })',
      '({ n: -9007199254740992 })',
      '({ n: 1e21 })',
      '({ n: -0 })',
      '({ nested: [0, -0] })',
      '({ n: NaN })',
      '({ n: Infinity })',
      '({ n: -Infinity })',
      'JSON.parse(\'{"__proto__":{"admin":true},"score":1}\')',
      '({ sub: JSON.parse(\'{"__proto__":1}\') })',
      '({ arr: [JSON.parse(\'{"__proto__":1}\')] })',
      '({ big: "x".repeat(8200) })',
    ];
    for (const expr of badPayloads) {
      await assert.rejects(vm.runInContext('Pyrmi.seal(' + expr + ')', p.ctx), /Pyrmi:/, 'seal ' + expr);
      await assert.rejects(vm.runInContext('Pyrmi.sign(' + expr + ')', p.ctx), /Pyrmi:/, 'sign ' + expr);
    }

    // Depth 64 succeeds; depth 65 rejects.
    const okDeep = await p.Pyrmi.seal(makeDeep(64));
    assert.ok(okDeep.pyrmi && typeof okDeep.pyrmi.sig === 'string');
    await assert.rejects(p.Pyrmi.seal(makeDeep(65)), /nested too deep/);
    await assert.rejects(p.Pyrmi.sign(makeDeep(65)), /nested too deep/);

    // Safe boundary values succeed.
    const good = await p.Pyrmi.seal({ zero: 0, maxSafe: 9007199254740991, minSafe: -9007199254740991, frac: 1.5, nil: null });
    assert.equal(good.zero, 0);
    assert.equal(good.maxSafe, 9007199254740991);
    assert.ok(good.pyrmi.sig.length >= 40);
  });
}

test('10. scripts/build-sdk.js uses static string unescaping (no Function/eval) and built SDK survives Array.prototype.map override', () => {
  const buildSrc = fs.readFileSync(path.join(ROOT, 'scripts/build-sdk.js'), 'utf8');
  assert.ok(!/\bFunction\s*\(/.test(buildSrc), 'build-sdk.js must not invoke Function()');
  assert.ok(!/\beval\s*\(/.test(buildSrc), 'build-sdk.js must not invoke eval()');

  assert.equal(buildSdk.unescapeString("'a\\nb\\tc\\\\d\\'\\\"\\0\\x41\\u0042\\u{43}'", 0), 'a\nb\tc\\d\'"\0ABC');
  assert.throws(() => buildSdk.unescapeString("'\\1'", 0), /octal/);
  assert.throws(() => buildSdk.unescapeString("'\\xZZ'", 0), /bad \\x/);
  assert.throws(() => buildSdk.unescapeString("'\\u12'", 0), /bad \\u/);
  assert.throws(() => buildSdk.tokenize("'unterminated\n'"), /unterminated/);

  // Poison Array.prototype.map, Array.prototype.forEach and String.prototype.split before loading built sdk/pyrmi.js.
  const p = makeSdkPage(path.join(ROOT, 'sdk/pyrmi.js'), {
    prelude: [
      'Array.prototype.map = function () { throw new Error("map poisoned"); };',
      'Array.prototype.forEach = function () { throw new Error("forEach poisoned"); };',
      'String.prototype.split = function () { throw new Error("split poisoned"); };',
    ].join('\n'),
  });
  assert.equal(p.Pyrmi.version, sdkMeta.version);
  assert.equal(typeof p.Pyrmi.seal, 'function');
});
