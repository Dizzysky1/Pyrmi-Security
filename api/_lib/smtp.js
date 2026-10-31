'use strict';
// A small SMTP client, enough to send one sign-in email through a normal mailbox (Namecheap Private Email, Gmail,
// Zoho...). No dependencies. Port 465 is TLS from the first byte; any other port must offer STARTTLS, and the
// connection is upgraded before the password is sent. Plain text is allowed only to 127.0.0.1 or localhost (tests).
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

const LOCAL = new Set(['127.0.0.1', 'localhost', '::1']);

function config(env) {
  env = env || process.env;
  if (!env.SMTP_HOST || !env.SMTP_USER || !env.SMTP_PASS) return null;
  const port = parseInt(env.SMTP_PORT, 10) || 465;
  return { host: env.SMTP_HOST, port, user: env.SMTP_USER, pass: env.SMTP_PASS };
}

// Reads SMTP replies (multi-line "250-..." until "250 ...") from whichever socket is current.
function replies(sock) {
  let buf = '', waiting = null, ended = null;
  const queue = [];
  const onData = (d) => {
    buf += d.toString('utf8');
    let m;
    while ((m = /^(\d{3})([ -])(.*)\r?\n/m.exec(buf)) && m.index === 0) {
      buf = buf.slice(m[0].length);
      (queue.lines = queue.lines || []).push(m[3]);
      if (m[2] === ' ') {
        const r = { code: Number(m[1]), lines: queue.lines };
        queue.lines = null;
        if (waiting) { const w = waiting; waiting = null; w.resolve(r); } else queue.push(r);
      }
    }
  };
  const onEnd = (e) => { ended = e || new Error('smtp_closed'); if (waiting) { const w = waiting; waiting = null; w.reject(ended); } };
  sock.on('data', onData); sock.on('error', onEnd); sock.on('close', () => onEnd());
  return {
    next() {
      if (queue.length) return Promise.resolve(queue.shift());
      if (ended) return Promise.reject(ended);
      return new Promise((resolve, reject) => { waiting = { resolve, reject }; });
    },
    detach() { sock.removeListener('data', onData); },
  };
}

const enc = (s) => '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
const addr = (s) => (/<([^<>\s]+)>/.exec(s) || [null, s.trim()])[1];
const noCrlf = (s) => String(s).replace(/[\r\n]+/g, ' ');

function build(msg, from) {
  const boundary = 'pyrmi-' + crypto.randomBytes(9).toString('hex');
  const domain = addr(from).split('@')[1] || 'localhost';
  const nameMatch = /^\s*([^<]+?)\s*</.exec(from);
  const fromHeader = nameMatch ? enc(nameMatch[1]) + ' <' + addr(from) + '>' : addr(from);
  const b64 = (s) => Buffer.from(s, 'utf8').toString('base64').replace(/.{76}/g, '$&\r\n');
  return [
    'From: ' + fromHeader,
    'To: ' + noCrlf(msg.to),
    'Subject: ' + enc(noCrlf(msg.subject)),
    'Date: ' + new Date().toUTCString(),
    'Message-ID: <' + crypto.randomBytes(12).toString('hex') + '@' + domain + '>',
    'MIME-Version: 1.0',
    'Content-Type: multipart/alternative; boundary="' + boundary + '"',
    '',
    '--' + boundary,
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(msg.text),
    '--' + boundary,
    'Content-Type: text/html; charset=UTF-8',
    'Content-Transfer-Encoding: base64',
    '',
    b64(msg.html || msg.text),
    '--' + boundary + '--',
    '',
  ].join('\r\n');
}

// Sends one message. Rejects with a short reason (never the password) if anything goes wrong.
async function send(msg, opts) {
  const cfg = opts || config();
  if (!cfg) throw new Error('smtp_not_configured');
  const from = msg.from || ('Pyrmi Security <' + cfg.user + '>');
  const timeoutMs = cfg.timeoutMs || 10000;
  const implicitTls = cfg.port === 465;
  let sock = implicitTls
    ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host })
    : net.connect({ host: cfg.host, port: cfg.port, lookup: cfg.lookup });
  const timer = setTimeout(() => sock.destroy(new Error('smtp_timeout')), timeoutMs);
  let r = replies(sock);
  const write = (line) => sock.write(line + '\r\n');
  const expect = async (want, what) => {
    const res = await r.next();
    if (!want.includes(res.code)) throw new Error('smtp_' + what + '_' + res.code);
    return res;
  };
  try {
    await expect([220], 'greeting');
    write('EHLO pyrmi.com');
    let ehlo = await expect([250], 'ehlo');
    if (!implicitTls) {
      if (ehlo.lines.some((l) => /^STARTTLS\b/i.test(l))) {
        write('STARTTLS');
        await expect([220], 'starttls');
        r.detach();
        sock = tls.connect({ socket: sock, servername: cfg.host });
        r = replies(sock);
        await new Promise((resolve, reject) => { sock.once('secureConnect', resolve); sock.once('error', reject); });
        write('EHLO pyrmi.com');
        ehlo = await expect([250], 'ehlo');
      } else if (!LOCAL.has(cfg.host)) {
        throw new Error('smtp_no_starttls');
      }
    }
    write('AUTH PLAIN ' + Buffer.from('\0' + cfg.user + '\0' + cfg.pass, 'utf8').toString('base64'));
    await expect([235], 'auth');
    write('MAIL FROM:<' + addr(from) + '>');
    await expect([250], 'mail_from');
    write('RCPT TO:<' + addr(msg.to) + '>');
    await expect([250, 251], 'rcpt');
    write('DATA');
    await expect([354], 'data');
    sock.write(build(msg, from).replace(/\r\n\./g, '\r\n..') + '\r\n.\r\n');
    await expect([250], 'sent');
    write('QUIT');
    await r.next().catch(() => {});
  } finally {
    clearTimeout(timer);
    sock.end();
  }
}

module.exports = { config, send, build };
