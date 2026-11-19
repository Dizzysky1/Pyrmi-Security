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

const MAX_SMTP_BUF = 64 * 1024;
const MAX_SMTP_LINES = 100;
const MAX_SMTP_QUEUE = 100;

// Reads SMTP replies (multi-line "250-..." until "250 ..." or textless "250") from whichever socket is current.
function replies(sock) {
  let buf = '', waiting = null, ended = null;
  const queue = [];
  const onEnd = (e) => { if (ended) return; ended = e || new Error('smtp_closed'); if (waiting) { const w = waiting; waiting = null; w.reject(ended); } };
  const abort = (code) => { queue.length = 0; const err = new Error(code); onEnd(err); sock.destroy(err); };
  const onData = (d) => {
    if (ended) return;
    buf += d.toString('utf8');
    if (buf.length > MAX_SMTP_BUF) return abort('smtp_reply_too_large');
    let m;
    while ((m = /^(\d{3})(?:([ -])(.*))?\r?\n/.exec(buf))) {
      buf = buf.slice(m[0].length);
      const lines = (queue.lines = queue.lines || []);
      lines.push(m[3] || '');
      if (lines.length > MAX_SMTP_LINES) return abort('smtp_too_many_lines');
      if (m[2] !== '-') {
        const r = { code: Number(m[1]), lines };
        queue.lines = null;
        if (waiting) { const w = waiting; waiting = null; w.resolve(r); } else {
          if (queue.length >= MAX_SMTP_QUEUE) return abort('smtp_too_many_replies');
          queue.push(r);
        }
      }
    }
  };
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
const addr = (s) => {
  const first = String(s || '').split(/[\r\n]/)[0].replace(/[\u0000-\u001f\u007f]+/g, '').trim();
  const m = /^[^<>]*<([^<>\s]+)>\s*$/.exec(first);
  return m ? m[1] : first.replace(/[<>\s]+/g, '');
};
const noCrlf = (s) => String(s).replace(/[\r\n\u0000-\u001f\u007f]+/g, ' ');

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
  const sni = net.isIP(cfg.host) ? {} : { servername: cfg.host };
  let sock = implicitTls
    ? tls.connect({ host: cfg.host, port: cfg.port, ...sni })
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
        sock = tls.connect({ socket: sock, ...sni });
        r = replies(sock);
        await new Promise((resolve, reject) => {
          const done = (err) => {
            sock.removeListener('secureConnect', onConnect);
            sock.removeListener('error', onError);
            sock.removeListener('close', onClose);
            if (err) reject(err); else resolve();
          };
          const onConnect = () => done();
          const onError = (e) => done(e);
          const onClose = () => done(new Error('smtp_closed'));
          sock.once('secureConnect', onConnect);
          sock.once('error', onError);
          sock.once('close', onClose);
        });
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
    sock.destroy();
  }
}

module.exports = { config, send, build };
