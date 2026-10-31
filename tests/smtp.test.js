'use strict';
// Sending sign-in codes through a mailbox over SMTP, against a fake mail server on 127.0.0.1:  node --test tests/*.test.js
process.env.PYRMI_KV = 'memory';
process.env.PYRMI_SECRET = 'test-secret-test-secret-test-secret-1234';
// Tests start many sessions from one address in a few seconds; the per-site minting limit has its own test (round11).
process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN = process.env.PYRMI_SESSIONS_PER_IP_PER_SITE_PER_MIN || '100000';
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const smtp = require('../api/_lib/smtp');

// A tiny SMTP server that records what it's told. Plain text is fine here because the host is 127.0.0.1.
function fakeServer(opts) {
  opts = opts || {};
  const seen = { lines: [], data: '' };
  const server = net.createServer((sock) => {
    let buf = '', inData = false;
    sock.write('220 fake ESMTP\r\n');
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\r\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        if (inData) {
          if (line === '.') { inData = false; sock.write('250 queued\r\n'); } else seen.data += line + '\r\n';
          continue;
        }
        seen.lines.push(line);
        if (/^EHLO/.test(line)) sock.write('250-fake\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n');
        else if (/^AUTH PLAIN /.test(line)) sock.write(opts.badAuth ? '535 nope\r\n' : '235 ok\r\n');
        else if (/^MAIL FROM/.test(line)) sock.write('250 ok\r\n');
        else if (/^RCPT TO/.test(line)) sock.write('250 ok\r\n');
        else if (line === 'DATA') { inData = true; sock.write('354 go\r\n'); }
        else if (line === 'QUIT') { sock.write('221 bye\r\n'); sock.end(); }
        else sock.write('500 what\r\n');
      }
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ server, seen, port: server.address().port })));
}

const decodeParts = (data) => [...data.matchAll(/base64\r\n\r\n([\s\S]*?)\r\n--/g)].map((m) => Buffer.from(m[1].replace(/\r\n/g, ''), 'base64').toString('utf8'));

test('config needs a host, a user and a password, and defaults to port 465', () => {
  assert.equal(smtp.config({ SMTP_HOST: 'mail.privateemail.com', SMTP_USER: 'a@pyrmi.com' }), null);
  assert.deepEqual(smtp.config({ SMTP_HOST: 'mail.privateemail.com', SMTP_USER: 'a@pyrmi.com', SMTP_PASS: 'x' }),
    { host: 'mail.privateemail.com', port: 465, user: 'a@pyrmi.com', pass: 'x' });
});

test('a message goes through: login, sender, recipient and the code in both parts', async () => {
  const { server, seen, port } = await fakeServer();
  await smtp.send({ to: 'carol@example.com', subject: 'Your Pyrmi sign-in code: 123456', text: 'Your code is 123456', html: '<b>123456</b>' },
    { host: '127.0.0.1', port, user: 'login@pyrmi.com', pass: 'pw' });
  server.close();
  assert.ok(seen.lines.includes('AUTH PLAIN ' + Buffer.from('\0login@pyrmi.com\0pw').toString('base64')));
  assert.ok(seen.lines.includes('MAIL FROM:<login@pyrmi.com>'));
  assert.ok(seen.lines.includes('RCPT TO:<carol@example.com>'));
  assert.ok(seen.lines.includes('QUIT'));
  assert.match(seen.data, /^To: carol@example\.com\r\n/m);
  const [text, html] = decodeParts(seen.data);
  assert.equal(text, 'Your code is 123456');
  assert.equal(html, '<b>123456</b>');
});

test('headers can\'t be smuggled in through the address or subject', async () => {
  const raw = smtp.build({ to: 'a@example.com\r\nBcc: evil@example.com', subject: 'hi\r\nBcc: evil@example.com', text: 'x' }, 'Pyrmi Security <login@pyrmi.com>');
  assert.ok(!/^Bcc:/m.test(raw));
});

test('a refused login is an error that never contains the password', async () => {
  const { server, port } = await fakeServer({ badAuth: true });
  await assert.rejects(smtp.send({ to: 'c@example.com', subject: 's', text: 't' }, { host: '127.0.0.1', port, user: 'u@pyrmi.com', pass: 'sekrit-pass' }),
    (e) => e.message === 'smtp_auth_535' && !e.message.includes('sekrit'));
  server.close();
});

test('a remote server that doesn\'t offer STARTTLS on port 587 is refused before the password is sent', async () => {
  const { server, seen, port } = await fakeServer();
  // "localhost.test" isn't a local host, so the plain connection must not be used; point it at the fake server via lookup
  await assert.rejects(smtp.send({ to: 'c@example.com', subject: 's', text: 't' },
    { host: 'mail.example.test', port, user: 'u', pass: 'p', lookup: (h, o, cb) => (o && o.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4)) }), /smtp_no_starttls/);
  server.close();
  assert.ok(!seen.lines.some((l) => l.startsWith('AUTH')));
});

test('with SMTP_* set, email sign-in is on and codes go out through the mailbox', async () => {
  const { server, seen, port } = await fakeServer();
  const accounts = require('../api/_lib/accounts');
  delete process.env.RESEND_API_KEY;
  assert.equal(accounts.emailConfigured(), false);
  Object.assign(process.env, { SMTP_HOST: '127.0.0.1', SMTP_PORT: String(port), SMTP_USER: 'login@pyrmi.com', SMTP_PASS: 'pw' });
  assert.equal(accounts.providers().email, true);
  await accounts.sendMail({ to: 'dan@example.com', subject: 'Your Pyrmi sign-in code: 654321', text: 'Your code is 654321' });
  assert.ok(seen.lines.includes('RCPT TO:<dan@example.com>'));
  assert.match(decodeParts(seen.data)[0], /654321/);
  // a failed send is a plain 502 for the visitor
  server.close();
  await assert.rejects(accounts.sendMail({ to: 'dan@example.com', subject: 's', text: 't' }), (e) => e.status === 502 && e.code === 'email_failed');
  for (const k of ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASS']) delete process.env[k];
});
