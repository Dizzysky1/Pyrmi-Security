// Cloudflare Worker entrypoint for Pyrmi Security (/api/v1/*).
// Static files are served directly at Cloudflare's edge via Workers Static Assets (.cf-assets/),
// while /api/* routes run here via assets.run_worker_first.

import authHandler from '../api/v1/auth/[provider].js';
import dashboardHandler from '../api/v1/dashboard.js';
import demoHandler from '../api/v1/demo.js';
import meHandler from '../api/v1/me.js';
import projectHandler from '../api/v1/project.js';
import sessionHandler from '../api/v1/session.js';
import signalHandler from '../api/v1/signal.js';
import sitesHandler from '../api/v1/sites.js';
import verifyHandler from '../api/v1/verify.js';

const API_ROUTES = new Map([
  ['/api/v1/dashboard', dashboardHandler],
  ['/api/v1/demo', demoHandler],
  ['/api/v1/me', meHandler],
  ['/api/v1/project', projectHandler],
  ['/api/v1/session', sessionHandler],
  ['/api/v1/signal', signalHandler],
  ['/api/v1/sites', sitesHandler],
  ['/api/v1/verify', verifyHandler],
]);

const GLOBAL_SECURITY_HEADERS = [
  ['X-Content-Type-Options', 'nosniff'],
  ['Referrer-Policy', 'strict-origin-when-cross-origin'],
  ['Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()'],
  ['Strict-Transport-Security', 'max-age=63072000'],
  ['Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"],
  ['X-Frame-Options', 'DENY'],
];

const CORS_API_ROUTES = new Set([
  '/api/v1/session',
  '/api/v1/signal',
]);

function normalizePath(pathname) {
  return pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
}

function applySecurityHeaders(headers, { corsRoute = false } = {}) {
  for (const [k, v] of GLOBAL_SECURITY_HEADERS) {
    if (!headers.has(k)) headers.set(k, v);
  }
  if (!corsRoute && !headers.has('Cross-Origin-Resource-Policy')) {
    headers.set('Cross-Origin-Resource-Policy', 'same-origin');
  }
  return headers;
}

function createNodeAdapter(request, url, { corsRoute = false } = {}) {
  const inHeaders = Object.create(null);
  for (const [k, v] of request.headers.entries()) {
    inHeaders[k.toLowerCase()] = v;
  }
  // Never pass caller-controllable proxy headers into Node handlers on Cloudflare Workers.
  delete inHeaders['x-vercel-forwarded-for'];
  delete inHeaders['x-forwarded-for'];
  delete inHeaders['x-forwarded-host'];
  delete inHeaders['x-forwarded-proto'];
  delete inHeaders['x-real-ip'];
  if (!inHeaders.host) inHeaders.host = url.host;

  // Cloudflare overwrites CF-Connecting-IP at the edge; http.js reads req.socket.remoteAddress
  // when neither PYRMI_PROXY_HOPS nor VERCEL_ENV is set, so spoofed X-Forwarded-For is ignored.
  const remoteAddress = request.headers.get('cf-connecting-ip') || '127.0.0.1';

  const req = {
    method: request.method,
    url: url.pathname + url.search,
    headers: inHeaders,
    socket: { remoteAddress },
    async *[Symbol.asyncIterator]() {
      if (!request.body) return;
      const reader = request.body.getReader();
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value && value.byteLength) yield Buffer.from(value.buffer, value.byteOffset, value.byteLength);
        }
      } finally {
        try { await reader.cancel(); } catch (_) { /* stream already closed */ }
      }
    },
  };

  const outHeaders = new Headers();
  let ended = false;
  let resolveResponse;
  const responsePromise = new Promise((resolve) => { resolveResponse = resolve; });

  const res = {
    statusCode: 200,
    setHeader(name, value) {
      if (ended) return;
      const key = String(name);
      if (Array.isArray(value)) {
        outHeaders.delete(key);
        for (const item of value) outHeaders.append(key, String(item));
      } else if (value !== undefined) {
        outHeaders.set(key, String(value));
      }
    },
    getHeader(name) {
      const key = String(name);
      if (key.toLowerCase() === 'set-cookie') {
        return outHeaders.getSetCookie();
      }
      return outHeaders.get(key);
    },
    end(chunk) {
      if (ended) return;
      ended = true;
      applySecurityHeaders(outHeaders, { corsRoute });
      const status = Number(res.statusCode) || 200;
      const noBody = status === 204 || status === 304 || request.method === 'HEAD';
      resolveResponse(new Response(noBody ? null : (chunk ?? null), { status, headers: outHeaders }));
    },
  };

  return { req, res, responsePromise, isEnded: () => ended };
}

function resolveHandler(pathname) {
  const clean = normalizePath(pathname);
  if (API_ROUTES.has(clean)) return API_ROUTES.get(clean);
  if (/^\/api\/v1\/auth\/[a-z]+$/.test(clean)) return authHandler;
  return null;
}

export default {
  async fetch(request, env) {
    delete process.env.VERCEL_ENV;
    // Sync string bindings into process.env in case a compatibility flag override is ever used
    if (env && typeof env === 'object') {
      for (const [k, v] of Object.entries(env)) {
        if (k === 'VERCEL_ENV') continue;
        if (typeof v === 'string' && process.env[k] === undefined) {
          process.env[k] = v;
        }
      }
    }

    const url = new URL(request.url);
    if (url.hostname === 'www.pyrmi.com') {
      const lower = url.pathname.toLowerCase();
      const isAuthNav = (request.method === 'GET' || request.method === 'HEAD')
        && (lower === '/api/v1/auth' || lower.startsWith('/api/v1/auth/'));
      // Only redirect OAuth navigations on www.pyrmi.com here; redirecting fetch() /api/v1/* with 308
      // while www.pyrmi.com static pages still serve connect-src 'self' would break the www dashboard.
      // Full www -> apex canonicalization for static pages belongs in a Cloudflare Zone Redirect Rule.
      if (isAuthNav) {
        const headers = applySecurityHeaders(new Headers({
          Location: 'https://pyrmi.com' + url.pathname + url.search,
          'Cache-Control': 'no-store',
        }));
        return new Response(null, { status: 302, headers });
      }
    }

    const lowerPath = url.pathname.toLowerCase();
    if (url.pathname !== '/api' && lowerPath !== '/api' && !lowerPath.startsWith('/api/')) {
      if (env && env.ASSETS) return env.ASSETS.fetch(request);
      return new Response(request.method === 'HEAD' ? null : 'Not Found', {
        status: 404,
        headers: applySecurityHeaders(new Headers({ 'Content-Type': 'text/plain; charset=utf-8' })),
      });
    }

    const handler = resolveHandler(url.pathname);
    if (!handler) {
      const headers = applySecurityHeaders(new Headers({
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
      }));
      const body = request.method === 'HEAD'
        ? null
        : JSON.stringify({ ok: false, error: 'not_found', message: 'not_found' });
      return new Response(body, { status: 404, headers });
    }

    const corsRoute = CORS_API_ROUTES.has(normalizePath(url.pathname));
    const { req, res, responsePromise, isEnded } = createNodeAdapter(request, url, { corsRoute });
    try {
      await handler(req, res);
      if (!isEnded()) res.end();
    } catch (err) {
      console.error('[worker]', err);
      if (!isEnded()) {
        const headers = applySecurityHeaders(new Headers({
          'Content-Type': 'application/json; charset=utf-8',
          'Cache-Control': 'no-store',
        }));
        const body = request.method === 'HEAD'
          ? null
          : JSON.stringify({ ok: false, error: 'server_error', message: 'Something went wrong on our side.' });
        return new Response(body, { status: 500, headers });
      }
    }
    return responsePromise;
  },
};
