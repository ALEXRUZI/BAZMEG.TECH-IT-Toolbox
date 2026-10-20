import { validateHeaderValue } from 'node:http';
import { isIP } from 'node:net';
import { defineConfig, loadEnv, type ConfigEnv, type Plugin, type ProxyOptions, type UserConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { sshForgeBundleEvidence } from './scripts/sshForgeBundleEvidence.js';

const apiPath = /^\/api(?:\/|\?|$)/;

export function createDevProxy(env: Record<string, string>): { plugin: Plugin; proxy: ProxyOptions } {
  let target: URL;
  try {
    target = new URL(env.BACKEND_ORIGIN || 'http://127.0.0.1:3001');
    if (!['http:', 'https:'].includes(target.protocol) || target.username || target.password ||
      target.pathname !== '/' || target.search || target.hash) throw new Error();
  } catch {
    throw new Error('BACKEND_ORIGIN must be an HTTP(S) origin without credentials, a path, query, or fragment.');
  }
  // URL parsing canonicalizes IP literals. Do not infer loopback from a DNS name.
  const hostname = target.hostname.replace(/^\[/, '').replace(/\]$/, '');
  const loopbackOrigin = hostname === '::1' || (isIP(hostname) === 4 && hostname.startsWith('127.'));
  if (target.protocol === 'http:' && !loopbackOrigin) {
    throw new Error('BACKEND_ORIGIN requires HTTPS unless the host is a loopback IP literal (127.0.0.0/8 or [::1]).');
  }
  const secret = env.BACKEND_SECRET;
  try {
    if (secret) validateHeaderValue('X-Toolbox-Backend-Secret', secret);
  } catch {
    throw new Error('BACKEND_SECRET is not a valid HTTP header value.');
  }
  if (env.ALLOW_LAN_API_PROXY && !['true', 'false'].includes(env.ALLOW_LAN_API_PROXY)) {
    throw new Error('ALLOW_LAN_API_PROXY must be true or false.');
  }
  const allowLan = env.ALLOW_LAN_API_PROXY === 'true';

  return {
    plugin: {
      name: 'local-development-api-guard',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          if (!apiPath.test(req.url || '')) return next();
          const peer = req.socket.remoteAddress || '';
          const loopback = peer === '::1' || /^127\./.test(peer) || /^::ffff:127\./.test(peer);
          const message = !secret?.trim()
            ? 'Development API proxy requires BACKEND_SECRET. Set it server-side and restart Vite.'
            : !loopback && !allowLan
              ? 'LAN API proxy access is disabled. Set ALLOW_LAN_API_PROXY=true only for a trusted development network.'
              : null;
          if (message) {
            res.writeHead(!secret?.trim() ? 503 : 403, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: { code: 'DEV_PROXY_DISABLED', message } }));
            return;
          }
          // Socket identity is authoritative; ignore browser-supplied proxy identity.
          for (const name of Object.keys(req.headers)) {
            if (name === 'x-toolbox-backend-secret' || name === 'x-toolbox-client-ip' ||
              name === 'forwarded' || name.startsWith('x-forwarded-') ||
              name === 'x-real-ip' || name === 'cf-connecting-ip' || name === 'true-client-ip') {
              delete req.headers[name];
            }
          }
          next();
        });
      },
    },
    proxy: {
      target: target.origin,
      changeOrigin: true,
      secure: true,
      xfwd: false,
      ws: false,
      followRedirects: false,
      configure(proxy) {
        proxy.on('proxyReq', (request) => {
          request.setHeader('X-Toolbox-Backend-Secret', secret || '');
        });
        proxy.on('error', (error, _req, res) => {
          // Vite's subsequent error listener logs this error: keep its text non-sensitive.
          error.message = 'Development API proxy could not reach the configured backend.';
          error.stack = error.message;
          if ('writeHead' in res && !res.headersSent && !res.writableEnded) {
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ ok: false, error: { code: 'DEV_PROXY_UNAVAILABLE', message: error.message } }));
          }
        });
      },
    },
  };
}

export function createAppConfig({ mode, command, isPreview }: ConfigEnv, enableDevProxy = true): UserConfig {
  const dev = enableDevProxy && command === 'serve' && !isPreview
    ? createDevProxy(loadEnv(mode, '.', ''))
    : null;
  const evidence = sshForgeBundleEvidence();
  return {
    plugins: [react(), tailwindcss(), evidence.app, ...(dev ? [dev.plugin] : [])],
    worker: { plugins: evidence.worker },
    // Worker-only imports are not all found by the HTML entry scanner. Discover
    // them before serving pages so the first SSH operation cannot trigger an
    // optimizer reload that discards the user's local key/passphrase form.
    optimizeDeps: {
      include: ['@noble/curves/ed25519.js', '@noble/curves/ed448.js', '@noble/curves/nist.js', '@noble/ciphers/aes.js', 'bcrypt-pbkdf', 'hash-wasm', 'micro-rsa-dsa-dh/dsa.js', 'micro-rsa-dsa-dh/rsa.js', 'micro-rsa-dsa-dh/primality.js', 'node-forge/lib/des.js', 'node-forge/lib/cipher.js', 'node-forge/lib/util.js', '@noble/hashes/legacy.js', '@noble/hashes/sha2.js'],
    },
    server: {
      proxy: dev ? { '^/api(?:/|\\?|$)': dev.proxy } : {},
    },
    // Static preview must not inherit an authenticated development proxy.
    preview: { proxy: {} },
  };
}

export default defineConfig((env) => createAppConfig(env));
