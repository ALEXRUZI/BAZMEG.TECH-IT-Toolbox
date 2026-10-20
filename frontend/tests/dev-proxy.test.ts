// @vitest-environment node
import { randomUUID } from 'node:crypto';
import { createServer as createHttpServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { build, createServer, type ViteDevServer } from 'vite';
import { createAppConfig, createDevProxy } from '../vite.config.ts';

const appConfig = fileURLToPath(new URL('../vite.config.ts', import.meta.url));
const e2eConfig = fileURLToPath(new URL('../vite.e2e.config.ts', import.meta.url));
const servers: Server[] = [];
const viteServers: ViteDevServer[] = [];
let secret: string;
type Received = { method: string | undefined; url: string | undefined; headers: import('node:http').IncomingHttpHeaders; body: string };

beforeEach(() => {
  secret = randomUUID();
  vi.stubEnv('BACKEND_ORIGIN', '');
  vi.stubEnv('BACKEND_SECRET', secret);
  vi.stubEnv('ALLOW_LAN_API_PROXY', 'false');
});

afterEach(async () => {
  await Promise.all(viteServers.splice(0).map((server) => server.close()));
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
    server.closeAllConnections();
  })));
  vi.unstubAllEnvs();
});

async function backend() {
  const received: Received[] = [];
  const server = createHttpServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    received.push({ method: req.method, url: req.url, headers: req.headers, body });
    if (req.headers['x-toolbox-backend-secret'] !== secret || req.url === '/api/unauthorized') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'unauthorized' }));
    } else if (req.url === '/api/redirect') {
      res.writeHead(302, { Location: '/api/must-not-follow' });
      res.end('redirect response');
    } else {
      res.writeHead(req.method === 'POST' ? 422 : 200, { 'Content-Type': 'application/json', 'X-Test-Response': 'preserved' });
      res.end(JSON.stringify({ ok: true, message: 'toolbox API reachable', body }));
    }
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, received, origin: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

async function frontend(configFile = appConfig, simulatedLanPeer = false) {
  const server = await createServer({
    configFile, mode: 'test', logLevel: 'silent',
    server: { host: '127.0.0.1', port: 0, strictPort: true },
    // Exercise the access gate with a non-loopback socket identity without LAN traffic.
    plugins: simulatedLanPeer ? [{
      name: 'test-lan-peer', enforce: 'pre',
      configureServer(vite) {
        vite.middlewares.use((req, _res, next) => {
          Object.defineProperty(req.socket, 'remoteAddress', { value: '192.0.2.10', configurable: true });
          next();
        });
      },
    }] : [],
  });
  viteServers.push(server);
  await server.listen();
  return { server, origin: `http://127.0.0.1:${(server.httpServer!.address() as AddressInfo).port}` };
}

describe('development target configuration', () => {
  it('defaults to loopback and supports deliberate local and external origins with TLS verification', () => {
    expect(createDevProxy({}).proxy.target).toBe('http://127.0.0.1:3001');
    for (const target of ['http://127.0.0.1:4000', 'http://127.255.255.254:4000', 'http://[::1]:4000',
      'https://explicit-backend.example', 'https://192.168.1.10:4000']) {
      const { proxy } = createDevProxy({ BACKEND_ORIGIN: target, BACKEND_SECRET: secret });
      expect(proxy.target).toBe(target);
      expect(proxy.secure).toBe(true);
      expect(proxy.followRedirects).toBe(false);
      expect(proxy.xfwd).toBe(false);
      expect(proxy.proxyTimeout).toBeUndefined();
      expect(proxy.timeout).toBeUndefined();
    }
  });

  it('rejects non-loopback HTTP origins, including hostname lookalikes, even with LAN opt-in', () => {
    for (const target of ['http://explicit-backend.example', 'http://192.168.1.10:3001', 'http://10.0.0.1',
      'http://0.0.0.0', 'http://126.255.255.255', 'http://128.0.0.1', 'http://[::]', 'http://[::2]',
      'http://[::ffff:192.168.1.10]', 'http://localhost:3001', 'http://localhost.example',
      'http://127.0.0.1.example', 'http://127.example']) {
      expect(() => createDevProxy({ BACKEND_ORIGIN: target, BACKEND_SECRET: secret, ALLOW_LAN_API_PROXY: 'true' }))
        .toThrow('BACKEND_ORIGIN requires HTTPS unless the host is a loopback IP literal (127.0.0.0/8 or [::1]).');
    }
  });

  it('rejects non-loopback HTTP in the actual Vite configuration before starting a proxy', async () => {
    vi.stubEnv('BACKEND_ORIGIN', 'http://explicit-backend.example');
    await expect(frontend()).rejects.toThrow('BACKEND_ORIGIN requires HTTPS');
  });

  it('rejects malformed settings without disclosing configured values', () => {
    for (const origin of ['not-a-url', 'ftp://example.com', `https://${secret}@example.com`, 'https://example.com/api',
      'https://example.com/?target=other', 'https://example.com/#fragment']) {
      expect(() => createDevProxy({ BACKEND_ORIGIN: origin })).toThrow(/^BACKEND_ORIGIN must be/);
    }
    expect(() => createDevProxy({ BACKEND_SECRET: `${secret}\r\ninvalid` })).toThrow('BACKEND_SECRET is not a valid HTTP header value.');
    expect(() => createDevProxy({ ALLOW_LAN_API_PROXY: 'yes' })).toThrow('ALLOW_LAN_API_PROXY must be true or false.');
  });

  it('selects the local default in the actual Vite configuration', async () => {
    const { server } = await frontend();
    const proxy = Object.values(server.config.server.proxy!)[0];
    expect(typeof proxy === 'object' && proxy.target).toBe('http://127.0.0.1:3001');
    expect(server.config.env.BACKEND_SECRET).toBeUndefined();
  });
});

describe('real loopback request forwarding through the Vite configuration', () => {
  it('injects the secret, strips spoofed identity, and retains GET paths and query strings', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    const { origin } = await frontend();
    const response = await fetch(`${origin}/api/ping?target=https%3A%2F%2Fbrowser.example&x=1`, { headers: {
      'X-Toolbox-Backend-Secret': 'browser-override', 'X-Toolbox-Client-IP': '10.0.0.1',
      Forwarded: 'for=10.0.0.1', 'X-Forwarded-For': '10.0.0.1', 'X-Forwarded-Host': 'browser.example',
      'X-Forwarded-Proto': 'https', 'CF-Connecting-IP': '10.0.0.1', 'X-Real-IP': '10.0.0.1',
    } });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, message: 'toolbox API reachable', body: '' });
    expect(upstream.received).toHaveLength(1);
    const request = upstream.received[0];
    expect(request.method).toBe('GET');
    expect(request.url).toBe('/api/ping?target=https%3A%2F%2Fbrowser.example&x=1');
    expect(request.headers['x-toolbox-backend-secret'] === secret).toBe(true);
    expect(request.headers.host).toBe(new URL(upstream.origin).host);
    for (const name of ['x-toolbox-client-ip', 'forwarded', 'x-forwarded-for', 'x-forwarded-host',
      'x-forwarded-proto', 'cf-connecting-ip', 'x-real-ip']) expect(request.headers[name]).toBeUndefined();
  });

  it('retains POST JSON, content type, status and response body', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    const { origin } = await frontend();
    const body = JSON.stringify({ target: 'example.test', protocolMode: 'both' });
    const response = await fetch(`${origin}/api/tools/mock?q=1`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body,
    });
    expect(response.status).toBe(422);
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(response.headers.get('x-test-response')).toBe('preserved');
    expect(await response.json()).toEqual({ ok: true, message: 'toolbox API reachable', body });
    expect(upstream.received[0].body).toBe(body);
    expect(upstream.received[0].url).toBe('/api/tools/mock?q=1');
    expect(upstream.received[0].headers['content-type']).toBe('application/json');
  });

  it('preserves backend authentication failure and redirects without following them', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    const { origin } = await frontend();
    const denied = await fetch(`${origin}/api/unauthorized`);
    expect(denied.status).toBe(401);
    expect(await denied.json()).toEqual({ error: 'unauthorized' });
    const redirect = await fetch(`${origin}/api/redirect`, { redirect: 'manual' });
    expect(redirect.status).toBe(302);
    expect(redirect.headers.get('location')).toBe('/api/must-not-follow');
    expect(await redirect.text()).toBe('redirect response');
    expect(upstream.received.map((request) => request.url)).toEqual(['/api/unauthorized', '/api/redirect']);
  });

  it('fails closed with no server secret even if the browser supplies one', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    vi.stubEnv('BACKEND_SECRET', '');
    const { origin } = await frontend();
    const response = await fetch(`${origin}/api/ping`, { headers: { 'X-Toolbox-Backend-Secret': secret } });
    expect(response.status).toBe(503);
    const text = await response.text();
    expect(text).toContain('requires BACKEND_SECRET');
    expect(text.includes(secret)).toBe(false);
    expect(upstream.received).toHaveLength(0);
  });

  it('reports unavailable backends safely with no fallback', async () => {
    const upstream = await backend();
    await new Promise<void>((resolve) => upstream.server.close(() => resolve()));
    servers.splice(servers.indexOf(upstream.server), 1);
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    const { origin } = await frontend();
    const response = await fetch(`${origin}/api/ping`);
    expect(response.status).toBe(502);
    const text = await response.text();
    expect(text).toContain('DEV_PROXY_UNAVAILABLE');
    expect(text.includes(secret)).toBe(false);
    expect(text).not.toContain('ECONNREFUSED');
  });

  it('blocks non-loopback API peers unless LAN API access is explicitly enabled', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', upstream.origin);
    const blocked = await frontend(appConfig, true);
    const denied = await fetch(`${blocked.origin}/api/ping`, { headers: { 'X-Forwarded-For': '127.0.0.1' } });
    expect(denied.status).toBe(403);
    expect(upstream.received).toHaveLength(0);
    vi.stubEnv('ALLOW_LAN_API_PROXY', 'true');
    const allowed = await frontend(appConfig, true);
    expect((await fetch(`${allowed.origin}/api/ping`)).status).toBe(200);
    expect(upstream.received).toHaveLength(1);
  });

  it('keeps the E2E server completely isolated even with invalid development settings', async () => {
    const upstream = await backend();
    vi.stubEnv('BACKEND_ORIGIN', 'invalid-origin');
    vi.stubEnv('BACKEND_SECRET', '');
    const { server, origin } = await frontend(e2eConfig);
    expect(server.config.server.proxy).toEqual({});
    await fetch(`${origin}/api/ping`);
    expect(upstream.received).toHaveLength(0);
  });
});

it('excludes server credentials and proxy configuration from builds and static preview', async () => {
  const config = createAppConfig({ command: 'serve', mode: 'test', isPreview: true });
  expect(config.server?.proxy).toEqual({});
  expect(config.preview?.proxy).toEqual({});
  const result = await build({ configFile: appConfig, mode: 'test', logLevel: 'silent', build: { write: false } });
  for (const output of (Array.isArray(result) ? result : [result])) {
    if (!('output' in output)) throw new Error('Expected build output');
    for (const artifact of output.output) {
      const text = artifact.type === 'chunk' ? artifact.code : String(artifact.source);
      expect(text.includes(secret)).toBe(false);
      expect(text).not.toContain('X-Toolbox-Backend-Secret');
    }
  }
}, 30_000);
