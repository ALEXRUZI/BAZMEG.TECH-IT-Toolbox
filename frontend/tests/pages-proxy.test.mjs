// @vitest-environment node
// JavaScript keeps Node's test Web APIs separate from the Workers-only TS globals.
// The production handler is independently checked by functions/tsconfig.json.
import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { writeFile, unlink } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { build } from 'vite';
import { onRequest } from '../functions/api/[[path]].ts';

let secret;
let upstream;
let logs;
const incoming = 'https://toolbox.example/api/tools/mock';
const origin = 'https://backend.example:8443';

beforeEach(() => {
  secret = randomUUID();
  upstream = vi.fn().mockResolvedValue(new Response('backend response'));
  vi.stubGlobal('fetch', upstream); // No real network fetch is ever available to the handler.
  logs = ['log', 'info', 'warn', 'error', 'debug'].map((name) => vi.spyOn(console, name).mockImplementation(() => {}));
});

afterEach(() => {
  const emittedLogs = logs.some((log) => log.mock.calls.length !== 0);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
  expect(emittedLogs).toBe(false);
});

async function invoke(request = new Request(incoming), env = {}) {
  try {
    return await onRequest({
      request,
      env: { BACKEND_ORIGIN: origin, BACKEND_SECRET: secret, ...env },
      params: { path: ['tools', 'mock'] },
      data: {},
      functionPath: '/api',
      waitUntil: () => { throw new Error('Unexpected background work'); },
      passThroughOnException: () => { throw new Error('Unexpected fallback'); },
      next: () => { throw new Error('Unexpected next handler'); },
    });
  } catch {
    // Even a regression throwing a credential-bearing exception must not print it.
    throw new Error('Pages handler threw an exception (details suppressed)');
  }
}

function outbound() {
  expect(upstream.mock.calls.length).toBe(1);
  const [url, init] = upstream.mock.calls[0];
  expect(init.headers.get('x-toolbox-backend-secret') === secret).toBe(true);
  expect(init.redirect).toBe('manual');
  return { url, ...init };
}

async function safeError(response, status, code) {
  expect(response.status).toBe(status);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const text = await response.text();
  expect(text.includes(secret)).toBe(false);
  expect(JSON.parse(text).error.code).toBe(code);
  expect(JSON.stringify([...response.headers]).includes(secret)).toBe(false);
}

describe('server authentication and configuration', () => {
  it.each(['X-Toolbox-Backend-Secret', 'x-toolbox-backend-secret', 'X-tOoLbOx-BaCkEnD-sEcReT'])('replaces protected credential casing %s', async (name) => {
    const response = await invoke(new Request(incoming, { headers: { [name]: 'browser override' } }));
    outbound();
    expect((await response.text()).includes(secret)).toBe(false);
    expect(JSON.stringify([...response.headers]).includes(secret)).toBe(false);
  });

  it.each([
    ['missing', () => undefined], ['empty', () => ''], ['spaces', () => ' \t '],
    ['newline', () => `${secret}\r\nspoofed: value`], ['non-ByteString', () => `${secret}\u0100`],
    ['control', () => `${secret}\0`], ['padded', () => ` ${secret} `],
  ])('fails closed for %s credentials without disclosing them', async (_name, value) => {
    await safeError(await invoke(new Request(incoming, { headers: { 'x-toolbox-backend-secret': 'browser override' } }), {
      BACKEND_SECRET: value(),
    }), 503, 'PAGES_PROXY_CONFIGURATION');
    expect(upstream.mock.calls.length).toBe(0);
  });

  it.each([undefined, '', 'not a URL', 'ftp://backend.example', 'https://user:password@backend.example'])('rejects invalid upstream configuration #%#', async (value) => {
    await safeError(await invoke(undefined, { BACKEND_ORIGIN: value }), 503, 'PAGES_PROXY_CONFIGURATION');
    expect(upstream.mock.calls.length).toBe(0);
  });

  it('keeps a backend 401 distinct from local configuration errors', async () => {
    upstream.mockResolvedValue(new Response('{"error":"unauthorized"}', { status: 401 }));
    const response = await invoke();
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'unauthorized' });
    outbound();
  });

  it('does not embed the server secret or Pages handler in browser artifacts', async () => {
    vi.stubEnv('BACKEND_SECRET', secret);
    vi.stubEnv('BACKEND_ORIGIN', origin);
    const result = await build({ configFile: fileURLToPath(new URL('../vite.config.ts', import.meta.url)),
      mode: 'test', logLevel: 'silent', build: { write: false } });
    for (const output of (Array.isArray(result) ? result : [result])) {
      for (const artifact of output.output) {
        const text = artifact.type === 'chunk' ? artifact.code : String(artifact.source);
        expect(text.includes(secret)).toBe(false);
        expect(text.includes('PAGES_PROXY_CONFIGURATION')).toBe(false);
        expect(text.toLowerCase().includes('x-toolbox-backend-secret')).toBe(false);
      }
    }
  }, 30_000);
});

describe('edge identity and hop-by-hop sanitization', () => {
  const forwardedHeaders = [
    ['X-Forwarded-Port', '123'], ['X-Forwarded-Prefix', '/admin'],
    ['X-Forwarded-SSL', 'on'], ['X-Forwarded-Scheme', 'http'],
    ['X-Forwarded-Server', 'client.example'], ['X-Forwarded-Custom', 'untrusted'],
  ];
  const casingCases = forwardedHeaders.flatMap(([name, value]) => [
    [name, value], [name.toLowerCase(), value],
    [Array.from(name, (char, index) => index % 2 ? char.toUpperCase() : char.toLowerCase()).join(''), value],
  ]);

  it.each(casingCases)('strips incoming forwarding-family header %s and reconstructs only trusted values', async (name, value) => {
    await invoke(new Request(incoming, { headers: {
      [name]: value, 'X-Forwarded-Host': 'attacker.example',
      'CF-Connecting-IP': '192.0.2.10', 'X-Toolbox-Client-IP': '10.0.0.1',
      'X-Toolbox-Backend-Secret': 'browser override',
      'X-Application': 'preserved', 'X-Forwardedness': 'not in the family',
      Accept: 'application/json',
    } }));
    const { headers } = outbound();
    expect(headers.has(name)).toBe(false);
    expect([...headers.keys()].filter((key) => key.toLowerCase().startsWith('x-forwarded-'))).toEqual(['x-forwarded-host']);
    expect(headers.get('x-forwarded-host')).toBe('toolbox.example');
    expect(headers.get('x-toolbox-client-ip')).toBe('192.0.2.10');
    expect(headers.get('x-application')).toBe('preserved');
    expect(headers.get('x-forwardedness')).toBe('not in the family');
    expect(headers.get('accept')).toBe('application/json');
  });

  it('strips all forwarding-family members together without skipping adjacent headers', async () => {
    await invoke(new Request(incoming, { headers: Object.fromEntries(forwardedHeaders) }));
    const { headers } = outbound();
    for (const [name] of forwardedHeaders) expect(headers.has(name)).toBe(false);
    expect([...headers.keys()].filter((key) => key.toLowerCase().startsWith('x-forwarded-'))).toEqual(['x-forwarded-host']);
    expect(headers.get('x-forwarded-host')).toBe('toolbox.example');
  });

  it.each(['X-Toolbox-Client-IP', 'x-toolbox-client-ip', 'x-ToOlBoX-cLiEnT-iP'])('uses edge IP instead of %s', async (name) => {
    await invoke(new Request(incoming, { headers: {
      [name]: '10.0.0.1', 'CF-Connecting-IP': '192.0.2.10', 'X-FoRwArDeD-HoSt': 'attacker.example',
      Forwarded: 'for=10.0.0.1;host=attacker.example;proto=http', 'X-FoRwArDeD-FoR': '10.0.0.1, 127.0.0.1',
      'X-Forwarded-Proto': 'http', 'X-Real-IP': '10.0.0.1', 'True-Client-IP': '10.0.0.1',
    } }));
    const { headers } = outbound();
    expect(headers.get('x-toolbox-client-ip')).toBe('192.0.2.10');
    expect(headers.get('x-forwarded-host')).toBe('toolbox.example');
    for (const name of ['forwarded', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'true-client-ip', 'cf-connecting-ip']) {
      expect(headers.has(name)).toBe(false);
    }
  });

  it('leaves no fabricated IP or spoofed fallback when the edge IP is absent', async () => {
    await invoke(new Request(incoming, { headers: {
      'X-Toolbox-Client-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1',
      Forwarded: 'for=127.0.0.1', 'X-Real-IP': '127.0.0.1', 'True-Client-IP': '127.0.0.1',
    } }));
    const { headers } = outbound();
    for (const name of ['x-toolbox-client-ip', 'x-forwarded-for', 'forwarded', 'x-real-ip', 'true-client-ip']) {
      expect(headers.has(name)).toBe(false);
    }
  });

  it('removes standard and Connection-nominated headers before reinjecting protected ones', async () => {
    const names = ['Host', 'Keep-Alive', 'Proxy-Authenticate', 'Proxy-Authorization', 'TE', 'Trailer', 'Transfer-Encoding', 'Upgrade'];
    await invoke(new Request(incoming, { headers: {
      ...Object.fromEntries(names.map((name) => [name, 'untrusted'])),
      CoNnEcTiOn: 'keep-alive, X-Custom-Hop, x-toolbox-backend-secret, X-Toolbox-Client-IP, X-FoRwArDeD-HoSt',
      'X-Custom-Hop': 'remove', 'X-Ordinary': 'preserve', 'CF-Connecting-IP': '2001:db8::10',
      ...Object.fromEntries(forwardedHeaders), 'X-Forwarded-Host': 'attacker.example',
      'X-Toolbox-Client-IP': '10.0.0.1', 'X-Toolbox-Backend-Secret': 'browser override',
    } }));
    const { headers } = outbound();
    for (const name of [...names, 'connection', 'x-custom-hop']) expect(headers.has(name)).toBe(false);
    for (const [name] of forwardedHeaders) expect(headers.has(name)).toBe(false);
    expect(headers.get('x-toolbox-client-ip')).toBe('2001:db8::10');
    expect(headers.get('x-forwarded-host')).toBe('toolbox.example');
    expect(headers.get('x-ordinary')).toBe('preserve');
  });
});

describe('URL and HTTP request forwarding', () => {
  it.each(['/api/ping', '/api/tools/a%2Fb', '/api//nested/path'])('preserves path %s and exact encoded query on the configured origin', async (path) => {
    const query = '?target=https%3a%2f%2fattacker.example&x=a+b&x=%20&encoded=%252F&empty=';
    await invoke(new Request(`https://toolbox.example${path}${query}#incoming-fragment`), {
      BACKEND_ORIGIN: `${origin}/ignored/base?ignored=1#configured-fragment`,
    });
    expect(outbound().url).toBe(`${origin}${path}${query}`);
  });

  it.each(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])('preserves %s and passes the original unread body stream', async (method) => {
    const hasBody = method !== 'GET' && method !== 'HEAD';
    const body = JSON.stringify({ value: 'local test' });
    const request = new Request(`${incoming}?q=1`, { method, headers: { 'Content-Type': 'application/json', 'X-Ordinary': 'value' },
      ...(hasBody ? { body } : {}) });
    await invoke(request);
    const sent = outbound();
    expect(sent.method).toBe(method);
    expect(sent.url).toBe(`${origin}/api/tools/mock?q=1`);
    expect(sent.headers.get('content-type')).toBe('application/json');
    expect(sent.headers.get('x-ordinary')).toBe('value');
    expect(request.bodyUsed).toBe(false);
    expect(sent.body === (hasBody ? request.body : undefined)).toBe(true);
    if (hasBody) expect(await new Response(sent.body).text()).toBe(body);
  });

  it.each(['text/plain', 'application/octet-stream'])('preserves non-JSON bytes for %s', async (contentType) => {
    const bytes = new Uint8Array([0, 1, 127, 128, 255, 13, 10]);
    await invoke(new Request(incoming, { method: 'POST', headers: { 'Content-Type': contentType }, body: bytes }));
    const sent = outbound();
    expect(sent.headers.get('content-type')).toBe(contentType);
    expect(new Uint8Array(await new Response(sent.body).arrayBuffer())).toEqual(bytes);
  });
});

describe('unchanged upstream responses and manual redirects', () => {
  it.each([200, 201, 204, 400, 401, 403, 404, 429, 500, 502, 503])('preserves response status %s, headers and body', async (status) => {
    const backendResponse = new Response(status === 204 ? null : 'original backend body', {
      status, headers: { 'Content-Type': 'text/plain', 'X-Backend': 'preserved', 'Retry-After': '5' },
    });
    upstream.mockResolvedValue(backendResponse);
    const response = await invoke();
    expect(response === backendResponse).toBe(true);
    expect(response.status).toBe(status);
    expect(response.headers.get('content-type')).toBe('text/plain');
    expect(response.headers.get('x-backend')).toBe('preserved');
    expect(response.headers.get('retry-after')).toBe('5');
    expect(await response.text()).toBe(status === 204 ? '' : 'original backend body');
    outbound();
  });

  it.each([301, 302, 307, 308])('returns %s without sending credentials to a redirect host', async (status) => {
    const location = 'https://another-host.example/do-not-fetch';
    upstream.mockResolvedValue(new Response('redirect body', { status, headers: { Location: location } }));
    const response = await invoke();
    expect(response.status).toBe(status);
    expect(response.headers.get('location')).toBe(location);
    expect(await response.text()).toBe('redirect body');
    expect(outbound().url).toBe(`${origin}/api/tools/mock`);
  });

  it('returns the original response stream without buffering it', async () => {
    let controller;
    const stream = new ReadableStream({ start(value) { controller = value; } });
    const backendResponse = new Response(stream);
    upstream.mockResolvedValue(backendResponse);
    const response = await invoke();
    expect(response.body === stream).toBe(true);
    expect(response.bodyUsed).toBe(false);
    controller.enqueue(new TextEncoder().encode('first'));
    controller.enqueue(new TextEncoder().encode('second'));
    controller.close();
    expect(await response.text()).toBe('firstsecond');
  });
});

describe('failure and cancellation without retries', () => {
  it.each(['unavailable', 'fetch rejection'])('returns a safe 502 for %s', async () => {
    upstream.mockRejectedValue(new TypeError(`Internal failure containing ${secret}`, {
      cause: new Error('ECONNREFUSED'),
    }));
    await safeError(await invoke(), 502, 'PAGES_PROXY_UNAVAILABLE');
    outbound();
  });

  it('does not fetch an already-aborted request', async () => {
    const controller = new AbortController();
    controller.abort(new Error(`Abort reason ${secret}`));
    await safeError(await invoke(new Request(incoming, { signal: controller.signal })), 499, 'PAGES_PROXY_CANCELLED');
    expect(upstream.mock.calls.length).toBe(0);
  });

  it('propagates cancellation to a controlled pending fetch and handles its rejection', async () => {
    const controller = new AbortController();
    const request = new Request(incoming, { signal: controller.signal });
    let started;
    const ready = new Promise((resolve) => { started = resolve; });
    upstream.mockImplementation((_url, init) => new Promise((_resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason), { once: true });
      started();
    }));
    const pending = invoke(request);
    await ready;
    expect(outbound().signal === request.signal).toBe(true);
    controller.abort(new Error(`Abort reason ${secret}`));
    await safeError(await pending, 499, 'PAGES_PROXY_CANCELLED');
    expect(upstream.mock.calls.length).toBe(1);
  });
});

it('proves Pages TS errors fail the dedicated check while the old app configs omit Functions', async () => {
  const cwd = fileURLToPath(new URL('..', import.meta.url));
  const tsc = fileURLToPath(new URL('../node_modules/typescript/bin/tsc', import.meta.url));
  for (const config of ['tsconfig.json', 'tsconfig.test.json']) {
    const result = JSON.parse(execFileSync(process.execPath, [tsc, '--project', config, '--showConfig'], { cwd, encoding: 'utf8' }));
    expect(result.files.some((file) => file.includes('/functions/'))).toBe(false);
  }
  const probe = fileURLToPath(new URL(`../functions/typecheck-probe-${randomUUID()}.ts`, import.meta.url));
  await writeFile(probe, 'export const pagesTypecheckProbe: string = 123;\n', { flag: 'wx' });
  try {
    let rejected = false;
    try {
      execFileSync(process.execPath, [tsc, '--project', 'functions/tsconfig.json', '--pretty', 'false'], { cwd, stdio: 'pipe' });
    } catch (error) {
      rejected = error.status !== 0 && String(error.stdout).includes('TS2322') && String(error.stdout).includes('typecheck-probe-');
    }
    expect(rejected).toBe(true);
  } finally {
    await unlink(probe);
  }
  execFileSync(process.execPath, [tsc, '--project', 'functions/tsconfig.json'], { cwd, stdio: 'pipe' });
}, 30_000);
