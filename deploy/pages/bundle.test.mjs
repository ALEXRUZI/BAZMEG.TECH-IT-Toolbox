// Offline qualification of the exact production precompilation method. No live
// Cloudflare/backend calls, real credentials, secret-bearing diagnostics or CDN.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../../', import.meta.url));
const wrangler = fileURLToPath(new URL('node_modules/.bin/wrangler', import.meta.url));

test('precompiled Pages Worker preserves API routing, server bindings and static fallback', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'toolbox-pages-bundle-'));
  const originalFetch = globalThis.fetch;
  try {
    execFileSync(wrangler, ['pages', 'functions', 'build', path.join(root, 'frontend/functions'),
      '--outdir', path.join(directory, '_worker.js'),
      '--output-routes-path', path.join(directory, '_routes.json')], {
      cwd: directory, stdio: 'pipe',
      env: { ...process.env, WRANGLER_SEND_METRICS: 'false' },
      timeout: 60_000,
    });
    const routes = JSON.parse(await readFile(path.join(directory, '_routes.json'), 'utf8'));
    assert.equal(routes.version, 1);
    assert.deepEqual(routes.include, ['/api/*']);
    assert.deepEqual(routes.exclude, []);
    const code = await readFile(path.join(directory, '_worker.js/index.js'), 'utf8');
    assert.ok(!code.startsWith('------formdata-'), 'must be executable Worker, not multipart upload data');
    const { default: worker } = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
    const fixtureSecret = 'disposable-pages-runtime-binding';
    let upstreamCalls = 0;
    globalThis.fetch = async (url, init) => {
      upstreamCalls++;
      assert.equal(url, 'https://backend.example.test/api/ping?test=1');
      assert.equal(init.redirect, 'manual');
      assert.ok(init.headers.get('X-Toolbox-Backend-Secret') === fixtureSecret, 'server binding not preserved');
      assert.equal(init.headers.get('X-Toolbox-Client-IP'), '192.0.2.1');
      return Response.json({ ok: true, message: 'toolbox API reachable' });
    };
    const context = { waitUntil() {}, passThroughOnException() {} };
    const env = { BACKEND_ORIGIN: 'https://backend.example.test', BACKEND_SECRET: fixtureSecret,
      ASSETS: { fetch: async () => new Response('static fixture') } };
    const request = new Request('https://pages.example.test/api/ping?test=1', { headers: {
      'X-Toolbox-Backend-Secret': 'disposable-spoof', 'CF-Connecting-IP': '192.0.2.1',
    } });
    const result = await worker.fetch(request, env, context);
    assert.equal(result.status, 200);
    assert.equal((await result.json()).ok, true);
    assert.equal(upstreamCalls, 1);
    const missingBinding = await worker.fetch(request, { ...env, BACKEND_SECRET: undefined }, context);
    assert.equal(missingBinding.status, 503);
    assert.equal(upstreamCalls, 1);
    const staticResult = await worker.fetch(new Request('https://pages.example.test/'), env, context);
    assert.equal(await staticResult.text(), 'static fixture');
  } finally {
    globalThis.fetch = originalFetch;
    await rm(directory, { recursive: true, force: true });
  }
});
