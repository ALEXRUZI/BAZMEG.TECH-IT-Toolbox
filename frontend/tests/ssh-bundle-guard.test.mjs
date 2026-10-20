// @vitest-environment node
// Real production builds; injected imports exist only in a diagnostic transform.
import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { build, loadConfigFromFile } from 'vite';
import { afterAll, beforeAll, expect, test } from 'vitest';

const root = resolve(import.meta.dirname, '..');
const temporary = mkdtempSync(join(tmpdir(), 'ssh-bundle-guard-'));
const production = join(temporary, 'production');
async function diagnosticBuild(outDir, forbidden) {
  const loaded = await loadConfigFromFile({ command: 'build', mode: 'production' }, resolve(root, 'vite.config.ts'), root);
  const config = loaded.config;
  await build({
    ...config, root, configFile: false, logLevel: 'silent',
    worker: {
      ...config.worker,
      plugins: () => [...config.worker.plugins(), ...(forbidden ? [{
        name: 'negative-test-forge-import',
        transform(code, id) {
          if (id.endsWith('/sshSsh1.ts')) return { code: `import 'node-forge/lib/${forbidden}';\n${code}`, map: null };
        },
      }] : [])],
    },
    build: { ...config.build, outDir, emptyOutDir: true },
  });
}
function guard(dist) {
  const result = spawnSync(process.execPath, ['scripts/check-ssh-forge-bundle.mjs', '--dist', dist], { cwd: root, encoding: 'utf8', timeout: 30_000 });
  expect(result.error).toBeUndefined();
  return result;
}
function altered(name, change) {
  const dist = join(temporary, name);
  cpSync(production, dist, { recursive: true });
  const file = join(dist, 'ssh-forge-bundle.json');
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  change(dist, manifest);
  return guard(dist);
}
beforeAll(async () => { await diagnosticBuild(production); }, 60_000);
afterAll(() => { rmSync(temporary, { recursive: true, force: true }); });

test('guard verifies existing hashed production chunks without rebuilding or modifying them', () => {
  const manifest = readFileSync(join(production, 'ssh-forge-bundle.json'));
  const result = guard(production);
  expect(result.status).toBe(0);
  expect(result.stdout).toContain('RSA/ASN.1 absent');
  expect(readFileSync(join(production, 'ssh-forge-bundle.json')).equals(manifest)).toBe(true);
});
for (const forbidden of ['rsa.js', 'asn1.js', 'md5.js']) test(`actual injected Forge ${forbidden} production import fails nonzero`, async () => {
  const dist = join(temporary, forbidden);
  await diagnosticBuild(dist, forbidden);
  const result = guard(dist);
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Unexpected production Forge graph');
}, 60_000);

test('missing production directory fails nonzero rather than rebuilding', () => {
  const result = guard(join(temporary, 'missing'));
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('run npm run build');
});
test('missing build evidence fails nonzero', () => {
  const result = altered('missing-evidence', dist => rmSync(join(dist, 'ssh-forge-bundle.json')));
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Production Forge evidence unavailable');
});
test('missing SSH worker artifact fails nonzero', () => {
  const result = altered('missing-worker', (dist, manifest) => {
    const chunk = manifest.builds.flatMap(result => result.chunks).find(chunk => chunk.entry?.endsWith('/ssh.worker.ts'));
    rmSync(join(dist, chunk.file));
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Missing production artifact');
});
test('changed artifact bytes fail nonzero', () => {
  const result = altered('changed-worker', (dist, manifest) => {
    const chunk = manifest.builds.flatMap(result => result.chunks).find(chunk => chunk.entry?.endsWith('/ssh.worker.ts'));
    writeFileSync(join(dist, chunk.file), '// altered production output');
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Production artifact mismatch');
});
test('additional unanalyzed production JavaScript fails nonzero', () => {
  const result = altered('unexpected-chunk', dist => writeFileSync(join(dist, 'assets/unexpected.js'), '// unexpected chunk'));
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Unanalyzed or missing production JavaScript');
});
test('incomplete worker graph evidence fails nonzero', () => {
  const result = altered('incomplete-evidence', (dist, manifest) => {
    manifest.builds = manifest.builds.filter(result => result.scope === 'app');
    writeFileSync(join(dist, 'ssh-forge-bundle.json'), JSON.stringify(manifest));
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Unanalyzed or missing production JavaScript');
});
test('empty application graph fails nonzero', () => {
  const result = altered('empty-app-graph', (dist, manifest) => {
    manifest.builds.find(result => result.scope === 'app').graph = [];
    writeFileSync(join(dist, 'ssh-forge-bundle.json'), JSON.stringify(manifest));
  });
  expect(result.status).toBe(1);
  expect(result.stderr).toContain('Incomplete production graph/chunk evidence');
});
