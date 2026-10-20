// AUD-SSH-002: observe the real production app AND every Vite worker build.
// This is a regression boundary, not a vulnerability scanner or audit waiver.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';

const root = resolve(import.meta.dirname, '..');
const expected = ['baseN.js', 'cipher.js', 'cipherModes.js', 'des.js', 'forge.js', 'util.js'];
const prefix = 'node_modules/node-forge/lib/';
const isForge = id => id.includes('/node-forge/') || id.startsWith('node_modules/node-forge/');
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const lock = JSON.parse(readFileSync(resolve(root, 'package-lock.json'), 'utf8'));
assert.equal(pkg.dependencies['node-forge'], '1.4.0', 'Re-review the exception before changing Forge');
assert.equal(lock.packages[''].dependencies['node-forge'], '1.4.0', 'Lockfile root must pin Forge exactly');
assert.equal(lock.packages['node_modules/node-forge'].version, '1.4.0');
assert.equal(JSON.parse(readFileSync(resolve(root, 'node_modules/node-forge/package.json'), 'utf8')).version, '1.4.0', 'Installed Forge version differs from the exception');

// Independently walk literal CommonJS requires, rather than relying on minified
// symbol searches. Manual review is still required for computed/runtime loading.
const source = [];
const pending = ['des.js', 'cipher.js', 'util.js'];
while (pending.length) {
  const name = pending.pop();
  if (source.some(module => module.name === name)) continue;
  assert(expected.includes(name), `Unexpected Forge dependency: ${name}`);
  const bytes = readFileSync(resolve(root, prefix, name));
  const code = bytes.toString('utf8');
  const dependencies = [...code.matchAll(/require\(['"]([^'"]+)['"]\)/g)].map(match => {
    assert(match[1].startsWith('./'), `Nonlocal Forge require: ${match[1]}`);
    return `${match[1].slice(2).replace(/\.js$/, '')}.js`;
  }).sort();
  source.push({ name, sha256: sha256(bytes), dependencies });
  pending.push(...dependencies);
}
source.sort((a, b) => a.name.localeCompare(b.name));
assert.deepEqual(source.map(module => module.name).sort(), expected);

// Evidence is emitted by the SAME Vite build that wrote the deployment output.
// Never rebuild here: missing/stale/tampered output must fail, not be repaired.
const args = process.argv.slice(2);
const distOption = args.indexOf('--dist');
assert(distOption < 0 || args[distOption + 1], '--dist requires a production output directory');
const dist = resolve(root, distOption < 0 ? 'dist' : args.splice(distOption, 2)[1]);
assert(args.length <= 1, 'Usage: check:ssh-bundle -- [evidence.json] [--dist directory]');
function artifact(file) {
  assert(typeof file === 'string' && file && !file.includes('\\') && !file.split('/').includes('..') && !file.startsWith('/'), 'Invalid production artifact path');
  try { return readFileSync(resolve(dist, file)); }
  catch { throw new Error(`Missing production artifact ${file}; run npm run build before check:ssh-bundle.`); }
}
let manifest;
try { manifest = JSON.parse(artifact('ssh-forge-bundle.json').toString('utf8')); }
catch (error) { throw new Error(`Production Forge evidence unavailable or invalid; run npm run build. ${error.message}`); }
assert.equal(manifest.schema, 1, 'Unsupported production evidence schema');
const { builds, artifacts } = manifest;
assert(Array.isArray(builds) && builds.length && Array.isArray(artifacts) && artifacts.length, 'Incomplete production evidence');
for (const result of builds) {
  assert(['app', 'worker'].includes(result.scope) && Array.isArray(result.graph) && result.graph.length && Array.isArray(result.chunks) && result.chunks.length, 'Incomplete production graph/chunk evidence');
  const ids = new Set(result.graph.map(module => module.id));
  assert.equal(ids.size, result.graph.length, 'Duplicate production graph IDs');
  for (const module of result.graph) {
    assert(typeof module.id === 'string' && typeof module.sourceAvailable === 'boolean', 'Invalid production graph node');
    for (const edges of [module.imports, module.dynamicImports, module.importers, module.dynamicImporters]) {
      assert(Array.isArray(edges) && edges.every(id => typeof id === 'string' && ids.has(id)), 'Incomplete production graph edges');
    }
  }
  for (const chunk of result.chunks) {
    // Rolldown adds its internal runtime after exposing the application graph.
    assert(Array.isArray(chunk.modules) && chunk.modules.length && chunk.modules.every(id => ids.has(id) || id === '\0rolldown/runtime.js'), 'Incomplete rendered chunk membership');
    assert(Array.isArray(chunk.imports) && Array.isArray(chunk.dynamicImports), 'Incomplete rendered chunk imports');
  }
}
assert.equal(builds.filter(result => result.scope === 'app').length, 1, 'Expected exactly one app graph');
const observedFiles = new Set();
for (const item of [...artifacts, ...builds.flatMap(result => result.chunks)]) {
  const bytes = artifact(item.file);
  assert(bytes.length > 0 && bytes.length === item.bytes && sha256(bytes) === item.sha256, `Production artifact mismatch: ${item.file}; rebuild and recheck before publication`);
  observedFiles.add(item.file);
}
assert(observedFiles.has('index.html'), 'Production HTML entry was not analyzed');
function javascriptFiles(directory, base = '') {
  return readdirSync(directory, { withFileTypes: true }).flatMap(item => {
    const file = base + item.name;
    if (item.isDirectory()) return javascriptFiles(resolve(directory, item.name), `${file}/`);
    assert(!item.isSymbolicLink(), 'Symlinks are not accepted in production output');
    return /\.(?:js|mjs|cjs)$/.test(file) ? [file] : [];
  });
}
const chunks = builds.flatMap(result => result.chunks);
assert.deepEqual(javascriptFiles(dist).sort(), [...new Set(chunks.map(chunk => chunk.file))].sort(), 'Unanalyzed or missing production JavaScript');
assert.equal(chunks.filter(chunk => chunk.entry === 'src/tools/ssh-key-generator/ssh.worker.ts').length, 1, 'Expected exactly one analyzed production SSH worker');

const forgeIds = [...new Set(builds.flatMap(result => result.graph.filter(module => isForge(module.id)).map(module => module.id)))].sort();
assert.deepEqual(forgeIds, expected.map(name => prefix + name).sort(), 'Unexpected production Forge graph');
const rendered = [...new Set(builds.flatMap(result => result.chunks.flatMap(chunk => chunk.modules.filter(isForge))))].sort();
assert.deepEqual(rendered, forgeIds, 'Forge rendered closure differs from loaded closure');
for (const result of builds) {
  for (const module of result.graph.filter(module => isForge(module.id))) {
    assert.equal(result.scope, 'worker', 'Forge must not enter the UI bundle');
    assert.equal(module.sourceAvailable, true, 'Forge source must be bundled, not external');
    assert.deepEqual(module.dynamicImports, [], 'Forge dynamic imports require review');
    assert(module.imports.every(id => forgeIds.includes(id)), 'Forge import escaped the reviewed closure');
  }
  for (const chunk of result.chunks.filter(chunk => chunk.modules.some(isForge))) {
    assert.equal(chunk.entry, 'src/tools/ssh-key-generator/ssh.worker.ts', 'Forge must stay in the SSH worker');
    assert.deepEqual(chunk.imports, [], 'SSH worker runtime imports require review');
    assert.deepEqual(chunk.dynamicImports, [], 'SSH worker runtime dynamic imports require review');
  }
}
assert(builds.some(result => result.scope === 'app'), 'App graph was not observed');
assert(builds.some(result => result.chunks.some(chunk => chunk.entry === 'src/tools/ssh-key-generator/ssh.worker.ts')), 'SSH worker was not observed');

const evidence = { forgeVersion: '1.4.0', source, forgeIds, builds, artifacts };
if (args[0]) {
  writeFileSync(resolve(args[0]), `${JSON.stringify(evidence, null, 2)}\n`);
  console.info(`Full app/worker graph: ${relative(process.cwd(), resolve(args[0]))}`);
}
console.info('AUD-SSH-002: production Forge closure matches six reviewed modules; RSA/ASN.1 absent.');
console.info('The high-severity package advisory remains open; this check does not fix or waive it.');
for (const result of builds) {
  console.info(`${result.scope}: ${result.graph.length} graph modules; ${result.chunks.length} chunks`);
  for (const chunk of result.chunks.filter(chunk => chunk.modules.some(isForge))) console.info(`${chunk.file}: ${chunk.bytes} bytes; SHA-256 ${chunk.sha256}`);
}
