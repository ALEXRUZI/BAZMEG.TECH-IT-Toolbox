// Build-time evidence only: no sources, inputs, keys or environment values.
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import type { Plugin } from 'vite';

export function sshForgeBundleEvidence() {
  const builds: unknown[] = [];
  let root = '';
  const normalize = (id: string) => id.replaceAll(`${root}/`, '');
  const sha256 = (bytes: string | Uint8Array) => createHash('sha256').update(bytes).digest('hex');
  function observe(scope: 'app' | 'worker'): Plugin {
    return {
      name: `aud-ssh-002-${scope}`,
      apply: 'build',
      enforce: 'post',
      configResolved(config) { root = resolve(config.root); },
      buildStart() { if (scope === 'app') builds.length = 0; },
      generateBundle(_options, bundle) {
        const graph = [...this.getModuleIds()].sort().map(id => {
          const info = this.getModuleInfo(id)!;
          return {
            id: normalize(id),
            imports: info.importedIds.map(normalize).sort(),
            dynamicImports: info.dynamicallyImportedIds.map(normalize).sort(),
            importers: info.importers.map(normalize).sort(),
            dynamicImporters: info.dynamicImporters.map(normalize).sort(),
            sourceAvailable: info.code !== null,
          };
        });
        const chunks = Object.values(bundle).filter(item => item.type === 'chunk').map(chunk => ({
          file: chunk.fileName,
          entry: chunk.facadeModuleId && normalize(chunk.facadeModuleId),
          sha256: sha256(chunk.code),
          bytes: Buffer.byteLength(chunk.code),
          imports: chunk.imports,
          dynamicImports: chunk.dynamicImports,
          modules: Object.keys(chunk.modules).map(normalize).sort(),
        }));
        builds.push({ scope, graph, chunks });
        if (scope === 'app') {
          const artifacts = Object.values(bundle).map(item => {
            const bytes = item.type === 'chunk' ? item.code : item.source;
            return { file: item.fileName, bytes: Buffer.byteLength(bytes), sha256: sha256(bytes) };
          });
          this.emitFile({ type: 'asset', fileName: 'ssh-forge-bundle.json', source: JSON.stringify({ schema: 1, builds, artifacts }) });
        }
      },
    };
  }
  return { app: observe('app'), worker: () => [observe('worker')] };
}
