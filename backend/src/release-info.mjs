// Read once from the executing immutable release, never from a mutable current
// symlink, request input, environment label or private Git checkout.
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export function releaseInfo(source = import.meta.url) {
  let revision = null;
  let archiveSha256 = null;
  try {
    const root = dirname(dirname(realpathSync(fileURLToPath(source))));
    const name = basename(root);
    const marker = join(root, ".archive-sha256");
    const info = lstatSync(marker);
    if (!info.isFile() || info.size > 65) return { revision, archiveSha256, apiContract: "toolbox-api-v1" };
    const digest = readFileSync(marker, "utf8").trim();
    if (/^[0-9a-f]{40}$/.test(name) && /^[0-9a-f]{64}$/.test(digest)) {
      revision = name;
      archiveSha256 = digest;
    }
  } catch {
    // Local/preview/legacy installations honestly report unknown identity.
  }
  return { revision, archiveSha256, apiContract: "toolbox-api-v1" };
}
