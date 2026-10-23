// Read once from the executing immutable release, never from a mutable current
// symlink, request input, environment label or private Git checkout.
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import * as fs from "node:fs";

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

// Fixed root-controlled read-only projection, NOT the private anti-replay state.
// Read per request: same-SHA reauthorization intentionally does not restart Node.
// Options are dependency injection for offline tests, never request/env settings.
export function acceptedAuthorization(release, {
  filesystem = fs,
  evidence = "/var/lib/toolbox-release/accepted.json",
  current = "/opt/toolbox-api/current",
  source = import.meta.url,
} = {}) {
  let fd;
  const trusted = (info) => info.uid === 0 && (info.mode & 0o022) === 0;
  try {
    if (!release.revision || !release.archiveSha256) return null;
    // Ancestors cannot be replaced by toolboxapi/toolboxdeploy. Only trusted root
    // may rename entries here; final open+fstat+bounded read use ONE inode, never
    // lstat then readFile(path), so atomic replacement cannot substitute bytes.
    for (let path = dirname(evidence); ; path = dirname(path)) {
      const info = filesystem.lstatSync(path);
      if (!info.isDirectory() || !trusted(info)) return null;
      if (path === dirname(path)) break;
    }
    const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = fs.constants;
    fd = filesystem.openSync(evidence, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    const info = filesystem.fstatSync(fd);
    if (!info.isFile() || !trusted(info) || info.nlink !== 1 || info.size > 4096) return null;
    const bytes = Buffer.alloc(4097);
    const length = filesystem.readSync(fd, bytes, 0, bytes.length, 0);
    if (length > 4096) return null;
    const text = bytes.subarray(0, length).toString("utf8");
    const record = JSON.parse(text);
    if (!record || Object.keys(record).sort().join(",") !==
        "archiveSha256,commit,keyId,manifestSha256,release,schema,sequence" || record.schema !== 1) return null;
    // Match the root writer's canonical ASCII JSON, rejecting duplicate keys,
    // partial/alternate encodings and hand-edited noncanonical records too.
    if (JSON.stringify(record, Object.keys(record).sort()) + "\n" !== text) return null;
    const { schema, ...identity } = record;
    const releaseIdentity = typeof identity.release === "string" && identity.release.match(
      /^production-([1-9][0-9]{0,18})-([1-9][0-9]{0,18})-([0-9a-f]{40})$/);
    if (typeof identity.sequence !== "string" || !/^[1-9][0-9]{0,18}$/.test(identity.sequence) ||
        BigInt(identity.sequence) >= 2n ** 63n ||
        !releaseIdentity || releaseIdentity[1] !== identity.sequence ||
        BigInt(releaseIdentity[2]) >= 2n ** 63n || releaseIdentity[3] !== release.revision ||
        identity.commit !== release.revision || identity.archiveSha256 !== release.archiveSha256 ||
        typeof identity.manifestSha256 !== "string" || !/^[0-9a-f]{64}$/.test(identity.manifestSha256) ||
        typeof identity.keyId !== "string" || !/^[a-z0-9-]{1,48}$/.test(identity.keyId)) return null;
    // Do not attest a stopped/rolled-back process or unresolved helper transaction.
    const root = dirname(dirname(filesystem.realpathSync(fileURLToPath(source))));
    if (filesystem.realpathSync(current) !== root) return null;
    try {
      filesystem.lstatSync(join(dirname(current), ".deployment-transaction"));
      return null;
    } catch (error) {
      if (error.code !== "ENOENT") return null;
    }
    return identity;
  } catch {
    // Missing, inaccessible, malformed, legacy or interrupted evidence is unknown.
    return null;
  } finally {
    if (fd !== undefined) filesystem.closeSync(fd);
  }
}
