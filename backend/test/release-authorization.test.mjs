import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { acceptedAuthorization } from "../src/release-info.mjs";

test("root evidence is fresh per read, bounded, inode-checked and bound to the executing release", (t) => {
  const directory = fs.mkdtempSync(join(tmpdir(), "toolbox-authorization-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const revision = "a".repeat(40), archiveSha256 = "b".repeat(64);
  const release = { revision, archiveSha256 };
  const root = join(directory, revision);
  fs.mkdirSync(join(root, "src"), { recursive: true });
  const source = pathToFileURL(join(root, "src/release-info.mjs")).href;
  fs.writeFileSync(new URL(source), "// fixture");
  const current = join(directory, "current");
  fs.symlinkSync(root, current);
  const evidence = join(directory, "accepted.json");
  const identity = { release: `production-7-17-${revision}`, sequence: "7", commit: revision,
    archiveSha256, manifestSha256: "c".repeat(64), keyId: "test-key" };
  // Fixtures run unprivileged. Only root ownership and external ancestor modes
  // are simulated; nofollow, descriptor reads, renames, links and size are real.
  let uid = 0, fileUid = 0, parentUnsafe = false, unreadable = false;
  const filesystem = { ...fs,
    lstatSync(path) {
      const info = fs.lstatSync(path);
      info.uid = uid;
      if (!path.startsWith(directory)) info.mode &= ~0o022;
      if (parentUnsafe && path === directory) info.mode |= 0o020;
      return info;
    },
    fstatSync(fd) { const info = fs.fstatSync(fd); info.uid = fileUid; return info; },
    openSync(...args) { if (unreadable) throw Object.assign(new Error(), { code: "EACCES" }); return fs.openSync(...args); },
  };
  const read = () => acceptedAuthorization(release, { filesystem, evidence, current, source });
  const write = (value) => {
    fs.writeFileSync(evidence + ".next", JSON.stringify(value, value && Object.keys(value).sort()) + "\n", { mode: 0o644 });
    fs.renameSync(evidence + ".next", evidence);
  };
  const record = { schema: 1, ...identity };
  assert.equal(read(), null); // missing
  write(record);
  assert.deepEqual(read(), identity);
  const next = { ...record, sequence: "8", release: `production-8-18-${revision}`, manifestSha256: "d".repeat(64) };
  write(null); // reservation invalidates old acceptance before activation
  assert.equal(read(), null);
  write(next); // same executing process and exact commit/archive, new authorization
  const { schema, ...nextIdentity } = next;
  assert.deepEqual(read(), nextIdentity);
  for (const bad of [null, {}, { ...next, schema: 2 }, { ...next, sequence: 8 },
    { ...next, sequence: "9223372036854775808" }, { ...next, commit: "f".repeat(40) },
    { ...next, release: `production-8-9223372036854775808-${revision}` },
    { ...next, archiveSha256: "e".repeat(64) }, { ...next, release: identity.release },
    { ...next, manifestSha256: "bad" }, { ...next, keyId: "bad\nkey" }, { ...next, extra: true }]) {
    write(bad); assert.equal(read(), null);
  }
  for (const bad of ["{interrupted", "x".repeat(4097)]) {
    fs.writeFileSync(evidence, bad); assert.equal(read(), null);
  }
  write(next);
  unreadable = true; assert.equal(read(), null); unreadable = false;
  uid = 1000; assert.equal(read(), null); uid = 0;
  fileUid = 1000; assert.equal(read(), null); fileUid = 0;
  parentUnsafe = true; assert.equal(read(), null); parentUnsafe = false;
  fs.chmodSync(evidence, 0o664); assert.equal(read(), null); fs.chmodSync(evidence, 0o644);
  fs.linkSync(evidence, evidence + ".hardlink"); assert.equal(read(), null); fs.unlinkSync(evidence + ".hardlink");
  fs.renameSync(evidence, evidence + ".real");
  fs.symlinkSync(evidence + ".real", evidence); assert.equal(read(), null); fs.unlinkSync(evidence);
  execFileSync("mkfifo", [evidence]); assert.equal(read(), null); fs.unlinkSync(evidence);
  const linkedParent = directory + "-link";
  fs.symlinkSync(directory, linkedParent);
  try {
    assert.equal(acceptedAuthorization(release, { filesystem, evidence: join(linkedParent, "accepted.json"), current, source }), null);
  } finally { fs.unlinkSync(linkedParent); }
  write(next);
  // Root atomic rename after open must not swap the inode being inspected/read.
  const raceReader = { ...filesystem, openSync(...args) {
    const fd = filesystem.openSync(...args);
    write(null);
    return fd;
  } };
  assert.equal(acceptedAuthorization(release, { filesystem: raceReader, evidence, current, source }), null);
  assert.equal(read(), null); // unlinked inode (nlink=0) fails conservatively
  write(next);
  const raceAfterStat = { ...filesystem, fstatSync(fd) {
    const info = filesystem.fstatSync(fd);
    write(null);
    return info;
  } };
  assert.deepEqual(acceptedAuthorization(release, { filesystem: raceAfterStat, evidence, current, source }), nextIdentity);
  assert.equal(read(), null);
  write(next);
  const canonical = fs.readFileSync(evidence, "utf8");
  fs.writeFileSync(evidence, canonical.replace('"schema":1', '"schema":1,"schema":1'));
  assert.equal(read(), null);
  write(next);
  fs.writeFileSync(join(directory, ".deployment-transaction"), "pending");
  assert.equal(read(), null);
  fs.unlinkSync(join(directory, ".deployment-transaction"));
  fs.unlinkSync(current); fs.symlinkSync(directory, current);
  assert.equal(read(), null); // post-activation/manual rollback is not this executing release
  // The production defaults never trust an ordinary application-owned fixture.
  assert.equal(acceptedAuthorization(release, { evidence, current, source }), null);
});
