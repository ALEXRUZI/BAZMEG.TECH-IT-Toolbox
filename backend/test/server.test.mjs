import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { createInterface } from "node:readline";
import test from "node:test";
import { cp, mkdtemp, mkdir, writeFile, symlink, rm, readFile, rename } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { releaseInfo } from "../src/release-info.mjs";

const toolPaths = ["dns-check", "http-header-check", "tls-check", "rdap-lookup"]
  .map((tool) => `/api/tools/${tool}`);

// Exercise the real entry point without exporting/restructuring production routing.
// All diagnostic inputs fail validation before DNS or outbound connections.
async function startServer(t, secret = "", directory = new URL("../", import.meta.url)) {
  const child = spawn(process.execPath, ["src/server.mjs"], {
    cwd: directory,
    env: { ...process.env, PORT: "0", BACKEND_SECRET: secret, TRUST_TOOLBOX_PROXY_HEADERS: "false" },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const lines = createInterface({ input: child.stdout });
  t.after(async () => {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) {
      const exited = once(child, "exit");
      child.kill("SIGKILL");
      await exited;
    }
  });
  const origin = await new Promise((resolve, reject) => {
    const finish = (error, address) => {
      clearTimeout(timer);
      child.removeListener("error", failed);
      child.removeListener("exit", failed);
      lines.removeListener("line", line);
      if (error) reject(error);
      else resolve(address);
    };
    const timer = setTimeout(() => finish(new Error("Local test server startup timed out.")), 5000);
    const failed = () => finish(new Error("Local test server failed to start."));
    const line = (value) => {
      const match = value.match(/Server listening at (http:\/\/127\.0\.0\.1:\d+)/);
      if (match) finish(null, match[1]);
    };
    child.once("error", failed);
    child.once("exit", failed);
    lines.on("line", line);
  });
  return async (path, options = {}) => {
    const response = await fetch(`${origin}${path}`, {
      ...options, signal: AbortSignal.timeout(3000), redirect: "error",
    });
    return { status: response.status, body: await response.json() };
  };
}

test("server fails closed without configured credentials but keeps health public", { timeout: 10000 }, async (t) => {
  const request = await startServer(t);
  assert.deepEqual(await request("/healthz"), {
    status: 200, body: { status: "ok", service: "toolbox-api" },
  });
  for (const path of ["/api/ping", "/api/release", ...toolPaths]) {
    const response = await request(path, {
      method: toolPaths.includes(path) ? "POST" : "GET",
      headers: { "x-toolbox-backend-secret": randomUUID() },
    });
    assert.deepEqual(response, { status: 401, body: { error: "unauthorized" } });
  }
});

test("server authentication precedes parsing and ignores spoofed proxy headers", { timeout: 10000 }, async (t) => {
  const secret = randomUUID();
  const request = await startServer(t, secret);
  for (const path of ["/api/ping", "/api/release", ...toolPaths, "/missing", "/healthz?not-exempt=1"]) {
    for (const provided of [undefined, randomUUID()]) {
      const headers = {
        "content-type": "application/json",
        "x-forwarded-for": "203.0.113.10",
        "x-forwarded-host": "spoofed.invalid",
        "x-forwarded-proto": "https",
        "x-toolbox-client-ip": "203.0.113.11",
      };
      if (provided) headers["x-toolbox-backend-secret"] = provided;
      const isTool = toolPaths.includes(path);
      assert.deepEqual(await request(path, {
        method: isTool ? "POST" : "GET", headers,
        ...(isTool ? { body: "{" } : {}),
      }), { status: 401, body: { error: "unauthorized" } });
    }
  }
  assert.deepEqual(await request("/api/ping", {
    headers: { "x-toolbox-backend-secret": secret },
  }), { status: 200, body: { ok: true, message: "toolbox API reachable" } });
  assert.equal((await request("/healthz")).status, 200);
  assert.deepEqual(await request("/api/release", {
    headers: { "x-toolbox-backend-secret": secret },
  }), { status: 200, body: { ok: true, revision: null, archiveSha256: null, apiContract: "toolbox-api-v1", authorization: null } });
  assert.equal((await request("/missing", {
    headers: { "x-toolbox-backend-secret": secret },
  })).status, 404);
  // Malformed targets may fail before onRequest; they must not reach a protected handler.
  assert.equal((await request("/api/tools/%", { method: "POST" })).status, 400);
});

test("release identity comes from executing immutable path and regular hash marker, not environment", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "toolbox-release-info-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const revision = "a".repeat(40);
  const archiveSha256 = "b".repeat(64);
  const release = join(root, revision);
  await mkdir(join(release, "src"), { recursive: true });
  await writeFile(join(release, "src/release-info.mjs"), "// disposable fixture");
  const source = pathToFileURL(join(release, "src/release-info.mjs")).href;
  assert.equal(releaseInfo(source).revision, null);
  await writeFile(join(release, ".archive-sha256"), archiveSha256 + "\n");
  assert.deepEqual(releaseInfo(source), { revision, archiveSha256, apiContract: "toolbox-api-v1" });
  await symlink(release, join(root, "current"));
  assert.equal(releaseInfo(pathToFileURL(join(root, "current/src/release-info.mjs")).href).revision, revision);
  await writeFile(join(release, ".archive-sha256"), "malformed");
  assert.equal(releaseInfo(source).revision, null);
  await rm(join(release, ".archive-sha256"));
  await writeFile(join(root, "external-marker"), archiveSha256);
  await symlink(join(root, "external-marker"), join(release, ".archive-sha256"));
  assert.equal(releaseInfo(source).revision, null);
});

test("authenticated release endpoint identifies the running revision, not a later symlink/marker label", { timeout: 10000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "toolbox-running-release-"));
  const revision = "a".repeat(40);
  const archiveSha256 = "b".repeat(64);
  const directory = join(root, revision);
  await mkdir(directory);
  await cp(new URL("../src", import.meta.url), join(directory, "src"), { recursive: true });
  await symlink(fileURLToPath(new URL("../node_modules", import.meta.url)), join(directory, "node_modules"));
  await writeFile(join(directory, ".archive-sha256"), archiveSha256 + "\n");
  // Disposable local files only; the server helper always kills its child.
  t.after(() => rm(root, { recursive: true, force: true }));
  const secret = randomUUID();
  const request = await startServer(t, secret, directory);
  await writeFile(join(directory, ".archive-sha256"), "c".repeat(64));
  assert.deepEqual(await request("/api/release", {
    headers: { "x-toolbox-backend-secret": secret },
  }), { status: 200, body: { ok: true, revision, archiveSha256, apiContract: "toolbox-api-v1", authorization: null } });
});

test("authenticated endpoint observes same-commit signed acceptance after startup without restart", { timeout: 10000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "toolbox-live-authorization-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const revision = "a".repeat(40), archiveSha256 = "b".repeat(64);
  const directory = join(root, revision), evidence = join(root, "accepted.json"), current = join(root, "current");
  await mkdir(directory);
  await cp(new URL("../src", import.meta.url), join(directory, "src"), { recursive: true });
  await symlink(fileURLToPath(new URL("../node_modules", import.meta.url)), join(directory, "node_modules"));
  await symlink(directory, current);
  await writeFile(join(directory, ".archive-sha256"), archiveSha256 + "\n");
  // Test-only dependency injection in a disposable copy. Real route/reader, with
  // root ownership simulated because CI is unprivileged; no production env hook.
  const module = join(directory, "src/release-info.mjs");
  const code = (await readFile(module, "utf8")).replace(
    "export function acceptedAuthorization(", "function readAcceptedAuthorization(");
  await writeFile(module, code + `
export function acceptedAuthorization(release) {
  const filesystem = { ...fs,
    lstatSync(path) { const info = fs.lstatSync(path); info.uid = 0; info.mode &= ~0o022; return info; },
    fstatSync(fd) { const info = fs.fstatSync(fd); info.uid = 0; return info; }
  };
  return readAcceptedAuthorization(release, { filesystem, evidence: ${JSON.stringify(evidence)}, current: ${JSON.stringify(current)} });
}
`);
  const secret = randomUUID();
  const request = await startServer(t, secret, directory);
  const read = async () => (await request("/api/release", { headers: { "x-toolbox-backend-secret": secret } })).body;
  const write = async (value) => {
    await writeFile(evidence + ".next", JSON.stringify(value, value && Object.keys(value).sort()) + "\n", { mode: 0o644 });
    await rename(evidence + ".next", evidence);
  };
  assert.equal((await read()).authorization, null);
  const old = { release: `production-6-16-${revision}`, sequence: "6", commit: revision,
    archiveSha256, manifestSha256: "c".repeat(64), keyId: "test-key" };
  await write({ schema: 1, ...old });
  assert.deepEqual((await read()).authorization, old);
  await write(null); // pending/failed/interrupted: no successful authorization
  assert.equal((await read()).authorization, null);
  const next = { ...old, release: `production-7-17-${revision}`, sequence: "7", manifestSha256: "d".repeat(64) };
  await write({ schema: 1, ...next });
  assert.deepEqual(await read(), { ok: true, revision, archiveSha256, apiContract: "toolbox-api-v1", authorization: next });
  await writeFile(evidence, "{interrupted");
  assert.equal((await read()).authorization, null);
});

test("authenticated tool validation and JSON parser errors retain safe contracts and recover", { timeout: 10000 }, async (t) => {
  const secret = randomUUID();
  const request = await startServer(t, secret);
  const headers = { "content-type": "application/json", "x-toolbox-backend-secret": secret };
  const errors = [
    { code: "INVALID_MODE", message: "Choose single or burst DNS check mode." },
    { code: "INVALID_TARGET", message: "Enter a public website domain name." },
    { code: "INVALID_HOST", message: "Enter a valid public hostname." },
    { code: "INVALID_INPUT", message: "Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN." },
  ];
  for (const [index, path] of toolPaths.entries()) {
    const options = { method: "POST", headers, body: "{}" };
    const expected = { status: 400, body: { ok: false, error: errors[index], ...(index === 3 ? { attempts: [], rawResponses: [] } : {}) } };
    assert.deepEqual(await request(path, options), expected);
    const malformed = await request(path, { ...options, body: "{" });
    assert.equal(malformed.status, 400);
    assert.equal(malformed.body.code, "FST_ERR_CTP_INVALID_JSON_BODY");
    assert.equal(malformed.body.statusCode, 400);
    assert.equal("stack" in malformed.body, false);
    assert.deepEqual(await request(path, options), expected);
  }
});
