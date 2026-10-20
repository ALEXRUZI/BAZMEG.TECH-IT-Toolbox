import assert from "node:assert/strict";
import test from "node:test";
import dgram from "node:dgram";
import http from "node:http";
import { EventEmitter, getEventListeners } from "node:events";
import Fastify from "fastify";
import { checkDns, resetDnsCheckState, DnsCheckError, BURST_RESOLVER_IDS } from "../src/tools/dns-check.mjs";
import { admitDns, createDnsOperation, dnsResourceState, DNS_LIMITS } from "../src/tools/dns-resources.mjs";
import { registerDnsRoute } from "../src/dns-route.mjs";

const payload = (query = "example.com", extra = {}) => ({
  mode: "single", resolverId: "cloudflare", recordType: "A", dnssec: false, query, ...extra,
});
const response = (answer = []) => ({ rcodeName: "NOERROR", answer, authority: [], additional: [], flags: {} });
const mx = (name, count = 10) => Array.from({ length: count }, (_, index) => ({
  name, type: "MX", ttl: 60, data: { preference: index, exchange: `mail${index}.example.com` },
}));
const flush = () => new Promise(setImmediate);
const empty = () => assert.deepEqual(dnsResourceState(), { activeChecks: 0, clients: 0, sockets: 0 });

function harness(t, { delayedClose = false, onSend } = {}) {
  resetDnsCheckState();
  const sockets = [];
  t.mock.method(dgram, "createSocket", () => {
    const socket = new EventEmitter();
    socket.closeCount = 0;
    socket.send = (packet, port, server, callback) => {
      Object.assign(socket, { packet, port, server, callback });
      onSend?.();
    };
    socket.close = () => { socket.closeCount++; if (!delayedClose) socket.emit("close"); };
    sockets.push(socket);
    return socket;
  });
  function reply(socket, mxCount = 0) {
    let packet = Buffer.from(socket.packet);
    packet.writeUInt16BE(0x8180, 2);
    if (mxCount) {
      let offset = 12;
      while (packet[offset]) offset += packet[offset] + 1;
      packet = packet.subarray(0, offset + 5);
      packet.writeUInt16BE(0, 10);
      packet.writeUInt16BE(mxCount, 6);
      const answers = Array.from({ length: mxCount }, (_, index) => {
        const exchange = Buffer.concat(`mail${index}.example.com`.split('.').map((label) => Buffer.concat([
          Buffer.from([label.length]), Buffer.from(label),
        ])));
        const header = Buffer.from([0xc0, 0x0c, 0, 15, 0, 1, 0, 0, 0, 60, 0, 0, 0, index]);
        header.writeUInt16BE(exchange.length + 3, 10);
        return Buffer.concat([header, exchange, Buffer.from([0])]);
      });
      packet = Buffer.concat([packet, ...answers]);
    }
    socket.emit("message", packet, { address: socket.server, port: 53 });
  }
  function closed() {
    for (const socket of sockets) {
      assert.equal(socket.closeCount, 1);
      for (const event of ["message", "error", "close"]) assert.equal(socket.listenerCount(event), 0);
      socket.callback(new Error("late send callback"));
      reply(socket);
      assert.equal(socket.closeCount, 1);
    }
  }
  return { sockets, reply, closed };
}

test("admission release is idempotent and retains only active clients", () => {
  empty();
  for (let index = 0; index < 1000; index++) {
    const release = admitDns(`client-${index}`);
    assert.equal(dnsResourceState().clients, 1);
    release(); release();
    empty();
  }
});

test("global/per-client admission fails fast before sockets; validation first; exhaustion recovers", async (t) => {
  const h = harness(t);
  const controllers = Array.from({ length: 6 }, () => new AbortController());
  const checks = controllers.map((controller, index) => checkDns(payload(`host${index}.example.com`), {
    clientIp: `client-${Math.floor(index / 2)}`, signal: controller.signal,
  }));
  const settled = Promise.allSettled(checks);
  assert.equal(h.sockets.length, 6);
  await assert.rejects(checkDns(payload("extra.example.com"), { clientIp: "other" }), { code: "DNS_CAPACITY_EXHAUSTED" });
  await assert.rejects(checkDns(payload("localhost")), { code: "INVALID_QUERY" });
  controllers[4].abort(); controllers[5].abort();
  await flush();
  await assert.rejects(checkDns(payload("extra.example.com"), { clientIp: "client-0" }), { code: "DNS_CAPACITY_EXHAUSTED" });
  const recovery = checkDns(payload("recovery.example.com"), { clientIp: "other" });
  h.reply(h.sockets.at(-1));
  assert.equal((await recovery).ok, true);
  controllers.forEach((controller) => controller.abort());
  assert.ok((await settled).every((result) => result.reason.code === "DNS_CHECK_CANCELLED"));
  h.closed(); empty();
});

test("success, resolver failure and rate rejection release admission", async (t) => {
  const h = harness(t);
  const good = checkDns(payload());
  h.reply(h.sockets[0]);
  await good; empty();
  const bad = checkDns(payload("bad.example.com"));
  h.sockets[1].emit("error", new Error("private failure"));
  assert.equal((await bad).status, "resolver-error");
  empty(); h.closed();
  for (let index = 0; index < 100; index++) {
    await checkDns(payload(`rate${index}.example.com`), { clientIp: "rate", queryDns: async () => response() });
  }
  await assert.rejects(checkDns(payload("rate-extra.example.com"), { clientIp: "rate" }), { code: "RATE_LIMITED" });
  empty();
});

test("six burst checks own at most 24 sockets, four per check; cancel pending sends and late packets", async (t) => {
  const h = harness(t);
  const controllers = Array.from({ length: 6 }, () => new AbortController());
  const checks = controllers.map((controller, index) => checkDns(payload(`burst${index}.example.com`, {
    mode: "burst", resolverId: undefined,
  }), { clientIp: `client${index}`, signal: controller.signal }));
  const settled = Promise.allSettled(checks);
  assert.equal(h.sockets.length, 24);
  assert.equal(dnsResourceState().sockets, 24);
  controllers.forEach((controller) => controller.abort());
  await settled;
  assert.equal(h.sockets.length, 24, "cancellation must not launch waiting providers");
  h.closed(); empty();
  controllers.forEach((controller) => assert.equal(getEventListeners(controller.signal, "abort").length, 0));
});

test("socket slots/admission remain owned until asynchronous close finishes", async (t) => {
  const h = harness(t, { delayedClose: true });
  const controller = new AbortController();
  const pending = checkDns(payload(), { signal: controller.signal });
  const settled = assert.rejects(pending, { code: "DNS_CHECK_CANCELLED" });
  controller.abort();
  await flush();
  assert.equal(dnsResourceState().sockets, 1);
  assert.equal(dnsResourceState().activeChecks, 1);
  h.sockets[0].emit("error", new Error("late close error"));
  h.sockets[0].emit("close");
  await settled;
  h.closed(); empty();
});

test("cancellation inside socket.send is race-safe and closes once", async (t) => {
  const controller = new AbortController();
  const h = harness(t, { onSend: () => controller.abort() });
  await assert.rejects(checkDns(payload(), { signal: controller.signal }), { code: "DNS_CHECK_CANCELLED" });
  assert.equal(h.sockets.length, 1);
  h.closed(); empty();
});

test("cancellation in final cleanup turn cannot insert a successful cache entry", async () => {
  resetDnsCheckState();
  const controller = new AbortController();
  let calls = 0;
  await assert.rejects(checkDns(payload(), {
    signal: controller.signal,
    queryDns: async () => response(),
    now: () => { if (++calls === 2) queueMicrotask(() => controller.abort()); return 1_000_000; },
  }), { code: "DNS_CHECK_CANCELLED" });
  empty();
  const result = await checkDns(payload(), { now: () => 1_000_000, queryDns: async () => response() });
  assert.equal(result.cache.fromCache, false);
  const aborted = new AbortController(); aborted.abort();
  await assert.rejects(checkDns(payload(), { now: () => 1_000_000, signal: aborted.signal }), { code: "DNS_CHECK_CANCELLED" });
  empty();
});

test("burst workers retain ten ordered providers and prioritize all primaries", async () => {
  resetDnsCheckState();
  let active = 0, maxActive = 0, primaries = 0, sends = 0;
  const result = await checkDns(payload("mx.example.com", { mode: "burst", resolverId: undefined, recordType: "MX" }), {
    queryDns: async (_server, name, type) => {
      sends++;
      active++; maxActive = Math.max(active, maxActive);
      if (type === "MX") primaries++;
      else assert.equal(primaries, 10);
      await flush(); active--;
      return response(type === "MX" ? mx(name) : []);
    },
  });
  assert.equal(maxActive, 4);
  assert.equal(sends, 70);
  assert.deepEqual(result.providers.map((provider) => provider.resolver.id), BURST_RESOLVER_IDS);
  assert.ok(result.providers.every((provider) => provider.records.length === 10));
  assert.ok(result.providers.every((provider) => provider.diagnostics.some((item) => item.id === "optional_diagnostics_incomplete")));
  empty();
});

test("production burst MX queues enrichment behind four sockets and cancellation clears waiting work", async (t) => {
  const h = harness(t);
  const controller = new AbortController();
  const pending = checkDns(payload("mx.example.com", { mode: "burst", resolverId: undefined, recordType: "MX" }), {
    signal: controller.signal,
  });
  const rejected = assert.rejects(pending, { code: "DNS_CHECK_CANCELLED" });
  for (let index = 0; index < 10; index++) {
    assert.ok(h.sockets[index]);
    h.reply(h.sockets[index], 10);
    await flush();
  }
  assert.equal(h.sockets.length, 14, "four active enrichment sockets, remaining work queued");
  assert.equal(dnsResourceState().sockets, 4);
  controller.abort();
  await rejected;
  assert.equal(h.sockets.length, 14, "queued enrichment never sends after cancellation");
  h.closed(); empty();
});

test("normal single MX plus DNSSEC fits 33 logical queries and preserves full ten-target enrichment", async () => {
  resetDnsCheckState();
  let sends = 0;
  const result = await checkDns(payload("mx.example.com", { recordType: "MX", dnssec: true }), {
    queryDns: async (_server, name, type) => { sends++; return response(type === "MX" ? mx(name) : []); },
  });
  assert.equal(sends, 33);
  assert.equal(result.diagnostics.filter((item) => item.id === "mx_host_resolution").length, 10);
  assert.equal(result.dnssec.deepChecksDisabled, false);
  assert.ok(!result.diagnostics.some((item) => item.id === "optional_diagnostics_incomplete"));
  empty();
});

for (const mode of ["single", "burst"]) {
  test(`${mode} worst-case MX fallback sends never exceed attempt budget`, async () => {
    resetDnsCheckState();
    let sends = 0, logical = 0;
    const result = await checkDns(payload(`${mode}.example.com`, {
      mode, resolverId: mode === "single" ? "cloudflare" : undefined, recordType: "MX", dnssec: true,
    }), { queryDns: async (server, name, type) => {
      sends++;
      if (type === "MX") { logical++; return response(mx(name, 50)); }
      if (["1.1.1.1", "8.8.8.8", "208.67.222.222", "9.9.9.9", "96.45.45.45", "94.140.14.14", "64.6.64.6", "84.200.69.80", "8.26.56.26", "4.2.2.1"].includes(server)) logical++;
      throw Object.assign(new Error("offline"), { code: "DNS_TIMEOUT" });
    } });
    assert.equal(sends, DNS_LIMITS[mode].attempts);
    assert.ok(logical <= DNS_LIMITS[mode].queries);
    const providers = mode === "single" ? [result] : result.providers;
    assert.ok(providers.every((provider) => provider.records.length === 50));
    assert.ok(providers.every((provider) => provider.diagnostics.some((item) => item.id === "optional_diagnostics_incomplete")));
    assert.ok(providers.every((provider) => !provider.warnings.some((warning) => warning.includes("does not resolve"))));
    empty();
  });

  test(`${mode} production UDP sends, including fallback, enforce exact attempt cap`, async (t) => {
    const h = harness(t);
    let done = false;
    const pending = checkDns(payload(`${mode}.example.com`, {
      mode, resolverId: mode === "single" ? "cloudflare" : undefined, recordType: "MX", dnssec: true,
    }));
    pending.then(() => { done = true; }, () => { done = true; });
    let processed = 0;
    let waves = 0;
    while (!done && waves++ < 1000) {
      for (const socket of h.sockets.slice(processed)) {
        processed++;
        let offset = 12;
        while (socket.packet[offset]) offset += socket.packet[offset] + 1;
        if (socket.packet.readUInt16BE(offset + 1) === 15) h.reply(socket, 50);
        else socket.emit("error", Object.assign(new Error("offline"), { code: "DNS_TIMEOUT" }));
      }
      await flush();
    }
    assert.equal(done, true);
    const result = await pending;
    assert.equal(h.sockets.length, DNS_LIMITS[mode].attempts);
    const providers = mode === "single" ? [result] : result.providers;
    assert.ok(providers.some((provider) => provider.warnings.some((warning) => warning.includes("work budget"))));
    assert.ok(providers.some((provider) => provider.diagnostics.some((item) => item.omittedQueries?.some((query) => query.reason === "work-budget"))));
    h.closed(); empty();
  });
}

test("logical query budgets and bounded/cancellable concurrency queue", async () => {
  const controller = new AbortController();
  const operation = createDnsOperation("single", { signal: controller.signal });
  for (let index = 0; index < DNS_LIMITS.single.queries; index++) operation.query();
  assert.throws(() => operation.query(), { code: "DNS_WORK_BUDGET_EXHAUSTED" });
  const active = Array.from({ length: 4 }, () => operation.run(() => new Promise((resolve, reject) => {
    operation.signal.addEventListener("abort", () => reject(operation.signal.reason), { once: true });
  })));
  let launched = 0;
  const queued = Array.from({ length: 12 }, () => operation.run(() => { launched++; }));
  assert.throws(() => operation.run(() => {}), { code: "DNS_WORK_BUDGET_EXHAUSTED" });
  const settled = Promise.allSettled([...active, ...queued]);
  controller.abort();
  assert.ok((await settled).every((result) => result.reason.code === "DNS_CHECK_CANCELLED"));
  assert.equal(launched, 0);
  await operation.dispose(); empty();
});

test("TXT/DMARC and DNSSEC fallback are bounded and omitted failures do not claim missing records", async () => {
  resetDnsCheckState();
  let sends = 0;
  const result = await checkDns(payload("txt.example.com", { recordType: "TXT", dnssec: true }), {
    queryDns: async (_server, name, type) => {
      sends++;
      if (name === "txt.example.com" && type === "TXT") return response();
      throw Object.assign(new Error("offline"), { code: "DNS_TIMEOUT" });
    },
  });
  assert.equal(sends, 13); // primary + four attempts each for DMARC, DS, DNSKEY
  assert.equal(result.dnssec.deepChecksDisabled, true);
  assert.ok(!result.warnings.some((warning) => warning.includes("No DMARC")));
  assert.ok(!result.diagnostics.some((item) => item.id === "dnssec_deep_checks"));
  empty();
});

test("overall monotonic deadline spans fallback and never refreshes; timed-out checks are not cached", async (t) => {
  const h = harness(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let clock = 0;
  const pending = checkDns(payload(), { deadlineMs: 5000, monotonic: () => clock });
  const rejected = assert.rejects(pending, { code: "DNS_DIAGNOSTIC_TIMEOUT" });
  clock = 3000; t.mock.timers.tick(3000); await flush();
  assert.equal(h.sockets.length, 2);
  clock = 4999; t.mock.timers.tick(1999);
  assert.equal(h.sockets[1].closeCount, 0);
  clock = 5000; t.mock.timers.tick(1);
  await rejected;
  h.closed(); empty();
  const recovery = checkDns(payload());
  h.reply(h.sockets.at(-1));
  assert.equal((await recovery).cache.fromCache, false);
  empty();
});

test("deadline rejects late success even before timer delivery", async () => {
  resetDnsCheckState();
  let clock = 0;
  await assert.rejects(checkDns(payload(), { monotonic: () => clock, queryDns: async () => {
    clock = 15_000; return response();
  } }), { code: "DNS_DIAGNOSTIC_TIMEOUT" });
  empty();
});

for (const mode of ["single", "burst"]) {
  test(`${mode} default overall deadline cancels active UDP and clears timers`, async (t) => {
    const h = harness(t);
    t.mock.timers.enable({ apis: ["setTimeout"] });
    const pending = checkDns(payload(`${mode}.example.com`, { mode, resolverId: mode === "single" ? "cloudflare" : undefined }));
    const rejected = assert.rejects(pending, { code: "DNS_DIAGNOSTIC_TIMEOUT" });
    t.mock.timers.tick(DNS_LIMITS[mode].deadlineMs);
    await rejected;
    h.closed(); empty();
    const count = h.sockets.length;
    t.mock.timers.tick(100_000);
    assert.equal(h.sockets.length, count);
    empty();
  });
}

test("cancellation during enrichment stops queries and prevents successful cache insertion", async (t) => {
  const h = harness(t);
  const controller = new AbortController();
  const pending = checkDns(payload("mx.example.com", { recordType: "MX" }), { signal: controller.signal });
  const rejected = assert.rejects(pending, { code: "DNS_CHECK_CANCELLED" });
  h.reply(h.sockets[0]);
  await flush();
  assert.equal(h.sockets.length, 3, "no-MX enrichment started");
  controller.abort();
  await rejected;
  h.closed(); empty();
  const recovery = await checkDns(payload("mx.example.com", { recordType: "MX" }), { queryDns: async () => response() });
  assert.equal(recovery.cache.fromCache, false);
  empty();
});

test("cache hits bypass full admission and rate charging; pre-abort consumes no live capacity", async (t) => {
  const h = harness(t);
  await checkDns(payload("cached.example.com"), { queryDns: async () => response() });
  const controllers = Array.from({ length: 6 }, () => new AbortController());
  const pending = controllers.map((controller, index) => checkDns(payload(`live${index}.example.com`), {
    clientIp: `client${index}`, signal: controller.signal,
  }));
  const settled = Promise.allSettled(pending);
  for (let index = 0; index < 120; index++) assert.equal((await checkDns(payload("cached.example.com"))).cache.fromCache, true);
  const cancelled = new AbortController(); cancelled.abort();
  await assert.rejects(checkDns(payload("cancelled.example.com"), { signal: cancelled.signal }), { code: "DNS_CHECK_CANCELLED" });
  assert.equal(h.sockets.length, 6);
  controllers.forEach((controller) => controller.abort());
  await settled; h.closed(); empty();
});

test("DNS route maps sanitized errors and preserves POST-body completion", async () => {
  const app = Fastify();
  let code = "DNS_CAPACITY_EXHAUSTED";
  registerDnsRoute(app, () => "client", async (_body, { signal }) => {
    assert.equal(signal.aborted, false);
    throw new DnsCheckError(code, "Safe message.");
  });
  try {
    for (const [error, status] of [["DNS_CAPACITY_EXHAUSTED", 503], ["DNS_DIAGNOSTIC_TIMEOUT", 504],
      ["DNS_CHECK_CANCELLED", 499], ["RATE_LIMITED", 429], ["INVALID_QUERY", 400]]) {
      code = error;
      const result = await app.inject({ method: "POST", url: "/api/tools/dns-check", payload: {} });
      assert.equal(result.statusCode, status);
      assert.deepEqual(result.json(), { ok: false, error: { code, message: "Safe message." } });
    }
  } finally { await app.close(); }
});

test("burst preserves individual resolver timeout results without converting them to overall expiration", async () => {
  resetDnsCheckState();
  const result = await checkDns(payload("burst.example.com", { mode: "burst", resolverId: undefined }), {
    queryDns: async (server) => {
      if (["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"].includes(server)) {
        throw Object.assign(new Error("offline"), { code: "DNS_TIMEOUT" });
      }
      return response();
    },
  });
  assert.equal(result.providers.length, 10);
  assert.equal(result.providers[0].status, "timeout");
  assert.equal(result.providers.filter((provider) => provider.ok).length, 9);
  empty();
});

test("DNS route removes lifecycle listeners, ignores ordinary close and suppresses even late success after abort", async () => {
  let handler;
  let complete;
  const app = { post: (_path, callback) => { handler = callback; } };
  let signal;
  registerDnsRoute(app, () => "client", (_body, options) => {
    signal = options.signal;
    return new Promise((resolve) => { complete = resolve; });
  });
  const request = { body: {}, raw: new EventEmitter() };
  const reply = { raw: new EventEmitter(), code: () => { throw new Error("must not respond"); } };
  const pending = handler(request, reply);
  request.raw.emit("close");
  assert.equal(signal.aborted, false);
  request.raw.emit("aborted");
  assert.equal(signal.aborted, true);
  complete({ ok: true });
  assert.equal(await pending, undefined);
  assert.equal(request.raw.listenerCount("aborted"), 0);
  assert.equal(reply.raw.listenerCount("close"), 0);
});

test("real Fastify loopback disconnect cancels live DNS and releases resources after a complete POST body", async (t) => {
  const h = harness(t);
  const app = Fastify();
  let started, finished;
  const start = new Promise((resolve) => { started = resolve; });
  const finish = new Promise((resolve) => { finished = resolve; });
  let signal;
  registerDnsRoute(app, () => "loopback", async (body, options) => {
    signal = options.signal;
    started();
    try { return await checkDns(body, options); }
    finally { finished(); }
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const request = http.request({ host: "127.0.0.1", port: app.server.address().port,
    path: "/api/tools/dns-check", method: "POST", headers: { "content-type": "application/json" },
  });
  request.on("error", () => {});
  try {
    request.end(JSON.stringify(payload()));
    await start;
    await flush();
    assert.equal(signal.aborted, false, "normal POST completion is not disconnect");
    assert.equal(h.sockets.length, 1);
    request.destroy();
    await finish;
    assert.equal(signal.aborted, true);
    h.closed(); empty();
    assert.equal(getEventListeners(signal, "abort").length, 0);
  } finally { request.destroy(); await app.close(); }
});
