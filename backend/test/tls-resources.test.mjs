import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter, getEventListeners, once } from "node:events";
import net from "node:net";
import tls from "node:tls";
import Fastify from "fastify";
import { createTlsChecker, TlsCheckError } from "../src/tools/tls-check.mjs";
import { TLS_BUDGETS } from "../src/tools/tls-network.mjs";
import { registerTlsRoute } from "../src/tls-route.mjs";

const input = { host: "www.example.com", port: 443 };
const public4 = ["8.8.8.1", "8.8.8.2", "8.8.8.3", "8.8.8.4", "8.8.8.5"];
const public6 = "2606:4700:4700::1111";
const flush = async () => { for (let i = 0; i < 40; i += 1) await Promise.resolve(); };
const observe = (promise) => promise.then((value) => ({ value }), (error) => ({ error }));
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

class Socket extends EventEmitter {
  destroyed = false;
  authorized = false;
  authorizationError = "SELF_SIGNED_CERT_IN_CHAIN";
  destroy() {
    if (this.destroyed) return;
    this.destroyed = true;
    queueMicrotask(() => this.emit("close"));
  }
  getCipher() { return { standardName: "TLS_AES_256_GCM_SHA384" }; }
  getProtocol() { return "TLSv1.3"; }
  getPeerCertificate() {
    const issuer = { subject: { CN: "Example CA" }, issuer: { CN: "Example CA" }, fingerprint256: "BB", ca: true };
    return {
      subject: { CN: input.host }, issuer: issuer.subject, subjectaltname: `DNS:${input.host}`,
      valid_from: "Jan 1 00:00:00 2026 GMT", valid_to: "Jan 1 00:00:00 2030 GMT",
      fingerprint256: "AA", issuerCertificate: issuer,
    };
  }
}

function harness({ v4 = public4.slice(0, 2), v6 = [], resolve4, resolve6, lookup,
  behavior = "stall", connect } = {}) {
  let time = 0;
  let dnsCalls = 0;
  let lookupCalls = 0;
  let cancels = 0;
  let peak = 0;
  const timers = new Map();
  const sockets = [];
  const options = [];
  const dependencies = {
    now: () => time,
    setTimer: (callback, duration) => {
      const id = Symbol();
      timers.set(id, { at: time + duration, callback });
      return id;
    },
    clearTimer: (id) => timers.delete(id),
    createResolver: () => ({
      resolve4: (host) => { dnsCalls += 1; return resolve4 ? resolve4(host) : Promise.resolve(v4); },
      resolve6: (host) => { dnsCalls += 1; return resolve6 ? resolve6(host) : Promise.resolve(v6); },
      cancel: () => { cancels += 1; },
    }),
    lookup: (...args) => { lookupCalls += 1; return lookup ? lookup(...args) : Promise.resolve([]); },
    connect: (opts) => {
      options.push(opts);
      const socket = connect ? connect(opts) : new Socket();
      sockets.push(socket);
      peak = Math.max(peak, sockets.filter((item) => !item.destroyed).length);
      if (behavior === "success") queueMicrotask(() => socket.emit("secureConnect"));
      if (behavior === "fail") queueMicrotask(() => socket.emit("error", new Error("private details")));
      return socket;
    },
  };
  return {
    check: createTlsChecker(dependencies), timers, sockets, options,
    get dnsCalls() { return dnsCalls; }, get lookupCalls() { return lookupCalls; },
    get cancels() { return cancels; }, get peak() { return peak; },
    jump(duration) { time += duration; },
    async advance(duration) {
      const target = time + duration;
      await flush();
      for (;;) {
        const next = [...timers].filter(([, timer]) => timer.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        if (!next) break;
        time = next[1].at;
        timers.delete(next[0]);
        next[1].callback();
        await flush();
      }
      time = target;
      await flush();
    },
    clean(signal) {
      assert.equal(timers.size, 0, "all owned timers cleared");
      assert.ok(sockets.every((socket) => socket.destroyed), "all sockets destroyed");
      assert.ok(sockets.every((socket) => socket.eventNames().length === 0), "socket listeners removed");
      if (signal) assert.equal(getEventListeners(signal, "abort").length, 0);
    },
  };
}

test("successful diagnostics preserve trust, hostname, certificate and issuer reporting; clear resources and release slots", async () => {
  const h = harness({ behavior: "success" });
  const controller = new AbortController();
  for (let i = 0; i < 4; i += 1) {
    const result = await h.check(input, { clientIp: "client", signal: controller.signal });
    assert.equal(result.ok, true);
    assert.deepEqual(result.resolvedAddresses, public4.slice(0, 2));
    assert.equal(result.tls.authorized, false);
    assert.equal(result.tls.authorizationError, "SELF_SIGNED_CERT_IN_CHAIN");
    assert.equal(result.tls.protocol, "TLSv1.3");
    assert.equal(result.tls.cipher, "TLS_AES_256_GCM_SHA384");
    assert.equal(result.summary.hostnameMatches, true);
    assert.equal(result.certificate.fingerprint256, "AA");
    assert.equal(result.serverProvidedCertificateCount, null);
    assert.deepEqual(result.issuerChain.map((entry) => entry.source), ["peer", "inferred"]);
    assert.ok(result.checks.length >= 5);
    assert.ok(result.warnings.some((warning) => warning.includes("signature strength is unknown")));
    h.clean(controller.signal);
  }
  assert.ok(h.options.every((opts) => opts.servername === input.host && opts.rejectUnauthorized === false));
  assert.ok(h.options.every((opts) => public4.includes(opts.host)));
});

test("a never-completing handshake is destroyed at seven seconds and releases admission", async () => {
  const h = harness({ v4: [public4[0]] });
  for (let i = 0; i < 3; i += 1) {
    const result = observe(h.check(input));
    await h.advance(6999);
    assert.equal(h.sockets.at(-1).destroyed, false);
    await h.advance(1);
    assert.equal((await result).error.code, "TLS_CONNECTION_FAILED");
    h.clean();
  }
});

test("DNS timeout cancels resolver, fallback has its own finite budget, late completions cannot connect", async () => {
  const dns = deferred();
  const fallback = deferred();
  const h = harness({ resolve4: () => dns.promise, resolve6: () => dns.promise, lookup: () => fallback.promise });
  const result = observe(h.check(input));
  await h.advance(3000);
  assert.equal(h.lookupCalls, 1);
  assert.ok(h.cancels > 0);
  await h.advance(3000);
  assert.equal((await result).error.code, "DNS_LOOKUP_FAILED");
  dns.resolve(public4);
  fallback.resolve(public4.map((address) => ({ address })));
  await flush();
  assert.equal(h.options.length, 0);
  h.clean();
});

test("a stalled DNS family does not discard the other family's successful addresses", async () => {
  const stalled = deferred();
  const h = harness({ v4: [], resolve6: () => stalled.promise, resolve4: () => Promise.resolve([public4[0]]), behavior: "success" });
  const result = observe(h.check(input));
  await h.advance(3000);
  assert.deepEqual((await result).value.resolvedAddresses, [public4[0]]);
  assert.equal(h.lookupCalls, 0);
  stalled.reject(new Error("late resolver cancellation"));
  await flush();
  h.clean();
});

test("successful system fallback uses validated dual-stack addresses within its remaining budget", async () => {
  const h = harness({ v4: [], lookup: () => Promise.resolve([{ address: "::1" }, { address: public6 }]), behavior: "success" });
  const result = await h.check(input);
  assert.deepEqual(result.resolvedAddresses, [public6]);
  assert.equal(h.lookupCalls, 1);
  assert.equal(h.options[0].host, public6);
  h.clean();
});

test("late DNS/fallback completions cannot beat the monotonic overall deadline even if timer delivery is delayed", async () => {
  for (const phase of ["dns", "fallback"]) {
    const pending = deferred();
    const h = harness(phase === "dns" ? { resolve4: () => pending.promise }
      : { v4: [], lookup: () => pending.promise });
    const result = observe(h.check(input));
    await flush();
    h.jump(15_000);
    pending.resolve(phase === "dns" ? public4 : public4.map((address) => ({ address })));
    assert.equal((await result).error.code, "TLS_DIAGNOSTIC_TIMEOUT");
    assert.equal(h.options.length, 0);
    h.clean();
  }
});

test("end-to-end deadline limits later waves to remaining time, destroys every socket and releases slots", async () => {
  const d4 = deferred();
  const d6 = deferred();
  const fallback = deferred();
  const h = harness({ resolve4: () => d4.promise, resolve6: () => d6.promise, lookup: () => fallback.promise });
  const controller = new AbortController();
  const result = observe(h.check(input, { signal: controller.signal }));
  await h.advance(3000);
  await h.advance(2000);
  fallback.resolve(public4.map((address) => ({ address })));
  await flush();
  assert.equal(h.options.length, 2);
  await h.advance(7000);
  assert.equal(h.options.length, 4);
  assert.equal(h.peak, 2);
  await h.advance(2999);
  assert.equal(h.sockets[2].destroyed, false);
  await h.advance(1);
  assert.equal((await result).error.code, "TLS_DIAGNOSTIC_TIMEOUT");
  h.clean(controller.signal);
  // New requests must be admitted after timeout, not leak a per-client slot.
  const retry = observe(h.check(input));
  await h.advance(15000);
  assert.notEqual((await retry).error.code, "TLS_CAPACITY_EXHAUSTED");
  h.clean();
});

test("dual-stack fallback succeeds, destroys stalled losers, never exceeds four addresses/two sockets", async () => {
  const h = harness({ v4: public4, v6: [public6] });
  const result = observe(h.check(input));
  await flush();
  assert.deepEqual(h.options.map((opts) => opts.host), [public4[0], public6]);
  h.sockets[0].emit("error", new Error("failure"));
  await flush();
  assert.equal(h.options.length, 3);
  h.sockets[1].emit("secureConnect");
  assert.ok(h.sockets.every((socket) => socket.destroyed), "losers destroyed immediately at secureConnect");
  assert.equal((await result).value.ok, true);
  assert.equal(h.peak, 2);
  assert.equal(h.options.length, 3);
  h.clean();

  const failed = harness({ v4: public4, v6: [public6], behavior: "fail" });
  await assert.rejects(failed.check(input), { code: "TLS_CONNECTION_FAILED" });
  assert.equal(failed.options.length, 4);
  assert.equal(failed.peak, 2);
  failed.clean();
});

test("global admission is eight, fails before DNS with no queue, and recovers after simultaneous cancellations", async () => {
  const h = harness();
  const controllers = Array.from({ length: 8 }, () => new AbortController());
  const pending = controllers.map((controller, index) => observe(h.check(input, {
    clientIp: `client-${index}`, signal: controller.signal,
  })));
  await flush();
  assert.equal(h.options.length, 16);
  assert.equal(h.peak, 16);
  const before = h.dnsCalls;
  await assert.rejects(h.check(input, { clientIp: "ninth" }), { code: "TLS_CAPACITY_EXHAUSTED" });
  assert.equal(h.dnsCalls, before);
  controllers.forEach((controller) => { controller.abort(); controller.abort(); });
  assert.ok((await Promise.all(pending)).every((result) => result.error.code === "TLS_CHECK_CANCELLED"));
  controllers.forEach((controller) => h.clean(controller.signal));
  const next = controllers.map((_, index) => new AbortController());
  const retries = next.map((controller, index) => observe(h.check(input, { clientIp: `new-${index}`, signal: controller.signal })));
  await flush();
  await assert.rejects(h.check(input, { clientIp: "new-ninth" }), { code: "TLS_CAPACITY_EXHAUSTED" });
  next.forEach((controller) => controller.abort());
  assert.ok((await Promise.all(retries)).every((result) => result.error.code === "TLS_CHECK_CANCELLED"));
  h.clean();
});

test("per-client admission is two; cancellation stops later attempts and releases exactly once", async () => {
  const h = harness({ v4: public4 });
  const controller = new AbortController();
  const first = observe(h.check(input, { signal: controller.signal }));
  const second = observe(h.check(input, { signal: controller.signal }));
  await flush();
  const before = h.dnsCalls;
  await assert.rejects(h.check(input), { code: "TLS_CAPACITY_EXHAUSTED" });
  assert.equal(h.dnsCalls, before);
  controller.abort();
  assert.equal((await first).error.code, "TLS_CHECK_CANCELLED");
  assert.equal((await second).error.code, "TLS_CHECK_CANCELLED");
  const attempts = h.options.length;
  // A queued late handshake is ignored after cleanup.
  h.sockets.forEach((socket) => socket.emit("secureConnect"));
  await h.advance(30_000);
  assert.equal(h.options.length, attempts);
  h.clean(controller.signal);
  const retryController = new AbortController();
  const retries = [0, 1].map(() => observe(h.check(input, { signal: retryController.signal })));
  await flush();
  await assert.rejects(h.check(input), { code: "TLS_CAPACITY_EXHAUSTED" });
  retryController.abort();
  assert.ok((await Promise.all(retries)).every((result) => result.error.code === "TLS_CHECK_CANCELLED"));
  h.clean(retryController.signal);
});

test("late handshake completion cannot return success when overall timer delivery is delayed", async () => {
  const h = harness();
  const result = observe(h.check(input));
  await flush();
  h.jump(TLS_BUDGETS.deadlineMs);
  h.sockets[0].emit("secureConnect");
  assert.equal((await result).error.code, "TLS_DIAGNOSTIC_TIMEOUT");
  assert.equal(h.options.length, 2);
  h.clean();
});

test("already-cancelled requests do not consume admission or rate history", async () => {
  const h = harness({ behavior: "success" });
  const controller = new AbortController();
  controller.abort();
  for (let i = 0; i < 21; i += 1) {
    await assert.rejects(h.check(input, { signal: controller.signal }), { code: "TLS_CHECK_CANCELLED" });
  }
  assert.equal(h.dnsCalls, 0);
  assert.equal((await h.check(input)).ok, true);
  h.clean(controller.signal);
});

test("rolling per-client rate limit rejects the 21st check and recovers exactly at expiry", async () => {
  const h = harness({ behavior: "fail" });
  for (let i = 0; i < 20; i += 1) await assert.rejects(h.check(input), { code: "TLS_CONNECTION_FAILED" });
  const before = h.dnsCalls;
  await assert.rejects(h.check(input), { code: "RATE_LIMITED" });
  await h.advance(59_999);
  await assert.rejects(h.check(input), { code: "RATE_LIMITED" });
  assert.equal(h.dnsCalls, before);
  await h.advance(1);
  await assert.rejects(h.check(input), { code: "TLS_CONNECTION_FAILED" });
  h.clean();
});

test("retained client state is capped and expires without evicting rate history", async () => {
  const h = harness({ behavior: "fail", v4: [public4[0]] });
  for (let i = 0; i < TLS_BUDGETS.clientEntries; i += 1) {
    await assert.rejects(h.check(input, { clientIp: `client-${i}` }), { code: "TLS_CONNECTION_FAILED" });
  }
  const before = h.dnsCalls;
  await assert.rejects(h.check(input, { clientIp: "extra" }), { code: "TLS_CAPACITY_EXHAUSTED" });
  assert.equal(h.dnsCalls, before);
  await h.advance(TLS_BUDGETS.rateWindowMs);
  await assert.rejects(h.check(input, { clientIp: "extra" }), { code: "TLS_CONNECTION_FAILED" });
  h.clean();
});

test("uncancellable fallback slots remain bounded after caller timeouts and recover only on underlying settlement", async () => {
  const fallback = deferred();
  const h = harness({ v4: [], lookup: () => fallback.promise });
  for (let i = 0; i < 8; i += 1) {
    const result = observe(h.check(input));
    await h.advance(3000);
    assert.equal((await result).error.code, "DNS_LOOKUP_FAILED");
  }
  await assert.rejects(h.check(input), { code: "TLS_CAPACITY_EXHAUSTED" });
  assert.equal(h.lookupCalls, 8);
  h.clean();
  fallback.resolve([{ address: public4[0] }]);
  await flush();
  assert.equal(h.options.length, 0);
  const result = observe(h.check(input));
  await h.advance(7000);
  assert.equal((await result).error.code, "TLS_CONNECTION_FAILED");
  assert.equal(h.lookupCalls, 9);
  h.clean();
});

test("cancelling pending DNS/fallback ignores late success, clears listeners/timers and restores admission", async () => {
  for (const phase of ["dns", "fallback"]) {
    const pending = deferred();
    const h = harness(phase === "dns" ? { resolve4: () => pending.promise }
      : { v4: [], lookup: () => pending.promise });
    const controller = new AbortController();
    const result = observe(h.check(input, { signal: controller.signal }));
    await flush();
    controller.abort();
    assert.equal((await result).error.code, "TLS_CHECK_CANCELLED");
    pending.resolve(phase === "dns" ? public4 : public4.map((address) => ({ address })));
    await flush();
    assert.equal(h.options.length, 0);
    h.clean(controller.signal);
  }
});

test("invalid input is rejected without consuming admission, DNS or sockets", async () => {
  const h = harness();
  for (const host of ["localhost", "127.0.0.1", "::1", "https://example.com", "bad", "-bad.example", "user@example.com"]) {
    await assert.rejects(h.check({ ...input, host }), { code: "INVALID_HOST" });
  }
  for (const port of [80, 22, 0, 443.1, "443"]) await assert.rejects(h.check({ ...input, port }), { code: "INVALID_PORT" });
  assert.equal(h.dnsCalls, 0);
  assert.equal(h.options.length, 0);
  h.clean();
});

test("blocked/reserved/mapped addresses are never connected, including after public transport failure", async () => {
  const blocked = ["127.0.0.1", "10.0.0.1", "192.0.2.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "fc00::1", "fe80::1", "2001:db8::1", "invalid"];
  const only = harness({ v4: blocked });
  await assert.rejects(only.check(input), { code: "BLOCKED_TARGET" });
  assert.equal(only.options.length, 0);
  only.clean();
  const mixed = harness({ v4: [...blocked, public4[0]], behavior: "fail" });
  await assert.rejects(mixed.check(input), { code: "TLS_CONNECTION_FAILED" });
  assert.deepEqual(mixed.options.map((opts) => opts.host), [public4[0]]);
  mixed.clean();
});

test("TLS route uses established identity and sanitized status contracts", async () => {
  const app = Fastify();
  const errors = [
    ["RATE_LIMITED", 429], ["TLS_CAPACITY_EXHAUSTED", 503], ["TLS_DIAGNOSTIC_TIMEOUT", 504],
    ["TLS_CONNECTION_FAILED", 502], ["INVALID_HOST", 400], ["DNS_LOOKUP_FAILED", 400],
  ];
  let code;
  registerTlsRoute(app, () => "trusted-identity", async (_, options) => {
    assert.equal(options.clientIp, "trusted-identity");
    if (code === "raw") throw new Error("private socket state");
    throw new TlsCheckError(code, "Safe failure.");
  });
  try {
    for (const [next, status] of errors) {
      code = next;
      const response = await app.inject({ method: "POST", url: "/api/tools/tls-check", payload: input });
      assert.equal(response.statusCode, status);
      assert.deepEqual(response.json(), { ok: false, error: { code, message: "Safe failure." } });
    }
    code = "raw";
    const response = await app.inject({ method: "POST", url: "/api/tools/tls-check", payload: input });
    assert.equal(response.statusCode, 502);
    assert.deepEqual(response.json(), { ok: false, error: { code: "TLS_CONNECTION_FAILED", message: "TLS connection failed." } });
  } finally { await app.close(); }
});

test("route ignores normal request close, cancels premature response close, removes lifecycle listeners", async () => {
  let handler;
  const raw = new EventEmitter();
  const response = new EventEmitter();
  const h = harness();
  let signal;
  registerTlsRoute({ post: (_, route) => { handler = route; } }, () => "client", (body, options) => {
    signal = options.signal;
    return h.check(body, options);
  });
  const pending = handler({ raw, body: input }, { raw: response });
  await flush();
  raw.emit("close");
  assert.equal(signal.aborted, false);
  response.emit("close");
  await pending;
  assert.equal(signal.aborted, true);
  assert.equal(raw.listenerCount("aborted"), 0);
  assert.equal(response.listenerCount("close"), 0);
  h.clean(signal);
});

test("incoming abort cancels the route, while normal response completion does not", async () => {
  for (const mode of ["incoming-abort", "normal-completion"]) {
    let handler;
    let signal;
    const raw = new EventEmitter();
    const response = new EventEmitter();
    const h = harness();
    registerTlsRoute({ post: (_, route) => { handler = route; } }, () => "client", (body, options) => {
      signal = options.signal;
      return h.check(body, options);
    });
    const pending = handler({ raw, body: input }, { raw: response });
    await flush();
    if (mode === "incoming-abort") raw.emit("aborted");
    else {
      response.writableFinished = true;
      response.emit("close");
      assert.equal(signal.aborted, false);
      h.sockets[0].emit("secureConnect");
    }
    await pending;
    assert.equal(signal.aborted, mode === "incoming-abort");
    assert.equal(raw.listenerCount("aborted"), 0);
    assert.equal(response.listenerCount("close"), 0);
    h.clean(signal);
  }
});

test("actual Fastify POST disconnect propagates cancellation after a fully received request body", async () => {
  const app = Fastify();
  const h = harness();
  const started = deferred();
  const finished = deferred();
  let signal;
  registerTlsRoute(app, () => "client", async (body, options) => {
    signal = options.signal;
    const pending = h.check(body, options);
    started.resolve();
    try { return await pending; } finally { finished.resolve(); }
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const client = net.connect(app.server.address().port, "127.0.0.1");
  client.on("error", () => {});
  try {
    await once(client, "connect");
    const body = JSON.stringify(input);
    client.write(`POST /api/tools/tls-check HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`);
    await started.promise;
    await flush();
    assert.equal(signal.aborted, false, "normal request body completion must not cancel diagnostic");
    client.destroy();
    await finished.promise;
    await flush();
    assert.equal(signal.aborted, true);
    h.clean(signal);
  } finally {
    client.destroy();
    await app.close();
  }
});

test("actual Node TLS socket stalled on local TCP server is destroyed on cancellation and handshake timeout", async () => {
  const accepted = new Set();
  const server = net.createServer((socket) => {
    accepted.add(socket);
    socket.on("error", () => {});
    socket.on("data", () => {});
    socket.once("close", () => accepted.delete(socket));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const outbound = [];
  const h = harness({ v4: [public4[0]], connect: (opts) => {
    assert.equal(opts.host, public4[0]);
    assert.equal(opts.servername, input.host);
    const socket = tls.connect({ ...opts, host: "127.0.0.1", port: server.address().port });
    outbound.push(socket);
    return socket;
  } });
  try {
    for (const mode of ["cancel", "timeout"]) {
      const controller = new AbortController();
      const connection = once(server, "connection");
      const pending = observe(h.check(input, { signal: controller.signal }));
      await connection;
      if (mode === "cancel") controller.abort();
      else await h.advance(7000);
      assert.equal((await pending).error.code, mode === "cancel" ? "TLS_CHECK_CANCELLED" : "TLS_CONNECTION_FAILED");
      assert.ok(outbound.every((socket) => socket.destroyed));
      assert.ok(outbound.every((socket) => socket.listenerCount("secureConnect") === 0));
      assert.equal(h.timers.size, 0);
      assert.equal(getEventListeners(controller.signal, "abort").length, 0);
    }
  } finally {
    accepted.forEach((socket) => socket.destroy());
    await new Promise((resolve) => server.close(resolve));
  }
});
