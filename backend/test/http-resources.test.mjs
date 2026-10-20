import assert from "node:assert/strict";
import test from "node:test";
import { EventEmitter, getEventListeners } from "node:events";
import http from "node:http";
import Fastify from "fastify";
import { registerHttpRoute } from "../src/http-route.mjs";
import { checkHttpHeader, requestHeaders, requestHeadersAddress, resetHttpHeaderCheckState, HttpHeaderCheckError } from "../src/tools/http-header-check.mjs";
import { HTTP_LIMITS, admitHttp, acquireHttpSocket, createHttpOperation, resolveHttpAddresses, httpResourceState } from "../src/tools/http-resources.mjs";

const safe = ["93.184.216.34", "1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4"];
const response = { status: 200, headers: [] };
const options = { resolveAddresses: async () => safe, requestUrl: async () => response };
const target = { target: "example.com", protocolMode: "http" };
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const tick = () => new Promise((resolve) => setImmediate(resolve));
function idle() { assert.deepEqual(httpResourceState(), { activeChecks: 0, clients: 0, sockets: 0, pendingLookups: 0 }); }

test("admission preserves twelve units, two requests per client and Both costs; release is idempotent", () => {
  idle();
  const releases = [];
  for (let i = 0; i < 6; i++) releases.push(admitHttp(`client-${i}`, 2));
  assert.equal(httpResourceState().activeChecks, 12);
  assert.throws(() => admitHttp("extra", 1), { code: "HTTP_CAPACITY_EXHAUSTED" });
  for (const release of releases) { release(); release(); }
  const one = admitHttp("same", 2), two = admitHttp("same", 2);
  assert.throws(() => admitHttp("same", 1), { code: "HTTP_CAPACITY_EXHAUSTED" });
  one(); two(); idle();
});

test("live check admission, cache bypass, concurrency and release on failure/cancellation", async () => {
  resetHttpHeaderCheckState();
  await checkHttpHeader(target, options);
  const controller = new AbortController();
  const dns = deferred();
  const live = [0, 1].map((i) => checkHttpHeader({ target: `live-${i}.example.com`, protocolMode: "both" }, {
    ...options, clientIp: "same", signal: controller.signal, resolveAddresses: () => dns.promise,
  }));
  const settled = Promise.allSettled(live);
  assert.equal(httpResourceState().activeChecks, 4);
  await assert.rejects(checkHttpHeader({ target: "extra.example.com" }, { ...options, clientIp: "same" }), { code: "HTTP_CAPACITY_EXHAUSTED" });
  const cached = await checkHttpHeader(target, { ...options, clientIp: "same" });
  assert.equal(cached.budget.tokensConsumed, 0);
  controller.abort();
  assert.ok((await settled).every((entry) => entry.reason.code === "HTTP_CHECK_CANCELLED"));
  dns.resolve(safe); await tick(); idle();
  await assert.rejects(checkHttpHeader({ target: "failed.example.com" }, {
    ...options, requestUrl: async () => { throw new Error("failure"); },
  }));
  idle();
  await checkHttpHeader({ target: "retry.example.com" }, options); idle();
});

test("six live Both diagnostics reserve twelve units before DNS; full admission still permits cached results", async () => {
  resetHttpHeaderCheckState();
  await checkHttpHeader(target, options);
  const controller = new AbortController();
  let resolutions = 0;
  const pending = Array.from({ length: 6 }, (_, i) => checkHttpHeader({ target: `both-${i}.example.com`, protocolMode: "both" }, {
    ...options, signal: controller.signal, clientIp: `client-${i}`,
    resolveAddresses: () => { resolutions++; return new Promise(() => {}); },
  }));
  const settled = Promise.allSettled(pending);
  assert.equal(httpResourceState().activeChecks, 12);
  assert.equal(resolutions, 6);
  await assert.rejects(checkHttpHeader({ target: "overflow.example.com" }, {
    ...options, resolveAddresses: () => assert.fail("Capacity rejection reached DNS"),
  }), { code: "HTTP_CAPACITY_EXHAUSTED" });
  assert.equal((await checkHttpHeader(target, options)).budget.tokensConsumed, 0);
  controller.abort(); await settled; idle();
});

test("existing target rate limit remains distinct from capacity", async () => {
  resetHttpHeaderCheckState();
  const failing = { ...options, requestUrl: async () => { throw new Error("no headers"); } };
  for (let i = 0; i < 30; i++) await assert.rejects(checkHttpHeader(target, failing));
  await assert.rejects(checkHttpHeader(target, options), { code: "RATE_LIMITED" });
  idle();
});

test("client five-minute/hourly and global five-minute rate limits retain their original boundaries", async () => {
  for (const [count, stepMs, uniqueClients] of [[80, 0, false], [500, 7000, false], [350, 0, true]]) {
    resetHttpHeaderCheckState();
    let now = 1_000_000;
    for (let i = 0; i < count; i++) {
      await checkHttpHeader({ target: `rate-${i}.example.com` }, {
        ...options, clientIp: uniqueClients ? `rate-client-${i}` : "rate-client", now: () => now,
      });
      now += stepMs;
    }
    await assert.rejects(checkHttpHeader({ target: "overflow.example.com" }, {
      ...options, clientIp: uniqueClients ? "new-client" : "rate-client", now: () => now,
    }), { code: "RATE_LIMITED" });
    assert.equal((await checkHttpHeader({ target: `rate-${count - 1}.example.com` }, {
      ...options, clientIp: uniqueClients ? "new-client" : "rate-client", now: () => now,
    })).budget.tokensConsumed, 0);
    idle();
  }
});

test("shared monotonic deadline spans redirects and Both; timed-out partial results never enter cache", async () => {
  for (const protocolMode of ["auto", "http", "https", "both"]) {
    resetHttpHeaderCheckState();
    let time = 0, calls = 0;
    await assert.rejects(checkHttpHeader({ ...target, protocolMode }, {
      ...options, monotonic: () => time, deadlineMs: 100,
      requestUrl: async () => {
        calls++;
        time += 60;
        return protocolMode === "both" ? response : { status: 302, headers: [{ name: "location", value: "/next" }] };
      },
    }), { code: "HTTP_DIAGNOSTIC_TIMEOUT" });
    assert.equal(calls, 2);
    const retry = await checkHttpHeader({ ...target, protocolMode }, options);
    assert.equal(retry.budget.cachedChecks, 0);
    idle();
  }
  assert.equal(HTTP_LIMITS.singleMs, 15_000);
  assert.equal(HTTP_LIMITS.bothMs, 25_000);
});

test("stalled DNS is independently cancelled; late results cannot start transport", async () => {
  for (const cancelled of [false, true]) {
    resetHttpHeaderCheckState();
    const controller = new AbortController();
    const late = deferred();
    let cancels = 0, requests = 0;
    const promise = checkHttpHeader(target, {
      deadlineMs: 20, signal: controller.signal,
      createResolver: () => ({ resolve4: () => late.promise, resolve6: () => late.promise, cancel: () => { cancels++; } }),
      lookup: () => assert.fail("Stalled DNS must not launch a late system lookup"),
      requestUrl: async () => { requests++; return response; },
    });
    if (cancelled) controller.abort();
    await assert.rejects(promise, { code: cancelled ? "HTTP_CHECK_CANCELLED" : "HTTP_DIAGNOSTIC_TIMEOUT" });
    late.resolve(safe); await tick();
    assert.ok(cancels >= 2); assert.equal(requests, 0); idle();
  }
});

test("system lookups retain independent capacity after cancellation and deadline until underlying completion", async () => {
  const late = deferred();
  let calls = 0;
  const dependencies = {
    createResolver: () => ({ resolve4: async () => [], resolve6: async () => [], cancel() {} }),
    lookup: () => { calls++; return late.promise; },
  };
  for (let i = 0; i < HTTP_LIMITS.pendingLookups; i++) {
    const controller = new AbortController();
    const operation = createHttpOperation("http", { deadlineMs: i ? 10_000 : 20, signal: controller.signal });
    const promise = resolveHttpAddresses("example.com", operation, dependencies);
    await tick();
    if (i) controller.abort();
    await assert.rejects(promise, { code: i ? "HTTP_CHECK_CANCELLED" : "HTTP_DIAGNOSTIC_TIMEOUT" });
    operation.dispose();
  }
  assert.equal(httpResourceState().pendingLookups, 12);
  const operation = createHttpOperation("http");
  await assert.rejects(resolveHttpAddresses("example.com", operation, dependencies), { code: "HTTP_CAPACITY_EXHAUSTED" });
  operation.dispose(); assert.equal(calls, 12);
  late.resolve([{ address: safe[0] }]); await tick(); idle();
});

test("DNS family timers are cleared on success and an empty IPv4 family does not discard IPv6", async () => {
  const operation = createHttpOperation("http");
  const value = await resolveHttpAddresses("example.com", operation, {
    createResolver: () => ({ resolve4: async () => [], resolve6: async () => ["2606:4700:4700::1111"], cancel() {} }),
    lookup: () => assert.fail("Unexpected fallback"),
  });
  assert.deepEqual(value, ["2606:4700:4700::1111"]);
  operation.dispose(); idle();
});

test("stalled family is cancelled at three seconds while IPv6 survives; successful-family timers cannot fire later", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const operation = createHttpOperation("http");
  let cancelled = 0;
  const pending = resolveHttpAddresses("example.com", operation, {
    createResolver: () => ({ resolve4: () => new Promise(() => {}), resolve6: async () => ["2606:4700:4700::1111"], cancel() { cancelled++; } }),
    lookup: () => assert.fail("A successful family must bypass fallback"),
  });
  await tick();
  assert.equal(cancelled, 1);
  t.mock.timers.tick(3000);
  assert.deepEqual(await pending, ["2606:4700:4700::1111"]);
  assert.equal(cancelled, 3);
  assert.equal(getEventListeners(operation.signal, "abort").length, 0);
  operation.dispose(); t.mock.timers.tick(25_000);
  assert.equal(operation.signal.aborted, false); idle();
});

test("system fallback wait is finite even before the overall deadline, and late rejection is handled", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const operation = createHttpOperation("http");
  let rejectLookup;
  const pending = resolveHttpAddresses("example.com", operation, {
    createResolver: () => ({ resolve4: async () => [], resolve6: async () => [], cancel() {} }),
    lookup: () => new Promise((_resolve, reject) => { rejectLookup = reject; }),
  });
  await tick(); t.mock.timers.tick(3000);
  await assert.rejects(pending, { code: "DNS_LOOKUP_FAILED" });
  assert.equal(httpResourceState().pendingLookups, 1);
  assert.equal(getEventListeners(operation.signal, "abort").length, 0);
  rejectLookup(new Error("late system error")); await tick();
  operation.dispose(); idle();
});

// Mock the transport, not public destination policy. All sockets own asynchronous
// close events, including cases where request close precedes socket close.
function mockTransport(t, behavior, closeGate) {
  const attempts = [];
  let concurrent = 0, maximum = 0;
  t.mock.method(http, "request", (opts, callback) => {
    const req = new EventEmitter(), socket = new EventEmitter();
    let destroyed = false;
    req.destroy = () => {
      if (destroyed) return;
      destroyed = true;
      queueMicrotask(() => req.emit("close"));
      Promise.resolve(closeGate?.promise).then(() => {
        concurrent--; socket.closed = true; socket.emit("close");
      });
    };
    socket.destroy = req.destroy;
    req.end = () => queueMicrotask(() => {
      attempts.push(opts); concurrent++; maximum = Math.max(maximum, concurrent);
      req.emit("socket", socket);
      behavior(req, callback, attempts.length);
    });
    return req;
  });
  return { attempts, maximum: () => maximum };
}

test("four distinct sequential attempts, full mixed-answer validation before cap", async (t) => {
  const mock = mockTransport(t, (req) => req.emit("error", Object.assign(new Error("refused"), { code: "ECONNREFUSED" })));
  await assert.rejects(requestHeaders(new URL("http://example.com"), { addresses: [...safe, safe[0]] }), { code: "CONNECTION_REFUSED" });
  assert.equal(mock.attempts.length, 4); assert.equal(mock.maximum(), 1); idle();
  await assert.rejects(requestHeaders(new URL("http://example.com"), { addresses: [...safe, "127.0.0.1"] }), { code: "BLOCKED_TARGET" });
  assert.equal(mock.attempts.length, 4);
});

test("four unreachable IPv4 answers do not crowd a reachable IPv6 answer out of fallback", async (t) => {
  const ipv6 = "2606:4700:4700::1111";
  const mock = mockTransport(t, (req, callback) => {
    if (mock.attempts.at(-1).host === ipv6) callback({ statusCode: 200, rawHeaders: [], destroy() {} });
    else req.emit("error", Object.assign(new Error("unreachable"), { code: "ECONNREFUSED" }));
  });
  const result = await requestHeaders(new URL("http://example.com"), { addresses: [...safe.slice(0, 4), ipv6] });
  assert.equal(result.status, 200);
  assert.deepEqual(mock.attempts.map((entry) => entry.host), [safe[0], ipv6]);
  assert.equal(mock.maximum(), 1); idle();
});

test("dual-stack selection preserves family order, deduplicates and enforces four sequential attempts", async (t) => {
  const ipv6 = ["2606:4700:4700::1111", "2001:4860:4860::8888", "2606:4700:4700::1001"];
  const mock = mockTransport(t, (req) => req.emit("error", Object.assign(new Error("unreachable"), { code: "ECONNREFUSED" })));
  await assert.rejects(requestHeaders(new URL("http://example.com"), {
    addresses: [ipv6[0], ...safe, ipv6[0], ...ipv6.slice(1), safe[0]],
  }), { code: "CONNECTION_REFUSED" });
  assert.deepEqual(mock.attempts.map((entry) => entry.host), [safe[0], ipv6[0], safe[1], ipv6[1]]);
  assert.equal(mock.maximum(), 1); idle();
});

test("single-family answers and uneven dual-stack answers retain order and fill remaining slots", async (t) => {
  const ipv6 = ["2606:4700:4700::1111", "2001:4860:4860::8888", "2606:4700:4700::1001", "2001:4860:4860::8844", "2606:4700::1111"];
  for (const [addresses, expected] of [
    [safe, safe.slice(0, 4)],
    [ipv6, ipv6.slice(0, 4)],
    [[...safe, ipv6[0]], [safe[0], ipv6[0], safe[1], safe[2]]],
    [[safe[0], ...ipv6], [safe[0], ipv6[0], ipv6[1], ipv6[2]]],
  ]) {
    await t.test(expected.join(", "), async (t) => {
      const mock = mockTransport(t, (req, callback, count) => {
        if (count === 4) callback({ statusCode: 200, rawHeaders: [], destroy() {} });
        else req.emit("error", Object.assign(new Error("unreachable"), { code: "ECONNREFUSED" }));
      });
      assert.equal((await requestHeaders(new URL("http://example.com"), { addresses })).status, 200);
      assert.deepEqual(mock.attempts.map((entry) => entry.host), expected);
      assert.equal(mock.maximum(), 1); idle();
    });
  }
});

test("dual-stack mixed safe/blocked answers are rejected before selection even beyond the first four", async (t) => {
  for (const blocked of ["127.0.0.1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"]) {
    await t.test(blocked, async (t) => {
      const mock = mockTransport(t, () => assert.fail("Blocked answer set reached transport"));
      await assert.rejects(requestHeaders(new URL("http://example.com"), {
        addresses: [...safe, "2606:4700:4700::1111", blocked],
      }), { code: "BLOCKED_TARGET" });
      assert.equal(mock.attempts.length, 0); idle();
    });
  }
});

test("initial and redirected hops use the same sequential dual-stack selection and close each socket", async (t) => {
  resetHttpHeaderCheckState();
  const ipv6 = ["2606:4700:4700::1111", "2001:4860:4860::8888"];
  const resolved = [];
  const mock = mockTransport(t, (req, callback, count) => {
    if (count % 4) req.emit("error", Object.assign(new Error("unreachable"), { code: "ECONNREFUSED" }));
    else callback({ statusCode: count === 4 ? 302 : 200,
      rawHeaders: count === 4 ? ["Location", "http://next.example.com/done"] : [], destroy() {} });
  });
  const result = await checkHttpHeader(target, { resolveAddresses: async (host) => {
    resolved.push(host); return [...safe, ...ipv6];
  } });
  assert.equal(result.ok, true);
  assert.equal(result.checks[0].redirectsFollowed, 1);
  assert.equal(result.checks[0].finalCheckedUrl, "http://next.example.com/done");
  assert.deepEqual(resolved, ["example.com", "next.example.com"]);
  assert.deepEqual(mock.attempts.map((entry) => entry.host), [safe[0], ipv6[0], safe[1], ipv6[1], safe[0], ipv6[0], safe[1], ipv6[1]]);
  assert.deepEqual(mock.attempts.map((entry) => entry.headers.Host), [
    ...Array(4).fill("example.com"), ...Array(4).fill("next.example.com"),
  ]);
  assert.equal(mock.maximum(), 1); idle();
});

test("active and closing sockets capped at twelve, success waits for close and holds admission", async (t) => {
  resetHttpHeaderCheckState();
  const gate = deferred();
  mockTransport(t, (_req, callback) => callback({ statusCode: 200, rawHeaders: [], destroy() {} }), gate);
  const promise = checkHttpHeader(target, { resolveAddresses: async () => safe });
  await tick();
  assert.equal(httpResourceState().sockets, 1); assert.equal(httpResourceState().activeChecks, 1);
  const slots = Array.from({ length: 11 }, () => acquireHttpSocket());
  assert.throws(acquireHttpSocket, { code: "HTTP_CAPACITY_EXHAUSTED" });
  gate.resolve(); await promise;
  for (const release of slots) { release(); release(); }
  idle();
});

test("stalled response headers: deadline/cancellation destroys request; no address fallback or cache write", async (t) => {
  for (const cancel of [false, true]) {
    await t.test(String(cancel), async (t) => {
      resetHttpHeaderCheckState();
      const controller = new AbortController(), gate = deferred();
      const mock = mockTransport(t, () => {}, gate);
      const promise = checkHttpHeader(target, { signal: controller.signal, deadlineMs: 20, resolveAddresses: async () => safe });
      const rejection = assert.rejects(promise, { code: cancel ? "HTTP_CHECK_CANCELLED" : "HTTP_DIAGNOSTIC_TIMEOUT" });
      await tick();
      if (cancel) controller.abort();
      else await new Promise((resolve) => setTimeout(resolve, 30));
      assert.equal(httpResourceState().activeChecks, 1); assert.equal(httpResourceState().sockets, 1);
      gate.resolve(); await rejection;
      assert.equal(mock.attempts.length, 1); idle();
      assert.equal((await checkHttpHeader(target, options)).budget.cachedChecks, 0);
    });
  }
});

test("attempt fallback uses remaining deadline, not a new full timeout", async (t) => {
  resetHttpHeaderCheckState();
  let time = 0;
  const mock = mockTransport(t, (req) => { time += 6000; req.emit("error", Object.assign(new Error("refused"), { code: "ECONNREFUSED" })); });
  await assert.rejects(checkHttpHeader(target, { deadlineMs: 15_000, monotonic: () => time, resolveAddresses: async () => safe }), { code: "HTTP_DIAGNOSTIC_TIMEOUT" });
  assert.deepEqual(mock.attempts.map((entry) => entry.timeout), [7000, 7000, 3000]);
  assert.equal(mock.maximum(), 1); idle();
});

test("cancel during redirect DNS prevents another hop and does not turn cancellation into a blocked redirect", async () => {
  resetHttpHeaderCheckState();
  const controller = new AbortController();
  let resolves = 0, requests = 0;
  await assert.rejects(checkHttpHeader(target, {
    signal: controller.signal,
    resolveAddresses: async () => { if (++resolves === 2) controller.abort(); return safe; },
    requestUrl: async () => { requests++; return { status: 302, headers: [{ name: "location", value: "/next" }] }; },
  }), { code: "HTTP_CHECK_CANCELLED" });
  assert.equal(requests, 1); idle();
});

test("cancellation after the first Both success prevents partial cache writes, even with a late injected response", async () => {
  resetHttpHeaderCheckState();
  const controller = new AbortController();
  let calls = 0;
  await assert.rejects(checkHttpHeader({ ...target, protocolMode: "both" }, {
    ...options, signal: controller.signal,
    requestUrl: async () => { if (++calls === 2) controller.abort(); return response; },
  }), { code: "HTTP_CHECK_CANCELLED" });
  assert.equal((await checkHttpHeader({ ...target, protocolMode: "both" }, options)).budget.cachedChecks, 0);
  assert.equal(getEventListeners(controller.signal, "abort").length, 0); idle();
});

test("ordinary second-protocol failure preserves existing reuse of the first successful protocol", async () => {
  resetHttpHeaderCheckState();
  await assert.rejects(checkHttpHeader({ ...target, protocolMode: "both" }, {
    ...options, requestUrl: async (url) => {
      if (url.protocol === "https:") throw new HttpHeaderCheckError("CONNECTION_REFUSED", "Connection refused by the website.");
      return response;
    },
  }), { code: "CONNECTION_REFUSED" });
  const retry = await checkHttpHeader({ ...target, protocolMode: "both" }, options);
  assert.equal(retry.budget.cachedChecks, 1);
  assert.equal(retry.budget.tokensConsumed, 1); idle();
});

test("actual loopback HTTP transport closes sockets on headers, stalled headers, and cancellation", async (t) => {
  const seen = [];
  const server = http.createServer((req, res) => {
    seen.push(req.headers.host);
    if (req.url === "/ok") { res.writeHead(200, { "x-test": "headers-only" }); res.flushHeaders(); }
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); return new Promise((resolve) => server.close(resolve)); });
  const port = server.address().port;
  // Internal low-level transport seam only; API validation cannot select loopback.
  const result = await requestHeadersAddress(new URL(`http://example.com:${port}/ok`), "127.0.0.1", 1000);
  assert.equal(result.status, 200); idle();
  await assert.rejects(requestHeadersAddress(new URL(`http://example.com:${port}/stall`), "127.0.0.1", 20), { code: "REQUEST_TIMEOUT" }); idle();
  const controller = new AbortController();
  const operation = createHttpOperation("http", { signal: controller.signal });
  const pending = requestHeadersAddress(new URL(`http://example.com:${port}/stall`), "127.0.0.1", 1000, { signal: operation.signal });
  const rejection = assert.rejects(pending, { code: "HTTP_CHECK_CANCELLED" });
  await tick(); controller.abort(); await rejection; operation.dispose(); idle();
  assert.ok(seen.every((host) => host === `example.com:${port}`));
});

test("connection failure without a socket cannot deadlock resource release", async (t) => {
  t.mock.method(http, "request", () => { throw Object.assign(new Error("sync failure"), { code: "ECONNREFUSED" }); });
  await assert.rejects(requestHeaders(new URL("http://example.com"), { addresses: safe }), { code: "CONNECTION_REFUSED" }); idle();
});

test("error before socket assignment releases on request close and clears all request/abort listeners", async (t) => {
  let req;
  t.mock.method(http, "request", () => {
    req = new EventEmitter();
    req.end = () => queueMicrotask(() => req.emit("error", Object.assign(new Error("refused"), { code: "ECONNREFUSED" })));
    req.destroy = () => queueMicrotask(() => req.emit("close"));
    return req;
  });
  const operation = createHttpOperation("http");
  await assert.rejects(requestHeadersAddress(new URL("http://example.com"), safe[0], 1000, { signal: operation.signal }), { code: "ECONNREFUSED" });
  assert.deepEqual(req.eventNames(), []);
  assert.equal(getEventListeners(operation.signal, "abort").length, 0);
  operation.dispose(); idle();
});

test("oversized response headers fail safely and close the actual loopback socket", async (t) => {
  const server = http.createServer((_req, res) => { res.writeHead(200, { "x-large": "x".repeat(17 * 1024) }); res.end(); });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(requestHeadersAddress(new URL(`http://example.com:${server.address().port}`), "127.0.0.1", 1000), { code: "HPE_HEADER_OVERFLOW" });
  idle();
});

test("route handles request abort, normal response close and late success without leaked lifecycle listeners", async () => {
  let handler;
  registerHttpRoute({ post(_path, callback) { handler = callback; } }, () => "test", async (_payload, { signal }) => {
    await tick(); return { ok: !signal.aborted };
  });
  for (const event of ["normal", "aborted", "disconnect"]) {
    const raw = new EventEmitter(), responseRaw = new EventEmitter();
    responseRaw.writableFinished = event === "normal";
    const result = handler({ raw, body: target }, { raw: responseRaw });
    if (event === "aborted") raw.emit("aborted"); else responseRaw.emit("close");
    assert.deepEqual(await result, event === "normal" ? { ok: true } : undefined);
    assert.deepEqual(raw.eventNames(), []); assert.deepEqual(responseRaw.eventNames(), []);
  }
});

test("Fastify safe status mappings and normal POST completion do not cancel", async (t) => {
  const app = Fastify(); t.after(() => app.close());
  let code;
  registerHttpRoute(app, () => "test", async (_payload, { signal }) => {
    await tick(); assert.equal(signal.aborted, false);
    if (code === "raw") throw new Error("sensitive socket detail");
    if (code) throw new HttpHeaderCheckError(code, "Safe message.");
    return { ok: true };
  });
  for (const [error, status] of [[undefined, 200], ["RATE_LIMITED", 429], ["HTTP_CAPACITY_EXHAUSTED", 503], ["HTTP_DIAGNOSTIC_TIMEOUT", 504], ["INVALID_PORT", 400], ["CONNECTION_REFUSED", 502], ["HTTP_CHECK_CANCELLED", 499], ["raw", 502]]) {
    code = error;
    const result = await app.inject({ method: "POST", url: "/api/tools/http-header-check", payload: target });
    assert.equal(result.statusCode, status);
    assert.equal(result.body.includes("sensitive"), false);
    if (error) assert.equal(result.json().error.code, error === "raw" ? "HTTP_HEADER_CHECK_FAILED" : error);
  }
});

test("actual Fastify loopback disconnect cancels diagnostic and releases admission without sending", async (t) => {
  resetHttpHeaderCheckState();
  const app = Fastify(); t.after(() => app.close());
  const entered = deferred(), finished = deferred();
  let observed;
  registerHttpRoute(app, () => "loopback", async (payload, routeOptions) => {
    try {
      return await checkHttpHeader(payload, { ...routeOptions, resolveAddresses: (_host, { signal }) => {
        observed = signal; entered.resolve(); return new Promise(() => {});
      } });
    } finally { finished.resolve(); }
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const req = http.request({ host: "127.0.0.1", port: app.server.address().port, path: "/api/tools/http-header-check", method: "POST", headers: { "content-type": "application/json" } }, () => assert.fail("Response after disconnect"));
  req.on("error", () => {}); req.end(JSON.stringify(target));
  await entered.promise; assert.equal(observed.aborted, false); req.destroy();
  await finished.promise; assert.equal(observed.aborted, true); idle();
});

test("actual Fastify disconnect destroys an in-flight HTTP socket and permits a successful retry", async (t) => {
  resetHttpHeaderCheckState();
  const reached = deferred(), finished = deferred();
  let serveHeaders = false;
  const outbound = http.createServer((_req, res) => {
    reached.resolve();
    if (serveHeaders) { res.writeHead(200, { "x-test": "retry" }); res.flushHeaders(); }
  });
  await new Promise((resolve) => outbound.listen(0, "127.0.0.1", resolve));
  t.after(() => { outbound.closeAllConnections(); return new Promise((resolve) => outbound.close(resolve)); });
  const originalRequest = http.request;
  // Rewrite only the already-validated outbound transport in this offline test.
  // Neither route payload nor production code can select this loopback endpoint.
  t.mock.method(http, "request", (opts, callback) => originalRequest(
    opts.host === safe[0] ? { ...opts, host: "127.0.0.1", port: outbound.address().port } : opts, callback,
  ));
  const app = Fastify(); t.after(() => app.close());
  registerHttpRoute(app, () => "loopback", async (payload, routeOptions) => {
    try { return await checkHttpHeader(payload, { ...routeOptions, resolveAddresses: async () => [safe[0]] }); }
    finally { finished.resolve(); }
  });
  await app.listen({ host: "127.0.0.1", port: 0 });
  const req = http.request({ host: "127.0.0.1", port: app.server.address().port,
    path: "/api/tools/http-header-check", method: "POST", headers: { "content-type": "application/json" } },
  () => assert.fail("Unexpected disconnected response"));
  req.on("error", () => {}); req.end(JSON.stringify(target));
  await reached.promise;
  assert.equal(httpResourceState().sockets, 1);
  req.destroy(); await finished.promise; idle();
  serveHeaders = true;
  const retry = await app.inject({ method: "POST", url: "/api/tools/http-header-check", payload: target });
  assert.equal(retry.statusCode, 200);
  assert.equal(retry.json().budget.cachedChecks, 0);
  assert.equal(retry.json().checks[0].status, 200); idle();
});
