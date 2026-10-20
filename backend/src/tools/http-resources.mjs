import dns from "node:dns/promises";
import { performance } from "node:perf_hooks";

export const HTTP_LIMITS = Object.freeze({
  activeChecks: 12, perClient: 2, sockets: 12, addresses: 4,
  pendingLookups: 12, dnsMs: 3000, attemptMs: 7000,
  singleMs: 15_000, bothMs: 25_000,
});

export class HttpHeaderCheckError extends Error {
  constructor(code, message, options = {}) {
    super(message, options);
    this.name = "HttpHeaderCheckError";
    this.code = code;
    this.safeMessage = message;
  }
}

export const httpCapacityError = () => new HttpHeaderCheckError("HTTP_CAPACITY_EXHAUSTED", "HTTP header checks are busy. Try again later.");
const cancelledError = () => new HttpHeaderCheckError("HTTP_CHECK_CANCELLED", "HTTP header check was cancelled.");
const timeoutError = () => new HttpHeaderCheckError("HTTP_DIAGNOSTIC_TIMEOUT", "HTTP header diagnostic timed out.");
const dnsError = () => new HttpHeaderCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
const clients = new Map();
let activeChecks = 0;
let sockets = 0;
let pendingLookups = 0;

export function httpResourceState() {
  return { activeChecks, clients: clients.size, sockets, pendingLookups };
}

export function admitHttp(client, cost) {
  if (!cost) return () => {};
  const count = clients.get(client) || 0;
  if (activeChecks + cost > HTTP_LIMITS.activeChecks || count >= HTTP_LIMITS.perClient) throw httpCapacityError();
  activeChecks += cost;
  clients.set(client, count + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeChecks -= cost;
    const remaining = clients.get(client) - 1;
    if (remaining) clients.set(client, remaining);
    else clients.delete(client);
  };
}

export function acquireHttpSocket() {
  if (sockets >= HTTP_LIMITS.sockets) throw httpCapacityError();
  sockets += 1;
  let released = false;
  return () => { if (!released) { released = true; sockets -= 1; } };
}

// Options are internal injection seams, never read from an API payload.
export function createHttpOperation(mode, options = {}) {
  const monotonic = options.monotonic || (() => performance.now());
  const duration = options.deadlineMs ?? (mode === "both" ? HTTP_LIMITS.bothMs : HTTP_LIMITS.singleMs);
  const deadline = monotonic() + duration;
  const controller = new AbortController();
  const signal = controller.signal;
  const cancel = () => controller.abort(cancelledError());
  const expire = () => controller.abort(timeoutError());
  const timer = setTimeout(expire, duration);
  options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) cancel();
  function assertLive() {
    if (!signal.aborted && monotonic() >= deadline) expire();
    if (signal.aborted) throw signal.reason;
  }
  function timeoutMs(maximum) {
    assertLive();
    return Math.max(1, Math.min(maximum, deadline - monotonic()));
  }
  // Cancel supported underlying work before settling. Attach both completion
  // handlers so even an uncancellable system lookup's late rejection is owned.
  function wait(promise, maximum, stop = () => {}) {
    return new Promise((resolve, reject) => {
      let settled = false;
      let localTimer;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(localTimer);
        signal.removeEventListener("abort", abort);
        if (error) reject(error); else resolve(value);
      };
      const abort = () => { stop(); finish(signal.reason); };
      Promise.resolve(promise).then((value) => {
        try { assertLive(); finish(null, value); } catch (error) { finish(error); }
      }, (error) => finish(error));
      signal.addEventListener("abort", abort, { once: true });
      try {
        assertLive();
        const deadlineLimited = maximum >= deadline - monotonic();
        if (Number.isFinite(maximum)) localTimer = setTimeout(() => {
          stop();
          if (deadlineLimited) expire();
          try { assertLive(); finish(dnsError()); } catch (error) { finish(error); }
        }, Math.ceil(timeoutMs(maximum)));
      } catch (error) { stop(); finish(error); }
    });
  }
  return {
    signal, assertLive, timeoutMs, wait,
    dispose() {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", cancel);
    },
  };
}

export async function resolveHttpAddresses(host, operation, options = {}) {
  const createResolver = options.createResolver || (() => new dns.Resolver());
  const lookup = options.lookup || dns.lookup;
  const family = async (method) => {
    operation.assertLive();
    const resolver = createResolver();
    try {
      return await operation.wait(resolver[method](host), HTTP_LIMITS.dnsMs, () => resolver.cancel());
    } catch {
      operation.assertLive();
      return [];
    } finally { resolver.cancel(); }
  };
  const addresses = (await Promise.all([family("resolve4"), family("resolve6")])).flat();
  operation.assertLive();
  if (addresses.length) return addresses;
  if (pendingLookups >= HTTP_LIMITS.pendingLookups) throw httpCapacityError();
  pendingLookups += 1;
  const pending = Promise.resolve().then(() => {
    operation.assertLive();
    return lookup(host, { all: true });
  }).finally(() => { pendingLookups -= 1; });
  try {
    const records = await operation.wait(pending, HTTP_LIMITS.dnsMs);
    operation.assertLive();
    return records.map((record) => record.address);
  } catch (error) {
    operation.assertLive();
    throw error instanceof HttpHeaderCheckError ? error : dnsError();
  }
}
