import { performance } from "node:perf_hooks";
import { setMaxListeners } from "node:events";

export const DNS_LIMITS = Object.freeze({
  activeChecks: 6, checksPerClient: 2, sockets: 24, socketsPerCheck: 4,
  providers: 4, queuedPerCheck: 12,
  single: Object.freeze({ queries: 33, attempts: 64, deadlineMs: 15_000 }),
  burst: Object.freeze({ queries: 70, attempts: 128, deadlineMs: 30_000 }),
});

export class DnsCheckError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "DnsCheckError";
    this.code = code;
    this.safeMessage = message;
  }
}

const clients = new Map();
let activeChecks = 0;
let sockets = 0;

export function dnsResourceState() {
  return { activeChecks, clients: clients.size, sockets };
}

export function admitDns(client) {
  const count = clients.get(client) || 0;
  if (activeChecks >= DNS_LIMITS.activeChecks || count >= DNS_LIMITS.checksPerClient) {
    throw new DnsCheckError("DNS_CAPACITY_EXHAUSTED", "DNS checks are busy. Please try again later.");
  }
  activeChecks += 1;
  clients.set(client, count + 1);
  let released = false;
  return () => {
    if (released) return;
    released = true;
    activeChecks -= 1;
    const remaining = clients.get(client) - 1;
    if (remaining) clients.set(client, remaining);
    else clients.delete(client);
  };
}

export function createDnsOperation(mode, options = {}) {
  const limits = DNS_LIMITS[mode];
  const monotonic = options.monotonic || (() => performance.now());
  const deadlineMs = options.deadlineMs ?? limits.deadlineMs; // Internal test injection only.
  const deadline = monotonic() + deadlineMs;
  const controller = new AbortController();
  const signal = controller.signal;
  // At most four transports and twelve queued entries own abort listeners.
  setMaxListeners(DNS_LIMITS.socketsPerCheck + DNS_LIMITS.queuedPerCheck, signal);
  let queries = 0;
  let attempts = 0;
  let active = 0;
  const queue = [];
  const pending = new Set();
  const cancel = () => controller.abort(new DnsCheckError("DNS_CHECK_CANCELLED", "DNS check was cancelled."));
  const expire = () => controller.abort(new DnsCheckError("DNS_DIAGNOSTIC_TIMEOUT", "DNS diagnostic timed out."));
  const timer = setTimeout(expire, deadlineMs);
  options.signal?.addEventListener("abort", cancel, { once: true });
  if (options.signal?.aborted) cancel();

  function assertLive() {
    if (!signal.aborted && monotonic() >= deadline) expire();
    if (signal.aborted) throw signal.reason;
  }

  function budgetError() {
    return new DnsCheckError("DNS_WORK_BUDGET_EXHAUSTED", "Optional DNS diagnostics were omitted because the work budget was exhausted.");
  }

  // Six admitted checks * four sockets = 24. No separate global wait queue is
  // needed: each check owns at most four slots, including asynchronous close.
  function run(task) {
    assertLive();
    if (active < DNS_LIMITS.socketsPerCheck && sockets < DNS_LIMITS.sockets) return launch(task);
    if (queue.length >= DNS_LIMITS.queuedPerCheck) throw budgetError();
    return new Promise((resolve, reject) => {
      const entry = { task, resolve, reject, aborted: null };
      entry.aborted = () => {
        const index = queue.indexOf(entry);
        if (index !== -1) queue.splice(index, 1);
        reject(signal.reason);
      };
      signal.addEventListener("abort", entry.aborted, { once: true });
      queue.push(entry);
    });
  }

  function drain() {
    while (queue.length && active < DNS_LIMITS.socketsPerCheck && sockets < DNS_LIMITS.sockets && !signal.aborted) {
      const entry = queue.shift();
      signal.removeEventListener("abort", entry.aborted);
      try { launch(entry.task).then(entry.resolve, entry.reject); }
      catch (error) { entry.reject(error); }
    }
  }

  function launch(task) {
    assertLive();
    active += 1;
    sockets += 1;
    let result;
    try { result = task(); } catch (error) { result = Promise.reject(error); }
    const promise = Promise.resolve(result).finally(() => {
      active -= 1;
      sockets -= 1;
      pending.delete(promise);
      drain();
    });
    pending.add(promise);
    return promise;
  }

  return {
    signal, assertLive, run,
    query() { assertLive(); if (queries >= limits.queries) throw budgetError(); queries += 1; },
    checkAttempt() { assertLive(); if (attempts >= limits.attempts) throw budgetError(); },
    attempt() { assertLive(); if (attempts >= limits.attempts) throw budgetError(); attempts += 1; },
    timeoutMs() {
      assertLive();
      const remaining = deadline - monotonic();
      if (remaining <= 0) { expire(); throw signal.reason; }
      return Math.min(3000, remaining);
    },
    async dispose() {
      await Promise.allSettled([...pending]);
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", cancel);
    },
  };
}

export async function mapDnsWorkers(items, callback) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(DNS_LIMITS.providers, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await callback(items[index], index);
    }
  });
  const settled = await Promise.allSettled(workers);
  const failed = settled.find((result) => result.status === "rejected");
  if (failed) throw failed.reason;
  return results;
}
