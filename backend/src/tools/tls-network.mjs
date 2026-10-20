import dns from "node:dns/promises";
import tls from "node:tls";
import { performance } from "node:perf_hooks";

// Process-local budgets: no queue, at most 16 outbound TLS sockets process-wide.
export const TLS_BUDGETS = Object.freeze({
  active: 8,
  perClientActive: 2,
  // TLS has no cache: charge every admitted diagnostic, including failures.
  // Twenty per rolling minute allows interactive retries without rapid handshake churn.
  requestsPerWindow: 20,
  rateWindowMs: 60_000,
  // At most 20 timestamps per entry. Expired idle entries are pruned on admission.
  clientEntries: 1024,
  addresses: 4,
  parallel: 2,
  deadlineMs: 15_000,
  dnsMs: 3000,
  connectMs: 7000,
  pendingSystemLookups: 8,
});

export class TlsCheckError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "TlsCheckError";
    this.code = code;
    this.safeMessage = message;
  }
}

const capacityError = () => new TlsCheckError("TLS_CAPACITY_EXHAUSTED", "TLS checker is busy. Try again later.");
const timeoutError = () => new TlsCheckError("TLS_DIAGNOSTIC_TIMEOUT", "TLS diagnostic timed out.");
const cancelledError = () => new TlsCheckError("TLS_CHECK_CANCELLED", "TLS diagnostic was cancelled.");
const connectionError = () => new TlsCheckError("TLS_CONNECTION_FAILED", "TLS connection failed.");

// Internal injection seam only; routes never accept dependencies or budgets from input.
export function createTlsNetwork({ isBlockedIp, now = () => performance.now(),
  setTimer = setTimeout, clearTimer = clearTimeout,
  createResolver = () => new dns.Resolver(), lookup = dns.lookup,
  connect = tls.connect } = {}) {
  const clients = new Map();
  let active = 0;
  let pendingLookups = 0;

  function acquire(client) {
    const time = now();
    for (const [key, entry] of clients) {
      entry.requests = entry.requests.filter((at) => time - at < TLS_BUDGETS.rateWindowMs);
      if (!entry.active && !entry.requests.length) clients.delete(key);
    }
    let entry = clients.get(client);
    if (active >= TLS_BUDGETS.active || (entry?.active || 0) >= TLS_BUDGETS.perClientActive) {
      throw capacityError();
    }
    if (entry && entry.requests.length >= TLS_BUDGETS.requestsPerWindow) {
      throw new TlsCheckError("RATE_LIMITED", "Too many TLS checks were requested recently. Try again later.");
    }
    if (!entry) {
      // Never evict live rate history to make room; fail closed until entries expire.
      if (clients.size >= TLS_BUDGETS.clientEntries) throw capacityError();
      entry = { active: 0, requests: [] };
      clients.set(client, entry);
    }
    entry.requests.push(time);
    entry.active += 1;
    active += 1;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      entry.active -= 1;
      active -= 1;
    };
  }

  function ensureLive(signal, deadline) {
    if (signal.aborted) throw signal.reason;
    if (now() >= deadline) throw timeoutError();
  }

  // Own and clear both timer and abort listener, including late underlying completions.
  function wait(promise, signal, deadline, duration) {
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = (error, value) => {
        if (settled) return;
        settled = true;
        clearTimer(timer);
        signal.removeEventListener("abort", abort);
        if (error) reject(error); else resolve(value);
      };
      const abort = () => finish(signal.reason);
      const timer = setTimer(() => {
        finish(now() >= deadline ? timeoutError() : new TlsCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname."));
      }, Math.max(0, Math.min(duration, deadline - now())));
      signal.addEventListener("abort", abort, { once: true });
      Promise.resolve(promise).then((value) => {
        try { ensureLive(signal, deadline); finish(null, value); } catch (error) { finish(error); }
      }, (error) => finish(error));
      // Attach rejection handlers even when cancellation/expiry already occurred.
      try { ensureLive(signal, deadline); } catch (error) { finish(error); }
    });
  }

  async function resolve(host, signal, deadline) {
    const resolver = createResolver();
    const cancel = () => resolver.cancel();
    signal.addEventListener("abort", cancel, { once: true });
    let addresses;
    try {
      ensureLive(signal, deadline);
      const family = (promise) => wait(promise, signal, deadline, TLS_BUDGETS.dnsMs).catch(() => {
        ensureLive(signal, deadline);
        return [];
      });
      // Preserve a successful family even if the other family fails or stalls.
      addresses = (await Promise.all([
        family(resolver.resolve4(host)),
        family(resolver.resolve6(host)),
      ])).flat();
    } finally {
      cancel();
      signal.removeEventListener("abort", cancel);
    }
    if (!addresses.length) {
      ensureLive(signal, deadline);
      // getaddrinfo cannot be cancelled. Hold this independent slot until it REALLY
      // settles, even after the diagnostic releases admission. Never queue a lookup.
      if (pendingLookups >= TLS_BUDGETS.pendingSystemLookups) throw capacityError();
      pendingLookups += 1;
      const pending = Promise.resolve().then(() => {
        ensureLive(signal, deadline);
        return lookup(host, { all: true });
      }).finally(() => { pendingLookups -= 1; });
      try {
        addresses = (await wait(pending, signal, deadline, TLS_BUDGETS.dnsMs)).map((record) => record.address);
      } catch (error) {
        ensureLive(signal, deadline);
        throw new TlsCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
      }
    }
    ensureLive(signal, deadline);
    if (!addresses.length) throw new TlsCheckError("DNS_LOOKUP_FAILED", "DNS lookup failed for this hostname.");
    const publicAddresses = [...new Set(addresses)].filter((address) => !isBlockedIp(address));
    if (!publicAddresses.length) throw new TlsCheckError("BLOCKED_TARGET", "The hostname resolves only to blocked addresses.");
    return publicAddresses;
  }

  function attempt(servername, port, address, signal, deadline, onSuccess) {
    ensureLive(signal, deadline);
    return new Promise((resolve, reject) => {
      let socket;
      let timer;
      let result;
      let error;
      const stop = (failure) => {
        if (result || error) return;
        error = failure;
        socket.destroy();
      };
      const abort = () => stop(signal.reason);
      const fail = () => stop(connectionError());
      const secure = () => {
        if (result || error) return;
        try {
          ensureLive(signal, deadline);
          result = {
            authorized: socket.authorized,
            authorizationError: socket.authorizationError || null,
            protocol: socket.getProtocol(),
            cipher: socket.getCipher()?.standardName || socket.getCipher()?.name || null,
            peerCertificate: socket.getPeerCertificate(true),
          };
          onSuccess(result);
        } catch (failure) { error = failure instanceof TlsCheckError ? failure : connectionError(); }
        socket.destroy();
      };
      const close = () => {
        clearTimer(timer);
        signal.removeEventListener("abort", abort);
        socket.removeListener("secureConnect", secure);
        socket.removeListener("error", fail);
        socket.removeListener("close", close);
        // A successful handshake cancels the pool immediately, including this
        // signal. Still wait for its close; the parent deadline/abort is checked
        // again before returning the diagnostic result.
        if (!result) {
          try { ensureLive(signal, deadline); } catch (failure) { error = failure; }
        } else if (now() >= deadline) error = timeoutError();
        if (error || !result) reject(error || connectionError()); else resolve(result);
      };
      try {
        socket = connect({ host: address, port, servername, rejectUnauthorized: false });
      } catch { reject(connectionError()); return; }
      socket.once("secureConnect", secure);
      socket.on("error", fail);
      socket.once("close", close);
      signal.addEventListener("abort", abort, { once: true });
      timer = setTimer(() => stop(now() >= deadline ? timeoutError() : connectionError()),
        Math.min(TLS_BUDGETS.connectMs, deadline - now()));
      if (signal.aborted) abort();
    });
  }

  async function connectAddresses(host, port, addresses, signal, deadline) {
    // Alternate families so a long IPv4 answer cannot crowd IPv6 out of the cap.
    const v4 = addresses.filter((address) => !address.includes(":"));
    const v6 = addresses.filter((address) => address.includes(":"));
    const candidates = [];
    for (let index = 0; candidates.length < TLS_BUDGETS.addresses && (index < v4.length || index < v6.length); index += 1) {
      if (v4[index]) candidates.push(v4[index]);
      if (v6[index] && candidates.length < TLS_BUDGETS.addresses) candidates.push(v6[index]);
    }
    const pool = new AbortController();
    const abort = () => pool.abort(signal.reason);
    signal.addEventListener("abort", abort, { once: true });
    let next = 0;
    let winner;
    async function worker() {
      while (!winner && !pool.signal.aborted && next < candidates.length) {
        const address = candidates[next++];
        try {
          await attempt(host, port, address, pool.signal, deadline, (result) => {
            ensureLive(signal, deadline);
            if (!winner) { winner = result; pool.abort(cancelledError()); }
          });
          ensureLive(signal, deadline);
        } catch {
          // Bounded fallback only; cancellation/deadline are checked before every attempt.
          if (now() >= deadline) pool.abort(timeoutError());
        }
      }
    }
    try {
      ensureLive(signal, deadline);
      await Promise.all(Array.from({ length: Math.min(TLS_BUDGETS.parallel, candidates.length) }, worker));
      ensureLive(signal, deadline);
      if (!winner) throw connectionError();
      return winner;
    } finally {
      pool.abort(cancelledError());
      signal.removeEventListener("abort", abort);
    }
  }

  return async function run(host, port, { clientIp = "unknown", signal } = {}, complete) {
    if (signal?.aborted) throw cancelledError();
    const release = acquire(clientIp);
    const controller = new AbortController();
    const deadline = now() + TLS_BUDGETS.deadlineMs;
    const abort = () => controller.abort(cancelledError());
    const timer = setTimer(() => controller.abort(timeoutError()), TLS_BUDGETS.deadlineMs);
    signal?.addEventListener("abort", abort, { once: true });
    try {
      if (signal?.aborted) abort();
      const addresses = await resolve(host, controller.signal, deadline);
      const result = await connectAddresses(host, port, addresses, controller.signal, deadline);
      ensureLive(controller.signal, deadline);
      // Synchronous certificate processing cannot be preempted by a Node timer.
      const response = complete(result, addresses);
      ensureLive(controller.signal, deadline);
      return response;
    } finally {
      controller.abort(cancelledError());
      clearTimer(timer);
      signal?.removeEventListener("abort", abort);
      release();
    }
  };
}
