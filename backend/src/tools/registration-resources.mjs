import { performance } from "node:perf_hooks";
import { BoundedCache, BoundedRateHistory, pruneHistory } from "./retained-state.mjs";
import { RegistrationError, fail } from "./registration-input.mjs";

export const REGISTRATION_LIMITS = Object.freeze({
  deadlineMs: 20000, attemptMs: 5000, dnsMs: 3000, exchanges: 8,
  redirects: 2, referrals: 2, responseBytes: 256 * 1024, bootstrapBytes: 1024 * 1024,
  totalBytes: 2 * 1024 * 1024, active: 4, perClient: 1, sockets: 8, dns: 8,
  clientRate: 20, globalRate: 100, windowMs: 60000, clients: 2048,
  cacheEntries: 128, cacheBytes: 512 * 1024, cacheMs: 60000,
  jsonDepth: 32, jsonNodes: 20000, whoisLines: 4000,
});
export const resultCache = new BoundedCache(REGISTRATION_LIMITS.cacheEntries, REGISTRATION_LIMITS.cacheBytes);
const clients = new BoundedRateHistory(REGISTRATION_LIMITS.clients, REGISTRATION_LIMITS.clientRate, REGISTRATION_LIMITS.windowMs);
const globalHistory = [], liveClients = new Map();
let live = 0, sockets = 0, dns = 0;

export function admitRegistration(client, now) {
  clients.prune(now); pruneHistory(globalHistory, now, REGISTRATION_LIMITS.windowMs);
  const limited = () => new RegistrationError("RATE_LIMITED", "Registration lookup rate limit reached. Try again later.");
  const bucket = clients.prepare(client, now, limited);
  if (bucket.length >= REGISTRATION_LIMITS.clientRate || globalHistory.length >= REGISTRATION_LIMITS.globalRate) throw limited();
  clients.commit(client, bucket, 1, now, limited); globalHistory.push({ time: now, cost: 1 });
  if (live >= REGISTRATION_LIMITS.active || liveClients.has(client)) fail("CAPACITY_EXHAUSTED", "Registration lookups are busy. Try again later.");
  live++; liveClients.set(client, true);
  return () => { live--; liveClients.delete(client); };
}

export function acquireRegistrationResource(type) {
  if (type === "dns") {
    if (dns >= REGISTRATION_LIMITS.dns) fail("CAPACITY_EXHAUSTED", "Registration DNS capacity is exhausted.");
    dns++; return () => { dns--; };
  }
  if (sockets >= REGISTRATION_LIMITS.sockets) fail("CAPACITY_EXHAUSTED", "Registration socket capacity is exhausted.");
  sockets++; return () => { sockets--; };
}

export function createRegistrationOperation(options = {}) {
  const controller = new AbortController();
  const started = performance.now(), deadline = options.deadlineMs ?? REGISTRATION_LIMITS.deadlineMs;
  const abort = () => controller.abort(new RegistrationError("CANCELLED", "Registration lookup was cancelled."));
  options.signal?.addEventListener("abort", abort, { once: true });
  if (options.signal?.aborted) abort();
  const timer = setTimeout(() => controller.abort(new RegistrationError("DEADLINE_EXHAUSTED", "Registration lookup deadline was exhausted.")), deadline);
  let exchanges = 0, bytes = 0;
  const assertLive = () => {
    if (controller.signal.aborted) throw controller.signal.reason;
    if (performance.now() - started >= deadline) fail("DEADLINE_EXHAUSTED", "Registration lookup deadline was exhausted.");
  };
  return {
    signal: controller.signal, assertLive,
    exchange() { assertLive(); if (++exchanges > REGISTRATION_LIMITS.exchanges) fail("LIMIT_EXCEEDED", "Registration exchange budget exhausted."); },
    bytes(count) { assertLive(); bytes += count; if (bytes > REGISTRATION_LIMITS.totalBytes) fail("LIMIT_EXCEEDED", "Registration received-byte budget exhausted."); },
    async wait(work, ms = REGISTRATION_LIMITS.attemptMs) {
      assertLive();
      return new Promise((resolve, reject) => {
        let settled = false;
        const onAbort = () => finish(controller.signal.reason);
        const timeout = setTimeout(() => finish(new RegistrationError("UPSTREAM_TIMEOUT", "Registration upstream request timed out.")), ms);
        const finish = (error, value) => {
          if (settled) return; settled = true;
          clearTimeout(timeout); controller.signal.removeEventListener("abort", onAbort);
          if (error) reject(error); else { try { assertLive(); resolve(value); } catch (e) { reject(e); } }
        };
        controller.signal.addEventListener("abort", onAbort, { once: true });
        Promise.resolve().then(() => { assertLive(); return work(); }).then((value) => finish(null, value), (error) => finish(error));
      });
    },
    dispose() { clearTimeout(timer); options.signal?.removeEventListener("abort", abort); },
  };
}
export function registrationState() { return { live, sockets, dns, cache: resultCache.size, clients: clients.size }; }
export function resetRegistrationState() { resultCache.clear(); clients.clear(); globalHistory.length = 0; }
