import assert from "node:assert/strict";
import test from "node:test";
import { BoundedCache, BoundedRateHistory, RETENTION_LIMITS } from "../src/tools/retained-state.mjs";
import { checkDns, dnsRetainedState, resetDnsCheckState } from "../src/tools/dns-check.mjs";
import { checkHttpHeader, httpRetainedState, resetHttpHeaderCheckState } from "../src/tools/http-header-check.mjs";
import { dnsResourceState } from "../src/tools/dns-resources.mjs";
import { httpResourceState } from "../src/tools/http-resources.mjs";

const dnsPayload = (query, mode = "single") => ({ query, mode, recordType: "A", dnssec: false,
  ...(mode === "single" ? { resolverId: "cloudflare" } : {}) });
const queryDns = async () => ({ rcodeName: "NOERROR", flags: {}, answer: [], authority: [], additional: [] });
const httpOptions = { resolveAddresses: async () => ["93.184.216.34"],
  requestUrl: async () => ({ status: 200, headers: [{ name: "server", value: "offline" }] }) };
const rateError = () => Object.assign(new Error("limited"), { code: "RATE_LIMITED" });

test("cache hard cap, expiration-first eviction, LRU, size ceiling and expired insertion", () => {
  const cache = new BoundedCache(2, 50);
  const entry = (expiresAt, response = { ok: true }) => ({ storedAt: 0, expiresAt, response });
  cache.set("live", entry(100), 0);
  cache.set("expired-first", entry(1), 0);
  cache.set("new", entry(100), 2);
  assert.equal(cache.size, 2);
  assert.ok(cache.get("live", 2));
  cache.set("third", entry(100), 2);
  assert.equal(cache.get("new", 2), undefined);
  assert.ok(cache.get("live", 2));
  cache.set("large", entry(100, { value: "x".repeat(100) }), 2);
  cache.set("already-expired", entry(2), 2);
  assert.equal(cache.size, 2);
  cache.get("unrelated", 100);
  assert.equal(cache.size, 0);
});

test("rate helper fails closed without active eviction, bounds arrays, reclaims expired histories and resets cursor", () => {
  const state = new BoundedRateHistory(2, 2, 100);
  const add = (key, now) => state.commit(key, state.prepare(key, now, rateError), 1, now, rateError);
  add("a", 0); add("a", 1); add("b", 2);
  for (let index = 0; index < 100; index += 1) assert.throws(() => add(`churn-${index}`, 50), { code: "RATE_LIMITED" });
  assert.throws(() => add("a", 50), { code: "RATE_LIMITED" });
  assert.equal(state.size, 2);
  assert.deepEqual(state.prepare("a", 50, rateError).map((entry) => entry.time), [0, 1]);
  add("new", 101);
  assert.equal(state.size, 2);
  state.prune(102, true);
  assert.equal(state.size, 1);
  state.clear(); state.prune(200);
  assert.equal(state.size, 0);
});

for (const [mode, ttl] of [["single", 60], ["burst", 300]]) {
  test(`DNS ${mode} TTL, deep clone, cache-hit accounting and unrelated expiration`, async () => {
    resetDnsCheckState();
    let time = 0;
    let calls = 0;
    const options = { now: () => time, queryDns: async (...args) => { calls += 1; return queryDns(...args); } };
    const payload = dnsPayload("ttl.example.com", mode);
    const first = await checkDns(payload, options);
    const originalCalls = calls;
    first.warnings.push("mutated");
    time = ttl * 1000 - 1;
    const hit = await checkDns(payload, options);
    assert.equal(hit.cache.fromCache, true);
    assert.equal(hit.cache.cacheAgeSeconds, ttl - 1);
    assert.equal(hit.cache.cacheExpiresInSeconds, 1);
    assert.equal(hit.cache.cacheTtlSeconds, ttl);
    assert.equal(hit.warnings.includes("mutated"), false);
    assert.equal(calls, originalCalls);
    assert.equal(dnsRetainedState().rateClientEntries, 1);
    time = ttl * 1000;
    await checkDns(dnsPayload("unrelated.example.com"), options);
    assert.equal(dnsRetainedState().cacheEntries, 1);
    assert.equal((await checkDns(payload, options)).cache.fromCache, false);
    assert.equal(dnsRetainedState().cacheEntries, 2);
  });
}

test("HTTP TTL, deep clone, Both accounting and unrelated expiration", async () => {
  resetHttpHeaderCheckState();
  let time = 0;
  let calls = 0;
  const options = { ...httpOptions, now: () => time, requestUrl: async () => { calls += 1; return httpOptions.requestUrl(); } };
  const payload = { target: "ttl.example.com", protocolMode: "both" };
  const first = await checkHttpHeader(payload, options);
  assert.equal(first.budget.tokensConsumed, 2);
  first.checks[0].headers[0].value = "mutated";
  time = 59_999;
  const hit = await checkHttpHeader(payload, options);
  assert.equal(hit.budget.tokensConsumed, 0);
  assert.equal(calls, 2);
  assert.equal(hit.checks[0].headers[0].value, "offline");
  assert.equal(hit.checks[0].cacheAgeSeconds, 59);
  assert.equal(hit.checks[0].cacheExpiresInSeconds, 1);
  assert.equal(hit.checks[0].cacheTtlSeconds, 60);
  assert.equal(httpRetainedState().globalHistoryEntries, 1);
  time = 60_000;
  await checkHttpHeader({ target: "unrelated.example.com" }, options);
  assert.equal(httpRetainedState().cacheEntries, 1);
  assert.equal((await checkHttpHeader(payload, options)).budget.tokensConsumed, 2);
});

test("DNS diverse-query churn enforces real cache cap and LRU; evicted misses run again", async () => {
  resetDnsCheckState();
  let calls = 0;
  const run = (index) => checkDns(dnsPayload(`q${index}.example.com`), {
    now: () => 0, clientIp: `client-${index}`, queryDns: async () => { calls += 1; return queryDns(); },
  });
  for (let index = 0; index < RETENTION_LIMITS.cacheEntries; index += 1) {
    await run(index);
    assert.ok(dnsRetainedState().cacheEntries <= RETENTION_LIMITS.cacheEntries);
  }
  await run(0);
  await run(512);
  assert.equal((await run(0)).cache.fromCache, true);
  assert.equal((await run(1)).cache.fromCache, false);
  assert.equal(calls, 514);
  assert.equal(dnsRetainedState().cacheEntries, 512);
});

test("DNS real client cap rejects churn, preserves existing limits, reclaims and recovers", async () => {
  resetDnsCheckState();
  let time = 0;
  const run = (client, query = client) => checkDns(dnsPayload(`${query}.example.com`), { now: () => time, clientIp: client, queryDns });
  for (let index = 0; index < RETENTION_LIMITS.dnsClients; index += 1) await run(`c${index}`);
  assert.equal(dnsRetainedState().rateClientEntries, 8192);
  assert.equal((await run("new-cache-client", "c8191")).cache.fromCache, true);
  for (let index = 0; index < 20; index += 1) await assert.rejects(run(`new${index}`), { code: "RATE_LIMITED" });
  for (let index = 0; index < 99; index += 1) await run("c0", `protected${index}`);
  await assert.rejects(run("c0", "limited"), { code: "RATE_LIMITED" });
  assert.equal(dnsRetainedState().rateClientEntries, 8192);
  time = 3_600_000;
  await run("recovered");
  assert.ok(dnsRetainedState().rateClientEntries < 8192);
  resetDnsCheckState();
  assert.deepEqual(dnsRetainedState(), { cacheEntries: 0, rateClientEntries: 0 });
  assert.deepEqual(dnsResourceState(), { activeChecks: 0, clients: 0, sockets: 0 });
});

test("HTTP real client/target caps, diverse cache churn, global history bound and recovery", async () => {
  resetHttpHeaderCheckState();
  let time = 0;
  const run = (index, client = `c${index}`) => checkHttpHeader({ target: `t${index}.example.com` }, { ...httpOptions, now: () => time, clientIp: client });
  for (let index = 0; index < RETENTION_LIMITS.httpTargets; index += 1) {
    time = Math.floor(index / 350) * 300_000;
    await run(index);
    const state = httpRetainedState();
    assert.ok(state.cacheEntries <= 512);
    assert.ok(state.rateClientEntries <= 4096);
    assert.ok(state.rateTargetEntries <= 4096);
    assert.ok(state.globalHistoryEntries <= 4200);
  }
  assert.equal(httpRetainedState().rateClientEntries, 4096);
  assert.equal(httpRetainedState().rateTargetEntries, 4096);
  const beforeHit = httpRetainedState().globalHistoryEntries;
  assert.equal((await run(4095, "new-cache-client")).budget.tokensConsumed, 0);
  assert.equal(httpRetainedState().globalHistoryEntries, beforeHit);
  await assert.rejects(run(5000), { code: "RATE_LIMITED" });
  await assert.rejects(run(5001, "c0"), { code: "RATE_LIMITED" });
  // The old key expired from cache: this is a genuinely new diagnostic.
  assert.equal((await run(0, "c0")).budget.tokensConsumed, 1);
  time = 3_600_000;
  assert.equal((await run(5000)).budget.tokensConsumed, 1);
  assert.ok(httpRetainedState().rateClientEntries < 4096);
  assert.ok(httpRetainedState().rateTargetEntries < 4096);
  resetHttpHeaderCheckState();
  assert.deepEqual(httpRetainedState(), { cacheEntries: 0, rateClientEntries: 0, rateTargetEntries: 0, globalHistoryEntries: 0 });
  assert.deepEqual(httpResourceState(), { activeChecks: 0, clients: 0, sockets: 0, pendingLookups: 0 });
});

test("HTTP failed target attempts cannot exhaust unbounded client histories or bypass their caps", async () => {
  resetHttpHeaderCheckState();
  const run = (client, target) => checkHttpHeader({ target }, {
    ...httpOptions, now: () => 0, clientIp: client, requestUrl: async () => { throw new Error("offline failure"); },
  });
  for (let index = 0; index < 30; index += 1) await assert.rejects(run(`initial${index}`, "limited.example.com"));
  for (let index = 30; index < RETENTION_LIMITS.httpClients; index += 1) {
    await assert.rejects(run(`initial${index}`, "limited.example.com"), { code: "RATE_LIMITED" });
  }
  assert.equal(httpRetainedState().rateClientEntries, 4096);
  await assert.rejects(run("new", "new.example.com"), { code: "RATE_LIMITED" });
  assert.equal(httpRetainedState().rateClientEntries, 4096);
  assert.equal(httpRetainedState().rateTargetEntries, 1);
  assert.equal(httpRetainedState().cacheEntries, 0);
});

test("failed DNS, failed HTTP results and oversized responses are returned but never cached", async () => {
  resetDnsCheckState(); resetHttpHeaderCheckState();
  const failedDns = await checkDns(dnsPayload("failure.example.com"), { queryDns: async () => { throw new Error("offline"); } });
  assert.equal(failedDns.ok, false);
  assert.equal(dnsRetainedState().cacheEntries, 0);
  const failedBurst = await checkDns(dnsPayload("burst-failure.example.com", "burst"), {
    queryDns: async (server) => {
      if (server === "1.1.1.1") throw new Error("offline");
      return queryDns();
    },
  });
  assert.equal(failedBurst.providers.some((provider) => provider.ok === false), true);
  assert.equal(dnsRetainedState().cacheEntries, 0);
  const largeDns = await checkDns(dnsPayload("large.example.com"), {
    queryDns: async () => ({ ...(await queryDns()), answer: [{ name: "large.example.com", type: "A", ttl: 60, data: "x".repeat(262_144) }] }),
  });
  assert.equal(largeDns.ok, true);
  assert.equal(largeDns.records[0].address.length, 262_144);
  assert.equal(dnsRetainedState().cacheEntries, 0);
  const failedHttp = await checkHttpHeader({ target: "failure.example.com" }, {
    ...httpOptions, requestUrl: async () => ({ status: 302, headers: [{ name: "location", value: "http://localhost/" }] }),
  });
  assert.equal(failedHttp.ok, false);
  assert.equal(httpRetainedState().cacheEntries, 0);
  const largeHttp = await checkHttpHeader({ target: "large.example.com" }, {
    ...httpOptions, requestUrl: async () => ({ status: 200, headers: [{ name: "x-large", value: "x".repeat(262_144) }] }),
  });
  assert.equal(largeHttp.ok, true);
  assert.equal(largeHttp.checks[0].headers[0].value.length, 262_144);
  assert.equal(httpRetainedState().cacheEntries, 0);
});

test("diagnostics whose cache TTL expires in flight are never retained", async () => {
  resetDnsCheckState(); resetHttpHeaderCheckState();
  let time = 0;
  await checkDns(dnsPayload("slow.example.com"), { now: () => time, queryDns: async () => { time = 60_000; return queryDns(); } });
  assert.equal(dnsRetainedState().cacheEntries, 0);
  time = 0;
  await checkHttpHeader({ target: "slow.example.com" }, { ...httpOptions, now: () => time,
    requestUrl: async () => { time = 60_000; return httpOptions.requestUrl(); } });
  assert.equal(httpRetainedState().cacheEntries, 0);
});

test("bounded incremental pruning removes idle identities without accessing their keys", () => {
  const state = new BoundedRateHistory(64, 2, 100);
  for (let index = 0; index < 64; index += 1) state.commit(index, [], 1, 0, rateError);
  for (let index = 0; index < 4; index += 1) state.prune(100);
  assert.equal(state.size, 0);
});

test("DNS burst token costs and five-minute/hour windows remain exact for unknown identity", async () => {
  resetDnsCheckState();
  let time = 0;
  let index = 0;
  const run = (mode = "burst") => checkDns(dnsPayload(`tokens${index++}.example.com`, mode), { now: () => time, queryDns });
  for (let window = 0; window < 7; window += 1) {
    time = window * 300_000;
    for (let burst = 0; burst < 10; burst += 1) await run();
    await assert.rejects(run("single"), { code: "RATE_LIMITED" });
  }
  time = 2_100_000;
  for (let burst = 0; burst < 5; burst += 1) await run();
  await assert.rejects(run("single"), { code: "RATE_LIMITED" });
  assert.equal(dnsRetainedState().rateClientEntries, 1);
  time = 3_600_000;
  assert.equal((await run()).cache.fromCache, false);
});

test("concurrent same-key DNS misses remain independently charged and last completion wins", async () => {
  resetDnsCheckState();
  const completions = [];
  const options = { now: () => 0, queryDns: () => new Promise((resolve) => completions.push(resolve)) };
  const payload = dnsPayload("same.example.com");
  const first = checkDns(payload, options);
  const second = checkDns(payload, options);
  assert.equal(completions.length, 2);
  assert.deepEqual(dnsRetainedState(), { cacheEntries: 0, rateClientEntries: 1 });
  completions[1]({ ...(await queryDns()), rcodeName: "NXDOMAIN" });
  await second;
  completions[0](await queryDns());
  await first;
  const hit = await checkDns(payload, { now: () => 0 });
  assert.equal(hit.cache.fromCache, true);
  assert.equal(hit.responseCode, "NOERROR");
  assert.equal(dnsRetainedState().cacheEntries, 1);
});

test("concurrent HTTP same-key misses remain charged; near-limit concurrency cannot bypass client limits", async () => {
  resetHttpHeaderCheckState();
  const completions = [];
  const options = { ...httpOptions, now: () => 0,
    requestUrl: () => new Promise((resolve) => completions.push(resolve)) };
  const payload = { target: "same.example.com" };
  const first = checkHttpHeader(payload, options);
  const second = checkHttpHeader(payload, options);
  // Injected DNS resolution still goes through the operation's async wait.
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(completions.length, 2);
  assert.equal(httpRetainedState().globalHistoryEntries, 2);
  completions[1]({ status: 201, headers: [] });
  assert.equal((await second).budget.tokensConsumed, 1);
  completions[0]({ status: 200, headers: [] });
  assert.equal((await first).budget.tokensConsumed, 1);
  assert.equal((await checkHttpHeader(payload, { ...httpOptions, now: () => 0 })).checks[0].status, 200);
  for (let index = 0; index < 77; index += 1) {
    await checkHttpHeader({ target: `near${index}.example.com` }, { ...httpOptions, now: () => 0 });
  }
  const results = await Promise.allSettled(["last", "rejected"].map((key) =>
    checkHttpHeader({ target: `${key}.example.com` }, { ...httpOptions, now: () => 0 })));
  assert.equal(results[0].status, "fulfilled");
  assert.equal(results[1].reason.code, "RATE_LIMITED");
  assert.equal(httpRetainedState().globalHistoryEntries, 80);
});

test("DNS concurrent rate admission cannot race past the last token", async () => {
  resetDnsCheckState();
  for (let index = 0; index < 99; index += 1) {
    await checkDns(dnsPayload(`near${index}.example.com`), { now: () => 0, queryDns });
  }
  const results = await Promise.allSettled(["last", "rejected"].map((key) =>
    checkDns(dnsPayload(`${key}.example.com`), { now: () => 0, queryDns })));
  assert.equal(results[0].status, "fulfilled");
  assert.equal(results[1].reason.code, "RATE_LIMITED");
  assert.deepEqual(dnsResourceState(), { activeChecks: 0, clients: 0, sockets: 0 });
});

test("HTTP global history reaches its hard ceiling without shortening the hour and reclaims at expiry", async () => {
  resetHttpHeaderCheckState();
  let time = 0;
  const run = (index) => checkHttpHeader({ target: `global${index}.example.com` }, {
    ...httpOptions, clientIp: `global${index}`, now: () => time,
  });
  for (let window = 0; window < 12; window += 1) {
    time = window * 300_000;
    for (let index = 0; index < 350; index += 1) await run(index);
    await assert.rejects(run(350), { code: "RATE_LIMITED" });
    assert.equal(httpRetainedState().globalHistoryEntries, (window + 1) * 350);
  }
  assert.equal(httpRetainedState().globalHistoryEntries, RETENTION_LIMITS.httpGlobalHistory);
  time = 3_600_000;
  await run(350);
  assert.equal(httpRetainedState().globalHistoryEntries, 3851);
});

test("cache publication rechecks diagnostic liveness after sizing, without partial Both entries", () => {
  const cache = new BoundedCache();
  const entries = ["http", "https"].map((key) => [key, { expiresAt: 100, response: { ok: true } }]);
  assert.throws(() => cache.setMany(entries, 0, () => { throw rateError(); }));
  assert.equal(cache.size, 0);
});
