# DNS and HTTP retained-state bounds (AUD-004)

Retention is process-local in `src/tools/retained-state.mjs`; API payloads cannot
override limits or clocks. Diagnostic transports, admission budgets, authentication
and trusted-proxy settings are unchanged.

| State | Hard limit | Retention |
| --- | --- | --- |
| DNS cache | 512 entries | Single 60 seconds; burst 300 seconds |
| HTTP cache | 512 protocol-check entries | 60 seconds |
| Each cached response | 256 KiB serialized UTF-8 JSON | Larger results returned intact, not cached |
| DNS client histories | 8,192 identities; 750 events per identity | Rolling hour |
| HTTP client histories | 4,096 identities; 500 events per identity | Rolling hour |
| HTTP target histories | 4,096 identities; 500 events per identity | Rolling hour |
| HTTP global history | 4,200 events | Rolling hour; existing five-minute guard remains 350 tokens |

HTTP's global limit permits at most 12 × 350 = 4,200 positive-cost events in a
rolling hour. A 4,096-identity ceiling allows nearly that entire hourly workload
while giving explicit fail-closed bounds to client-only charges on target rate
rejection. DNS has no matching global token guard, so its client ceiling is 8,192.
Positive token costs and the existing hourly guards bound per-identity arrays;
explicit insertion checks additionally enforce those array ceilings.

## Cleanup and churn

Cache lookup and publication sweep all expired entries, including unrelated keys,
with at most 512 entries per sweep. Expiration is preferred over eviction of any
live entry. Successful hits refresh Map order without changing timestamps; when
all entries are live, insertion removes the least recently used entry **before**
adding a new one. Replacing a key similarly deletes before insertion. Deep-clone,
age/expiry metadata and cache-hit zero-token semantics remain unchanged.

Every normalized DNS/HTTP operation incrementally prunes 16 buckets per identity
map, including cache hits. Each rate operation also prunes its accessed bucket
using the same captured request time. Before admitting a new identity to a full
map, a full expired-history sweep runs. Work is bounded by the hard map and array
ceilings; pruning compacts each array in linear time. Empty buckets are deleted.
The HTTP global array is pruned on each operation, including fully cached ones.
No cleanup timers or per-entry timers are introduced. During complete inactivity,
stale entries remain within these hard bounds until subsequent operations or reset;
cleanup never requires the original key to be accessed again.

Active rate histories are **never** evicted for new keys. If no expired slot can be
reclaimed, new live identities fail with the existing sanitized `RATE_LIMITED`
(429) response, without resetting or appending to any history. Existing identities
remain usable within their original limits; cache hits require no identity slot.
Repeated rejected keys cannot displace protection or extend/shorten its windows.
All checks and charges are synchronous before asynchronous diagnostics begin.

Existing DNS costs (single 1, burst 10), five-minute/hour guards (100/750), HTTP
fresh-protocol costs (Both up to 2), client guards (80/500), target guards (30/500),
and global five-minute guard (350) are unchanged. Missing client identity still
shares the `unknown` bucket. HTTP preflights both map capacities before charging;
ordinary target-rate rejection still preserves the existing client-first charge.
Admission accounting and rejection ordering otherwise remain unchanged.

## Publication and metrics

Failed DNS provider results (including bursts with a failed provider) and HTTP
`ok: false` checks are no longer cached. Valid complete negative DNS answers retain
their existing TTLs; truncated/error replies and incomplete optional DNS enrichment
are not cached (see `DNS_RESPONSE_CONTRACTS.md`, Phase 8H). Oversized
results and results whose cache TTL elapsed in flight are not retained. Diagnostic
cancellation/deadline checks remain mandatory before publication, including after
cache sizing. HTTP still retains a completed successful protocol on an ordinary
second-protocol failure; cancellation/overall expiration cannot publish partial
Both results. Same-key concurrent misses are **not** coalesced: each independently
uses existing rate/admission budgets, and the last successful cacheable completion
replaces the key, as before.

Internal exports (not public routes) return retained counts only:

- `dnsRetainedState()`: `cacheEntries`, `rateClientEntries`.
- `httpRetainedState()`: `cacheEntries`, `rateClientEntries`,
  `rateTargetEntries`, `globalHistoryEntries`.

Snapshots include stale entries awaiting pruning and expose no keys, response
bodies, IPs or secrets. Existing reset functions clear all cache/history state and
the incremental-pruning cursor, without resetting live admission resources.

## Verification and limitations

`test/retained-state.test.mjs` exercises fake clocks, offline injected diagnostics,
real caps, eviction, TTL boundaries, rate saturation/recovery, metrics, resets and
same-key concurrency. Existing DNS/HTTP/TLS resource and network-security suites
remain applicable. No public-network load testing is required or performed.

The 256 KiB ceiling measures serialized payload size, not exact V8 heap usage;
object/string overhead and transient diagnostic/serialization allocations remain.
At most 128 MiB of serialized response payload is retained per full cache, plus
bounded overhead. Full identity sweeps at saturation can be costlier than normal
incremental cleanup, but cannot grow beyond the documented caps. Limits are not
distributed across processes, do not replace ingress controls, and cannot preempt
synchronous parsing/serialization. Other audit findings remain out of scope.
