# DNS diagnostic resource budgets

Limits are process-local constants in `src/tools/dns-resources.mjs`, not request parameters.
The DNS transport remains UDP-only with the existing predefined resolver registry and
AUD-002 source, transaction, flags and exact-question correlation checks unchanged.

| Resource | Limit |
| --- | --- |
| Live checks | 6 globally; 2 per client |
| UDP sockets, including asynchronous close | 24 globally; 4 per check |
| Burst provider workers | 4, with all 10 providers retained in registry order |
| Queued endpoint operations | At most 12 per admitted check, cancellable; no admission queue |
| Single logical queries / attempted UDP sends | 33 / 64 |
| Burst logical queries / attempted UDP sends | 70 / 128 |
| Single / burst overall deadline | 15 / 30 seconds |
| Individual attempt timeout | Minimum of 3 seconds and remaining overall time |
| MX enrichment targets | First 10 single; first 2 per provider in burst |

Six checks times four owned sockets bounds transport concurrency at 24. Two checks per
client prevent one identity consuming all six slots. Admission retains only active
client entries (at most six), deleting them on final release. Checks fail fast when
capacity is full; capacity rejections do not charge tokens. Validation and cache lookup
precede admission; cached responses require neither slots nor rate tokens. Admitted live
single/burst checks retain their existing one/ten token costs and rate windows.

Every logical query consumes query budget once; each actual `socket.send` attempt
consumes attempt budget, including alternate IPv4/IPv6 endpoints and diagnostics.
Fallback retains all predefined endpoints, but shares the overall operation's deadline
and attempt budget. An individual resolver timeout is still a provider timeout, not an
overall diagnostic timeout. There is no fresh overall deadline for fallback.

All burst primary queries finish before enrichment begins. Worst-case successful
single MX diagnostics need 1 primary + 30 host queries + 2 DNSSEC queries = 33 queries.
Burst MX needs 10 primaries + 60 host queries = 70. Burst caps targets rather than
allowing 300 optional queries to overwhelm primary results. The separate 64/128 attempt
caps allow useful endpoint fallback without permitting four attempts for every optional
query. TXT adds at most one DMARC query per provider (a direct DMARC query reuses
its primary answer); single DNSSEC adds DS and DNSKEY queries.
The existing burst DNSSEC limitation remains unchanged.

Omitted MX targets, budget-exhausted queries and failed optional diagnostics produce
`optional_diagnostics_incomplete` diagnostics and warnings, including bounded lists of
failed/omitted query names, types and sanitized reasons. Failed/skipped MX resolution
does not assert the host is unresolvable; failed/skipped DMARC does not assert no record
exists; incomplete DNSSEC does not claim completed deep checks. Original records and
raw response sections remain available. Diagnostics with incomplete optional enrichment,
failed primaries or truncated replies are not cached. Complete diagnostics retain the
60-second single/300-second burst TTLs. Overall timeout or cancellation is an error
and is never inserted into the successful-result cache.

The route listens for incoming request `aborted` and premature response `close`, not
normal incoming POST-body `close`. Its AbortSignal reaches fallback, workers, optional
diagnostics, concurrency waits and UDP transport. Cancellation/deadline aborts queued
work and closes active sockets. Socket slots remain owned until close completes;
admission releases once after cleanup. Message/abort listeners and attempt/deadline
timers are removed, and late packets/send callbacks cannot launch more work. A late
completion also checks the monotonic deadline before success/cache insertion.

API failures use `{ ok: false, error: { code, message } }`:

- `DNS_CAPACITY_EXHAUSTED`: 503, "DNS checks are busy. Please try again later."
- `DNS_DIAGNOSTIC_TIMEOUT`: 504, "DNS diagnostic timed out."
- `DNS_CHECK_CANCELLED`: defensive 499, "DNS check was cancelled." No response is
  attempted after route-observed client disconnection.
- Existing `RATE_LIMITED`: 429; validation: 400; unexpected failure: sanitized 502.

Regression tests in `test/dns-resources.test.mjs` use fake UDP sockets, fake deadline
timers, internal dependency injection and a real ephemeral loopback Fastify listener.
`test/dns-check.test.mjs` retains AUD-002 wire-format coverage. Frontend browser tests
verify the new error envelopes allow retry and clear the loading state.

## Limitations

Limits apply per process, not across replicas; client identity depends on the existing
ingress configuration. Cache/rate-history retention is bounded as documented in
`RETAINED_STATE_LIMITS.md` (AUD-004). TXT owner-name validation and UDP truncation/error
classification are documented in `DNS_RESPONSE_CONTRACTS.md` (Phase 8H). TCP fallback
remains unimplemented. Like other
Node deadlines, timer delivery and socket-close completion depend on event-loop progress;
synchronous parsing/serialization cannot be preempted. No public-resolver load tests
or production verification are performed. Internal test clock/query overrides are
not accepted through API payloads.
