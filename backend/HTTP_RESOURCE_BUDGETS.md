# HTTP Header Checker resource budgets

All limits are process-local and enforced before starting the corresponding work.
No capacity wait queue is retained. API input cannot override budgets or transports.

| Resource | Limit |
| --- | --- |
| Fresh protocol-check units | 12 globally; Both reserves two if both are fresh |
| Live diagnostics per client | 2 (Both is one diagnostic) |
| Outbound HTTP/HTTPS sockets, including closing sockets | 12 globally |
| Address attempts | At most four distinct validated IPs per hop, interleaved by family, strictly sequential |
| Redirects | 2, hence at most 3 hops / 12 address attempts per protocol |
| Both mode | Sequential protocols, at most 6 hops / 24 address attempts |
| Overall monotonic deadline | 15 seconds for Auto/HTTP/HTTPS; 25 seconds for Both |
| Address attempt | 7 seconds maximum, clipped to remaining overall time |
| DNS family / system fallback wait | 3 seconds maximum, clipped to remaining time |
| Uncancellable outstanding system lookups | 12 globally, retained until actual completion |
| Response headers | 16 KiB (Node parser limit); bodies destroyed immediately |

Each hop uses two independent cancellable `dns.Resolver` instances, one per family,
and at most one bounded system lookup if neither family supplies an answer. Thus
there are at most 24 live family resolutions, six per protocol check (twelve for
Both), and three fallback invocations per protocol (six for Both). Successful
families are retained when the other fails/times out; IPv4 and IPv6 are supported.
All returned addresses are checked for blocked/private/reserved destinations before
selecting attempts. IPv4 and IPv6 candidates alternate, starting with IPv4 and
preserving relative order within each family. If either family runs out, remaining
slots use the other family; single-family answers retain their original order.
This selection applies independently to the initial hop and every redirect hop,
without changing the four-attempt cap or sequential socket-close ownership.
Redirect destination scheme, port, credentials and hostname are
validated before resolution, including same-host hops. Connections use only the
validated IP, with original hostname Host/SNI/certificate verification and strict
HTTPS trust verification. There are no automatic redirects or pooled sockets.

The deadline covers DNS, redirects, fallback, handshake, headers, both protocols
and cleanup without restarting. Incoming request `aborted` or premature response
`close` cancels the diagnostic; ordinary POST completion does not. Cancellation
cancels family resolvers, destroys requests/responses/sockets and blocks subsequent
work and cache writes. Header completion and failed attempts await socket `close`
before releasing a socket or live admission. Attempts without an assigned socket
release on request `close`; synchronous construction failures release immediately.
Timers and abort listeners are removed on success, failure and cancellation.

Cache entries for a diagnostic are staged until all fresh checks complete or an
ordinary failure occurs while still live. An ordinary second-protocol failure
retains the first successful protocol's cache entry, as before; a timed-out/cancelled
Both diagnostic cannot cache its first protocol's partial success. Successful
cache TTL (60 seconds), cache keys, result structure,
findings and token accounting remain unchanged. Fully cached requests bypass live
admission and rate tokens. Existing rates remain 80 per client / five minutes,
500 per client / hour, 30 per target / five minutes (existing hourly guard 500),
350 globally / five minutes. Rate accounting still precedes admission, so rejected
fresh capacity requests consume the existing rate tokens; no outbound work starts.

Safe failures: `HTTP_CAPACITY_EXHAUSTED` → 503, `HTTP_DIAGNOSTIC_TIMEOUT` → 504,
`RATE_LIMITED` → 429. `HTTP_CHECK_CANCELLED` has a defensive 499 mapping, but the
route sends nothing after an observed client disconnect. Existing validation and
connection/TLS classifications are retained.

## Limitations

System `getaddrinfo` cannot be forcibly cancelled. Late results cannot start HTTP
work; separate lookup capacity stays occupied until the underlying work settles,
even if its diagnostic has already ended. There is no queue when it is full.
Socket destruction is asynchronous: admission remains held through actual local
close, which can run after the deadline on a delayed event loop. Synchronous header
analysis cannot be preempted, but its transport input is bounded and the monotonic
deadline is checked before committing results. Limits do not aggregate across
multiple backend processes. Cache/rate-history bounds (AUD-004) are documented in
`RETAINED_STATE_LIMITS.md`; findings wording (AUD-018) is unchanged. Offline tests
do not validate a live deployment.
