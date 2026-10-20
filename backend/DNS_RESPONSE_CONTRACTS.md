# DNS query and response contracts (Phase 8H)

## Query names

TXT queries validate DNS owner names, not connection hostnames. After IDNA
normalization, labels may contain ASCII letters, digits, underscores and interior
hyphens; a label cannot start/end with a hyphen. This includes `_dmarc`,
`_acme-challenge`, `_domainkey`, and selectors such as `selector_name`.
Other ordinary record types retain hostname-style labels. SRV retains its separate
service plus `_tcp`/`_udp` validation. PTR retains public-IP validation.

All name queries retain fully-qualified/public-name restrictions, prohibited
local/internal suffixes, a maximum 63 bytes per normalized label, and a maximum
253-byte textual name (255-byte wire name including label lengths/root).
One terminal root dot is accepted. Empty labels, embedded whitespace/controls,
unsupported characters and invalid IDNA are rejected. Frontend TXT helpers validate
the final generated name, including prefix/selector length, and do not append
DMARC/ACME/DKIM prefixes to an already fully entered corresponding owner name.
TXT enrichment reuses a direct DMARC answer and checks `_dmarc.<domain>` for
DKIM/ACME helpers, not `_dmarc.<selector>._domainkey...` or
`_dmarc._acme-challenge...`. It does not guess a DMARC domain for other underscore
owner names.

## HTTP/API union

The route continues returning completed diagnostics with HTTP 200:

- `{ ok: true, mode, query, status, ... }`: complete primary diagnostic, including
  legitimate negative DNS answers (NXDOMAIN/NODATA).
- `{ ok: false, mode, query, status, warnings, resolver, ... }`: completed diagnostic
  with resolver/transport failure or an incomplete primary response. This is **not**
  an API error envelope and does not need an `error` property. Single and burst
  diagnostics preserve records, sections, duration, DNSSEC metadata and raw data.
- `{ ok: false, error: { code, message } }`: API/operation error. Existing validation,
  rate, capacity, deadline and cancellation HTTP status mappings are unchanged.

The frontend runtime-checks these shapes before rendering. It retains diagnostic
failures in simple/advanced/raw and image-export views, but displays API errors
separately. Missing/malformed envelopes receive a safe retryable fallback error.

## Classification and UDP-only truncation

| Reply | Primary status | `ok` |
| --- | --- | --- |
| Complete NOERROR with requested records | `ok` (or existing `possible-sinkhole` heuristic) | true |
| Complete NOERROR without requested records | `no-record` | true |
| Complete NXDOMAIN | `nxdomain` | true |
| Complete SERVFAIL | `servfail` / existing `possible-dnssec-failure` when requested | false |
| Complete REFUSED | `refused` | false |
| Complete FORMERR | `formerr` | false |
| Complete NOTIMP | `notimp` | false |
| Other RCODE (including EDNS extended RCODE) | `rcode-error` | false |
| Safely parsed TC=1, regardless of RCODE/answers | `incomplete` | false |
| Exhausted resolver transport attempt(s) | `timeout` / `resolver-error` | false |

TC takes precedence over negative, filtering/sinkhole and DNSSEC interpretations.
Available safely parsed partial answers remain diagnostic data, accompanied by an
explicit incompleteness warning. Raw flags and RCODE remain inspectable. There is
no TCP fallback. Malformed/truncated wire buffers are ignored, without fabricated
records or deadline extension; absent a subsequent valid reply the existing
bounded transport timeout/fallback path applies. RCODE and TC replies themselves
do not cause endpoint fallback. Existing correlation and socket ownership remain.

Optional enrichment rejects truncated/error replies rather than inferring missing
DMARC, MX addresses or DNSSEC records. Omitted diagnostics are visibly marked.
DNSSEC diagnostics remain observations, not independent cryptographic validation.

## Burst aggregation and cache

All ten providers remain inspectable. Only complete primary diagnostics contribute
answer fingerprints. If any provider fails/is truncated, the overall comparison
is `partial-failure` when another provider completed, otherwise `incomplete` if
any provider was truncated, otherwise `resolver-error`. These aggregates have
`ok: false`, with a warning that no full-provider comparison/absence/filtering/
DNSSEC conclusion can be made. Individual meaningful errors are preserved.
`different-answer`, uniform `nxdomain`/`no-record` and the sinkhole heuristic apply
only when every provider completed. Resolver errors alone do not imply filtering.

Failed/truncated primary diagnostics, mixed failed bursts and diagnostics with
omitted optional enrichment are not cached. Complete positive and negative
diagnostics retain the existing 60-second single/300-second burst TTLs, zero-token
cache-hit behavior, and bounded cache/rate state. Cache metadata describes the
configured TTL; it is not an assertion that a failed diagnostic was stored.

Offline regression tests cover wire flags, malformed buffers, correlation,
classification, cache treatment, burst aggregation and existing resource budgets.
Frontend tests consume actual offline backend outputs through
`test/fixtures/dns-contracts.mjs`; no public DNS queries are performed.
