# Backend API reference

Routes are registered in [server.mjs](../backend/src/server.mjs) and the [DNS](../backend/src/dns-route.mjs), [HTTP](../backend/src/http-route.mjs), and [TLS](../backend/src/tls-route.mjs) route modules. Browser clients use relative `/api/...` requests through Vite in development or the Pages Function in production. Do not ship a backend credential in a browser client.

Registration lookup additionally uses [registration-route.mjs](../backend/src/registration-route.mjs).

## Authentication and service checks

The backend compares `X-Toolbox-Backend-Secret` exactly against server-side `BACKEND_SECRET`. A missing configured secret or missing/incorrect request secret returns **401**:

```json
{"error":"unauthorized"}
```

This is not the tool error envelope. Authentication is service-to-service, not user login or per-user authorization. The proxies inject the secret server-side and replace browser-supplied authentication/identity headers.

| Endpoint | Authentication | HTTP 200 body |
| --- | --- | --- |
| `GET /healthz` | Exempt only for the exact request URL `/healthz` (no query string) | `{"status":"ok","service":"toolbox-api"}` |
| `GET /api/ping` | Required | `{"ok":true,"message":"toolbox API reachable"}` |
| `GET /api/release` | Required | `{"ok":true,"revision":null,"archiveSha256":null,"apiContract":"toolbox-api-v1"}` locally/when release identity is unavailable |

Health reports process reachability, not resolver connectivity, capacity, or successful diagnostics. The Pages handler covers `/api/*`, not `/healthz`; use backend/operator-controlled health access. [Local examples](../README.md#local-development) exercise health and authenticated ping without external network work.

`/api/release` has `Cache-Control: no-store`. In an immutable production release,
`revision` is its lowercase 40-hex public commit and `archiveSha256` its 64-hex
archive digest. [release-info.mjs](../backend/src/release-info.mjs) reads the executing
source's resolved directory and regular `.archive-sha256` marker once at startup.
Neither labels from request/environment nor a later `current` switch change that
process's identity. No paths, private commits or configuration are returned. This
is operational evidence, not cryptographic attestation or full API compatibility.
The production workflow additionally probes all tool routes with invalid `{}` input
and checks exact validation envelopes before permitting frontend deployment.

## Diagnostic requests

POST bodies use `Content-Type: application/json`. Examples below describe contracts only; executing a valid diagnostic would perform outbound work.

### `POST /api/tools/dns-check`

Validator: [dns-check.mjs](../backend/src/tools/dns-check.mjs); client contract: [dnsTypes.ts](../frontend/src/tools/dns-checker/dnsTypes.ts).

```json
{"mode":"single","recordType":"A","resolverId":"cloudflare","query":"example.com","dnssec":true}
```

| Field | Contract |
| --- | --- |
| `mode` | Required: `single` or `burst`; no default. |
| `recordType` | Required; trimmed/uppercased: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA`, `PTR`, `SRV`. |
| `resolverId` | Required in single: `cloudflare`, `google`, `opendns`, `quad9`, `fortiguard`, `adguard`, `verisign`, `dnswatch`, `comodo`, `level3`, `neustar`. Omit in burst (null/empty also accepted). Burst uses the first ten listed, not Neustar. |
| `query` | One name, or a public IP for PTR. Ordinary name queries also accept `domain`/`name` aliases; PTR accepts `input`/`name`. |
| `service`, `protocol`, `domain` | Alternative SRV form: all three supply service, `tcp`/`udp` (optional leading underscore), and public domain. Otherwise `query`/`name` must be a complete `_service._tcp.domain` or `_service._udp.domain` name. This protocol describes SRV records, not DNS transport. |
| `dnssec` | Single-mode diagnostics enabled unless exactly `false`; burst disables these checks. Flags/record observations are not independent cryptographic validation. |

Name queries require a fully qualified/public-style name, IDNA normalization, 63-byte labels, and at most 253 textual bytes; one terminal root dot is accepted. Local/internal suffixes and IPs as ordinary names are rejected. TXT permits underscore owner labels (DMARC/DKIM/ACME); SRV has separate service/protocol rules. PTR requires a nonblocked public IPv4/IPv6 address. Custom resolver destinations and bulk inputs are rejected; transport is fixed **UDP**, with no TCP fallback or user-selected DoH/DoT.

Completed diagnostics return HTTP 200 with `ok`, `mode`, normalized `query`, `status`, resolver/provider details, `records`, `answer`/`authority`/`additional`, `diagnostics`, `warnings`, `dnssec`, `raw`, and duration. Burst also retains individual `providers` and aggregate comparison status.

- Complete positive **and legitimate negative** answers (NXDOMAIN/NODATA) can have `ok: true`.
- Resolver failures and incomplete/truncated replies have `ok: false` **without `error`**. Safely parsed partial records remain inspectable; this is not a successful complete answer or proof of absence.
- Operational/validation failures use the error envelope below instead.

`cache` contains `fromCache`, `cacheScope: "site"`, `cacheTtlSeconds`, `cacheAgeSeconds`, and `cacheExpiresInSeconds`. It is shared process-local cache state, not private browser storage. Complete cacheable diagnostics use 60 seconds single / 300 seconds burst; failed/truncated primaries and incomplete optional enrichment are not cached. Reported TTL alone does not mean a response was stored. Cache hits cost zero rate tokens; live single costs one, burst ten. See [DNS response semantics](../backend/DNS_RESPONSE_CONTRACTS.md) and [resource budgets](../backend/DNS_RESOURCE_BUDGETS.md).

### `POST /api/tools/http-header-check`

Validator: [http-header-check.mjs](../backend/src/tools/http-header-check.mjs); client contract: [httpHeaderTypes.ts](../frontend/src/tools/http-header-checker/httpHeaderTypes.ts).

```json
{"target":"example.com","protocolMode":"https","port":443}
```

- `target` is the preferred required string; `url`, `host`, `input` are aliases. Domain or HTTP(S) URL input is normalized to a public hostname. The entered URL path/query/fragment does **not** select the initial resource: checks start at `/`. URL scheme does not override `protocolMode`.
- `protocolMode`: `auto`, `http`, `https`, `both`; missing/unrecognized values fall back to `auto`. Auto starts at HTTP port 80 and follows validated redirects. Both runs HTTP 80 then HTTPS 443 sequentially.
- `port`: optional for explicit HTTP/HTTPS modes, default 80/443; numeric conversion must produce an integer on that scheme's allowlist. Auto/Both ignore this field. HTTP ports: **80, 8000, 8008, 8080, 8081, 8888**. HTTPS ports: **443, 4443, 8443, 8444, 9443, 10443**.
- IP literals, local/internal hostnames, and URL credentials are rejected. Non-default ports embedded in input URLs are rejected; use `port`. URL parsing can normalize away an explicit default port. All resolved addresses are validated; a mixed blocked/public answer is rejected. Each hop connects to a validated IP while retaining hostname Host/SNI and HTTPS certificate verification.
- At most two redirects are followed; each destination's scheme, credentials, hostname, port, and addresses are revalidated. Response bodies are discarded; headers are limited to 16 KiB. Findings are hints, not a full website security assessment.

HTTP 200 results contain normalized `input`, `budget` (`checksRequested`, `freshChecks`, `cachedChecks`, `tokensConsumed`), `cache.ttlSeconds` (60), `redirectLimit` (2), and `checks`. Each check includes protocol/port, checked URLs, status, duration, redirect information, **ordered header entries preserving duplicates**, interesting headers, findings, and cache age/expiry metadata.

A blocked/over-limit redirect can produce a completed HTTP 200 result with overall/check `ok: false`, findings and `blockedRedirect`, rather than an API `error`. Initial target/connection failures generally use the route error envelope. Successful protocol checks are cached independently; Both can reuse one cached protocol and charge only the fresh one. An ordinary second-protocol failure can retain the first successful protocol in cache, but cancellation/overall timeout cannot publish partial Both results. See [HTTP budgets and cleanup](../backend/HTTP_RESOURCE_BUDGETS.md).

### `POST /api/tools/tls-check`

Validator: [tls-check.mjs](../backend/src/tools/tls-check.mjs); client contract: [tlsTypes.ts](../frontend/src/tools/tls-certificate-checker/tlsTypes.ts).

```json
{"host":"example.com","port":443}
```

- `host`: required ASCII public-style hostname; trimmed/lowercased, at least two labels, maximum 253 characters / 63 per label. No IP literal, URL, wildcard, or terminal dot. Unicode must already be represented as an ASCII IDNA name; this validator does not perform IDNA conversion.
- `port`: required JSON integer, with **no default**: **443, 4443, 7443, 8443, 9443, 10443**. Numeric strings are not accepted.
- Blocked resolved addresses are filtered; at least one public address must remain. Connections use validated IPs and requested hostname SNI/identity checks. Unlike HTTP, mixed blocked/public answers are filtered rather than wholly rejected.

HTTP 200 / `ok: true` means inspection completed, **not** that the certificate is valid. The inspector intentionally connects with `rejectUnauthorized: false` so invalid certificates can be reported. `tls.authorized`/`authorizationError`, `summary.trusted`, `summary.hostnameMatches`, expiration, checks and warnings must be considered separately.

Results include host/port, resolved addresses, protocol/cipher, leaf `certificate`, `chain`, `issuerChain`, and certificate-type reason/confidence (including heuristics). `expiresAt` is epoch milliseconds; `expirationState` is `valid`, `expiring-soon` (within 30 days), `expired`, or `unknown`; rounded `daysRemaining` is display-only. Unknown expiration yields `summary.notExpired: null`.

Only the leaf has peer provenance. Runtime issuer links have unverified wire/store origin: `serverProvidedCertificateCount`, `issuerChainComplete`, and `summary.chainProvided` remain null. A self-signed CA is not evidence of a trusted root. No revocation lookup is performed; “not known weak” signature metadata is not a comprehensive security verdict. See [certificate evidence semantics](../backend/TLS_CERTIFICATE_RESULTS.md). TLS has no result cache or public cache/budget metadata.

### `POST /api/tools/rdap-lookup`

Body: `{"target":"example.com","protocolMode":"auto"}`. Supports IDNA domains,
individual IPv4/IPv6 identifiers and AS-prefixed decimal ASNs. `auto` is the default;
`rdap` and `whois` are exclusive. No URLs, bulk input or custom endpoints.
Auto falls back only for absent HTTPS RDAP discovery or query HTTP 405/501, never
for not-found, rate limits, temporary failures, malformed replies, security rejection,
timeouts, cancellation or exhausted deadlines. Completed results include structured
and raw data, outcome (`record`/`not_found`/`unknown`), actual protocol/source/time,
attempts, discovery freshness and result-cache metadata. Registration errors extend
the usual safe envelope with `attempts` and `rawResponses`.

See [complete registration contracts, limits and primary sources](../backend/REGISTRATION_LOOKUP.md).
Four live / one per client, 20-second overall deadline, 5-second transport attempt,
3-second DNS wait, 8 exchanges, two redirects/referrals, 256 KiB response / 1 MiB
bootstrap / 2 MiB total; no decompression. Rates are 20/client and 100/global per
minute including cache hits. Result cache: 128 entries, 512 KiB entry ceiling,
60-second TTL. WHOIS uses plaintext TCP/43; no-match is not purchase availability.

## Errors, admission, and cancellation

Known tool errors return:

```json
{"ok":false,"error":{"code":"INVALID_HOST","message":"Enter a valid public hostname."}}
```

| HTTP status | Route-level meaning |
| --- | --- |
| 400 | Listed validation/address-policy errors (including `DNS_LOOKUP_FAILED` for HTTP/TLS); stable tool code and safe message. |
| 429 | `RATE_LIMITED`: rolling rate/history limits. |
| 503 | `DNS_CAPACITY_EXHAUSTED`, `HTTP_CAPACITY_EXHAUSTED`, `TLS_CAPACITY_EXHAUSTED`: process-local capacity full; fail fast, not queued admission. |
| 504 | `DNS_DIAGNOSTIC_TIMEOUT`, `HTTP_DIAGNOSTIC_TIMEOUT`, `TLS_DIAGNOSTIC_TIMEOUT`: overall deadline. |
| 499 | Defensive `DNS_CHECK_CANCELLED`, `HTTP_CHECK_CANCELLED`, `TLS_CHECK_CANCELLED` mapping if a response can be delivered. Do not expect a body after route-observed disconnection. |
| 502 | Other known diagnostic/network errors or sanitized unexpected failures. |

This table does not replace endpoint-specific HTTP 200 diagnostic failures or the authentication 401. Malformed JSON uses Fastify's parser response (400 with `statusCode`, `code: "FST_ERR_CTP_INVALID_JSON_BODY"`, `error`, `message`), not the tool envelope. Framework errors such as authenticated unknown-route 404 also differ; clients must check status and response shape.

Limits are constants, not API parameters, and apply **per backend process**, not across replicas:

| Tool | Rate / live admission overview | Overall deadline |
| --- | --- | --- |
| DNS | 100 tokens / 5 minutes, 750 / hour per client; 6 live globally, 2 per client; 24 UDP sockets | 15 seconds single / 30 burst |
| HTTP | Fresh protocol costs 1 (Both up to 2); per client 80 / 5 minutes, 500 / hour; per target 30 / 5 minutes (500 hourly guard); global 350 / 5 minutes; 12 fresh protocol units, 2 live diagnostics per client, 12 sockets | 15 seconds Auto/HTTP/HTTPS / 25 Both |
| TLS | 20 admitted checks / minute per client, including failures; 8 live globally, 2 per client; at most 4 IP attempts, 2 parallel per check; at most 16 outbound sockets | 15 seconds asynchronous network deadline |

DNS/HTTP cache hits do not consume rate tokens or fresh capacity. DNS capacity rejection does not charge tokens; HTTP fresh capacity rejection occurs after rate charging. TLS retained client entries cap at 1,024 and fail closed when full. DNS/HTTP cache/history caps, eviction, and failed-result publication rules are detailed in [retained-state limits](../backend/RETAINED_STATE_LIMITS.md); TLS resource ownership is in [tls-network.mjs](../backend/src/tools/tls-network.mjs).

Disconnect/deadline cancellation closes owned network work and prevents subsequent work/cache publication. System DNS fallback in HTTP/TLS cannot be forcibly cancelled; outstanding lookups have separate caps until actual completion. Synchronous parsing/certificate work cannot be preempted. Timer delivery and socket close depend on event-loop progress, so deadlines are not hard real-time guarantees.

## Proxy-generated errors

Pages returns the structured `ok: false` error shape with `Cache-Control: no-store`: **503** `PAGES_PROXY_CONFIGURATION`, **502** `PAGES_PROXY_UNAVAILABLE`, or **499** `PAGES_PROXY_CANCELLED`. Backend status/body otherwise pass through, including 401; redirects are returned without automatic following. See [Pages implementation notes](../frontend/functions/README.md).

Development Vite returns **503** (missing secret) or **403** (LAN disallowed) `DEV_PROXY_DISABLED`, and **502** `DEV_PROXY_UNAVAILABLE` for an unreachable backend. Neither proxy has a production fallback. Capacity/rate errors should prompt a delayed retry, not a rapid retry loop. No endpoint guarantees a retry-after duration.
