# RDAP / WHOIS Lookup: API, evidence and resource policy

Registration lookups are on demand only. No scheduled refresh,
monitoring, notifications, persistence, or history is added.

## Primary documentation verified 2026-10-14

- [RFC 9224](https://www.rfc-editor.org/rfc/rfc9224.html): bootstrap format,
  domain label-wise longest match, IP longest-prefix match and ASN ranges.
- IANA registries: [DNS](https://www.iana.org/assignments/rdap-dns/rdap-dns.xhtml),
  [IPv4](https://www.iana.org/assignments/rdap-ipv4/rdap-ipv4.xhtml),
  [IPv6](https://www.iana.org/assignments/rdap-ipv6/rdap-ipv6.xhtml),
  [ASN](https://www.iana.org/assignments/rdap-asn/rdap-asn.xhtml). These document
  `https://data.iana.org/rdap/{dns,ipv4,ipv6,asn}.json`.
- [IANA WHOIS service](https://www.iana.org/whois): domain, IP and AS queries,
  TCP port 43. Discovery queries `whois.iana.org`; domain discovery submits the
  ASCII TLD, number discovery the canonical identifier. The
  [IANA server guide](https://www.iana.org/help/whois) explicitly documents
  `whois.iana.org`, accepted identifiers, colon-delimited UTF-8 replies and `refer:`.
  Exact `refer:` / `whois:` fields select the registry; conflicts are rejected.
  No guessed or commercial registry mappings.
- [IANA .COM delegation](https://www.iana.org/domains/root/db/com.html) documents
  its WHOIS and RDAP endpoints; reviewed as a primary discovery example, not
  embedded as a mapping or asserted as a live connectivity test.
- [RFC 3912](https://www.rfc-editor.org/rfc/rfc3912.html): TCP/43, CRLF query,
  server EOF completion, no encoding negotiation, confidentiality or integrity.
- [ICANN EPP/RDAP status definitions](https://www.icann.org/resources/pages/epp-status-codes-2014-06-16-en):
  used for standard status explanations; unknown registry codes are not interpreted.

Documentation retrieval is **not** verification of live registry lookup
connectivity. All automated tests use offline fixtures or local/adapted services.

## Input and API contract

`POST /api/tools/rdap-lookup`, authenticated by the existing backend hook.
JSON body limit 2 KiB; only `{ target, protocolMode? }` is accepted.
`protocolMode` defaults to `auto`; other accepted values are `rdap`, `whois`.
Unknown fields/modes, custom endpoints, URLs, credentials, ports, CIDRs, bracketed
IP input, IPv6 zones, controls (including Unicode format controls), separators,
and bulk input are rejected before any network work.

Classification order: case-insensitive `AS` plus decimal digits (1..4294967295,
remove leading zeroes); Node-valid individual IPv4/IPv6; otherwise IDNA domain.
IPv4 disallows ambiguous leading zeroes. IPv6 uses URL-standard lowercase
compressed hexadecimal, including mapped identifiers. Domains trim outer
ordinary whitespace, lowercase/IDNA A-label conversion, accept one terminal root
dot, require at least two valid LDH labels, 63 bytes per label / 253 total, and
a nonnumeric final label. Browser validation mirrors this; backend validates
independently. Subdomains are queried as entered, not guessed registrable domains.

**Queried IPs are registration identifiers, not destination addresses.** Reserved
or mapped identifiers may be queried at a safe registry; no connection is made
to those identifiers. ASN special-purpose/private ranges likewise are identifiers.

HTTP 200 / `ok: true` means an inspectable completed result, not purchase
availability or proof of registrant identity. `outcome` is `record`, `not_found`,
or `unknown` (unrecognized/conflicting WHOIS, including mismatched domain/ASN
identifiers when recognizable). Results include original/canonical
input, selected mode, actual protocol, final source, lookup timestamp, normalized
fields/details/unknown/conflicts, discovery metadata, attempted protocols/hops,
raw query/discovery/referral responses, fallback reason, cache age/TTL and warnings.
RDAP raw text is retained without JSON reserialization; unknown extensions stay
in raw JSON. WHOIS retains the received text decoded as UTF-8; invalid legacy
bytes may be replaced (not a byte-exact archival format). Bootstrap JSON is not
copied into each result.

Errors retain `{ ok:false, error:{code,message}, attempts, rawResponses }`, with
safe fixed messages and no exceptions/stacks. Pre-admission errors have empty
diagnostics. HTTP status mappings:

| Status | Codes |
| --- | --- |
| 400 | `INVALID_INPUT`, `INVALID_MODE`, `SECURITY_REJECTION` |
| 429 | `RATE_LIMITED`, `UPSTREAM_RATE_LIMITED` |
| 503 | `CAPACITY_EXHAUSTED`, `DISCOVERY_UNAVAILABLE`, `UNSUPPORTED_DISCOVERY`, `PROTOCOL_UNAVAILABLE` |
| 504 | `UPSTREAM_TIMEOUT`, `DEADLINE_EXHAUSTED` |
| 499 | `CANCELLED` (defensive mapping; disconnected clients receive no body) |
| 502 | `TEMPORARY_FAILURE`, `UPSTREAM_FAILURE`, `MALFORMED_REPLY`, `RESPONSE_TOO_LARGE`, `LIMIT_EXCEEDED`, `LOOKUP_FAILED` |

Fastify parser/body-limit and proxy/authentication errors remain their existing
separate contracts. The frontend rejects unexpected API shapes and reports
failure rather than displaying asserted unvalidated values.

## Exact protocol policy

- Auto starts with IANA RDAP discovery. WHOIS fallback is allowed **only** for
  `UNSUPPORTED_DISCOVERY` (no matching bootstrap service or no HTTPS service)
  or `PROTOCOL_UNAVAILABLE` (the discovered RDAP query returns HTTP 405 or 501).
- RDAP 404 is `not_found` only with JSON content and `errorCode:404`; an arbitrary
  HTML/empty 404 is malformed. Domain 404s containing registration-object fields
  are also malformed rather than negative findings. No fallback for either case.
- No fallback for HTTP 429, 401/403, 5xx other than 501, bootstrap failure,
  connection/DNS failure, malformed response, oversized/over-budget reply,
  security rejection, timeout, cancellation or exhausted overall deadline.
- RDAP-only and WHOIS-only never switch. All attempts and available bounded raw
  responses survive ordinary failures/fallback. A valid no-match is not evidence
  of domain purchase availability. WHOIS denial/rate/temporary-failure detection
  runs before interpreting/following referrals; unfamiliar formats stay unknown.
- Domain WHOIS negatives require complete supported diagnostic lines, no parsed
  objects or unexplained content, and matching identifiers where published.
  `Domain not found.` is recognized only as the entire trimmed response from
  `whois.sk-nic.sk` on WHOIS/43, selected by the responding service adapter, not
  the query's TLD. This user-confirmed wording for `notregistered.sk` is covered
  offline; it is not a new live connectivity or authenticated-identity claim.
- WHOIS follows only explicit `Registrar WHOIS Server`, `Whois Server`,
  `ReferralServer` or `refer` lines after IANA discovery; conflicting endpoints
  are malformed. Loops track server + query (IANA-hosted .INT can use the same
  server for distinct discovery/registration queries). Loops and excess depth
  fail explicitly, not partial success.

## Discovery/cache behavior

Four process-local bootstrap entries, each at most 1 MiB received JSON. Fetch on
demand only over verified HTTPS. Validate format/version/publication/services,
entries and URLs before publication. HTTP-only candidate URLs are not connected.
Choose the first HTTPS candidate in the longest matching service; no retry of
other addresses/endpoints is implemented.

Bootstrap freshness uses HTTP `Cache-Control: max-age`, then `Expires`, otherwise
24 hours, clamped to **60 seconds..24 hours**. Expired discovery must refresh;
refresh failure fails closed (no stale service selection). Failures are retained
for 30 seconds in at most four cooldown entries; cancellation/deadline/capacity
failures do not poison refresh. Concurrent misses may fetch independently but
are charged and bounded by admission. Fetch source/time/publication, age,
expiration and freshness are exposed. Result-cache hits can retain a previous
lookup for their separate 60-second TTL, including discovery that has since
expired; its current freshness/age is updated and shown, without new outbound work.

WHOIS discovery is performed through IANA each fresh WHOIS run; no standalone
mapping cache. Its source/fetch time is retained in the result and `expiresAt`
is null (not a periodically refreshed WHOIS mapping).

Result cache: **128 entries**, **512 KiB serialized result per entry**, **60-second
TTL from completion**, expiration-first/LRU eviction. Keys include canonical kind,
identifier and selected mode. Only completed records/not-found are cached; unknown,
failed, cancelled and expired operations never publish. Oversized normalized/raw
combinations can be returned but are not cached. In-memory cache is shared across
clients and lost on restart; it is not historical tracking or private storage.
Expired entries are removed on subsequent cache access/publication, not by a timer;
TTL bounds reuse, not guaranteed physical memory erasure or idle retention time.

## Security and finite resource limits

All limits apply **per process**, not across replicas; no queue, shell, external
WHOIS executable, new dependency, persistent cache or runtime remote parser.

| Resource | Limit |
| --- | --- |
| Overall monotonic network/operation deadline | 20 seconds across discovery, protocols and hops |
| One transport attempt | 5 seconds, no retries; one validated resolved address per hop |
| DNS wait | 3 seconds; at most 32 answers, reject the entire mixed set |
| Exchanges | 8 per operation (bootstrap/query/redirect/WHOIS discovery/referral all count) |
| RDAP redirects | 2; bootstrap redirects are not followed |
| WHOIS referrals | 2 including IANA -> registry; at most one further referral |
| Received response body | 256 KiB each; bootstrap 1 MiB |
| Total received body bytes | 2 MiB across all operation exchanges |
| HTTP headers | 16 KiB per response |
| Decompression | None; request identity encoding; reject any nonidentity encoding |
| Concurrent diagnostics | 4 global / 1 per client |
| Active or closing transport sockets | 8 global; slot held until socket close |
| Outstanding OS DNS work | 8 global; slot held until actual settlement even after cancellation |
| Rolling request rate | 20 per client / 100 global per 60 seconds, including cache hits and capacity rejections |
| Client rate histories | 2,048 identities / 20 events each; never evict live rate history to admit an identity |
| JSON parsing | Depth 32 before parse; 20,000 visited nodes after parse; entity depth 8 |
| Bootstrap parsing | 4,000 services, 4,000 entries/service, 16 URLs/service, 253-character entry, 2,048-character URL; node/byte limits also apply |
| WHOIS parsing | 4,000 lines / 8,192 characters per line; body cap also applies |

Only hostname HTTPS/443 RDAP and hostname TCP/43 WHOIS destinations are accepted.
URLs are rejected for credentials, fragments, control/format characters, unsupported
schemes/ports, local suffixes, literals, and (WHOIS) paths/query strings. Every
redirect and referral is revalidated and resolved. All DNS addresses must be safe;
private/reserved/mapped addresses and mixed public/blocked sets are rejected.
The existing HTTP reserved-address helper is reused, with additional conservative
IPv6 global-unicast-only and transition/documentation exclusions; IPv4 192.88.99/24
is also blocked. Connections are pinned to the validated IP, not a later hostname
lookup. RDAP preserves Host/SNI and normal certificate/hostname verification; it
does not share the TLS inspection exception. WHOIS is plaintext/unauthenticated;
IANA discovery is authoritative service discovery, **not transport authentication**.

Disconnect cancellation destroys owned requests/responses/sockets, stops later
hops/fallback/cache publication, removes route/abort listeners, and releases
admission. OS DNS cannot be forcibly cancelled; independent slots prevent a caller
timeout from making its pending work invisible. Socket close and timers depend
on event-loop progress. Bounded synchronous parsing cannot be preempted; deadlines
are not hard real-time guarantees.

## UI, exports and unsupported cases

Lookup metadata precedes the overview: selected mode, actual protocol, final source,
UTC lookup timestamp, cache age/TTL, fallback reason, query and outcome. Domain records
show a prominent domain name, expiration date and automatically calculated remaining
time, separate Domain registrant and Registrar cards, then Additional information
(creation/update dates, individual nameservers and conditional published DNSSEC).
Domain `not_found` outcomes instead show **No registration record found** and an
explicit warning that this does not guarantee purchase or registration availability.
Domain `unknown` outcomes show **Registration status could not be determined**.
Neither renders empty registration cards; both retain metadata, diagnostics,
raw evidence, copying and downloads. Concise image exports use the same outcome
presentation without embedding detailed/raw evidence. IP/ASN presentation is unchanged.
IPs show queried address,
registered range/CIDR, network name, holder, registry/RIR, country and contacts;
ASNs show queried ASN and registered ASN range, ASN name, holder, registry/RIR,
country and contacts. Missing values are explicitly unavailable, not negative findings.
Expiration is domain-only, fixed at lookup completion (also for cache hits), with
no recalculation button, polling or automatic requests. All other published fields,
conflicts, unknown values and raw replies remain available separately and in the
appropriate exports.

RIR names are presentation-only exact service labels for the five HTTPS endpoints
published in [IANA IPv4 bootstrap](https://data.iana.org/rdap/ipv4.json), using
organization names from [IANA number resources](https://www.iana.org/numbers)
(verified 2026-10-14). They never override discovery or select destinations.
Identity requires a current verified IANA bootstrap selection for this IP/ASN,
unambiguous matching service labels, and a verified final HTTPS response within
an exact selected service base. A hostname substring, contact/holder name or
response-provided link is never an identity proof. Off-service redirects, new or
unrecognized endpoints, ambiguous service labels and WHOIS-only results show
unavailable/unknown identity. WHOIS discovery is unauthenticated; its published
organization claims remain in raw output, not promoted to verified RIR identity.
For RDAP, `normalized.details.registryEvidence` retains candidate labels, matched bases,
IANA source/publication and the reason for a known/unknown finding. Actual protocol,
final source URL, lookup timestamp, attempts and raw responses remain independent.

Existing registry entry `rdap-whois` is activated without a new ID. Structured
overview includes unavailable fields, conflicts and attribution; expandable JSON
details expose contacts/events/status/nameservers/DNSSEC/notices/unknown data.
Raw responses and untrusted links are rendered as text, never HTML, fetched
assets, active hyperlinks or automatic navigation. No overview field has an
individual Copy button. Copy the complete normalized result; download normalized
JSON, individual original raw JSON/text, or raw-with-metadata JSON; copy the structured result image using
existing local export components. Original raw files intentionally have no added
headers; use **raw-with-metadata** for the query, actual protocol, source, timestamp,
attempts and cache attribution. No remote rendering. Expiration is calculated on
lookup completion, without a timer; ambiguous/non-timezone
or conflicting WHOIS dates produce no invented countdown.

### Domain contact normalization (additive v3 fields)

The existing `fields: Record<string, string[]>` contract is unchanged. Optional
additive keys are `Registrant name`, `Registrant organization`,
`Registrant organization ID`, `Registrant phone`, `Registrant email`,
`Registrar organization`, `Registrar code`, `Registrar phone`, `Registrar email`;
the existing `Registrar` key remains the registrar name. Conflicting primary values
are withheld, with all candidates retained in `details.attribution` and raw replies.
Original WHOIS fields/unknowns and raw replies retain source
wording. RDAP contact details retain roles, handles, public IDs, values and original
`vcardArray`/entity redaction data; `details.redacted` retains top-level descriptors.
The existing browser string-array validator covers all additive fields.

Only direct domain entities with explicitly `registrant`/`registrar` roles supply
these overview fields. Roles on nested entities describe the containing entity,
not the domain. jCard `fn` (or structured `n` if no nonempty `fn`),
structured/multi-valued `org`, `tel` and `email` are supported. Nested abuse,
administrative and technical contacts are never inherited. Phone/email from a
card bearing both an ordinary and abuse/admin/technical role are too ambiguous
to promote; the card stays in detailed data. A card bearing both `registrant` and
`registrar` roles does not attribute its shared name, organization, phone, email
or generic organization IDs to either overview card; these remain detailed evidence.
Explicit registrar-typed public IDs and role-specific redaction descriptors remain
attributable, as do separate direct single-role entities. Multiple competing
direct entities for one role do not form a combined primary identity.
Entity handles and `uid` never become organization IDs. Registrant organization
IDs require explicit `org-id`, `x-org-id`,
`x-organization-id`, `x-company-number`, or public ID types Organization ID/Identifier,
Company Number/Registration Number/Registration ID, Legal Entity Identifier/LEI.
Registrar public IDs require IANA Registrar ID/Identifier or explicitly named
(Registry/Registry-specific) Registrar ID/Identifier/Code types. Codes show the
published system; an unqualified Registrar ID/Code is labeled **system unspecified**,
not asserted to be IANA. Registrar organization IDs are not registrar codes.

WHOIS accepts explicit `Registrant`/`Registrar` prefixes with Name,
Organization/Organisation, Phone/Phone Number/Telephone, Email/E-mail,
and registrant Organization/Organisation ID or Company Number. Space, hyphen and
underscore separators are supported. `Registrar`, `Registrar IANA ID`, `Registrar ID`
and `Registrar Identifier/Code` are also recognized. Bare `Registrar` supplies a
name only for verified flat gTLD syntax; adapters for handle-based registries
retain it as a registry-specific code. Explicit `Registry Registrar
ID/Identifier/Code` (including Registry-specific) and `Registrar Registry
ID/Identifier/Code` identify the registry code system; only explicitly IANA-labeled
codes claim IANA. Generic Name/Organization/Email fields and `Registrant ID` handles are
not promoted by the generic fallback. Abuse contacts retain their separate labels.
Verified SK-NIC and CZ.NIC adapters resolve role/contact references inside the same
response; EURid and Nominet adapters use explicit sections. No additional contact
queries occur. Unrecognized blocks, unresolved handles, arbitrary public ID types, text-vCard extensions,
and free-text/JSONPath-only privacy descriptions remain detailed/raw evidence.
No extra entity resolution or upstream request is made.

Missing values display **Unavailable**. **Redacted** requires an explicit upstream
marker (Redacted, Redacted for Privacy/GDPR, Data Redacted, Not Disclosed, Withheld
for Privacy) or a field-specific RFC 9537 `name.type` with a recognized method.
Partial-value redaction is labeled separately; fragments and replacement contacts
remain in evidence, not presented as complete unredacted contact values. RFC 9537's
omitted method defaults to removal. Registered whole-contact redactions are supported.
General notices, privacy-proxy organization names and empty strings do not imply
redaction. Unrecognized descriptors remain evidence, not invented field mappings.

Published DNSSEC is registry metadata, not live chain validation. Boolean
`delegationSigned` gets signed/unsigned wording; every published `dsData` entry
has its own card in source order, with key tag, numeric algorithm/digest type and
known descriptive names, plus the full wrapping digest. Unknown codes remain
visible; malformed fields are flagged without coercion and remain in detailed data.
Known digest types require their exact byte length: SHA-1 20, SHA-256 32,
GOST R 34.11-94 32 and SHA-384 48. Unknown types retain their published numeric
code and digest without an assumed length; invalid known lengths retain the
original digest and trigger the malformed-fields warning.
Absent metadata hides the subsection. WHOIS status text does not imply DS records.

### Record-aware domain WHOIS and provenance

`registration-whois.mjs` tokenizes bounded WHOIS text into blank-separated objects
and indented sections. Each entry retains its original key, value and 1-based line.
Exactly one matching domain object is required; other objects never contribute its
dates. Record associations grant explicit extraction scopes; an associated object
never gains the generic domain extractor's contact, registrar, status or DNSSEC fields.

| Record / section | Authorized normalized contributions |
| --- | --- |
| Unique matching flat domain object | Domain-local dates, nameservers, status, explicitly labelled DNSSEC/DS, role-prefixed contacts and registrar IDs |
| Nominet `Domain name` section | Domain identifier only |
| Exactly one CZ.NIC NSSET matching exactly one domain reference | Nameservers only; no contacts, registrar, status, dates or DNSSEC/DS |
| EURid / Nominet `Name servers` | Nameservers only |
| Nominet `Relevant dates` | Documented `Registered on`, `Expiry date`, `Last updated` labels only |
| Nominet `Registration status` | Status only |
| Nominet `DNSSEC` | Published DNSSEC and explicitly labelled DS evidence only; DS section regression syntax is synthetic, not live verification |
| EURid `Keys` | Labelled `flags:… protocol:… algorithm:… pubKey:…` DNSKEY evidence only; no inferred DS |
| Referenced SK-NIC / CZ.NIC contact or explicit EURid / Nominet role section | That role's contact properties only; SK-NIC registrar's explicit registry ID / Nominet tag retain their ID system |
| Other objects / sections, including CZ.NIC KEYSET | Original evidence only |

Section permissions are adapter-specific: EURid does not inherit Nominet's date,
status or DNSSEC section syntax. The first object anchor establishes its kind;
an NSSET containing a later contact ID cannot resolve as a holder. Duplicate
references/objects remain in uniqueness checks. Ambiguous repeated object anchors
without separators suppress extraction rather than assigning following attributes
to a guessed object. Unknown fields and original entry line numbers remain in
`details.records` / `unknown`; original text remains in `rawResponses`.

`registration-whois-adapters.mjs` selects syntax from an exact actual responding
TCP/43 service hostname, never the queried domain suffix or an earlier referral.
WHOIS remains unauthenticated: service matching selects a format, not proof of identity.
Unknown services use only conservative, domain-local explicit labels.

`details.attribution` is an additive map of field states (`available`, `ambiguous`,
`missing`, `redacted`, `unsupported`), protocol/source and original record/role/location
evidence. Lookup binds it to the final service; matching `rawResponses` contains the
original response. RDAP contact paths retain their parent, original card and events;
unknown extensions stay in `details.extensions`. Ambiguous fields stay out of the
primary overview and image. Evidence remains in normalized/full raw exports.

`YYYY-MM-DD` means a calendar date. Nominet's documented `DD-Mon-YYYY` converts to
that precision only. Invalid or timezone-ambiguous timestamps stay in evidence.
No timezone, midnight expiration or exact countdown is inferred. WHOIS explicit
`DS Record` / `ds-rdata` lines preserve every record and unknown numeric code;
DNSKEY/KEYSET data is not converted into fabricated DS data.

Fixture provenance and independently verified versus inferred coverage are recorded
in `test/fixtures/registration/README.md`. Passing synthetic fixtures is not live
registry validation. IANA bootstrap omissions (including an independently operated
RDAP service absent from bootstrap) do not authorize discovery bypasses.

Unsupported: bulk/CIDR/search/entity queries, custom upstreams, HTTP RDAP,
compressed bodies, registry-specific WHOIS flags/encodings not covered by generic
ASCII query + UTF-8 display, implicit/free-text referrals, extra referral levels,
multiple-address/base-URL retries, BGP, geolocation verification, live DNSSEC,
purchase availability guarantees, monitoring and historical tracking. Missing
registration fields are unavailable, not negative findings.
