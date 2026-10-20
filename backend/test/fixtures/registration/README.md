# Registration fixture provenance

Research date: 2026-10-19. Tests are entirely offline. All contact values are synthetic.
No fixture proves every domain, disclosure policy or future response of a registry.

| Files | Derivation | Evidence and limits |
| --- | --- | --- |
| `sknic-whois.txt` | Live-derived | One POST `query=sk-nic.sk&lang=en_SK` to the registry's https://whois.sk-nic.sk/ web form. HTML `<pre>` decoded; domain, holder, contact identifiers, names, organization numbers, phone/address/email replaced. Original three-object shape and calendar dates retained. TCP/43 was inaccessible; web/port-43 equivalence is not independently verified. Role/section semantics confirmed by https://sk-nic.sk/en/faq-en/general/ . |
| `net-rdap.json`, `cz-rdap.json`, `de-rdap.json`, `uk-rdap.json`, `org-rdap.json`, `tech-rdap.json` | Live-derived | GETs to registry services listed below. All entity cards, identifiers, notice text and links sanitized; object structure, event precision/actions, redaction descriptors, secureDNS and extension shapes retained. DNSKEY/DS values are public technical data. Not complete byte-for-byte captures. |
| `eurid-whois.txt` | Historical mirror-derived, partial | Section layout cross-checked against https://whois.nettools.cz/whois/registrar.eu/ (cached 2025-03-19). Names, addresses and DNSKEY replaced; disclaimer omitted. Official https://help.eurid.eu/ and IANA confirm WHOIS use/service identity, but current TCP/43 format was **not** independently retrieved. `Keys` retained as evidence; no invented DS conversion. |
| `cznic-whois.txt` | Documentation-derived plus synthetic edge cases | https://www.nic.cz/page/420/ documents domain/contact/nsset relations and templates. Synthetic admin-first ordering, conflicting contact/nsset dates and email added. Modern `expire` variant is regression-only, not a new live validation. |
| `cznic-auxiliary-adversarial-whois.txt` | Synthetic adversarial regression | Derived from the documented CZ.NIC object/reference shape above. NSSET and KEYSET deliberately contain hostile status, lifecycle, registrar, holder and DNSSEC/DS-looking fields. These injected attributes do **not** claim to reproduce actual CZ.NIC output. Only a unique referenced NSSET's nameservers may be promoted. |
| `nominet-whois.txt` | Documentation-derived | https://registrars.nominet.uk/uk-namespace/registration-and-domain-management/query-tools/whois/whois-detailed-instructions/ . Synthetic values instantiate its indented section/date/tag syntax. No live WHOIS claim. |
| `denic-whois.txt` | Documentation-informed synthetic | https://www.denic.de/en/services/whois-service/ confirms technical/status/last-change data via TCP/43. Layout is a conservative regression example; no live WHOIS claim. |
| `gtld-whois.txt` | Synthetic | Flat labelled domain data and DS regression; no claim that this DS syntax is currently published by every gTLD service. Actual gTLD coverage comes from live-derived RDAP fixtures. |

Live RDAP research targets (not test network destinations):

- https://rdap.verisign.com/net/v1/domain/example.net
- https://rdap.nic.cz/domain/nic.cz
- https://rdap.denic.de/domain/denic.de
- https://rdap.nominet.uk/uk/domain/nominet.uk
- https://rdap.publicinterestregistry.org/rdap/domain/example.org
- https://rdap.radix.host/rdap/domain/nic.tech

A .com HEAD request succeeded, but two subsequent GET attempts returned an intermediary
error/non-JSON body. .com shares the documented Verisign service family; `.net` fixture
coverage must not be called independently verified .com response compatibility.

Auxiliary-isolation tests also mutate EURid/Nominet sections and SK-NIC, DENIC,
gTLD and unknown-service objects with synthetic hostile labels. Nominet labelled
DS lines in a DNSSEC section test scope/provenance only, not current registry DS
publication. Missing separators and object-kind masquerading are malformed-input
regressions. None of these adversarial tests adds live registry validation.
