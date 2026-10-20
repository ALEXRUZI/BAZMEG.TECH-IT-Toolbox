import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { request as localRequest } from "node:http";
import Fastify from "fastify";
import { normalizeRegistration, ipNumber, RegistrationError } from "../src/tools/registration-input.mjs";
import { createRegistrationOperation, resetRegistrationState, registrationState, REGISTRATION_LIMITS as L, acquireRegistrationResource } from "../src/tools/registration-resources.mjs";
import { resetBootstrapState, matchBootstrap, validateBootstrap, registryEvidence } from "../src/tools/registration-discovery.mjs";
import { validateRegistrationDestination, blockedRegistrationAddress, resolveRegistrationHost, transport } from "../src/tools/registration-network.mjs";
import { parseRdap, parseWhois, boundedJson, whoisReferral } from "../src/tools/registration-parse.mjs";
import { lookupRegistration } from "../src/tools/registration-lookup.mjs";
import { registerRegistrationRoute } from "../src/registration-route.mjs";

const bootstrap = { version: "1.0", publication: "2026-10-01T00:00:00Z", services: [[["com", "xn--p1ai"], ["https://registry.example.org/rdap/"]]] };
const domain = { objectClassName: "domain", ldhName: "example.com", handle: "D-1", status: ["active"], nameservers: [{ ldhName: "ns1.example.com" }], events: [{ eventAction: "expiration", eventDate: "2030-01-01T00:00:00Z" }], secureDNS: { delegationSigned: true }, entities: [{ handle: "R-1", roles: ["registrar"], vcardArray: ["vcard", [["fn", {}, "text", "Fixture Registrar"]]] }], remarks: [{ description: ["<script>not executable</script>"] }] };
const json = (value, status = 200, headers = {}) => ({ status, headers: { "content-type": "application/rdap+json", ...headers }, text: JSON.stringify(value) });
const text = (value) => ({ status: 200, headers: {}, text: value });
function reset() { resetRegistrationState(); resetBootstrapState(); }
function fake(responses, extra = {}) {
  const calls = [];
  return { calls, clientIp: "fixture-client", lookup: async () => [{ address: "8.8.8.8", family: 4 }],
    transport: async (request) => { calls.push(request); const value = responses.shift(); if (value instanceof Error) throw value; if (typeof value === "function") return value(request); assert.ok(value, "No unexpected upstream call"); return value; }, ...extra };
}
const query = (protocolMode = "auto", target = "example.com") => ({ target, protocolMode });
const code = (value) => (error) => error instanceof RegistrationError && error.code === value;

test("IP and ASN registry identity requires exact IANA discovery and final response evidence", async () => {
  for (const [target, entry, record] of [
    ["8.8.8.8", "8.0.0.0/8", { objectClassName: "ip network", startAddress: "8.8.8.0", endAddress: "8.8.8.255", cidr0_cidrs: [{ v4prefix: "8.8.8.0", length: 24 }] }],
    ["2606:4700::1111", "2606::/16", { objectClassName: "ip network", startAddress: "2606:4700::", endAddress: "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", cidr0_cidrs: [{ v6prefix: "2606:4700::", length: 32 }] }],
    ["AS13335", "13335-13335", { objectClassName: "autnum", startAutnum: 13335, endAutnum: 13335 }],
  ]) {
    reset(); const base = "https://rdap.arin.net/registry/";
    const options = fake([json({ ...bootstrap, services: [[[entry], [base]]] }), json({ ...record, name: "Fixture network", country: "US", entities: [{ roles: ["registrant"], vcardArray: ["vcard", [["fn", {}, "text", "Holder One"], ["fn", {}, "text", "Holder Two"]]] }], privateExtension: { retained: true } })]);
    const result = await lookupRegistration(query("rdap", target), options);
    assert.deepEqual(result.normalized.fields["Registry / RIR"], ["ARIN"]);
    assert.equal(result.normalized.details.registryEvidence.service, base);
    assert.equal(result.normalized.details.registryEvidence.source, result.discovery.source);
    assert.ok(result.normalized.conflicts.includes("Registered holder"));
    assert.deepEqual(result.normalized.fields["Registered holder"], ["Holder One", "Holder Two"]);
    assert.equal(result.normalized.fields.Registrar, undefined);
    assert.equal(result.protocol, "rdap"); assert.equal(result.rawResponses[0].source, result.source);
    assert.equal(JSON.parse(result.rawResponses[0].text).privateExtension.retained, true);
    if (target.startsWith("AS")) assert.deepEqual(result.normalized.fields["ASN range"], ["AS13335 – AS13335"]);
    else { assert.deepEqual(result.normalized.fields.CIDR, [target.includes(":") ? "2606:4700::/32" : "8.8.8.0/24"]); assert.deepEqual(result.normalized.fields["Registered range"], [`${record.startAddress} – ${record.endAddress}`]); }
  }
});
test("registry identity stays unknown for spoofed names, redirects, domains and ambiguous discovery", () => {
  const discovery = { source: "https://data.iana.org/rdap/ipv4.json", publication: bootstrap.publication };
  for (const [kind, services, source] of [
    ["ipv4", ["https://arin.example.org/"], "https://arin.example.org/ip/8.8.8.8"],
    ["ipv4", ["https://rdap.arin.net/registry/"], "https://rdap.arin.net/other/ip/8.8.8.8"],
    ["ipv4", ["https://rdap.arin.net/registry/"], "https://other.example.org/ip/8.8.8.8"],
    ["asn", ["https://rdap.arin.net/registry/", "https://rdap.apnic.net/"], "https://rdap.apnic.net/autnum/13335"],
    ["domain", ["https://rdap.arin.net/registry/"], "https://rdap.arin.net/registry/domain/example.com"],
  ]) assert.equal(registryEvidence(kind, services, source, discovery).name, null);
});
test("WHOIS unknown registry and missing fields are not filled from hostname or holder", async () => {
  reset(); const result = await lookupRegistration(query("whois", "AS13335"), fake([text("as-block: 13335-13335\norganisation: ARIN\nwhois: arin.example.org\n"), text("aut-num: AS13335\norg-name: Fixture Holder\ncustom: preserved\n")]));
  assert.equal(result.normalized.fields["Registry / RIR"], undefined);
  assert.equal(result.normalized.fields["Network / ASN name"], undefined);
  assert.deepEqual(result.normalized.unknown.custom, ["preserved"]);
  assert.equal(result.rawResponses.length, 2);
});

test("classification canonicalizes IDN, addresses and AS-prefixed ASNs without resolving identifiers", () => {
  for (const [target, canonical, kind] of [[" EXAMPLE.COM. ", "example.com", "domain"], ["bücher.de", "xn--bcher-kva.de", "domain"], ["пример.рф", "xn--e1afmkfd.xn--p1ai", "domain"], ["as00013335", "AS13335", "asn"], ["2606:4700:0000:0000:0000:0000:0000:1111", "2606:4700::1111", "ipv6"], ["127.0.0.1", "127.0.0.1", "ipv4"], ["::ffff:127.0.0.1", "::ffff:7f00:1", "ipv6"]]) assert.deepEqual(normalizeRegistration({ target }), { original: target, canonical, kind, protocolMode: "auto" });
  assert.equal(ipNumber("::ffff:127.0.0.1"), ipNumber("::ffff:7f00:1"));
});
test("strict input rejects endpoints, controls, ports, prefixes, bulk and malformed identifiers", () => {
  for (const target of ["", "https://example.com", "example.com:43", "a.com b.com", "a.com\nb.com", " a.com\t", "a.com,b.com", "example.com/path", "example.com?upstream=x", "user@example.com", "[::1]", "fe80::1%eth0", "8.8.8.8/24", "010.0.0.1", "999.0.0.1", "12345", "AS0", "AS4294967296", "a..com", "a.com\u200b", "a.com\0", "-flag", "a".repeat(64) + ".com"]) assert.throws(() => normalizeRegistration({ target }), code("INVALID_INPUT"), target);
  assert.throws(() => normalizeRegistration({ target: "example.com", upstream: "https://bad.org" }), code("INVALID_INPUT"));
  assert.throws(() => normalizeRegistration(query("both")), code("INVALID_MODE"));
  assert.throws(() => normalizeRegistration(query(null)), code("INVALID_MODE"));
});
test("RFC9224 label-wise longest, IP prefix and ASN range discovery", () => {
  const data = { ...bootstrap, services: [[["com"], ["https://one.example.org/"]], [["example.com"], ["https://two.example.org/"]]] };
  assert.equal(matchBootstrap(validateBootstrap(data, "domain"), normalizeRegistration(query("auto", "a.example.com"))), "https://two.example.org/");
  assert.equal(matchBootstrap(data, normalizeRegistration(query("auto", "notexample.com"))), "https://one.example.org/");
  for (const [kind, target, entries] of [["ipv4", "8.8.8.8", ["0.0.0.0/0", "8.8.0.0/16"]], ["ipv6", "2606:4700::1111", ["::/0", "2606:4700::/32"]]]) {
    const b = { ...bootstrap, services: entries.map((entry, i) => [[entry], [`https://r${i}.example.org/`]]) };
    assert.equal(matchBootstrap(validateBootstrap(b, kind), normalizeRegistration(query("auto", target))), "https://r1.example.org/");
  }
  const b = { ...bootstrap, services: [[["13335-13335"], ["https://rir.example.org/"]]] };
  assert.equal(matchBootstrap(validateBootstrap(b, "asn"), normalizeRegistration(query("auto", "AS13335"))), "https://rir.example.org/");
  assert.throws(() => matchBootstrap(b, normalizeRegistration(query("auto", "AS13336"))), code("UNSUPPORTED_DISCOVERY"));
});
test("bootstrap shape, ranges and URL credentials are validated", () => {
  for (const services of [[[["com"], ["https://u:p@registry.example.org/"]]], [[["com"], ["https://registry.example.org:8443/"]]], [[["com"], ["file:///etc/"]]], [[["com"], ["http://127.0.0.1/"]]]]) assert.throws(() => validateBootstrap({ ...bootstrap, services }, "domain"));
  assert.throws(() => validateBootstrap({ ...bootstrap, services: [[["4294967296-4294967297"], ["https://rir.example.org/"]]] }, "asn"), code("MALFORMED_REPLY"));
  assert.throws(() => validateBootstrap({ ...bootstrap, services: [[["::/129"], ["https://rir.example.org/"]]] }, "ipv6"), code("MALFORMED_REPLY"));
  for (const [kind, entry] of [["ipv4", "8.8.0.0/16/0"], ["ipv4", "8.8.0.0/16junk"], ["ipv6", "::/128junk"], ["ipv6", "::/"]]) {
    assert.throws(() => validateBootstrap({ ...bootstrap, services: [[[entry], ["https://rir.example.org/"]]] }, kind), code("MALFORMED_REPLY"));
  }
});
test("RDAP normalization preserves contacts, DNSSEC, notices and raw unknown extensions", () => {
  const parsed = parseRdap(JSON.stringify(domain), "domain", 200, "example.com");
  assert.deepEqual(parsed.fields.Registrar, ["Fixture Registrar"]); assert.deepEqual(parsed.fields.Expires, ["2030-01-01T00:00:00Z"]);
  assert.equal(parsed.details.dnssec.delegationSigned, true); assert.equal(parsed.details.contacts[0].handle, "R-1");
  assert.throws(() => parseRdap(JSON.stringify(domain), "domain", 200, "other.com"), code("MALFORMED_REPLY"));
  assert.throws(() => parseRdap('{"ldhName":"example.com"}', "domain", 200), code("MALFORMED_REPLY"));
  assert.equal(parseRdap('{"errorCode":404}', "domain", 404).outcome, "not_found");
  assert.throws(() => parseRdap('{}', "domain", 404), code("MALFORMED_REPLY"));
  assert.equal(parseRdap('{"objectClassName":"autnum","startAutnum":13335,"endAutnum":13335}', "asn", 200, "AS13335").outcome, "record");
  assert.equal(parseRdap('{"objectClassName":"ip network","startAddress":"8.8.8.0","endAddress":"8.8.8.255"}', "ipv4", 200, "8.8.8.8").outcome, "record");
});
test("domain RDAP contacts are role-aware, nested, multi-valued and identifier-system explicit", () => {
  const card = (rows) => ["vcard", rows.map(([key, value]) => [key, {}, key === "tel" ? "uri" : "text", value])];
  const entities = [{ roles: ["registrar"], handle: "REG-HANDLE", publicIds: [{ type: "IANA Registrar ID", identifier: "1234" }, { type: "IANA Registrar ID", identifier: "5678" }, { type: "Registry Registrar ID", identifier: "REG-9" }, { type: "Organization ID", identifier: "NOT-A-REGISTRAR-CODE" }],
    vcardArray: card([["fn", "Registrar Name"], ["org", ["Registrar Ltd", "Registration Department"]], ["tel", "tel:+1-555-0100"], ["email", "registrar@example.org"]]),
    entities: [{ roles: ["abuse"], vcardArray: card([["fn", "Abuse Desk"], ["email", "abuse@example.org"], ["tel", "tel:+1-555-0199"]]) },
      { roles: ["registrant"], handle: "NOT-AN-ORG-ID", publicIds: [{ type: "Organization ID", identifier: "ORG-1" }, { type: "Legal Entity Identifier", identifier: "LEI-2" }, { type: "Registrant ID", identifier: "CONTACT-HANDLE" }],
        vcardArray: card([["FN", "Person One"], ["fn", "Person Two"], ["org", [["Example", "Alternative"], "Division"]], ["email", "one@example.org"], ["email", "two@example.org"], ["tel", "tel:+1-555-0111"], ["uid", "NOT-AN-ORG-ID"]]) }] },
    { roles: ["administrative"], vcardArray: card([["fn", "Admin Person"], ["org", "Admin Org"], ["email", "admin@example.org"]]) },
    { roles: ["technical"], vcardArray: card([["fn", "Technical Person"], ["email", "tech@example.org"]]) },
    { roles: ["registrar", "abuse"], vcardArray: card([["email", "ambiguous-abuse@example.org"], ["tel", "tel:+1-555-0999"]]) }];
  const parsed = parseRdap(JSON.stringify({ ...domain, entities }), "domain", 200);
  assert.deepEqual(parsed.fields.Registrar, ["Registrar Name"]);
  assert.deepEqual(parsed.fields["Registrar organization"], ["Registrar Ltd / Registration Department"]);
  assert.equal(parsed.fields["Registrar code"], undefined);
  assert.equal(parsed.details.attribution["Registrar code"].evidence.length, 3);
  assert.deepEqual(parsed.fields["Registrar phone"], ["tel:+1-555-0100"]);
  assert.deepEqual(parsed.fields["Registrar email"], ["registrar@example.org"]);
  for (const field of ["Registrant name", "Registrant organization", "Registrant organization ID", "Registrant email", "Registrant phone"]) assert.equal(parsed.fields[field], undefined);
  assert.ok(parsed.conflicts.includes("Registrar code"));
  // Nested registrant roles describe the containing registrar, not the domain.
  assert.equal(parsed.details.contacts[1].values.email[0], "abuse@example.org");
  assert.equal(parsed.details.contacts[2].handle, "NOT-AN-ORG-ID");
  assert.equal(parsed.details.contacts[2].vcardArray[1][0][0], "FN");
});
test("dual registrant/registrar entities retain evidence without duplicating ambiguous overview contacts", () => {
  for (const extraRoles of [[], ["abuse"], ["technical"], ["administrative"], ["abuse", "technical"]]) for (const roles of [["registrant", "registrar", ...extraRoles], ["registrar", ...extraRoles, "registrant"]]) for (const name of ["fn", "n"]) {
    const entity = { roles, handle: "SHARED-HANDLE", publicIds: [{ type: "Organization ID", identifier: "SHARED-ORG-ID" }, { type: "IANA Registrar ID", identifier: "1234" }],
      vcardArray: ["vcard", [[name, {}, "text", name === "fn" ? "Shared Name" : ["Shared", "Name", "", "", ""]], ["org", {}, "text", "Shared Org"], ["org-id", {}, "text", "SHARED-ORG-ID"], ["tel", {}, "uri", "tel:+1-555-0999"], ["email", {}, "text", "shared@example.org"]]] };
    const parsed = parseRdap(JSON.stringify({ ...domain, entities: [entity] }), "domain", 200);
    for (const field of ["Registrant name", "Registrant organization", "Registrant organization ID", "Registrant phone", "Registrant email", "Registrar", "Registrar organization", "Registrar phone", "Registrar email"]) assert.equal(parsed.fields[field], undefined, `${roles}: ${field}`);
    assert.deepEqual(parsed.fields["Registrar code"], ["1234 (IANA ID)"]);
    assert.deepEqual(parsed.details.contacts[0].roles, roles);
    assert.deepEqual(parsed.details.contacts[0].publicIds, entity.publicIds);
    assert.deepEqual(parsed.details.contacts[0].vcardArray, entity.vcardArray);
    assert.deepEqual(parsed.details.contacts[0].values.email, ["shared@example.org"]);
    assert.equal(parsed.details.contacts[0].handle, "SHARED-HANDLE");
    assert.deepEqual(parsed.conflicts, []);
  }
});
test("mixed-role evidence retains typed redactions and direct role attribution without promoting nested contacts", () => {
  const card = (name, email) => ["vcard", [["fn", {}, "text", name], ["org", {}, "text", `${name} Org`], ["email", {}, "text", email], ["tel", {}, "uri", "tel:+1-555-0100"]]];
  for (const extraRole of ["abuse", "technical", "administrative"]) {
    const entity = { roles: ["registrant", "registrar", extraRole], vcardArray: card("Shared", "shared@example.org"),
      redacted: [{ name: { type: "Registrant Phone" }, method: "removal" }],
      entities: [{ roles: ["registrant"], vcardArray: card("Holder", "holder@example.org") }, { roles: ["registrar"], vcardArray: card("Registrar", "registrar@example.org") }] };
    const parsed = parseRdap(JSON.stringify({ ...domain, entities: [entity] }), "domain", 200);
    for (const field of ["Registrant name", "Registrant organization", "Registrant email", "Registrar", "Registrar organization", "Registrar email", "Registrar phone"]) assert.equal(parsed.fields[field], undefined);
    assert.deepEqual(parsed.fields["Registrant phone"], ["Redacted"]);
    assert.deepEqual(parsed.details.contacts[0].redacted, entity.redacted);
    assert.equal(parsed.details.contacts.length, 3);
    // Preserve established attribution for a single ordinary role combined with
    // a specialist role: names/organizations/typed IDs, but not phone/email.
    for (const role of ["registrant", "registrar"]) {
      const single = parseRdap(JSON.stringify({ ...domain, entities: [{ roles: [role, extraRole], vcardArray: card("Named", "specialist@example.org"), publicIds: [{ type: "IANA Registrar ID", identifier: "1234" }, { type: "Organization ID", identifier: "ORG-1" }] }] }), "domain", 200);
      const prefix = role === "registrant" ? "Registrant" : "Registrar";
      assert.deepEqual(single.fields[role === "registrant" ? "Registrant name" : "Registrar"], ["Named"]);
      assert.deepEqual(single.fields[`${prefix} organization`], ["Named Org"]);
      assert.deepEqual(single.fields[role === "registrant" ? "Registrant organization ID" : "Registrar code"], [role === "registrant" ? "ORG-1 (Organization ID)" : "1234 (IANA ID)"]);
      assert.equal(single.fields[`${prefix} phone`], undefined);
      assert.equal(single.fields[`${prefix} email`], undefined);
      assert.deepEqual(single.details.contacts[0].values.email, ["specialist@example.org"]);
    }
  }
});
test("RDAP names, explicit privacy markers and typed redaction descriptors never infer absent contact fields", () => {
  const data = { ...domain, entities: [{ roles: ["registrant"], handle: "A-HANDLE", vcardArray: ["vcard", [["n", {}, "text", ["Family", "Given", "Middle", "Dr", "Jr"]], ["org", {}, "text", "Privacy Proxy Ltd"], ["email", {}, "text", "REDACTED FOR PRIVACY"]]] }],
    redacted: [{ name: { type: "Registrant Phone" }, method: "removal" }, { name: { type: "Registrant Name" }, method: "partialValue" }, { name: { description: "All registrant information is private" }, method: "removal" }, { name: { type: "Registrant Organization ID" }, method: "unknown" }] };
  const parsed = parseRdap(JSON.stringify(data), "domain", 200);
  assert.deepEqual(parsed.fields["Registrant name"], ["Redacted (partial value)"]);
  assert.deepEqual(parsed.fields["Registrant organization"], ["Privacy Proxy Ltd"]);
  assert.deepEqual(parsed.fields["Registrant email"], ["Redacted"]);
  assert.deepEqual(parsed.fields["Registrant phone"], ["Redacted"]);
  assert.equal(parsed.fields["Registrant organization ID"], undefined);
  assert.equal(parsed.fields["Registrar email"], undefined);
  assert.deepEqual(parsed.details.redacted, data.redacted);
  assert.deepEqual(parsed.details.contacts[0].values.email, ["REDACTED FOR PRIVACY"]);
  const missing = parseRdap(JSON.stringify({ ...domain, entities: [{ roles: ["registrant"], handle: "NOT-AN-ID" }] }), "domain", 200);
  assert.equal(missing.fields["Registrant name"], undefined); assert.equal(missing.fields["Registrant organization ID"], undefined);
});
test("explicit WHOIS contact fields retain conflicts and never promote unrelated or abuse contacts", () => {
  const raw = "Domain Name: EXAMPLE.COM\r\nRegistrar: Registrar Name\r\nRegistrar Organization: Registrar Ltd\r\nRegistrar IANA ID: 1234\r\nRegistrar IANA ID: 5678\r\nRegistrar ID: REG-9\r\nRegistrar Phone: +1.5550100\r\nRegistrar Email: registrar@example.org\r\nRegistrar Abuse Contact Email: abuse@example.org\r\nRegistrar Abuse Contact Phone: +1.5550199\r\nRegistrant Name: Person One\r\nRegistrant-Name: Person Two\r\nRegistrant_Organization: Holder Ltd\r\nRegistrant Organization ID: ORG-42\r\nRegistrant ID: NOT-AN-ORG-ID\r\nRegistrant Phone: REDACTED FOR PRIVACY\r\nRegistrant Email: owner@example.org\r\nRegistrant E-mail: other@example.org\r\nAdmin Email: admin@example.org\r\nTech Email: tech@example.org\r\nOrganization: Unattributed Org\r\nDNSSEC: signedDelegation\r\n";
  const parsed = parseWhois(raw, normalizeRegistration(query("whois")), "whois://whois.verisign-grs.com:43");
  assert.deepEqual(parsed.fields.Registrar, ["Registrar Name"]);
  assert.deepEqual(parsed.fields["Registrar organization"], ["Registrar Ltd"]);
  assert.equal(parsed.fields["Registrar code"], undefined);
  assert.equal(parsed.details.attribution["Registrar code"].evidence.length, 3);
  assert.deepEqual(parsed.fields["Registrar email"], ["registrar@example.org"]);
  assert.deepEqual(parsed.fields["Registrar phone"], ["+1.5550100"]);
  assert.equal(parsed.fields["Registrant name"], undefined);
  assert.equal(parsed.details.attribution["Registrant name"].evidence.length, 2);
  for (const label of ["Registrant organization", "Registrant organization ID", "Registrant email", "Registrant phone"]) assert.equal(parsed.fields[label], undefined);
  assert.deepEqual(parsed.details.attribution["Registrant email"].evidence.map((e) => e.value), ["owner@example.org", "other@example.org"]);
  assert.deepEqual(parsed.fields["Abuse email"], ["abuse@example.org"]);
  assert.deepEqual(parsed.unknown["registrant id"], ["NOT-AN-ORG-ID"]);
  assert.deepEqual(parsed.unknown["registrant phone"], ["REDACTED FOR PRIVACY"]);
  assert.deepEqual(parsed.fields["Published DNSSEC"], ["signedDelegation"]);
  assert.ok(parsed.conflicts.includes("Registrar code")); assert.ok(parsed.conflicts.includes("Registrant name"));
  const abuseOnly = parseWhois("Domain Name: EXAMPLE.COM\nRegistrar Abuse Contact Email: abuse@example.org\nRegistrar Abuse Contact Phone: +1.5550199\nName: Unattributed Name\nOrganization: Unattributed Org\n");
  assert.equal(abuseOnly.fields["Registrar phone"], undefined); assert.equal(abuseOnly.fields["Registrar email"], undefined);
  assert.equal(abuseOnly.fields["Registrant name"], undefined); assert.equal(abuseOnly.fields["Registrant organization"], undefined);
  const registryCode = parseWhois("Domain Name: EXAMPLE.COM\nRegistry Registrar ID: REG-10\nRegistrar Registry Code: REG-11\nRegistrar Identifier: REG-12\nRegistrar: REDACTED FOR PRIVACY\n");
  assert.deepEqual(registryCode.fields["Registrar code"], ["REG-10 (Registry registrar ID)", "REG-11 (Registry registrar ID)", "REG-12 (Registrar identifier; system unspecified)"]);
  assert.deepEqual(registryCode.fields.Registrar, ["Redacted"]);
  assert.deepEqual(registryCode.unknown.registrar, ["REDACTED FOR PRIVACY"]);
});
test("RDAP DNSSEC metadata is retained verbatim, including malformed or unknown fields and every DS record", () => {
  for (const secureDNS of [undefined, { delegationSigned: false }, { delegationSigned: "false", dsData: "unknown" }, { delegationSigned: true, dsData: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest: "AB".repeat(32) }, { keyTag: 2, algorithm: 250, digestType: 251, digest: "CD".repeat(32) }], custom: "preserved" }]) {
    assert.deepEqual(parseRdap(JSON.stringify({ ...domain, secureDNS }), "domain", 200).details.dnssec, secureDNS ?? null);
  }
});
test("WHOIS conservative extraction exposes unknown, conflicts, redaction and unfamiliar negatives", () => {
  const parsed = parseWhois("Domain Name: EXAMPLE.COM\r\nRegistrar: One\r\nRegistrar: Two\r\nCustom-field: withheld\r\nconstructor: safe\r\n__proto__: text\r\n% disclaimer\r\n");
  assert.equal(parsed.outcome, "unknown"); assert.deepEqual(parsed.conflicts, ["Registrar"]);
  assert.deepEqual(parsed.unknown.constructor, ["safe"]); assert.deepEqual(parsed.unknown["custom-field"], ["withheld"]);
  assert.equal(parseWhois('No match for "EXAMPLE.COM".\r\n').outcome, "not_found");
  assert.equal(parseWhois("No such object in this bespoke format").outcome, "unknown");
  assert.equal(parseWhois('Domain Name: EXAMPLE.COM\nNo match for "EXAMPLE.COM"').outcome, "unknown");
  assert.equal(parseWhois('Domain Name: OTHER.COM\n', normalizeRegistration(query())).outcome, "unknown");
  assert.equal(parseWhois('aut-num: AS15169\n', normalizeRegistration(query("whois", "AS13335"))).outcome, "unknown");
  assert.equal(parseWhois('aut-num: 13335\n', normalizeRegistration(query("whois", "AS13335"))).outcome, "record");
  assert.throws(() => parseWhois("Quota exceeded\nReferralServer: whois://other.example.org"), code("UPSTREAM_RATE_LIMITED"));
  assert.throws(() => parseWhois("% ERROR:201: access denied\nReferralServer: whois://other.example.org"), code("SECURITY_REJECTION"));
  assert.equal(parseWhois("Domain Name: EXAMPLE.COM\nremarks: This service may impose rate limits\nIf a query fails, try again later.").outcome, "record");
  assert.throws(() => whoisReferral("Whois Server: one.example.org\nWhois Server: two.example.org"), code("MALFORMED_REPLY"));
});
test("JSON and WHOIS parser budgets reject depth, nodes, line sizes and empty replies", () => {
  assert.throws(() => boundedJson("[".repeat(33) + "0" + "]".repeat(33)), code("LIMIT_EXCEEDED"));
  assert.throws(() => boundedJson(JSON.stringify(Array(20001).fill(0))), code("LIMIT_EXCEEDED"));
  assert.throws(() => boundedJson("{"), code("MALFORMED_REPLY"));
  assert.throws(() => boundedJson('{"value":1e999}'), code("MALFORMED_REPLY"));
  assert.throws(() => parseWhois("x\n".repeat(4001)), code("LIMIT_EXCEEDED"));
  assert.throws(() => parseWhois("x".repeat(8193)), code("LIMIT_EXCEEDED"));
  assert.throws(() => parseWhois(""), code("MALFORMED_REPLY"));
});
test("Auto defaults to RDAP; forced modes are exclusive; raw and sources are preserved", async () => {
  reset(); const options = fake([json(bootstrap), json({ ...domain, extension: { opaque: true } })]);
  const result = await lookupRegistration({ target: "example.com" }, options);
  assert.equal(result.protocol, "rdap"); assert.equal(result.input.protocolMode, "auto"); assert.equal(result.fallbackReason, null);
  assert.equal(JSON.parse(result.rawResponses[0].text).extension.opaque, true);
  assert.equal(result.discovery.source, "https://data.iana.org/rdap/dns.json");
  reset(); const whois = fake([text("domain: COM\nwhois: whois.registry.example.org\n"), text("Domain Name: EXAMPLE.COM\nRegistrar: Fixture\n")]);
  assert.equal((await lookupRegistration(query("whois"), whois)).protocol, "whois");
  assert.ok(whois.calls.every((v) => v.protocol === "whois")); assert.equal(whois.calls[0].query, "com");
  reset(); const rdap = fake([json({ ...bootstrap, services: [] })]);
  await assert.rejects(lookupRegistration(query("rdap"), rdap), code("UNSUPPORTED_DISCOVERY")); assert.equal(rdap.calls.length, 1);
});
for (const reason of ["absent", "http-only", 405, 501]) test(`Auto fallback only for supported policy: ${reason}`, async () => {
  reset(); const responses = reason === "absent" ? [json({ ...bootstrap, services: [] })] : reason === "http-only" ? [json({ ...bootstrap, services: [[["com"], ["http://registry.example.org/"]]] })] : [json(bootstrap), json({}, reason)];
  const options = fake([...responses, text("domain: COM\nwhois: whois.registry.example.org\n"), text("Domain Name: EXAMPLE.COM\n")]);
  const result = await lookupRegistration(query(), options);
  assert.equal(result.protocol, "whois"); assert.ok(result.fallbackReason); assert.ok(result.attempts.some((a) => a.outcome === result.fallbackReason));
});
for (const [response, expected] of [[json({ errorCode: 404 }, 404), "not_found"], [json({}, 404), "MALFORMED_REPLY"], [json({}, 429), "UPSTREAM_RATE_LIMITED"], [json({}, 503), "TEMPORARY_FAILURE"], [json({}, 403), "SECURITY_REJECTION"], [{ ...json({}), text: "garbage" }, "MALFORMED_REPLY"], [new RegistrationError("UPSTREAM_TIMEOUT", "Timed out."), "UPSTREAM_TIMEOUT"]]) test(`Auto never bypasses ${expected}`, async () => {
  reset(); const options = fake([json(bootstrap), response]);
  if (expected === "not_found") assert.equal((await lookupRegistration(query(), options)).outcome, expected);
  else await assert.rejects(lookupRegistration(query(), options), (error) => code(expected)(error) && error.attempts.at(-1).outcome === expected);
  assert.ok(options.calls.every((v) => v.protocol === "rdap"));
});
test("RDAP-only 501 never switches; WHOIS unsupported never switches", async () => {
  reset(); const r = fake([json(bootstrap), json({}, 501)]); await assert.rejects(lookupRegistration(query("rdap"), r), code("PROTOCOL_UNAVAILABLE"));
  reset(); const w = fake([text("domain: COM\norganisation: Fixture\n")]); await assert.rejects(lookupRegistration(query("whois"), w), code("UNSUPPORTED_DISCOVERY")); assert.equal(w.calls.length, 1);
  reset(); await assert.rejects(lookupRegistration(query("whois"), fake([text("Unrecognized discovery prose")])), code("MALFORMED_REPLY"));
});
test("bootstrap fetch failures do not justify fallback; failed refresh has cooldown and fails closed", async () => {
  reset(); let clock = 1000000000000;
  const options = fake([json({}, 503), json(bootstrap), json(domain)], { now: () => clock });
  await assert.rejects(lookupRegistration(query(), options), code("DISCOVERY_UNAVAILABLE"));
  await assert.rejects(lookupRegistration(query(), options), code("DISCOVERY_UNAVAILABLE")); assert.equal(options.calls.length, 1);
  clock += 31000; assert.equal((await lookupRegistration(query(), options)).protocol, "rdap");
});
test("bootstrap freshness follows bounded Cache-Control; stale refresh fails closed rather than using stale data", async () => {
  reset(); let clock = 1000000000000;
  const options = fake([json(bootstrap, 200, { "cache-control": "max-age=60" }), json(domain), json(domain), json({}, 503)], { now: () => clock });
  await lookupRegistration(query("rdap"), options);
  clock += 30000;
  const second = await lookupRegistration(query("auto"), options); assert.equal(second.discovery.ageSeconds, 30); assert.equal(options.calls.length, 3);
  clock += 31000; await assert.rejects(lookupRegistration(query("rdap"), options), code("DISCOVERY_UNAVAILABLE"));
});
test("bounded result cache separates modes, shows age and never caches unknown or cancelled results", async () => {
  reset(); let clock = 1000000000000; const options = fake([json(bootstrap), json(domain), json(domain)], { now: () => clock });
  const first = await lookupRegistration(query(), options); assert.equal(first.cache.cached, false);
  clock += 1000; const cached = await lookupRegistration(query(), options); assert.equal(cached.cache.cached, true); assert.equal(cached.cache.ageSeconds, 1); assert.equal(options.calls.length, 2);
  assert.equal((await lookupRegistration(query("rdap"), options)).cache.cached, false);
  for (let i = 0; i < 140; i++) resultCacheForTest(i, clock);
  assert.equal(registrationState().cache, 128);
});
import { resultCache } from "../src/tools/registration-resources.mjs";
function resultCacheForTest(i, clock) { resultCache.set(`fixture-${i}`, { expiresAt: clock + 60000, response: { value: i } }, clock); }
test("cache rejects oversized entries and expires old data", () => {
  reset(); resultCache.set("large", { expiresAt: 2000, response: { value: "x".repeat(L.cacheBytes) } }, 1000); assert.equal(resultCache.size, 0);
  resultCacheForTest(1, 1000); assert.equal(resultCache.get("fixture-1", 61000), undefined);
});
test("registration IP is not an upstream address", async () => {
  reset(); const b = { ...bootstrap, services: [[["127.0.0.0/8"], ["https://rir.example.org/"]]] };
  const options = fake([json(b), json({ objectClassName: "ip network", startAddress: "127.0.0.0", endAddress: "127.255.255.255" })]);
  const result = await lookupRegistration(query("rdap", "127.0.0.1"), options);
  assert.equal(result.input.canonical, "127.0.0.1"); assert.ok(options.calls.every((v) => v.address.address === "8.8.8.8"));
});
test("IDN, IPv6 and ASN lookups use their canonical protocol query path", async () => {
  for (const [target, kind, entries, response, suffix] of [
    ["пример.рф", "domain", ["xn--p1ai"], { objectClassName: "domain", ldhName: "xn--e1afmkfd.xn--p1ai" }, "domain/xn--e1afmkfd.xn--p1ai"],
    ["2606:4700::1111", "ipv6", ["2606:4700::/32"], { objectClassName: "ip network", startAddress: "2606:4700::", endAddress: "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff" }, "ip/2606:4700::1111"],
    ["as0013335", "asn", ["13335-13335"], { objectClassName: "autnum", startAutnum: 13335, endAutnum: 13335 }, "autnum/13335"],
  ]) {
    reset(); const options = fake([json({ ...bootstrap, services: [[entries, ["https://registry.example.org/"]]] }), json(response)]);
    const result = await lookupRegistration(query("rdap", target), options); assert.equal(result.input.kind, kind); assert.equal(options.calls.at(-1).url.pathname, `/${suffix}`);
  }
});
test("safe RDAP redirects re-resolve each hop and pin the returned public address", async () => {
  reset(); let lookups = 0;
  const options = fake([json(bootstrap), json({}, 302, { location: "https://second.example.org/domain/example.com" }), json(domain)], { lookup: async () => [{ address: ++lookups === 3 ? "1.1.1.1" : "8.8.8.8", family: 4 }] });
  const result = await lookupRegistration(query(), options); assert.equal(lookups, 3); assert.equal(options.calls.at(-1).address.address, "1.1.1.1"); assert.equal(result.source, "https://second.example.org/domain/example.com");
});
for (const destination of ["http://registry.example.org/", "https://u:p@registry.example.org/", "https://registry.example.org:8443/", "https://127.0.0.1/", "https://[::ffff:8.8.8.8]/", "https://registry.local/", "file:///etc/passwd", "https://regis\ttry.example.org/"]) test(`RDAP blocks redirect ${destination}`, async () => {
  reset(); const options = fake([json(bootstrap), json({}, 302, { location: destination })]);
  await assert.rejects(lookupRegistration(query(), options), code("SECURITY_REJECTION")); assert.equal(options.calls.length, 2);
});
for (const addresses of [[{ address: "127.0.0.1", family: 4 }], [{ address: "8.8.8.8", family: 4 }, { address: "10.0.0.1", family: 4 }], [{ address: "::ffff:8.8.8.8", family: 6 }]]) test("mixed/private/mapped DNS answers reject before connecting", async () => {
  reset(); const options = fake([], { lookup: async () => addresses });
  await assert.rejects(lookupRegistration(query(), options), code("SECURITY_REJECTION")); assert.equal(options.calls.length, 0);
});
test("rebinding cannot change the pinned IP; fresh blocked DNS on redirect is rejected", async () => {
  reset(); let n = 0;
  const options = fake([json(bootstrap), json({}, 302, { location: "https://registry.example.org/next" })], { lookup: async () => [{ address: ++n > 2 ? "127.0.0.1" : "8.8.8.8", family: 4 }] });
  await assert.rejects(lookupRegistration(query(), options), code("SECURITY_REJECTION")); assert.equal(options.calls.length, 2);
});
test("WHOIS validates IANA discovery and every subsequent referral; preserves all raw responses", async () => {
  reset(); const options = fake([text("domain: COM\nwhois: whois.registry.example.org\n"), text("Domain Name: EXAMPLE.COM\nRegistrar WHOIS Server: whois.registrar.example.org\n"), text("Domain Name: EXAMPLE.COM\nRegistrar: Fixture\n")]);
  const result = await lookupRegistration(query("whois"), options); assert.equal(result.rawResponses.length, 3); assert.equal(result.attempts.at(-1).phase, "referral");
  assert.ok(options.calls.every((v) => v.query === "com" || v.query === "example.com"));
  for (const referral of ["whois://127.0.0.1", "whois://user@whois.registry.example.org", "whois://whois.registry.example.org:80", "https://whois.registry.example.org/", "whois://whois.registry.example.org/path", "whois://regis\ttry.example.org"]) {
    reset(); await assert.rejects(lookupRegistration(query("whois"), fake([text(`domain: COM\nwhois: ${referral}\n`)])), code("SECURITY_REJECTION"));
  }
});
test("documented IANA refer discovery works and same-server different-query registration is not a loop", async () => {
  reset(); const options = fake([text("domain: COM\nrefer: registry.example.org\nwhois: registry.example.org\n"), text("Domain Name: EXAMPLE.COM\n")]);
  assert.equal((await lookupRegistration(query("whois"), options)).outcome, "record");
  reset(); const iana = fake([text("domain: INT\nwhois: whois.iana.org\n"), text("domain: fixture.int\norganisation: Fixture\n")]);
  const result = await lookupRegistration(query("whois", "fixture.int"), iana); assert.equal(result.source, "whois://whois.iana.org:43"); assert.equal(iana.calls[0].query, "int"); assert.equal(iana.calls[1].query, "fixture.int");
  assert.throws(() => whoisReferral("refer: one.example.org\nwhois: two.example.org\n", true), code("MALFORMED_REPLY"));
});
test("WHOIS rate limits and temporary failures never follow a referral", async () => {
  for (const [message, error] of [["Too many queries", "UPSTREAM_RATE_LIMITED"], ["Service unavailable", "TEMPORARY_FAILURE"], ["Access denied", "SECURITY_REJECTION"]]) {
    reset(); const options = fake([text("domain: COM\nwhois: whois.registry.example.org\n"), text(`${message}\nWhois Server: next.example.org\n`)]);
    await assert.rejects(lookupRegistration(query("whois"), options), code(error)); assert.equal(options.calls.length, 2);
  }
});
test("unknown WHOIS is inspectable but never cached; IP/ASN discovery submits identifiers rather than hosts", async () => {
  for (const target of ["8.8.8.8", "2606:4700::1111", "AS13335"]) {
    reset(); const options = fake([text("whois: registry.example.org\n"), text("Bespoke registry response without a recognized record")]);
    const result = await lookupRegistration(query("whois", target), options); assert.equal(result.outcome, "unknown"); assert.equal(registrationState().cache, 0); assert.ok(options.calls.every((value) => value.query === target));
  }
});
test("conflicting WHOIS fields remain inspectable and uncached; a fresh retry can recover", async () => {
  reset();
  const conflict = "Domain Name: EXAMPLE.COM\r\nRegistrar Name: One\r\nRegistrar Name: Two\r\n";
  const discovery = text("domain: COM\nwhois: registry.example.org\n");
  const options = fake([discovery, text(conflict), discovery, text("Domain Name: EXAMPLE.COM\nRegistrar: One\n")]);
  const first = await lookupRegistration(query("whois"), options);
  assert.equal(first.outcome, "unknown"); assert.equal(first.normalized.fields.Registrar, undefined);
  assert.deepEqual(first.normalized.details.attribution.Registrar.evidence.map((e) => e.value), ["One", "Two"]);
  assert.equal(first.rawResponses.at(-1).text, conflict); assert.equal(registrationState().cache, 0);
  const retry = await lookupRegistration(query("whois"), options);
  assert.equal(retry.outcome, "record"); assert.equal(retry.cache.cached, false); assert.equal(options.calls.length, 4);
  assert.equal(registrationState().cache, 1);
});
test("redirect/referral loops and depth budgets stop rather than return partial success", async () => {
  reset(); await assert.rejects(lookupRegistration(query(), fake([json(bootstrap), json({}, 302, { location: "/rdap/domain/example.com" })])), code("LIMIT_EXCEEDED"));
  reset(); await assert.rejects(lookupRegistration(query(), fake([json(bootstrap), json({}, 302, { location: "/one" }), json({}, 302, { location: "/two" }), json({}, 302, { location: "/three" })])), code("LIMIT_EXCEEDED"));
  reset(); await assert.rejects(lookupRegistration(query("whois", "AS13335"), fake([text("as-block: 13335-13335\nrefer: whois.iana.org\n")])), code("LIMIT_EXCEEDED"));
  reset(); await assert.rejects(lookupRegistration(query("whois"), fake([text("domain: COM\nwhois: one.example.org\n"), text("Domain Name: EXAMPLE.COM\nWhois Server: two.example.org\n"), text("Domain Name: EXAMPLE.COM\nWhois Server: three.example.org\n")])), code("LIMIT_EXCEEDED"));
});
test("received bytes, exchange count and whole-operation deadlines are finite", async () => {
  reset(); await assert.rejects(lookupRegistration(query(), fake([json(bootstrap), text("x".repeat(L.responseBytes + 1))])), code("RESPONSE_TOO_LARGE"));
  const operation = createRegistrationOperation({ deadlineMs: 10 });
  await assert.rejects(operation.wait(() => new Promise(() => {}), 100), code("DEADLINE_EXHAUSTED")); operation.dispose();
  const other = createRegistrationOperation();
  assert.throws(() => other.bytes(L.totalBytes + 1), code("LIMIT_EXCEEDED"));
  for (let i = 0; i < L.exchanges; i++) other.exchange(); assert.throws(() => other.exchange(), code("LIMIT_EXCEEDED")); other.dispose();
});
test("cancellation releases admission, prevents fallback/cache publication and permits recovery", async () => {
  reset(); const controller = new AbortController(); let started;
  const ready = new Promise((resolve) => { started = resolve; });
  const options = fake([json(bootstrap), () => { started(); return new Promise(() => {}); }], { signal: controller.signal });
  const pending = lookupRegistration(query(), options); await ready; controller.abort();
  await assert.rejects(pending, code("CANCELLED")); assert.equal(registrationState().live, 0); assert.equal(registrationState().cache, 0);
  assert.equal((await lookupRegistration(query(), fake([json(domain)]))).outcome, "record");
});
test("cancellation before queued work begins cannot start DNS or transport", async () => {
  const controller = new AbortController(), operation = createRegistrationOperation({ signal: controller.signal });
  let calls = 0;
  const pending = resolveRegistrationHost("registry.example.org", operation, { lookup: async () => { calls++; return [{ address: "8.8.8.8", family: 4 }]; } });
  controller.abort(); await assert.rejects(pending, code("CANCELLED"));
  await new Promise((resolve) => setImmediate(resolve)); assert.equal(calls, 0); assert.equal(registrationState().dns, 0); operation.dispose();
});
test("client/global rates include cache hits; active/client admission fails fast and recovers", async () => {
  reset(); const options = fake([json(bootstrap), json(domain)]);
  for (let i = 0; i < 20; i++) await lookupRegistration(query(), options);
  await assert.rejects(lookupRegistration(query(), options), code("RATE_LIMITED"));
  reset(); const controllers = [], pending = [];
  for (let i = 0; i < 4; i++) {
    const c = new AbortController(); controllers.push(c); pending.push(lookupRegistration(query(), fake([() => new Promise(() => {})], { clientIp: `c${i}`, signal: c.signal })).catch((error) => error));
  }
  await assert.rejects(lookupRegistration(query(), fake([], { clientIp: "fifth" })), code("CAPACITY_EXHAUSTED"));
  await assert.rejects(lookupRegistration(query(), fake([], { clientIp: "c0" })), code("CAPACITY_EXHAUSTED"));
  controllers.forEach((c) => c.abort()); await Promise.all(pending); assert.equal(registrationState().live, 0);
});
test("global rate is exactly bounded and expired windows permit recovery", async () => {
  reset(); let clock = 1000000000000;
  const options = fake([json(bootstrap), json(domain)], { now: () => clock });
  for (let i = 0; i < 100; i++) await lookupRegistration(query(), { ...options, clientIp: `client-${i}` });
  await assert.rejects(lookupRegistration(query(), { ...options, clientIp: "next" }), code("RATE_LIMITED"));
  clock += 60000; options.transport = fake([json(domain)]).transport;
  assert.equal((await lookupRegistration(query(), { ...options, clientIp: "next" })).outcome, "record");
});
test("uncancellable OS DNS retains a separate capped slot until actual settlement", async () => {
  const operation = createRegistrationOperation({ deadlineMs: 5 }); let settle;
  const work = resolveRegistrationHost("registry.example.org", operation, { lookup: () => new Promise((resolve) => { settle = resolve; }) });
  await assert.rejects(work, code("DEADLINE_EXHAUSTED")); operation.dispose(); assert.equal(registrationState().dns, 1);
  settle([{ address: "8.8.8.8", family: 4 }]); await new Promise((resolve) => setImmediate(resolve)); assert.equal(registrationState().dns, 0);
  const releases = Array.from({ length: 8 }, () => acquireRegistrationResource("dns")); assert.throws(() => acquireRegistrationResource("dns"), code("CAPACITY_EXHAUSTED")); releases.forEach((release) => release());
});
test("destination policy conservatively blocks reserved and transition addresses", () => {
  for (const address of ["0.0.0.0", "100.64.0.1", "192.0.2.1", "198.18.0.1", "192.88.99.1", "224.0.0.1", "::1", "::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1", "2001:db8::1", "3fff::1", "fc00::1", "fe80::1", "ff02::1"]) assert.equal(blockedRegistrationAddress(address), true, address);
  for (const address of ["8.8.8.8", "2606:4700::1111"]) assert.equal(blockedRegistrationAddress(address), false);
  assert.throws(() => validateRegistrationDestination("whois://a.example.org:443", "whois"), code("SECURITY_REJECTION"));
});

class FakeSocket extends EventEmitter {
  constructor() { super(); this.destroyed = false; }
  destroy() { if (!this.destroyed) { this.destroyed = true; queueMicrotask(() => this.emit("close")); } }
  write(value, encoding) { this.written = value; this.encoding = encoding; }
}
test("HTTPS transport pins lookup, preserves SNI and verification, bounds bytes and cleans resources", async () => {
  const operation = createRegistrationOperation(), socket = new FakeSocket(); let settings;
  const request = new FakeSocket(); request.end = () => queueMicrotask(() => {
    request.emit("socket", socket); const res = new FakeSocket(); res.headers = { "content-type": "application/rdap+json" }; res.statusCode = 200;
    request.callback(res); res.emit("data", Buffer.from('{}')); res.emit("end");
  });
  const result = await transport({ url: new URL("https://registry.example.org/"), protocol: "rdap", query: "", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 100 }, { request: (_url, opts, callback) => { settings = opts; request.callback = callback; return request; } });
  assert.equal(result.text, '{}'); assert.equal(settings.servername, "registry.example.org"); assert.equal(settings.rejectUnauthorized, true); assert.equal(settings.agent, false);
  settings.lookup("registry.example.org", {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, "8.8.8.8"); assert.equal(family, 4); });
  await new Promise((resolve) => setImmediate(resolve)); assert.equal(registrationState().sockets, 0); operation.dispose();
});
test("WHOIS transport completes only at EOF, preserves raw text and holds slot until close", async () => {
  const operation = createRegistrationOperation(), socket = new FakeSocket();
  const pending = transport({ url: new URL("whois://registry.example.org:43/"), protocol: "whois", query: "AS13335", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 1000 }, { connect: () => socket });
  socket.emit("connect"); socket.emit("data", Buffer.from("aut-num: AS13335\r\n")); socket.emit("data", Buffer.from("as-name: FIXTURE\r\n"));
  assert.equal(registrationState().sockets, 1); socket.emit("end");
  assert.equal((await pending).text, "aut-num: AS13335\r\nas-name: FIXTURE\r\n");
  await new Promise((resolve) => setImmediate(resolve)); assert.equal(registrationState().sockets, 0); operation.dispose();
});
test("transport deadline and five-second attempt timeout destroy stalled sockets", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  for (const deadline of [1000, 20000]) {
    const operation = createRegistrationOperation({ deadlineMs: deadline }), socket = new FakeSocket();
    const pending = transport({ url: new URL("whois://registry.example.org:43/"), protocol: "whois", query: "example.com", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 1000 }, { connect: () => socket });
    const rejected = assert.rejects(pending, code(deadline === 1000 ? "DEADLINE_EXHAUSTED" : "UPSTREAM_TIMEOUT"));
    t.mock.timers.tick(Math.min(deadline, 5000)); await rejected; assert.equal(socket.destroyed, true); operation.dispose();
    await new Promise((resolve) => setImmediate(resolve)); assert.equal(registrationState().sockets, 0);
  }
});
test("socket capacity accounts for closing sockets until actual close", async () => {
  const operation = createRegistrationOperation(), sockets = [], pending = [];
  for (let i = 0; i < 8; i++) {
    const socket = new FakeSocket(); socket.destroy = () => { socket.destroyed = true; }; sockets.push(socket);
    pending.push(transport({ url: new URL("whois://registry.example.org:43"), protocol: "whois", query: "example.com", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 1000 }, { connect: () => socket }));
    socket.emit("data", Buffer.from("Domain Name: EXAMPLE.COM\r\n")); socket.emit("end");
  }
  await Promise.all(pending); assert.equal(registrationState().sockets, 8);
  assert.throws(() => acquireRegistrationResource("socket"), code("CAPACITY_EXHAUSTED"));
  sockets.forEach((socket) => socket.emit("close")); assert.equal(registrationState().sockets, 0); operation.dispose();
});
for (const scenario of ["oversized", "compressed", "cancelled", "reset"]) test(`transport handles ${scenario} and releases sockets`, async () => {
  const controller = new AbortController(), operation = createRegistrationOperation({ signal: controller.signal }), socket = new FakeSocket();
  if (scenario === "compressed") {
    const req = new FakeSocket(); req.end = () => queueMicrotask(() => { req.emit("socket", socket); const res = new FakeSocket(); res.headers = { "content-encoding": "gzip" }; req.callback(res); });
    await assert.rejects(transport({ url: new URL("https://registry.example.org/"), protocol: "rdap", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 10 }, { request: (_u, _o, cb) => { req.callback = cb; return req; } }), code("MALFORMED_REPLY"));
  } else {
    const promise = transport({ url: new URL("whois://registry.example.org/"), protocol: "whois", query: "example.com", address: { address: "8.8.8.8", family: 4 }, operation, maxBytes: 10 }, { connect: (opts) => { assert.equal(opts.host, "8.8.8.8"); assert.equal(opts.port, 43); return socket; } });
    socket.emit("connect"); assert.equal(socket.written, "example.com\r\n");
    if (scenario === "oversized") socket.emit("data", Buffer.alloc(11)); else if (scenario === "cancelled") controller.abort(); else socket.emit("error", new Error("non-public diagnostic"));
    await assert.rejects(promise, code(scenario === "oversized" ? "RESPONSE_TOO_LARGE" : scenario === "cancelled" ? "CANCELLED" : "TEMPORARY_FAILURE"));
  }
  await new Promise((resolve) => setImmediate(resolve)); operation.dispose(); assert.equal(registrationState().sockets, 0);
});
test("Fastify route maps safe errors, preserves attempts and propagates cancellation", async () => {
  const app = Fastify(); let receivedSignal;
  registerRegistrationRoute(app, () => "client", async (_body, options) => { receivedSignal = options.signal; const error = new RegistrationError("UPSTREAM_RATE_LIMITED", "Registry rate limited."); error.attempts = [{ protocol: "rdap", outcome: "UPSTREAM_RATE_LIMITED" }]; throw error; });
  const response = await app.inject({ method: "POST", url: "/api/tools/rdap-lookup", payload: query() });
  assert.equal(response.statusCode, 429); assert.equal(receivedSignal.aborted, false); assert.equal(response.json().attempts.length, 1); assert.equal("stack" in response.json(), false); await app.close();
  let handler;
  registerRegistrationRoute({ post: (_path, _opts, fn) => { handler = fn; } }, () => "client", (_body, { signal }) => new Promise((resolve) => { signal.addEventListener("abort", () => resolve({ ok: true })); }));
  const raw = new EventEmitter(), replyRaw = new EventEmitter(); replyRaw.writableFinished = false;
  const pending = handler({ raw, body: query() }, { raw: replyRaw }); replyRaw.emit("close"); await pending;
  assert.equal(raw.listenerCount("aborted"), 0); assert.equal(replyRaw.listenerCount("close"), 0);
});
test("actual local Fastify disconnect cancels a fully received lookup and permits recovery", { timeout: 5000 }, async (t) => {
  reset(); const app = Fastify(); t.after(() => app.close());
  let markStarted, markFinished;
  const started = new Promise((resolve) => { markStarted = resolve; }), finished = new Promise((resolve) => { markFinished = resolve; });
  const options = fake([json(bootstrap), () => { markStarted(); return new Promise(() => {}); }]);
  registerRegistrationRoute(app, () => "local-client", async (body, requestOptions) => {
    try { return await lookupRegistration(body, { ...options, ...requestOptions }); }
    finally { markFinished(); }
  });
  const address = await app.listen({ host: "127.0.0.1", port: 0 });
  const req = localRequest(`${address}/api/tools/rdap-lookup`, { method: "POST", headers: { "content-type": "application/json" } });
  req.on("error", () => {}); t.after(() => req.destroy()); req.end(JSON.stringify(query()));
  await started; req.destroy(); await finished; assert.equal(registrationState().live, 0); assert.equal(registrationState().cache, 0);
  assert.equal((await lookupRegistration(query(), fake([json(domain)]))).outcome, "record");
});
test("route status mappings and body limit stay safe without exposing unexpected errors", async () => {
  let current;
  const app = Fastify(); registerRegistrationRoute(app, () => "fixture", async () => { throw current; });
  for (const [codeValue, status] of [["INVALID_INPUT", 400], ["SECURITY_REJECTION", 400], ["RATE_LIMITED", 429], ["UNSUPPORTED_DISCOVERY", 503], ["CAPACITY_EXHAUSTED", 503], ["DEADLINE_EXHAUSTED", 504], ["UPSTREAM_TIMEOUT", 504], ["CANCELLED", 499], ["MALFORMED_REPLY", 502]]) {
    current = new RegistrationError(codeValue, "Fixed safe fixture message.");
    const response = await app.inject({ method: "POST", url: "/api/tools/rdap-lookup", payload: query() }); assert.equal(response.statusCode, status); assert.equal(response.json().error.code, codeValue);
  }
  current = new Error("PRIVATE STACK/EXCEPTION MUST NOT LEAK");
  const response = await app.inject({ method: "POST", url: "/api/tools/rdap-lookup", payload: query() }); assert.equal(response.statusCode, 502); assert.equal(response.body.includes("PRIVATE"), false);
  assert.equal((await app.inject({ method: "POST", url: "/api/tools/rdap-lookup", payload: { target: "x".repeat(2048) } })).statusCode, 413); await app.close();
});
