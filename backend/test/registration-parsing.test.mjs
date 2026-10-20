import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseWhois, parseRdap } from "../src/tools/registration-parse.mjs";
import { whoisRecords } from "../src/tools/registration-whois.mjs";
import { whoisAdapter } from "../src/tools/registration-whois-adapters.mjs";
import { registrationDate } from "../src/tools/registration-evidence.mjs";
import { lookupRegistration } from "../src/tools/registration-lookup.mjs";
import { resetBootstrapState } from "../src/tools/registration-discovery.mjs";
import { resetRegistrationState } from "../src/tools/registration-resources.mjs";

const fixture = (name) => readFileSync(new URL(`./fixtures/registration/${name}`, import.meta.url), "utf8");
const input = (tld = "sk") => ({ kind: "domain", canonical: `example.${tld}` });
const whois = (text, host = "whois.sk-nic.sk", tld = "sk") => parseWhois(text, input(tld), `whois://${host}:43`);
const rdap = (data) => parseRdap(JSON.stringify(data), "domain", 200, "example.com");
const card = (role, name, extra = {}) => ({ roles: [role], vcardArray: ["vcard", [["fn", {}, "text", name], ["email", {}, "text", `${role}@example.test`]]], ...extra });
const domain = { objectClassName: "domain", ldhName: "example.com" };

test("SK-NIC exact negative is service-bound, whole-response-only and retains line evidence", () => {
  const query = { kind: "domain", canonical: "notregistered.sk" };
  const parsed = parseWhois("Domain not found.\r\n", query, "whois://whois.sk-nic.sk:43");
  assert.equal(parsed.outcome, "not_found"); assert.deepEqual(parsed.fields, {});
  assert.deepEqual(parsed.details.unparsed, [{ line: 1, text: "Domain not found." }]);
  for (const source of [null, "whois://registrar.example.org:43", "whois://whois.sk-nic.sk.evil.org:43", "https://whois.sk-nic.sk", "whois://whois.sk-nic.sk:44"]) {
    assert.equal(parseWhois("Domain not found.", query, source).outcome, "unknown");
  }
  for (const text of ["Domain not found", "Domain not found. Try later", "Error: Domain not found.", "% Domain not found.", "# Domain not found.", "Remarks: Domain not found.",
    "Contact: OTHER\nDomain not found.", "Domain: other.sk\nDomain not found.", "Domain: example.sk\nDomain not found.", "Upstream failure\nDomain not found."]) {
    assert.equal(whois(text).outcome, "unknown", text);
  }
  assert.equal(whois(fixture("sknic-whois.txt") + "\nDomain not found.\n").outcome, "unknown");
  assert.equal(whois(fixture("sknic-whois.txt") + "\n% Domain not found.\n").outcome, "record");
});
test("existing domain negatives require complete diagnostics, not substrings or auxiliary objects", () => {
  for (const text of ['No match for "EXAMPLE.SK".', "Not found.", "No entries found", "% No entries found", "%ERROR: 101: no entries found"]) {
    assert.equal(whois(text).outcome, "not_found", text);
    for (const prefix of ["Remarks: ", "# ", "Contact: OTHER\n", "Unrecognized failure\n", "% Error: upstream database failed\n"]) assert.equal(whois(prefix + text).outcome, "unknown", prefix + text);
    assert.equal(whois("Domain: example.sk\n" + text).outcome, "unknown");
  }
  for (const text of ['No match for "OTHER.SK".', "No entries found in upstream cache", "Not found. Error", "% Documentation: no entries found"]) assert.equal(whois(text).outcome, "unknown");
});
test("SK-NIC negative cannot bypass rate limits, access denial or temporary failures", () => {
  for (const [line, code] of [["Rate limit exceeded", "UPSTREAM_RATE_LIMITED"], ["Service unavailable", "TEMPORARY_FAILURE"], ["Try again later", "TEMPORARY_FAILURE"], ["Access denied", "SECURITY_REJECTION"]]) {
    assert.throws(() => whois(`Domain not found.\n${line}`), (error) => error.code === code);
  }
});
test("domain RDAP not-found requires HTTP and JSON 404 without conflicting record data", () => {
  const data = { errorCode: 404, title: "Not Found", description: ["No domain record"] };
  assert.equal(parseRdap(JSON.stringify(data), "domain", 404, "example.com").outcome, "not_found");
  for (const extra of [{ errorCode: 429 }, { errorCode: 503 }, { ...domain }, { ldhName: "other.com" }, { entities: [] }, { nameservers: [] }]) {
    assert.throws(() => parseRdap(JSON.stringify({ ...data, ...extra }), "domain", 404, "example.com"), (error) => error.code === "MALFORMED_REPLY");
  }
  assert.throws(() => parseRdap(JSON.stringify(data), "domain", 200, "example.com"), (error) => error.code === "MALFORMED_REPLY");
});
test("SK-NIC not-found lookup retains IANA delegation only as discovery and preserves raw exports", async () => {
  resetRegistrationState(); resetBootstrapState();
  const replies = ["domain: SK\norganisation: Delegation operator\nwhois: whois.sk-nic.sk\n", "Domain not found.\r\n"];
  const result = await lookupRegistration({ target: "notregistered.sk", protocolMode: "whois" }, { clientIp: "negative-test", lookup: async () => [{ address: "8.8.8.8", family: 4 }], transport: async () => ({ status: 200, headers: {}, text: replies.shift() }) });
  assert.equal(result.outcome, "not_found"); assert.deepEqual(result.normalized.fields, {});
  assert.equal(result.rawResponses.length, 2); assert.match(result.rawResponses[0].text, /domain: SK/);
  assert.equal(result.rawResponses[1].text, "Domain not found.\r\n"); assert.equal(result.attempts[1].outcome, "not_found");
  assert.equal(result.source, "whois://whois.sk-nic.sk:43"); assert.equal(result.discovery.source, "whois://whois.iana.org:43");
});

test("live-derived SK-NIC objects keep domain dates, actual holder and registrar roles separate", () => {
  const parsed = whois(fixture("sknic-whois.txt"));
  assert.equal(parsed.outcome, "record"); assert.equal(parsed.details.parser, "sknic");
  assert.deepEqual(parsed.fields.Created, ["2003-06-10"]); assert.deepEqual(parsed.fields.Updated, ["2026-06-04"]);
  assert.deepEqual(parsed.fields.Expires, ["2027-06-10"]); assert.equal(parsed.fields.Nameservers.length, 4);
  assert.deepEqual(parsed.fields["Registrant name"], ["Fixture Registry Ltd"]);
  assert.deepEqual(parsed.fields["Registrar code"], ["REG-TEST (Registry registrar ID)"]);
  assert.deepEqual(parsed.fields["Registrant organization ID"], ["00000000"]);
  assert.equal(parsed.details.attribution["Registrant email"].evidence[0].role, "registrant");
  assert.notEqual(parsed.details.attribution["Registrant email"].evidence[0].record, parsed.details.attribution["Registrar email"].evidence[0].record);
  assert.equal(parsed.details.attribution.Created.evidence[0].location, "line:2");
  assert.ok(parsed.details.records.some((r) => r.entries.some((e) => e.key === "created" && e.value === "2017-09-01")));
});
test("SK-NIC contact references resolve by identifier regardless of object order, never by first contact", () => {
  const header = "Domain: example.sk\nRegistrant: HOLDER\nRegistrar: REG-TEST\nCreated: 2001-01-01\n";
  const objects = ["Contact: ADMIN\nName: Administrator\nEmail: admin@example.test\n", "Contact: HOLDER\nName: Holder\nEmail: holder@example.test\nCreated: 1990-01-01\n", "Registrar: REG-TEST\nName: Registrar\nEmail: registrar@example.test\nCreated: 2017-09-01\n"];
  for (const order of [objects, [...objects].reverse()]) {
    const parsed = whois([header, ...order].join("\n"));
    assert.deepEqual(parsed.fields["Registrant email"], ["holder@example.test"]); assert.deepEqual(parsed.fields["Registrar email"], ["registrar@example.test"]);
    assert.deepEqual(parsed.fields.Created, ["2001-01-01"]); assert.deepEqual(parsed.fields.Registrar, ["Registrar"]);
  }
  const absent = whois(header + "\n" + objects[0]);
  assert.equal(absent.fields["Registrant name"], undefined); assert.equal(absent.fields.Registrar, undefined);
  assert.deepEqual(absent.fields["Registrar code"], ["REG-TEST (Registry registrar ID)"]);
});
test("duplicate handles, inconsistent domains, conflicting refs and unrelated objects never form a combined contact", () => {
  const raw = "Domain: example.sk\nRegistrant: HOLDER\n\nContact: HOLDER\nName: One\n\nContact: HOLDER\nEmail: two@example.test\n";
  const parsed = whois(raw);
  for (const label of ["Registrant name", "Registrant email"]) { assert.equal(parsed.fields[label], undefined); assert.equal(parsed.details.attribution[label].state, "ambiguous"); }
  assert.equal(parsed.outcome, "unknown");
  for (const text of ["Domain: other.sk\nName: Wrong\n", raw + "\nDomain: other.sk\n", "Domain: example.sk\nRegistrant: H1\nRegistrant: H2\n\nContact: H1\nName: One\n"]) {
    const result = whois(text); assert.equal(result.fields["Registrant name"], undefined); assert.equal(result.outcome, "unknown");
  }
});
test("adapters follow the responding WHOIS service; suffix and lookalike endpoints cannot select SK-NIC", () => {
  for (const source of [null, "whois://whois.sk-nic.sk.evil.org:43", "https://whois.sk-nic.sk", "whois://whois.sk-nic.sk:44", "whois://u:p@whois.sk-nic.sk:43"]) assert.equal(whoisAdapter(source), "generic");
  const parsed = whois(fixture("sknic-whois.txt"), "registrar.example.org");
  assert.equal(parsed.details.parser, "generic"); assert.equal(parsed.fields["Registrant name"], undefined); assert.equal(parsed.fields.Expires, undefined);
  assert.equal(whoisAdapter("whois://whois.sk-nic.sk:43"), "sknic");
});
test("EURid indented sections never borrow reseller or on-site information for the registrant/registrar", () => {
  const parsed = whois(fixture("eurid-whois.txt"), "whois.eu", "eu");
  assert.equal(parsed.outcome, "record"); assert.deepEqual(parsed.fields.Registrar, ["Fixture Registrar Ltd"]);
  assert.deepEqual(parsed.fields["Registrant email"], ["Redacted"]); assert.equal(parsed.fields["Registrar email"], undefined);
  assert.equal(parsed.details.attribution["Registrant email"].state, "redacted"); assert.equal(parsed.details.attribution.Expires.state, "unsupported");
  assert.deepEqual(parsed.fields.Nameservers, ["ns1.example.test", "ns2.example.test"]);
  assert.ok(parsed.unknown.email.includes("reseller@example.test")); assert.equal(parsed.details.dnssec.rawKeyData.length, 1);
  assert.equal(parsed.details.dnssec.dsData, undefined); // A published key is not a fabricated DS record.
});
test("CZ.NIC follows registrant and nsset references but excludes contact and nsset lifecycle events", () => {
  const parsed = whois(fixture("cznic-whois.txt"), "whois.nic.cz", "cz");
  assert.deepEqual(parsed.fields["Registrant name"], ["Fixture Holder"]);
  assert.deepEqual(parsed.fields["Registrant email"], ["holder@example.test"]); assert.deepEqual(parsed.fields.Created, ["2000-01-01"]);
  assert.deepEqual(parsed.fields.Expires, ["2030-01-01"]); assert.equal(parsed.fields.Registrar, undefined);
  assert.equal(parsed.fields["Registrar email"], undefined); // Contact's sponsoring registrar is only a reference.
  assert.deepEqual(parsed.fields["Registrar code"], ["REG-TEST (Registry registrar ID)"]);
  assert.deepEqual(parsed.fields.Nameservers, ["ns1.example.test", "ns2.example.test"]);
});
test("referenced CZ.NIC NSSET authorizes only nameservers, retaining hostile auxiliary evidence and exact lines", () => {
  const raw = fixture("cznic-auxiliary-adversarial-whois.txt");
  const p = whois(raw, "whois.nic.cz", "cz");
  assert.equal(p.outcome, "record"); assert.deepEqual(p.conflicts, []);
  assert.deepEqual(p.fields, {
    Domain: ["example.cz"], Created: ["2000-01-01"], Updated: ["2026-01-01T12:00:00+01:00"], Expires: ["2030-01-01"],
    Nameservers: ["ns1.example.test", "ns2.example.test"], "Registrant name": ["Fixture Holder"],
    "Registrant organization": ["Fixture Holder Ltd"], "Registrant email": ["holder@example.test"],
    "Registrar code": ["REG-TEST (Registry registrar ID)"],
  });
  assert.equal(p.details.dnssec, undefined);
  const nsset = p.details.records.find((r) => r.entries[0]?.key === "nsset");
  assert.deepEqual(p.details.attribution.Nameservers.evidence.map((e) => [e.record, e.location]), [[nsset.id, "line:11"], [nsset.id, "line:12"]]);
  for (const [label, item] of Object.entries(p.details.attribution)) {
    if (label !== "Nameservers") assert.ok(item.evidence.every((e) => e.record !== nsset.id), label);
  }
  for (const entry of nsset.entries) {
    assert.ok(raw.split("\n")[entry.line - 1].endsWith(entry.value));
    assert.ok(p.unknown[entry.key].includes(entry.value));
  }
  assert.deepEqual(p.unknown["custom-field"], ["AUXILIARY-UNKNOWN"]);
  // Authorized root values must survive; auxiliary values must not even cause conflicts.
  const owned = whois(raw.replace("registered: 2000-01-01", "status: DOMAIN-STATUS\ndnssec: DOMAIN-DNSSEC\nds-rdata: 1234 250 251 CDEF\nregistered: 2000-01-01"), "whois.nic.cz", "cz");
  assert.deepEqual(owned.fields.Status, ["DOMAIN-STATUS"]); assert.deepEqual(owned.fields["Published DNSSEC"], ["DOMAIN-DNSSEC"]);
  assert.deepEqual(owned.details.dnssec.dsData, [{ keyTag: 1234, algorithm: 250, digestType: 251, digest: "CDEF" }]);
  assert.deepEqual(owned.conflicts, []);
});

const hostile = ["status: AUXILIARY-STATUS", "created: 1900-01-01", "updated date: 1900-02-01", "expiration date: 1900-03-01",
  "registrar iana id: 9999", "registrar code: AUXILIARY-CODE", "registry registrar id: AUXILIARY-REGISTRY-ID",
  "registrar name: Auxiliary Registrar", "registrar email: auxiliary-registrar@example.test", "registrar abuse contact email: auxiliary-abuse@example.test",
  "registrant name: Auxiliary Intruder", "registrant organization: Auxiliary Organization", "registrant organization id: AUXILIARY-ORG-ID",
  "registrant phone: +1.5550100999", "registrant email: auxiliary-holder@example.test", "dnssec: AUXILIARY-DNSSEC", "ds-rdata: 9999 250 251 ABCD",
  "registered on: 01-Jan-1900", "expiry date: 02-Jan-1900", "last updated: 03-Jan-1900", "name server: auxiliary.example.test"];
for (const [adapter, host, tld, sections] of [
  ["eurid", "whois.eu", "eu", ["Name servers", "Keys", "Relevant dates", "Registration status", "DNSSEC", "Reseller"]],
  ["nominet", "whois.nic.uk", "uk", ["Name servers", "Relevant dates", "Registration status", "DNSSEC", "Keys", "Reseller"]],
]) for (const section of sections) test(`${adapter} ${section} section cannot contribute fields outside its scope`, () => {
  const raw = fixture(`${adapter}-whois.txt`), heading = new RegExp(`^\\s*${section}:\\s*$`, "mi"), match = raw.match(heading);
  // Each section receives fields owned by every other scope; its own labels are
  // tested separately below. These are synthetic adversarial mutations.
  const forbidden = hostile.filter((line) => !(section === "Registration status" && adapter === "nominet" && line.startsWith("status:"))
    && !(section === "DNSSEC" && adapter === "nominet" && /^(?:dnssec|ds-rdata):/.test(line))
    && !(section === "Relevant dates" && adapter === "nominet" && /^(?:registered on|expiry date|last updated):/.test(line))
    && !(section === "Name servers" && line.startsWith("name server:")));
  const injected = forbidden.map((line) => `        ${line}`).join("\n");
  const text = match ? raw.replace(match[0], `${match[0]}\n${injected}`) : `${raw}\n\n${section}:\n${injected}\n`;
  const before = whois(raw, host, tld), after = whois(text, host, tld);
  assert.deepEqual(after.fields, before.fields); assert.deepEqual(after.conflicts, before.conflicts);
  assert.deepEqual(after.details.dnssec, before.details.dnssec);
  for (const line of forbidden) { const split = line.indexOf(":"); assert.ok(after.unknown[line.slice(0, split)].includes(line.slice(split + 1).trim())); }
});
test("unreferenced, duplicate and wrong-kind CZ.NIC NSSET records never supply nameservers or contacts", () => {
  const raw = fixture("cznic-auxiliary-adversarial-whois.txt");
  for (const text of [raw.replace("nsset: NSSET-TEST\nkeyset", "nsset: MISSING\nkeyset"),
    `${raw}\nnsset: NSSET-TEST\nnserver: ns3.example.test\n`,
    `${raw}\nnsset: NSSET-TEST\nnserver: ns3.example.test\nnsset: UNCERTAIN\n`,
    raw.replace("nsset: NSSET-TEST\nnserver", "contact: NSSET-TEST\nnserver")]) {
    const p = whois(text, "whois.nic.cz", "cz");
    assert.equal(p.fields.Nameservers, undefined); assert.deepEqual(p.fields["Registrant name"], ["Fixture Holder"]);
    assert.equal(p.fields.Status, undefined); assert.equal(p.details.dnssec, undefined);
  }
});
test("object identity precedes contained identifiers, and ambiguous missing object separators are suppressed", () => {
  const raw = fixture("cznic-auxiliary-adversarial-whois.txt");
  const masquerade = raw.replace("nsset: NSSET-TEST\nnserver", "nsset: NSSET-TEST\nnic-hdl: HOLDER-TEST\nname: False Holder\nemail: false-holder@example.test\nnserver");
  const p = whois(masquerade, "whois.nic.cz", "cz");
  assert.deepEqual(p.fields["Registrant name"], ["Fixture Holder"]); assert.deepEqual(p.fields["Registrant email"], ["holder@example.test"]);
  assert.deepEqual(p.fields.Nameservers, ["ns1.example.test", "ns2.example.test"]); assert.deepEqual(p.conflicts, []);
  const noSeparator = whois(raw.replace("expire: 2030-01-01\n\nnsset", "expire: 2030-01-01\nnsset"), "whois.nic.cz", "cz");
  assert.equal(noSeparator.outcome, "unknown"); assert.deepEqual(noSeparator.fields, {});
  assert.ok(noSeparator.conflicts.includes("WHOIS object boundaries are ambiguous"));
  const contactBoundary = whois("domain: example.cz\nregistrant: HOLDER\n\ncontact: HOLDER\nname: Holder\nnsset: SET\nemail: false-holder@example.test\n", "whois.nic.cz", "cz");
  assert.equal(contactBoundary.fields["Registrant name"], undefined); assert.equal(contactBoundary.fields["Registrant email"], undefined);
  assert.equal(contactBoundary.details.attribution["Registrant email"].state, "ambiguous");
});
test("an auxiliary object or unrelated section cannot masquerade as the requested domain through a contained domain label", () => {
  for (const prefix of ["nsset: SET\n", "contact: HOLDER\n", "Name servers:\n        "]) {
    const raw = `${prefix}domain name: example.cz\nstatus: AUXILIARY-STATUS\nregistrant name: Auxiliary Intruder\n`;
    const p = whois(raw, "whois.nic.cz", "cz");
    assert.equal(p.outcome, "unknown"); assert.deepEqual(p.fields, {});
    assert.deepEqual(p.unknown["domain name"], ["example.cz"]);
    assert.equal(p.details.attribution.Domain.state, "missing");
  }
});
for (const [host, tld] of [["whois.sk-nic.sk", "sk"], ["whois.denic.de", "de"], ["whois.verisign-grs.com", "com"], ["registrar.example.org", "test"]])
  test(`${host} never promotes unrelated auxiliary object fields`, () => {
    const own = `Domain: example.${tld}\nCreated: 2000-01-01\nRegistrant Name: Holder\nName Server: ns1.example.test\n`;
    const before = whois(own, host, tld), after = whois(`${own}\nnsset: UNRELATED\n${hostile.join("\n")}\n`, host, tld);
    assert.deepEqual(after.fields, before.fields); assert.deepEqual(after.conflicts, before.conflicts); assert.equal(after.details.dnssec, undefined);
    assert.ok(after.unknown["registrant name"].includes("Auxiliary Intruder"));
  });
test("Nominet identifier and contact sections cannot grant generic domain-field privileges", () => {
  const raw = fixture("nominet-whois.txt"), before = whois(raw, "whois.nic.uk", "uk");
  for (const line of ["example.uk", "Fixture Holder Ltd", "Fixture Registrar Ltd [Tag = FIXTURE]"]) {
    const after = whois(raw.replace(line, `${line}\n${hostile.map((v) => `        ${v}`).join("\n")}`), "whois.nic.uk", "uk");
    assert.deepEqual(after.fields, before.fields); assert.deepEqual(after.conflicts, before.conflicts); assert.deepEqual(after.details.dnssec, before.details.dnssec);
  }
});
for (const [adapter, host, tld] of [["eurid", "whois.eu", "eu"], ["nominet", "whois.nic.uk", "uk"]])
  test(`${adapter} invalid duplicate role sections remain in ambiguity checks`, () => {
    for (const role of ["Registrant", "Registrar"]) {
      const raw = fixture(`${adapter}-whois.txt`) + `\n${role}:\n        nsset: AUXILIARY\n        Name: False Identity\n        Email: false-identity@example.test\n`;
      const p = whois(raw, host, tld), labels = role === "Registrant" ? ["Registrant name", "Registrant email"] : ["Registrar", "Registrar code", "Registrar email"];
      for (const label of labels) { assert.equal(p.fields[label], undefined); assert.equal(p.details.attribution[label].state, "ambiguous"); }
      assert.equal(p.outcome, "unknown"); assert.ok(p.unknown.name.includes("False Identity"));
    }
  });
test("Nominet's DNSSEC section authorizes only published DNSSEC/DS evidence with original provenance", () => {
  const raw = fixture("nominet-whois.txt") + "        ds-rdata: 1234 250 251 ABCD\n        ds record: 1235 13 2 CDEF\n";
  const p = whois(raw, "whois.nic.uk", "uk");
  assert.equal(p.outcome, "record"); assert.deepEqual(p.fields["Published DNSSEC"], ["Signed"]);
  assert.deepEqual(p.details.dnssec.dsData.map((e) => e.keyTag), [1234, 1235]);
  const section = p.details.records.find((r) => r.section === "dnssec");
  assert.ok(p.details.attribution.DS.evidence.every((e) => e.record === section.id && e.role === "domain"));
  assert.ok(p.details.attribution.DS.evidence.every((e) => raw.split("\n")[Number(e.location.slice(5)) - 1].includes(e.value)));
});
test("Nominet section dates remain calendar-only and tag identifiers never become IANA IDs", () => {
  const parsed = whois(fixture("nominet-whois.txt"), "whois.nic.uk", "uk");
  assert.deepEqual(parsed.fields.Expires, ["2030-06-10"]); assert.deepEqual(parsed.fields.Created, ["2003-06-10"]);
  assert.deepEqual(parsed.fields["Registrar code"], ["FIXTURE (Nominet tag)"]); assert.deepEqual(parsed.fields["Published DNSSEC"], ["Signed"]);
});
test("DENIC technical fields and gTLD DS labels retain multiple records and unknown algorithm codes", () => {
  const de = whois(fixture("denic-whois.txt"), "whois.denic.de", "de");
  assert.deepEqual(de.fields.Updated, ["2026-01-01T12:00:00+01:00"]); assert.equal(de.fields.Expires, undefined); assert.equal(de.fields["Registrant name"], undefined);
  const g = whois(fixture("gtld-whois.txt"), "whois.verisign-grs.com", "com");
  assert.equal(g.outcome, "record"); assert.equal(g.details.dnssec.dsData.length, 2); assert.equal(g.details.dnssec.dsData[1].algorithm, 250);
  assert.equal(g.details.attribution.DS.evidence.length, 2); assert.equal(g.fields["Registrar email"], undefined);
  const malformed = whois(fixture("gtld-whois.txt") + "DS Record: unknown syntax\n", "whois.verisign-grs.com", "com");
  assert.deepEqual(malformed.details.dnssec.dsData[2], { original: "unknown syntax" });
  const huge = whois(fixture("gtld-whois.txt") + `DS Record: ${"9".repeat(500)} 13 2 AB\n`, "whois.verisign-grs.com", "com");
  assert.ok(huge.details.dnssec.dsData[2].original); assert.doesNotThrow(() => JSON.stringify(huge));
});
test("generic extraction only promotes domain-local, explicitly role-labelled fields and preserves unknown evidence", () => {
  const p = whois("Domain Name: example.sk\nRegistrant Name: Holder\nRegistrar Name: Registrar\nconstructor: safe\nCreated: 2000-01-01\n\nContact: OTHER\nRegistrant Email: wrong@example.test\nCreated: 1900-01-01\n", "registrar.example.org");
  assert.deepEqual(p.fields["Registrant name"], ["Holder"]); assert.deepEqual(p.fields.Registrar, ["Registrar"]);
  assert.equal(p.fields["Registrant email"], undefined); assert.deepEqual(p.fields.Created, ["2000-01-01"]); assert.deepEqual(p.unknown.constructor, ["safe"]);
  assert.deepEqual(Object.keys(p.fields).sort(), ["Created", "Domain", "Registrar", "Registrant name"].sort());
  assert.equal(whois("Bespoke registration prose", "registrar.example.org").outcome, "unknown");
  assert.equal(whois('No match for "EXAMPLE.SK"').outcome, "not_found");
  assert.equal(whois('No match for "OTHER.SK"').outcome, "unknown");
  const conflict = whois("Domain: example.sk\nRegistrant Name: One\nRegistrant Name: Two\nRegistrant Email: uncertain@example.test\n", "registrar.example.org");
  assert.equal(conflict.fields["Registrant email"], undefined); assert.equal(conflict.details.attribution["Registrant email"].state, "ambiguous");
  assert.equal(whoisRecords("Domain: example.sk\r\n\r\nContact: H\r\nName: Person\r\n").records.length, 2);
});
for (const tld of ["net", "cz", "de", "uk", "org", "tech"]) test(`live-derived sanitized ${tld} RDAP structure retains domain fields and technical evidence`, () => {
  const raw = fixture(`${tld}-rdap.json`), data = JSON.parse(raw), p = parseRdap(raw, "domain", 200, `example.${tld}`);
  assert.equal(p.outcome, "record"); assert.equal(p.details.attribution.Domain.state, "available"); assert.deepEqual(p.details.dnssec, data.secureDNS);
  assert.deepEqual(p.details.events, data.events); assert.equal(p.fields.Nameservers.length, data.nameservers.length);
  if (tld === "cz") { assert.ok(p.details.extensions.fred_nsset); assert.equal(p.fields["Registrant name"], undefined); }
  if (tld === "uk") { assert.deepEqual(p.fields["Registrant email"], ["Redacted"]); assert.equal(p.fields["Registrar email"], undefined); }
  if (tld === "tech") assert.equal(p.details.attribution["Registrant name"].state, "redacted");
});
test("RDAP nested contacts describe their parent, never the domain registrant, including nested redactions/events", () => {
  const p = rdap({ ...domain, entities: [card("registrar", "Registrar", { entities: [card("registrant", "Wrong Holder", { events: [{ eventAction: "registration", eventDate: "1900-01-01T00:00:00Z" }] }), card("abuse", "Abuse")] }), card("registrant", "Real Holder")] });
  assert.deepEqual(p.fields["Registrant name"], ["Real Holder"]); assert.equal(p.fields.Created, undefined);
  assert.deepEqual(p.fields["Registrar email"], ["registrar@example.test"]); assert.equal(p.details.contacts[1].parent, "$/entities/0");
  assert.equal(p.details.contacts[1].events.length, 1); assert.equal(p.details.attribution["Registrant name"].evidence[0].record, "$/entities/1");
});
test("separate RDAP role records with complementary properties cannot be combined into an invented identity", () => {
  const p = rdap({ ...domain, entities: [card("registrant", "One"), { roles: ["registrant"], vcardArray: ["vcard", [["org", {}, "text", "Other Org"]]] }] });
  for (const key of ["Registrant name", "Registrant organization", "Registrant email"]) { assert.equal(p.fields[key], undefined); assert.equal(p.details.attribution[key].state, "ambiguous"); }
  assert.equal(p.details.contacts.length, 2);
});
test("typed RDAP redactions override partial/replacement data and use the standard default removal method", () => {
  const p = rdap({ ...domain, entities: [card("registrant", "Partial Name")], redacted: [{ name: { type: "Registrant Name" }, method: "partialValue" }, { name: { type: "Registrant Email" }, method: "replacementValue" }, { name: { type: "Registrant Phone" } }] });
  assert.deepEqual(p.fields["Registrant name"], ["Redacted (partial value)"]); assert.deepEqual(p.fields["Registrant email"], ["Redacted"]); assert.deepEqual(p.fields["Registrant phone"], ["Redacted"]);
  assert.equal(p.details.contacts[0].values.fn[0], "Partial Name");
  const unrelated = rdap({ ...domain, entities: [card("technical", "Technician", { redacted: [{ name: { type: "Registrant Name" } }] }), card("registrant", "Holder")] });
  assert.deepEqual(unrelated.fields["Registrant name"], ["Holder"]);
});
test("calendar and timestamp validation does not roll invalid dates or invent timezone instants", () => {
  for (const value of ["2030-01-01", "2024-02-29", "2030-01-01T00:00:00Z", "2030-01-01T00:00:00+01:00"]) assert.equal(registrationDate(value), true);
  for (const value of ["2030-02-29", "2030-02-30", "2030-01-01T12:00:00", "1/2/2030", "2030-01-01T25:00:00Z"]) {
    assert.equal(registrationDate(value), false); const p = whois(`Domain: example.sk\nValid Until: ${value}\n`); assert.equal(p.fields.Expires, undefined); assert.equal(p.details.attribution.Expires.state, "unsupported");
  }
  const p = whois("Domain: example.sk\nValid Until: 2030-01-01\nValid Until: 2031-01-01\n"); assert.equal(p.fields.Expires, undefined); assert.equal(p.details.attribution.Expires.evidence.length, 2);
});
test("lookup binds parser provenance to the final referral service, retaining metadata and raw response", async () => {
  resetRegistrationState(); resetBootstrapState();
  const replies = ["domain: SK\nwhois: whois.sk-nic.sk\n", "Domain: example.sk\nWhois Server: registrar.example.org\n", "Domain: example.sk\nRegistrar Name: Final Registrar\n"];
  const result = await lookupRegistration({ target: "example.sk", protocolMode: "whois" }, { clientIp: "parsing-test", lookup: async () => [{ address: "8.8.8.8", family: 4 }], transport: async () => ({ status: 200, headers: {}, text: replies.shift() }) });
  assert.equal(result.normalized.details.parser, "generic"); assert.equal(result.normalized.details.attribution.Registrar.source, result.source);
  assert.equal(result.source, "whois://registrar.example.org:43"); assert.equal(result.rawResponses.length, 3); assert.equal(result.fallbackReason, null); assert.equal(result.cache.cached, false);
});
