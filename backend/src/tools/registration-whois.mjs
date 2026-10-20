import { domainToASCII } from "node:url";
import { evidenceCollector, OVERVIEW_FIELDS } from "./registration-evidence.mjs";
import { whoisAdapter, whoisSectionScope, DATE_LABELS, ADAPTER_DATES, contactLabel, REDACTED, canonicalDate } from "./registration-whois-adapters.mjs";

// Blanks delimit objects. Empty section headings delimit EURid/Nominet blocks.
// Preserve every parsed field with its original 1-based line, including fields
// that are unsupported or cannot be associated with the requested domain.
export function whoisRecords(text) {
  const records = [], unparsed = [];
  let record = null, heading = null;
  const start = (section = null) => { record = { id: `whois:${records.length}`, section, entries: [] }; records.push(record); heading = section; };
  for (const [index, line] of text.split(/\r?\n/).entries()) {
    if (!line.trim()) { record = null; heading = null; continue; }
    if (/^\s*[%#]/.test(line)) { unparsed.push({ line: index + 1, text: line }); continue; }
    const match = line.match(/^\s*([A-Za-z][A-Za-z0-9 '_-]{0,79}):\s*(.*?)\s*$/);
    if (match) {
      const key = match[1].trim().toLowerCase().replace(/\s+/g, " "), value = match[2];
      if (!value) { start(key); continue; }
      // Explicit object starts also survive missing blank separators. A registrar
      // key inside a domain/contact is a reference, not a new registrar object.
      if (["domain", "domain name", "contact", "nic-hdl", "domain registrant"].includes(key) && record?.entries.some((e) => e.key === key || ["domain", "domain name"].includes(e.key))) start();
      if (!record) start();
      record.entries.push({ key, value, line: index + 1 });
    } else if (record && /^\s+\S/.test(line) && heading) record.entries.push({ key: "$text", value: line.trim(), line: index + 1 });
    else unparsed.push({ line: index + 1, text: line });
  }
  return { records, unparsed };
}
const entries = (record, keys) => record.entries.filter((e) => keys.includes(e.key));
const vals = (record, keys) => entries(record, keys).map((e) => e.value);
const ascii = (value) => domainToASCII(value.toLowerCase().replace(/\.$/, ""));
const roleFields = (role) => OVERVIEW_FIELDS.filter((k) => role === "registrar" ? /^Registrar(?: |$)/.test(k) : k.startsWith("Registrant "));
const recordKind = (record) => {
  // The first object anchor establishes the kind. A later contact/registrar
  // identifier in an NSSET cannot turn that NSSET into a holder/registrar.
  for (const e of record.entries) {
    if (["domain", "domain name"].includes(e.key)) return "domain";
    if (["contact", "nic-hdl", "domain registrant"].includes(e.key)) return "contact";
    if (["nsset", "keyset", "registrar"].includes(e.key)) return e.key;
  }
  return "unknown";
};
const ambiguousObjectBoundary = (record, adapter) => {
  // With no blank separator, a repeated set/registrar anchor might be another
  // object or another reference. Do not guess and extract its following fields.
  const anchors = ["nsset", "keyset", ...(["sknic", "cznic"].includes(adapter) ? ["registrar"] : [])];
  return anchors.some((key) => entries(record, [key]).length > 1)
    || recordKind(record) === "contact" && entries(record, ["nsset", "keyset"]).length > 0;
};

export function parseDomainWhois(text, input, source = null) {
  const adapter = whoisAdapter(source), { records, unparsed } = whoisRecords(text);
  const fields = {}, unknown = Object.create(null), collector = evidenceCollector("whois", source);
  const add = (label, e, record, role = "domain", value = e.value) => collector.add(label, REDACTED.test(value) ? "Redacted" : value, record.id, role, `line:${e.line}`, REDACTED.test(value) ? "redacted" : "available");
  const domains = records.filter((r) => r.section === "domain name" || !r.section && recordKind(r) === "domain" && entries(r, ["domain", "domain name"]).length);
  const matchedDomain = domains.length === 1 && (domains[0].section === "domain name"
    ? vals(domains[0], ["$text"]).length === 1 && ascii(vals(domains[0], ["$text"])[0]) === input.canonical
    : entries(domains[0], ["domain", "domain name"]).every((e) => ascii(e.value) === input.canonical)) ? domains[0] : null;
  const boundaryConflict = matchedDomain && ambiguousObjectBoundary(matchedDomain, adapter);
  const domain = boundaryConflict ? null : matchedDomain;
  // Never combine data for multiple domains or an identifier-mismatched record.
  const identifierConflict = boundaryConflict ? ["WHOIS object boundaries are ambiguous"] : domains.length && !domain ? ["Registration identifier does not match a unique domain record"] : [];
  const selectedRoles = { registrant: [], registrar: [] };
  if (domain) {
    for (const e of entries(domain, ["domain", "domain name", ...(domain.section === "domain name" ? ["$text"] : [])])) add("Domain", e, domain);
    // Only the matched flat domain object owns generic domain fields. Nominet's
    // Domain name section owns the identifier alone. Every other association
    // grants an explicit extraction scope, not access to the domain extractor.
    const scopedRecords = [{ record: domain, scope: domain.section ? "identifier" : "domain" }];
    if (["eurid", "nominet"].includes(adapter)) {
      // These registries use explicit sibling sections within one domain reply.
      for (const r of records) {
        if (["registrant", "registrar"].includes(r.section)) selectedRoles[r.section].push(r);
        const scope = whoisSectionScope(adapter, r.section);
        if (scope && recordKind(r) === "unknown") scopedRecords.push({ record: r, scope });
      }
    }
    if (["sknic", "cznic"].includes(adapter)) {
      for (const role of ["registrant", "registrar"]) {
        const references = [...new Set(vals(domain, role === "registrant" ? ["registrant", "domain registrant"] : ["registrar"]))];
        const ids = role === "registrant" ? ["contact", "nic-hdl", "domain registrant"] : ["registrar"];
        const expectedKind = role === "registrant" ? "contact" : "registrar";
        const eligible = records.filter((r) => r !== domain && !r.section && recordKind(r) === expectedKind);
        const explicit = eligible.filter((r) => entries(r, role === "registrant" ? ["domain registrant"] : ["registrar"]).length);
        const referenced = eligible.filter((r) => vals(r, ids).some((v) => references.includes(v)));
        // SK-NIC publishes role-tagged sections, CZ.NIC contact handles require
        // an exact domain reference. Never use the first arbitrary contact.
        selectedRoles[role] = references.length === 1 ? referenced : references.length > 1 ? [] : adapter === "sknic" ? explicit : [];
        if (references.length > 1) for (const label of roleFields(role)) collector.ambiguous.add(label);
        if (role === "registrar" && references.length === 1) {
          const e = entries(domain, ["registrar"])[0]; add("Registrar code", e, domain, "registrar", `${e.value} (Registry registrar ID)`);
        }
      }
      if (adapter === "cznic") {
        const refs = [...new Set(vals(domain, ["nsset"]))];
        const sets = records.filter((r) => r !== domain && !r.section && recordKind(r) === "nsset" && r.entries[0]?.key === "nsset" && refs.includes(r.entries[0].value));
        if (refs.length === 1 && sets.length === 1 && !ambiguousObjectBoundary(sets[0], adapter)) scopedRecords.push({ record: sets[0], scope: "nameservers" });
        // A keyset DNSKEY is not a DS record. Keep it in the original evidence.
      }
    }
    for (const { record: r, scope } of scopedRecords) for (const e of r.entries) {
      const dates = ADAPTER_DATES[adapter] ?? {};
      const date = scope === "domain" && Object.hasOwn(DATE_LABELS, e.key) ? DATE_LABELS[e.key] : Object.hasOwn(dates, e.key) ? dates[e.key] : null;
      if ((scope === "domain" || scope === "dates") && date) add(date, e, r, "domain", canonicalDate(e.value, adapter));
      if ((scope === "domain" || scope === "nameservers") && (["name server", "nserver", "nameserver"].includes(e.key) || r.section === "name servers" && e.key === "$text")) {
        const name = e.value.split(/\s+/)[0].replace(/\.$/, "").toLowerCase();
        if (name.includes(".") && name.split(".").every((v) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v))) add("Nameservers", e, r, "domain", name);
      }
      if ((scope === "domain" || scope === "status") && (["domain status", "status", "registration status"].includes(e.key) || scope === "status" && e.key === "$text")) add("Status", e, r);
      if ((scope === "domain" || scope === "dnssec") && (e.key === "dnssec" || scope === "dnssec" && e.key === "$text")) add("Published DNSSEC", e, r);
      if ((scope === "domain" || scope === "dnssec") && ["ds record", "ds-rdata"].includes(e.key)) add("DS", e, r);
      // Keep only the retained labelled DNSKEY shape as key evidence. Other
      // labels in Keys remain in records/unknown, not published DNSSEC evidence.
      if (scope === "keys" && e.key === "flags" && /^\S+\s+protocol:\S+\s+algorithm:\S+\s+pubKey:\S+$/i.test(e.value)) add("DNSKEY evidence", e, r, "domain", `${e.key}: ${e.value}`);
      if (scope !== "domain") continue;
      // Generic role-prefixed fields are safe only on this domain object.
      const contact = e.key.replace(/[_-]/g, " ").match(/^(registrant|registrar) (name|organization|organisation|organization id|organisation id|company number|phone|phone number|telephone|email|e mail)$/);
      if (contact) {
        const label = contactLabel(contact[1], contact[2] === "e mail" ? "email" : contact[2]);
        if (label) add(label, e, r, contact[1]);
      }
      if (e.key === "registrar iana id") add("Registrar code", e, r, "registrar", `${e.value} (IANA ID)`);
      if (/^registrar (?:id|identifier|code)$/.test(e.key)) add("Registrar code", e, r, "registrar", `${e.value} (${e.key}; system unspecified)`);
      if (e.key === "registrar abuse contact email") add("Abuse email", e, r, "abuse");
      if (e.key === "registrar abuse contact phone") add("Abuse phone", e, r, "abuse");
      if (e.key === "registrar" && adapter === "gtld") add("Registrar", e, r, "registrar");
      if (/^(?:registry(?: specific)? registrar|registrar registry) (?:id|identifier|code)$/.test(e.key.replace(/[_-]/g, " "))) add("Registrar code", e, r, "registrar", `${e.value} (Registry registrar ID)`);
    }
    for (const [role, candidates] of Object.entries(selectedRoles)) {
      if (candidates.length > 1) for (const label of roleFields(role)) collector.ambiguous.add(label);
      for (const r of candidates) {
        // Invalid role sections still count as candidates. Filtering one out
        // before ambiguity checks could falsely select another competing role.
        if (ambiguousObjectBoundary(r, adapter) || ["eurid", "nominet"].includes(adapter) && recordKind(r) !== "unknown") {
          for (const label of roleFields(role)) collector.ambiguous.add(label);
          continue;
        }
        for (const e of r.entries) {
          const label = contactLabel(role, e.key);
          if (label) add(label, e, r, role);
          if (e.key === "$text" && ["eurid", "nominet"].includes(adapter) && r.section === role) {
            if (REDACTED.test(e.value)) for (const label of roleFields(role)) add(label, e, r, role, "Redacted");
            else if (adapter === "nominet") {
              if (role === "registrar") {
                const tag = e.value.match(/^(.*?)\s*\[Tag\s*=\s*([^\]]+)\]$/i);
                if (tag) { add("Registrar", e, r, role, tag[1]); add("Registrar code", e, r, role, `${tag[2]} (Nominet tag)`); }
              } else if (entries(r, ["$text"]).length === 1) add("Registrant name", e, r, role);
            }
          }
          if (adapter === "sknic" && role === "registrar" && e.key === "registrar") add("Registrar code", e, r, role, `${e.value} (Registry registrar ID)`);
        }
      }
    }
  }
  // Preserve all fields, including unmatched contacts and unsupported keys.
  for (const r of records) for (const e of r.entries) (unknown[e.key] ??= []).push(e.value);
  // Whole diagnostic lines only. SK-NIC's identifier-free wording is accepted
  // only as the complete response from that responding service, never by TLD.
  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const sknicNegative = adapter === "sknic" && text.trim() === "Domain not found.";
  const isNegative = (line) => /^(?:no match for\s+["']?[a-z0-9.-]+["']?\.?|not found\.?|no entries found\.?|%\s*(?:no entries found\.?|error:\s*101:\s*no entries found\.?))$/i.test(line);
  const negativeLines = lines.filter(isNegative);
  const mismatchedNegative = negativeLines.some((line) => {
    const match = line.match(/^no match for\s+["']?([a-z0-9.-]+)/i);
    return match && ascii(match[1]) !== input.canonical;
  });
  const negative = (adapter === "sknic" && lines.includes("Domain not found.")) || negativeLines.length > 0;
  // Object fields, comments and unexplained prose cannot establish absence.
  // Only the explicitly supported percent-prefixed diagnostics count as such.
  const confirmedNegative = sknicNegative || negativeLines.length > 0 && records.length === 0
    && lines.every(isNegative);
  if (["eurid", "denic"].includes(adapter)) for (const label of ["Created", "Expires"]) collector.unsupported.add(label);
  if (adapter === "eurid") for (const label of roleFields("registrant")) collector.unsupported.add(label);
  if (adapter === "generic") for (const label of roleFields("registrar")) collector.unsupported.add(label);
  const { attribution, conflicts } = collector.finish(fields, [...identifierConflict, ...(mismatchedNegative ? ["No-match identifier does not match the query"] : []), ...(negative && domain ? ["Conflicting record / no-match statements"] : [])]);
  // DS syntax only where explicitly labelled; preserve every original line and
  // unknown numeric code. Malformed records remain visible in detailed evidence.
  const ds = (collector.evidence.DS ?? []).map((e) => {
    const m = e.value.match(/^(\d+)\s+(\d+)\s+(\d+)\s+([a-f0-9]+)$/i);
    const numbers = m?.slice(1, 4).map(Number);
    return numbers?.every(Number.isSafeInteger) ? { keyTag: numbers[0], algorithm: numbers[1], digestType: numbers[2], digest: m[4] } : { original: e.value };
  });
  const keys = collector.evidence["DNSKEY evidence"] ?? [];
  if (keys.length && !attribution["Published DNSSEC"].evidence.length) attribution["Published DNSSEC"] = { state: "available", protocol: "whois", source, evidence: keys };
  delete fields.DS; delete fields["DNSKEY evidence"];
  return { outcome: conflicts.length ? "unknown" : domain && !negative ? "record" : confirmedNegative && !domains.length ? "not_found" : "unknown", fields, unknown, conflicts,
    details: { parser: adapter, records, unparsed, attribution, ...(ds.length || keys.length ? { dnssec: { ...(ds.length ? { dsData: ds } : {}), ...(keys.length ? { rawKeyData: keys.map((e) => e.value) } : {}) } } : {}),
      warning: "Record-aware WHOIS extraction; missing values do not imply redaction. WHOIS is unauthenticated. UTF-8 decoding may replace legacy bytes." } };
}
