import { REGISTRATION_LIMITS as L } from "./registration-resources.mjs";
import net from "node:net";
import { domainToASCII } from "node:url";
import { fail, ipNumber } from "./registration-input.mjs";
import { parseDomainWhois } from "./registration-whois.mjs";
import { evidenceCollector } from "./registration-evidence.mjs";

export function boundedJson(text) {
  if (typeof text !== "string" || Buffer.byteLength(text) > L.bootstrapBytes) fail("RESPONSE_TOO_LARGE", "Registration JSON exceeds the byte limit.");
  // Bound nesting before JSON.parse, including unknown extension data.
  let depth = 0, quoted = false, escaped = false;
  for (const char of text) {
    if (quoted) { if (escaped) escaped = false; else if (char === "\\") escaped = true; else if (char === '"') quoted = false; }
    else if (char === '"') quoted = true;
    else if (char === "{" || char === "[") { if (++depth > L.jsonDepth) fail("LIMIT_EXCEEDED", "Registration JSON nesting limit exceeded."); }
    else if (char === "}" || char === "]") depth--;
  }
  let data;
  try { data = JSON.parse(text); } catch { fail("MALFORMED_REPLY", "Registration service returned malformed JSON."); }
  let nodes = 0;
  const visit = (value) => {
    if (++nodes > L.jsonNodes) fail("LIMIT_EXCEEDED", "Registration JSON node limit exceeded.");
    if (typeof value === "number" && !Number.isFinite(value)) fail("MALFORMED_REPLY", "Non-finite registration JSON number.");
    if (value && typeof value === "object") for (const child of Object.values(value)) visit(child);
  };
  visit(data); return data;
}
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const strings = (v) => Array.isArray(v) && v.every((s) => typeof s === "string");

// Only explicitly attributed properties become domain overview fields. Handles,
// UID properties and untyped public IDs are not organization/registrar numbers.
const CONTACT_LABELS = {
  registrant: { name: "Registrant name", organization: "Registrant organization", id: "Registrant organization ID", phone: "Registrant phone", email: "Registrant email" },
  registrar: { name: "Registrar", organization: "Registrar organization", code: "Registrar code", phone: "Registrar phone", email: "Registrar email" },
};
const redactionText = /^(?:redacted(?: for (?:privacy|gdpr))?|data redacted|not disclosed|withheld for privacy)$/i;
const contactText = (value) => {
  if (typeof value === "string") return value.trim();
  // jCard structured org/name components and multi-valued components.
  if (Array.isArray(value)) return value.map(contactText).filter(Boolean).join(" / ");
  return "";
};
function addContact(fields, label, value) {
  const text = contactText(value);
  if (text) (fields[label] ??= []).push(redactionText.test(text) ? "Redacted" : text);
}
function publicContactId(type, role) {
  if (typeof type !== "string") return null;
  if (role === "registrar") {
    if (/^iana registrar (?:id|identifier)$/i.test(type)) return "IANA ID";
    if (/^registry(?:-specific)? registrar (?:id|identifier|code)$/i.test(type)) return type;
    if (/^registrar (?:id|identifier|code)$/i.test(type)) return `${type}; system unspecified`;
  } else if (/^(?:organization (?:id|identifier)|company (?:registration (?:number|id)|number)|legal entity identifier|lei)$/i.test(type)) return type;
  return null;
}
function domainEntityFields(entity, values, fields) {
  const sharedRoles = entity.roles?.includes("registrant") && entity.roles.includes("registrar");
  for (const role of ["registrant", "registrar"]) {
    if (!entity.roles?.includes(role)) continue;
    const labels = CONTACT_LABELS[role];
    // A shared jCard does not say which ordinary role its name/organization or
    // contact details describe. Keep it as evidence, not duplicated overview data.
    if (!sharedRoles) {
      for (const value of values.fn ?? []) addContact(fields, labels.name, value);
      if (!(values.fn ?? []).some(contactText)) for (const value of values.n ?? []) {
        if (Array.isArray(value) && value.length === 5) addContact(fields, labels.name, [value[3], value[1], value[2], value[0], value[4]].map(contactText).filter(Boolean).join(" "));
      }
      for (const value of values.org ?? []) addContact(fields, labels.organization, value);
    }
    // A multi-role abuse/admin/technical card does not establish ordinary contact
    // attribution. Never borrow a child abuse card's email or phone either.
    if (!sharedRoles && !entity.roles.some((v) => ["abuse", "administrative", "technical"].includes(v))) {
      for (const value of values.tel ?? []) addContact(fields, labels.phone, value);
      for (const value of values.email ?? []) addContact(fields, labels.email, value);
    }
    if (role === "registrant" && !sharedRoles) for (const key of ["org-id", "x-org-id", "x-organization-id", "x-company-number"]) {
      for (const value of values[key] ?? []) addContact(fields, labels.id, value);
    }
    for (const id of Array.isArray(entity.publicIds) ? entity.publicIds : []) {
      // Registrar-typed IDs remain attributable; generic organization IDs on a
      // shared card do not establish the registrant's organization identity.
      if (sharedRoles && role === "registrant") continue;
      if (!object(id) || typeof id.identifier !== "string" || !id.identifier.trim()) continue;
      const system = publicContactId(id.type, role);
      if (system) addContact(fields, role === "registrar" ? labels.code : labels.id, `${id.identifier} (${system})`);
    }
  }
}
function domainRedactions(redacted, fields, roles = null) {
  // RFC 9537 registered, field-specific names only. Do not infer a field or role
  // from a free-text description, arbitrary JSONPath, or a general privacy notice.
  for (const entry of Array.isArray(redacted) ? redacted : []) {
    if (!object(entry) || !object(entry.name) || typeof entry.name.type !== "string"
      || ![undefined, "removal", "emptyValue", "partialValue", "replacementValue"].includes(entry.method)) continue;
    const whole = entry.name.type.match(/^(Registrant|Registrar) Contact$/i);
    if (whole) {
      if (roles && !roles.includes(whole[1].toLowerCase())) continue;
      for (const label of Object.values(CONTACT_LABELS[whole[1].toLowerCase()])) fields[label] = ["Redacted"];
      continue;
    }
    const match = entry.name.type.match(/^(Registrant|Registrar) (Name|Organization|Organization ID|Phone|Email)$/i);
    if (!match) continue;
    if (roles && !roles.includes(match[1].toLowerCase())) continue;
    const labels = CONTACT_LABELS[match[1].toLowerCase()];
    const key = ({ name: "name", organization: "organization", "organization id": "id", phone: "phone", email: "email" })[match[2].toLowerCase()];
    // A partial/replacement value is not an unredacted contact detail. Never
    // leave it in the overview alongside an apparently complete value.
    if (labels[key]) fields[labels[key]] = [entry.method === "partialValue" ? "Redacted (partial value)" : "Redacted"];
  }
}

export function parseRdap(text, kind, status, canonical) {
  const data = boundedJson(text);
  if (!object(data)) fail("MALFORMED_REPLY", "RDAP response must be an object.");
  if (status === 404) {
    if (data.errorCode !== 404) fail("MALFORMED_REPLY", "RDAP 404 did not contain a valid not-found response.");
    if (kind === "domain" && ["objectClassName", "ldhName", "unicodeName", "handle", "entities", "nameservers", "events", "status", "secureDNS"].some((key) => data[key] !== undefined)) fail("MALFORMED_REPLY", "RDAP not-found response contains conflicting registration data.");
    return { outcome: "not_found", fields: {}, details: { notices: data.notices ?? [], description: data.description ?? [] }, unknown: {}, conflicts: [] };
  }
  const expected = kind === "domain" ? "domain" : kind === "asn" ? "autnum" : "ip network";
  if (data.objectClassName !== expected || data.errorCode !== undefined
    || (kind === "domain" && typeof data.ldhName !== "string")
    || (kind === "asn" && (!Number.isInteger(data.startAutnum) || !Number.isInteger(data.endAutnum)))
    || (["ipv4", "ipv6"].includes(kind) && (typeof data.startAddress !== "string" || typeof data.endAddress !== "string"))) fail("MALFORMED_REPLY", "RDAP response has an invalid registration object.");
  if (data.status !== undefined && !strings(data.status)) fail("MALFORMED_REPLY", "Invalid RDAP status list.");
  if (kind === "domain" && canonical && domainToASCII(data.ldhName.toLowerCase()) !== canonical) fail("MALFORMED_REPLY", "RDAP domain does not match the query.");
  if (kind === "asn" && (data.startAutnum < 0 || data.endAutnum > 4294967295 || data.startAutnum > data.endAutnum
    || (canonical && (Number(canonical.slice(2)) < data.startAutnum || Number(canonical.slice(2)) > data.endAutnum)))) fail("MALFORMED_REPLY", "RDAP ASN range does not match the query.");
  if (["ipv4", "ipv6"].includes(kind)) {
    const family = kind === "ipv4" ? 4 : 6;
    if (net.isIP(data.startAddress) !== family || net.isIP(data.endAddress) !== family || ipNumber(data.startAddress) > ipNumber(data.endAddress)
      || (canonical && (ipNumber(canonical) < ipNumber(data.startAddress) || ipNumber(canonical) > ipNumber(data.endAddress)))) fail("MALFORMED_REPLY", "RDAP IP range does not match the query.");
  }
  for (const key of ["entities", "events", "nameservers", "notices", "remarks", "links"]) {
    if (data[key] !== undefined && (!Array.isArray(data[key]) || !data[key].every(object))) fail("MALFORMED_REPLY", "Invalid RDAP detail list.");
  }
  const fields = {}, collector = evidenceCollector("rdap");
  for (const [key, label] of Object.entries({ ldhName: "Domain", unicodeName: "Unicode domain", handle: "Identifier", name: "Network / ASN name", country: "Published country", type: "Registration type", startAddress: "Range start", endAddress: "Range end", startAutnum: "ASN range start", endAutnum: "ASN range end" })) {
    if (data[key] !== undefined) {
      if (!["string", "number"].includes(typeof data[key])) fail("MALFORMED_REPLY", "Invalid RDAP registration field.");
      fields[label] = [String(data[key])];
    }
  }
  if (data.status) fields.Status = data.status;
  if (["ipv4", "ipv6"].includes(kind)) fields["Registered range"] = [`${data.startAddress} – ${data.endAddress}`];
  if (kind === "asn") fields["ASN range"] = [`AS${data.startAutnum} – AS${data.endAutnum}`];
  if (Array.isArray(data.cidr0_cidrs)) {
    const cidrs = data.cidr0_cidrs.filter((v) => object(v) && Number.isInteger(v.length)
      && v.length >= 0 && v.length <= (kind === "ipv4" ? 32 : 128)
      && net.isIP(v.v4prefix ?? v.v6prefix) === (kind === "ipv4" ? 4 : 6));
    if (cidrs.length) fields.CIDR = cidrs.map((v) => `${v.v4prefix ?? v.v6prefix}/${v.length}`);
  }
  if (data.nameservers) fields.Nameservers = data.nameservers.map((v) => v.ldhName).filter((v) => typeof v === "string");
  for (const event of data.events ?? []) {
    if (typeof event.eventAction !== "string" || typeof event.eventDate !== "string") fail("MALFORMED_REPLY", "Invalid RDAP registration event.");
    const labels = { registration: "Created", expiration: "Expires", "last changed": "Updated" };
    const label = Object.hasOwn(labels, event.eventAction) ? labels[event.eventAction] : null;
    if (label) (fields[label] ??= []).push(event.eventDate);
  }
  // Domain events belong to this object only. Entity events stay in evidence.
  if (kind === "domain") for (const [label, values] of Object.entries(fields)) {
    for (const value of values) collector.add(label, value, "$", "domain", label === "Nameservers" ? "$/nameservers" : ["Created", "Updated", "Expires"].includes(label) ? "$/events" : "$" );
  }
  const contacts = [], roleRecords = { registrant: [], registrar: [] };
  const entities = (list, depth = 0, parent = "$") => {
    if (depth > 8) fail("LIMIT_EXCEEDED", "RDAP entity depth exceeded.");
    for (const [index, entity] of list.entries()) {
      const path = `${parent}/entities/${index}`;
      if (!object(entity) || (entity.roles !== undefined && !strings(entity.roles))) fail("MALFORMED_REPLY", "Invalid RDAP entity.");
      const values = Object.create(null);
      if (entity.vcardArray !== undefined) {
        if (!Array.isArray(entity.vcardArray) || entity.vcardArray[0] !== "vcard" || !Array.isArray(entity.vcardArray[1])) fail("MALFORMED_REPLY", "Invalid RDAP contact card.");
        for (const row of entity.vcardArray[1]) {
          if (!Array.isArray(row) || row.length !== 4 || typeof row[0] !== "string") fail("MALFORMED_REPLY", "Invalid RDAP contact property.");
          (values[row[0].toLowerCase()] ??= []).push(row[3]);
        }
      }
      contacts.push({ record: path, parent, handle: entity.handle ?? null, roles: entity.roles ?? [], values, publicIds: entity.publicIds ?? [], vcardArray: entity.vcardArray ?? null, redacted: entity.redacted ?? [], events: entity.events ?? [] });
      if (kind === "domain" && depth === 0) {
        const local = {};
        domainEntityFields(entity, values, local); domainRedactions(entity.redacted, local, entity.roles ?? []);
        for (const role of ["registrant", "registrar"]) if (entity.roles?.includes(role) && Object.keys(local).some((label) => role === "registrar" ? /^Registrar(?: |$)/.test(label) : label.startsWith("Registrant "))) roleRecords[role].push(path);
        for (const [label, values] of Object.entries(local)) for (const value of values) collector.add(label, value, path, label.startsWith("Registrant ") ? "registrant" : "registrar", path, value.startsWith("Redacted") ? "redacted" : "available");
      }
      else if (kind !== "domain" && entity.roles?.includes("registrar")) fields.Registrar = [...(fields.Registrar ?? []), ...(values.fn ?? []).filter((v) => typeof v === "string")];
      if (kind !== "domain" && entity.roles?.includes("registrant")) fields["Registered holder"] = [...(fields["Registered holder"] ?? []), ...(values.org ?? values.fn ?? []).filter((v) => typeof v === "string")];
      if (entity.entities !== undefined) { if (!Array.isArray(entity.entities)) fail("MALFORMED_REPLY", "Invalid nested RDAP entities."); entities(entity.entities, depth + 1, path); }
    }
  };
  entities(data.entities ?? []);
  let attribution, conflicts;
  if (kind === "domain") {
    const redacted = {}; domainRedactions(data.redacted, redacted);
    for (const [label, values] of Object.entries(redacted)) {
      // A response-level typed redaction takes precedence over contact data.
      collector.evidence[label] = [];
      for (const value of values) collector.add(label, value, "$", label.startsWith("Registrant ") ? "registrant" : "registrar", "$/redacted", "redacted");
    }
    for (const [role, records] of Object.entries(roleRecords)) if (records.length > 1) {
      for (const label of Object.keys(collector.evidence)) if (role === "registrar" ? /^Registrar(?: |$)/.test(label) : label.startsWith("Registrant ")) collector.ambiguous.add(label);
    }
    if (data.secureDNS !== undefined) collector.add("Published DNSSEC", JSON.stringify(data.secureDNS), "$", "domain", "$/secureDNS");
    ({ attribution, conflicts } = collector.finish(fields));
    delete fields["Published DNSSEC"]; // The UI renders secureDNS structurally.
  } else conflicts = Object.keys(fields).filter((key) => ["Created", "Expires", "Updated", "Registrar", "Registered holder"].includes(key) && new Set(fields[key]).size > 1);
  const standard = new Set(["objectClassName", "ldhName", "unicodeName", "handle", "name", "country", "type", "startAddress", "endAddress", "startAutnum", "endAutnum", "status", "entities", "events", "nameservers", "notices", "remarks", "links", "secureDNS", "redacted", "cidr0_cidrs", "rdapConformance", "port43"]);
  return { outcome: "record", fields, details: { contacts, events: data.events ?? [], notices: data.notices ?? [], remarks: data.remarks ?? [], links: data.links ?? [], dnssec: data.secureDNS ?? null, redacted: data.redacted ?? [], cidrs: data.cidr0_cidrs ?? [], extensions: Object.fromEntries(Object.entries(data).filter(([key]) => !standard.has(key))), ...(attribution ? { attribution } : {}) }, unknown: {}, conflicts };
}

const WHOIS_FIELDS = {
  "domain name": "Domain", domain: "Domain", registrar: "Registrar", "registrar iana id": "Registrar ID",
  "registry domain id": "Identifier", netname: "Network / ASN name", "as-name": "Network / ASN name", "aut-num": "ASN", "as-block": "ASN range",
  inetnum: "Registered range", inet6num: "Registered range", netrange: "Registered range", cidr: "CIDR",
   organization: "Registered holder", orgname: "Registered holder", "org-name": "Registered holder", "registrant organization": "Registered holder",
  country: "Published country", "name server": "Nameservers", nserver: "Nameservers",
  "domain status": "Status", status: "Status", dnssec: "Published DNSSEC",
  "creation date": "Created", created: "Created", "registry expiry date": "Expires", "registrar registration expiration date": "Expires", "expiration date": "Expires", "paid-till": "Expires",
  "updated date": "Updated", "last-modified": "Updated", "registrar abuse contact email": "Abuse email", "abuse-mailbox": "Abuse email", "registrar abuse contact phone": "Abuse phone",
};
function whoisContactLabel(key) {
  const normalized = key.replace(/[_-]/g, " ").replace(/\s+/g, " ");
  if (/^(?:registry(?: specific)? registrar|registrar registry) (?:id|identifier|code)$/.test(normalized)) return { label: "Registrar code", system: "Registry registrar ID" };
  const match = normalized.match(/^(registrant|registrar) (name|organization|organisation|organization id|organisation id|company number|phone|phone number|telephone|e mail|email|iana id|id|identifier|code)$/);
  if (!match) return null;
  const [, role, property] = match, labels = CONTACT_LABELS[role];
  const keyName = ({ name: "name", organization: "organization", organisation: "organization", "organization id": "id", "organisation id": "id", "company number": "id", phone: "phone", "phone number": "phone", telephone: "phone", "e mail": "email", email: "email" })[property];
  if (role === "registrar" && ["iana id", "id", "identifier", "code"].includes(property)) return { label: labels.code, system: property === "iana id" ? "IANA ID" : `Registrar ${property === "id" ? "ID" : property}; system unspecified` };
  return keyName && labels[keyName] ? { label: labels[keyName] } : null;
}
export function parseWhois(text, input = null, source = null) {
  if (Buffer.byteLength(text) > L.responseBytes) fail("RESPONSE_TOO_LARGE", "WHOIS response exceeds the byte limit.");
  const lines = text.split(/\r?\n/);
  if (lines.length > L.whoisLines || lines.some((v) => v.length > 8192)) fail("LIMIT_EXCEEDED", "WHOIS parsing limit exceeded.");
  if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(text) || !text.trim()) fail("MALFORMED_REPLY", "Empty or invalid WHOIS text.");
  // Match explicit diagnostic lines, not registration remarks explaining a
  // registry's general rate policy. Unknown error formats remain inspectable.
  const diagnostics = lines.filter((line) => /^(?:[%#]\s*)?(?:(?:error|warning|notice)\s*[: -]?\s*(?:\d+[: -]\s*)?)?(?:rate[ -]limit|too many queries|quota exceeded|query limit|limit exceeded|you have exceeded|your connection limit|access denied|permission denied|not authorized|access forbidden|query refused|temporarily unavailable|service unavailable|try again later)/i.test(line.trim())).join("\n");
  if (/rate[ -]limit|too many queries|quota exceeded|query limit|limit exceeded|you have exceeded|your connection limit/i.test(diagnostics)) fail("UPSTREAM_RATE_LIMITED", "WHOIS service rate-limited the query.");
  if (/access denied|permission denied|not authorized|access forbidden|query refused/i.test(diagnostics)) fail("SECURITY_REJECTION", "WHOIS service denied access.");
  if (/temporarily unavailable|service unavailable|try again later/i.test(diagnostics)) fail("TEMPORARY_FAILURE", "WHOIS service is temporarily unavailable.");
  if (input?.kind === "domain") return parseDomainWhois(text, input, source);
  const fields = {}, unknown = Object.create(null), unparsed = [];
  let negative = false;
  for (const line of lines) {
    if (/^(?:no match for\s|not found\.?$|no entries found|%\s*(?:no entries found|error: 101: no entries found))/i.test(line.trim())) negative = true;
    const match = line.match(/^([A-Za-z][A-Za-z0-9 _-]{0,79}):\s*(.*)$/);
    if (!match) { if (line.trim()) unparsed.push(line); continue; }
    const key = match[1].trim().toLowerCase(), label = Object.hasOwn(WHOIS_FIELDS, key) ? WHOIS_FIELDS[key] : null, value = match[2].trim();
    if (value) {
      // Keep original fields/unknown values as evidence, including redaction text.
      const contact = key === "registrar" ? { label: "Registrar" } : whoisContactLabel(key);
      if (label && contact?.label !== label) (fields[label] ??= []).push(value);
      else (unknown[key] ??= []).push(value);
      if (contact) addContact(fields, contact.label, contact.system ? `${value} (${contact.system})` : value);
    }
  }
  const conflicts = Object.keys(fields).filter((key) => !["Nameservers", "Status", "Abuse email", "Abuse phone"].includes(key) && new Set(fields[key]).size > 1);
  const hasRecord = ["Domain", "ASN", "Registered range", "Network / ASN name"].some((v) => fields[v]?.length);
  const mismatch = input?.kind === "domain" && fields.Domain?.some((v) => domainToASCII(v.replace(/\.$/, "").toLowerCase()) !== input.canonical)
    || input?.kind === "asn" && fields.ASN?.some((v) => /^(?:AS)?\d+$/i.test(v) && `AS${Number(v.replace(/^AS/i, ""))}` !== input.canonical);
  if (mismatch) conflicts.push("Registration identifier does not match the query");
  // Do not turn unfamiliar prose into an invented record or negative finding.
  return { outcome: conflicts.length ? "unknown" : negative && !hasRecord ? "not_found" : hasRecord && !negative ? "record" : "unknown", fields, details: { unparsed, warning: "Conservative WHOIS extraction; unknown/conflicting values remain visible. UTF-8 decoding may replace legacy bytes." }, unknown, conflicts: negative && hasRecord ? [...conflicts, "Conflicting record / no-match statements"] : conflicts };
}

export function whoisReferral(text, iana = false) {
  const matches = [];
  for (const line of text.split(/\r?\n/)) {
    const match = line.match(iana ? /^(?:refer|whois):\s*(.*?)\s*$/i : /^(?:Registrar WHOIS Server|Whois Server|ReferralServer|refer):\s*(.*?)\s*$/i);
    if (match?.[1]) matches.push(match[1]);
  }
  const values = [...new Set(matches.map((v) => v.toLowerCase()))];
  if (values.length > 1) fail("MALFORMED_REPLY", "Conflicting WHOIS referrals.");
  return values[0] ?? null;
}
