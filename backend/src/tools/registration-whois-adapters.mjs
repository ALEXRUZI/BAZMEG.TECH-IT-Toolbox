// Exact responding services, verified against registry documentation/IANA.
// This selects syntax, not an authenticated WHOIS identity. Never select by TLD.
const SERVICES = new Map([
  ["whois.sk-nic.sk", "sknic"], ["whois.eu", "eurid"],
  ["whois.nic.cz", "cznic"], ["whois.denic.de", "denic"], ["whois.nic.uk", "nominet"],
  ["whois.verisign-grs.com", "gtld"], ["whois.publicinterestregistry.org", "gtld"], ["whois.nic.tech", "gtld"],
]);
export function whoisAdapter(source) {
  try { const url = new URL(source); return url.protocol === "whois:" && (!url.port || url.port === "43") && !url.username && !url.password ? SERVICES.get(url.hostname) ?? "generic" : "generic"; }
  catch { return "generic"; }
}
// A sibling section is a narrow relationship, never another domain object.
// EURid's retained fixture shape has no Nominet lifecycle/status sections.
const SECTION_SCOPES = {
  eurid: { "name servers": "nameservers", keys: "keys" },
  nominet: { "name servers": "nameservers", "relevant dates": "dates", "registration status": "status", dnssec: "dnssec" },
};
export function whoisSectionScope(adapter, section) {
  const scopes = SECTION_SCOPES[adapter];
  return scopes && Object.hasOwn(scopes, section) ? scopes[section] : null;
}
export const DATE_LABELS = {
  "creation date": "Created", created: "Created", "registry expiry date": "Expires", "expiration date": "Expires",
  "registrar registration expiration date": "Expires", "updated date": "Updated", "last-modified": "Updated",
};
export const ADAPTER_DATES = {
  sknic: { "valid until": "Expires", updated: "Updated" },
  cznic: { registered: "Created", changed: "Updated", expire: "Expires" },
  nominet: { "registered on": "Created", "expiry date": "Expires", "last updated": "Updated" },
  denic: { changed: "Updated" },
};
export const CONTACT_KEYS = {
  name: "name", organization: "organization", organisation: "organization", org: "organization",
  "organization id": "organization ID", "organisation id": "organization ID", "company number": "organization ID",
  phone: "phone", "phone number": "phone", telephone: "phone", email: "email", "e-mail": "email",
};
export function contactLabel(role, key) {
  if (!Object.hasOwn(CONTACT_KEYS, key)) return null;
  if (role === "registrar" && CONTACT_KEYS[key] === "organization ID") return null; // not a registrar code
  return role === "registrar" && key === "name" ? "Registrar" : `${role === "registrar" ? "Registrar" : "Registrant"} ${CONTACT_KEYS[key]}`;
}
export const REDACTED = /^(?:redacted(?: for (?:privacy|gdpr))?|data redacted|not disclosed!?|withheld for privacy)$/i;
export function canonicalDate(value, adapter) {
  // Nominet documents English day-month-year dates. Keep calendar precision.
  if (adapter !== "nominet") return value;
  const m = value.match(/^(\d{2})-([a-z]{3})-(\d{4})$/i);
  const month = m && ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].indexOf(m[2].toLowerCase()) + 1;
  return month ? `${m[3]}-${String(month).padStart(2, "0")}-${m[1]}` : value;
}
