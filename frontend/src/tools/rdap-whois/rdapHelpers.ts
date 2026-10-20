import type { JsonValue, RegistrationKind, RegistrationResult } from './rdapTypes';

export function classifyRegistration(input: string): { canonical: string; kind: RegistrationKind } {
  if (input.length > 512 || /[\p{Cc}\p{Cf}]/u.test(input)) throw new Error('Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.');
  const value = input.trim();
  if (!value || /[\s/?#@\\\[\],;%]/u.test(value)) throw new Error('Enter one identifier, without a URL, port, prefix length, or bulk input.');
  if (/^AS\d+$/i.test(value)) {
    const n = Number(value.slice(2));
    if (!Number.isInteger(n) || n < 1 || n > 4294967295) throw new Error('ASN must be AS1 through AS4294967295.');
    return { kind: 'asn', canonical: `AS${n}` };
  }
  if (/^\d+\.\d+\.\d+\.\d+$/.test(value)) {
    if (value.split('.').some((v) => !/^(?:0|[1-9]\d{0,2})$/.test(v) || Number(v) > 255)) throw new Error('Enter a valid individual IP address.');
    return { kind: 'ipv4', canonical: value };
  }
  if (value.includes(':')) {
    try {
      const host = new URL(`https://[${value}]/`).hostname;
      if (!host.startsWith('[')) throw new Error();
      return { kind: 'ipv6', canonical: host.slice(1, -1) };
    } catch { throw new Error('Enter a valid IPv6 address, without brackets, zone, or port.'); }
  }
  if (/^[\d.]+$/.test(value)) throw new Error('Enter a valid individual IP address.');
  let canonical: string;
  try { canonical = new URL(`https://${value.replace(/\.$/, '').toLowerCase()}/`).hostname; }
  catch { throw new Error('Enter a valid domain.'); }
  const labels = canonical.split('.');
  if (canonical.length > 253 || labels.length < 2 || /^\d+$/.test(labels.at(-1) ?? '') || labels.some((v) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(v))) throw new Error('Enter a valid domain with at least two labels.');
  return { kind: 'domain', canonical };
}

export function expirationRemaining(result: RegistrationResult, now: number): string {
  if (result.normalized.conflicts.includes('Expires') || overviewState(result, 'Expires') === 'ambiguous') return 'Conflicting expiration values; no calculation';
  const values = [...new Set(result.normalized.fields.Expires ?? [])];
  if (values.length !== 1) return values.length ? 'Conflicting expiration values; no calculation' : 'Unavailable';
  // Do not assign a timezone to ambiguous registry date strings.
  const match = values[0].match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](\d{2}):(\d{2}))$/);
  if (!match) return /^\d{4}-\d{2}-\d{2}$/.test(values[0]) ? 'Calendar date only; exact expiration time and timezone unpublished' : 'Timezone-explicit expiration unavailable';
  const [, yearText, monthText, dayText, hourText, minuteText, secondText, offsetHour, offsetMinute] = match;
  const year = Number(yearText), month = Number(monthText), day = Number(dayText);
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  const monthDays = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (month < 1 || month > 12 || day < 1 || day > monthDays[month - 1] || Number(hourText) > 23 || Number(minuteText) > 59 || Number(secondText) > 59 || Number(offsetHour ?? 0) > 23 || Number(offsetMinute ?? 0) > 59) return 'Invalid expiration date; no calculation';
  const expires = Date.parse(values[0]);
  if (!Number.isFinite(expires) || !Number.isFinite(now)) return 'Unavailable';
  const ms = expires - now;
  return ms > 0 ? `${(ms / 86400000).toFixed(2)} days remaining (display rounded)` : ms === 0 ? 'Expires at this instant' : 'Expired';
}

export function normalizedExport(result: RegistrationResult) {
  const { rawResponses: _raw, ...normalized } = result;
  return normalized;
}

export function overviewState(result: RegistrationResult, key: string): string | undefined {
  const attribution = result.normalized.details.attribution;
  if (!jsonObject(attribution)) return undefined;
  const item = attribution[key];
  return jsonObject(item) && typeof item.state === 'string' ? item.state : undefined;
}
export function overviewValues(result: RegistrationResult, key: string): string[] {
  const state = overviewState(result, key);
  if (result.normalized.conflicts.includes(key) || state === 'ambiguous') return ['Conflicting / ambiguous; see detailed evidence'];
  if (state === 'unsupported') return ['Unsupported field or format; see detailed evidence'];
  const values = result.normalized.fields[key] ?? [];
  return ['Created', 'Updated', 'Expires'].includes(key) ? values.map((value) => /^\d{4}-\d{2}-\d{2}$/.test(value) ? `${value} (calendar date)` : value) : values;
}

export function registrationOverviewFields(result: RegistrationResult): Record<string, string> {
  const { fields, details, unknown } = result.normalized;
  const value = (key: string) => overviewValues(result, key).join('\n') || 'Unavailable';
  if (result.input.kind === 'domain') return { 'Domain name': overviewValues(result, 'Domain').join('\n') || result.input.canonical, 'Expiration date': value('Expires') };
  const contacts = details.contacts;
  const contactFields = Object.fromEntries(Object.entries({ ...unknown, ...fields }).filter(([key]) => /^(?:admin-c|tech-c|abuse-c|nic-hdl|person|role|e-mail|phone|address|Abuse email|Abuse phone)$/.test(key)));
  const contactText = Array.isArray(contacts) && contacts.length ? JSON.stringify(contacts, null, 2)
    : Object.keys(contactFields).length ? JSON.stringify(contactFields, null, 2) : 'Unavailable';
  return {
    ...(result.input.kind === 'asn' ? { ASN: result.input.canonical, 'ASN range': value('ASN range') }
      : { Address: result.input.canonical, 'Registered range': value('Registered range'), CIDR: value('CIDR') }),
    [result.input.kind === 'asn' ? 'ASN name' : 'Network name']: value('Network / ASN name'),
    'Registered holder': value('Registered holder'), 'Registry / RIR': fields['Registry / RIR']?.join('\n') || 'Unavailable / unknown',
    'Published country': value('Published country'), Contacts: contactText,
  };
}

export function registrationContactFields(result: RegistrationResult, role: 'registrant' | 'registrar'): Record<string, string[]> {
  const prefix = role === 'registrant' ? 'Registrant' : 'Registrar';
  const keys = { Name: role === 'registrant' ? 'Registrant name' : 'Registrar', Organization: `${prefix} organization`,
    [role === 'registrant' ? 'Organization ID' : 'Registrar code']: `${prefix} ${role === 'registrant' ? 'organization ID' : 'code'}`,
    Phone: `${prefix} phone`, Email: `${prefix} email` };
  return Object.fromEntries(Object.entries(keys).map(([label, key]) => [label, [...new Set(overviewValues(result, key))].filter((v) => v.trim())]));
}

export function lookupTimestamp(value: string): string {
  const time = Date.parse(value);
  return Number.isFinite(time) ? new Date(time).toISOString().replace('T', ' ').replace('Z', ' UTC') : 'Unavailable';
}

const dnssecAlgorithms: Record<number, string> = {
  1: 'RSA / MD5', 2: 'Diffie-Hellman', 3: 'DSA / SHA-1', 5: 'RSA / SHA-1', 6: 'DSA-NSEC3 / SHA-1', 7: 'RSA-NSEC3 / SHA-1',
  8: 'RSA / SHA-256', 10: 'RSA / SHA-512', 12: 'GOST R 34.10-2001', 13: 'ECDSA P-256 / SHA-256', 14: 'ECDSA P-384 / SHA-384', 15: 'Ed25519', 16: 'Ed448',
};
const dnssecDigests: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 3: 'GOST R 34.11-94', 4: 'SHA-384' };
const dnssecDigestBytes: Record<number, number> = { 1: 20, 2: 32, 3: 32, 4: 48 };
const jsonObject = (v: JsonValue | undefined): v is { [key: string]: JsonValue } => v !== null && typeof v === 'object' && !Array.isArray(v);
function dnssecNumber(value: JsonValue | undefined, max: number, names: Record<number, string> = {}): string {
  if (typeof value === 'number' && Number.isInteger(value) && value >= 0 && value <= max) return `${value}${Object.hasOwn(names, value) ? ` — ${names[value]}` : ''}`;
  return typeof value === 'string' || typeof value === 'number' ? `${value} (unrecognized format)` : 'Unavailable / malformed';
}
export function publishedDnssec(result: RegistrationResult) {
  const data = result.normalized.details.dnssec;
  const statuses = (result.normalized.fields['Published DNSSEC'] ?? []).filter((value) => value.trim());
  if ((data == null || (jsonObject(data) && !Object.keys(data).length)) && !statuses.length) return null;
  const dns = jsonObject(data) ? data : {};
  let malformed = data != null && !jsonObject(data);
  if (dns.delegationSigned !== undefined && typeof dns.delegationSigned !== 'boolean') malformed = true;
  if (dns.dsData !== undefined && !Array.isArray(dns.dsData)) malformed = true;
  const records = (Array.isArray(dns.dsData) ? dns.dsData : []).map((entry) => {
    if (!jsonObject(entry) || !['keyTag', 'algorithm', 'digestType', 'digest'].some((key) => Object.hasOwn(entry, key))) {
      malformed = true;
      return null; // An invalid entry is evidence, not an invented DS record.
    }
    const record = entry;
    const digestBytes = typeof record.digestType === 'number' ? dnssecDigestBytes[record.digestType] : undefined;
    const validDigest = typeof record.digest === 'string' && /^(?:[a-f0-9]{2})+$/i.test(record.digest)
      && (digestBytes === undefined || record.digest.length === digestBytes * 2);
    if (!validDigest || ['keyTag', 'algorithm', 'digestType'].some((key) => typeof record[key] !== 'number'
      || !Number.isInteger(record[key]) || Number(record[key]) < 0 || Number(record[key]) > (key === 'keyTag' ? 65535 : 255))) malformed = true;
    return { 'Key tag': dnssecNumber(record.keyTag, 65535), Algorithm: dnssecNumber(record.algorithm, 255, dnssecAlgorithms),
      'Digest type': dnssecNumber(record.digestType, 255, dnssecDigests), Digest: typeof record.digest === 'string' ? record.digest : 'Unavailable / malformed' };
  });
  return { status: dns.delegationSigned === true ? 'Signed delegation reported' : dns.delegationSigned === false ? 'Unsigned delegation reported' : 'Registry DNSSEC metadata reported', statuses, records, malformed };
}

// ICANN's published EPP / RDAP status mapping. These explain registration
// states only; they do not test DNS, reachability or purchase availability.
export function registrationStatusExplanation(value: string): string {
  const key = value.replace(/\s+https?:\/\/.*$/i, '').toLowerCase().replace(/\s/g, '');
  const known: Record<string, string> = {
    ok: 'Standard status: no pending operations or prohibitions are reported.',
    active: 'Standard status: no pending operations or prohibitions are reported.',
    inactive: 'The registry reports no associated delegation information.',
    addperiod: 'Grace period after initial registration.',
    autorenewperiod: 'Grace period after automatic registry renewal.',
    renewperiod: 'Grace period after explicit renewal.',
    transferperiod: 'Grace period after a completed registrar transfer.',
    redemptionperiod: 'Registry redemption state after a deletion request; restoration may be subject to registry policy.',
    pendingrestore: 'A restoration request is awaiting required completion/documentation.',
    pendingdelete: 'Pending deletion state; interpretation also depends on redemption/restore statuses. No purchase-availability guarantee.',
    pendingcreate: 'A creation request is being processed.', pendingrenew: 'A renewal request is being processed.',
    pendingtransfer: 'A transfer request is being processed.', pendingupdate: 'An update request is being processed.',
    clienthold: 'Registrar-set hold: the registry is instructed not to activate DNS delegation.',
    serverhold: 'Registry-set hold: DNS delegation is not activated by the registry.',
  };
  if (Object.hasOwn(known, key)) return known[key];
  const prohibited = key.match(/^(client|server)(delete|renew|transfer|update)prohibited$/);
  if (prohibited) return `${prohibited[1] === 'client' ? 'Registrar' : 'Registry'}-set restriction: ${prohibited[2]} requests are prohibited.`;
  return 'Registry-specific or unrecognized status; no interpretation inferred.';
}
export function downloadRegistration(value: string, filename: string, mime: string) {
  const url = URL.createObjectURL(new Blob([value], { type: mime }));
  const link = document.createElement('a'); link.href = url; link.download = filename;
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
