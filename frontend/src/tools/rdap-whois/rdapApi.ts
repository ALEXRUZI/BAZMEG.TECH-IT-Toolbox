import type { RegistrationMode, RegistrationResponse } from './rdapTypes';

const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === 'object' && !Array.isArray(v);
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every((s) => typeof s === 'string');
const stringMap = (v: unknown) => object(v) && Object.values(v).every(strings);
const finite = (v: unknown) => typeof v === 'number' && Number.isFinite(v) && v >= 0;
const date = (v: unknown) => typeof v === 'string' && Number.isFinite(Date.parse(v));
const protocol = (v: unknown) => v === 'rdap' || v === 'whois';

export function validateRegistrationResponse(value: unknown): RegistrationResponse {
  const bad = () => { throw new Error('The registration API returned an invalid response.'); };
  let nodes = 0;
  const visit = (v: unknown, depth: number) => {
    if (++nodes > 100000 || depth > 40 || (typeof v === 'number' && !Number.isFinite(v))) bad();
    if (v !== null && typeof v === 'object') for (const child of Object.values(v)) visit(child, depth + 1);
  };
  visit(value, 0);
  if (!object(value) || !Array.isArray(value.attempts) || value.attempts.length > 12 || !Array.isArray(value.rawResponses) || value.rawResponses.length > 8) return bad();
  for (const attempt of value.attempts) {
    if (!object(attempt) || !protocol(attempt.protocol) || !['phase', 'source', 'outcome'].every((key) => typeof attempt[key] === 'string') || !date(attempt.timestamp) || !(attempt.status === null || finite(attempt.status))) bad();
  }
  for (const raw of value.rawResponses) {
    if (!object(raw) || !protocol(raw.protocol) || !['phase', 'source', 'text'].every((key) => typeof raw[key] === 'string') || !date(raw.timestamp)) bad();
  }
  if (value.ok === false) {
    if (!object(value.error) || typeof value.error.code !== 'string' || typeof value.error.message !== 'string') return bad();
  } else if (value.ok === true) {
    if (!object(value.input) || typeof value.input.original !== 'string' || typeof value.input.canonical !== 'string'
      || typeof value.input.kind !== 'string' || !['domain', 'ipv4', 'ipv6', 'asn'].includes(value.input.kind)
      || typeof value.input.protocolMode !== 'string' || !['auto', 'rdap', 'whois'].includes(value.input.protocolMode)
      || !protocol(value.protocol) || typeof value.source !== 'string' || !date(value.timestamp)
      || typeof value.outcome !== 'string' || !['record', 'not_found', 'unknown'].includes(value.outcome)
      || !object(value.normalized) || value.normalized.outcome !== value.outcome || !stringMap(value.normalized.fields)
      || !object(value.normalized.details) || !stringMap(value.normalized.unknown) || !strings(value.normalized.conflicts)
      || !object(value.cache) || typeof value.cache.cached !== 'boolean' || !finite(value.cache.ageSeconds) || !finite(value.cache.ttlSeconds)
      || !object(value.discovery) || typeof value.discovery.source !== 'string' || !date(value.discovery.fetchedAt)
      || !finite(value.discovery.ageSeconds) || typeof value.discovery.fresh !== 'boolean'
      || !(value.discovery.expiresAt === null || date(value.discovery.expiresAt)) || !(value.discovery.publication === null || typeof value.discovery.publication === 'string')
      || !(value.fallbackReason === null || typeof value.fallbackReason === 'string') || !strings(value.warnings)) return bad();
    const attribution = value.normalized.details.attribution;
    if (attribution !== undefined) {
      if (!object(attribution)) return bad();
      for (const item of Object.values(attribution)) {
        if (!object(item) || typeof item.state !== 'string' || !['available', 'ambiguous', 'missing', 'redacted', 'unsupported'].includes(item.state)
          || item.protocol !== value.protocol || !(item.source === null || item.source === value.source) || !Array.isArray(item.evidence)) return bad();
        for (const entry of item.evidence) if (!object(entry) || !['value', 'record', 'role', 'location'].every((key) => typeof entry[key] === 'string') || typeof entry.state !== 'string' || !['available', 'redacted'].includes(entry.state)) return bad();
      }
    }
  } else return bad();
  // The assertion follows validation of every contract used by the UI.
  return value as unknown as RegistrationResponse;
}

export async function fetchRegistration(target: string, protocolMode: RegistrationMode, signal: AbortSignal) {
  const response = await fetch('/api/tools/rdap-lookup', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target, protocolMode }), signal });
  const text = await response.text();
  if (text.length > 4 * 1024 * 1024) throw new Error('The registration API response was too large.');
  const body = validateRegistrationResponse(JSON.parse(text));
  if (!response.ok && body.ok) throw new Error('The registration API returned an unsuccessful status.');
  return body;
}
