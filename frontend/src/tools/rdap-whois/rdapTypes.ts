export type RegistrationMode = 'auto' | 'rdap' | 'whois';
export type RegistrationKind = 'domain' | 'ipv4' | 'ipv6' | 'asn';
export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export type RegistrationAttempt = { protocol: 'rdap' | 'whois'; phase: string; source: string; timestamp: string; outcome: string; status: number | null };
export type RegistrationRaw = { protocol: 'rdap' | 'whois'; phase: string; source: string; timestamp: string; text: string };
export type RegistrationNormalized = {
  outcome: 'record' | 'not_found' | 'unknown'; fields: Record<string, string[]>;
  details: Record<string, JsonValue>; unknown: Record<string, string[]>; conflicts: string[];
};
export type RegistrationResult = {
  ok: true; input: { original: string; canonical: string; kind: RegistrationKind; protocolMode: RegistrationMode };
  protocol: 'rdap' | 'whois'; source: string; timestamp: string; outcome: RegistrationNormalized['outcome'];
  normalized: RegistrationNormalized;
  discovery: { source: string; fetchedAt: string; ageSeconds: number; fresh: boolean; expiresAt: string | null; publication: string | null };
  attempts: RegistrationAttempt[]; rawResponses: RegistrationRaw[]; fallbackReason: string | null;
  cache: { cached: boolean; ageSeconds: number; ttlSeconds: number }; warnings: string[];
};
export type RegistrationFailure = { ok: false; error: { code: string; message: string }; attempts: RegistrationAttempt[]; rawResponses: RegistrationRaw[] };
export type RegistrationResponse = RegistrationResult | RegistrationFailure;
