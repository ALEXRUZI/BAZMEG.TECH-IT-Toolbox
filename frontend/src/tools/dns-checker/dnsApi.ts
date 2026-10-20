import type { DnsCheckPayload, DnsCheckResponse, DnsCheckResult } from './dnsTypes';
import { isDnsSpfMechanism } from './dnsHelpers';

const object = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const strings = (value: unknown) => Array.isArray(value) && value.every((item) => typeof item === 'string');
const summary = (value: unknown) => object(value) && typeof value.id === 'string' && typeof value.name === 'string'
  && ['profile', 'category'].every((key) => value[key] === undefined || typeof value[key] === 'string');

function records(value: unknown) {
  return Array.isArray(value) && value.every((record) => object(record)
    && typeof record.name === 'string' && typeof record.type === 'string'
    && ['address', 'target', 'host', 'value', 'exchange', 'tag', 'mname', 'rname'].every((key) => record[key] === undefined || typeof record[key] === 'string')
    && ['ttl', 'preference', 'priority', 'weight', 'port', 'flags', 'serial', 'refresh', 'retry', 'expire', 'minimum'].every((key) => record[key] === undefined || (typeof record[key] === 'number' && Number.isFinite(record[key])))
    && ['chunks', 'resolvedA', 'resolvedAAAA'].every((key) => record[key] === undefined || strings(record[key])));
}

function diagnostic(value: unknown) {
  if (!object(value) || typeof value.ok !== 'boolean' || (value.mode !== 'single' && value.mode !== 'burst')
    || typeof value.status !== 'string' || typeof value.durationMs !== 'number' || !Number.isFinite(value.durationMs) || value.durationMs < 0
    || !(value.responseCode === null || typeof value.responseCode === 'string') || !object(value.query)) return false;
  const query = value.query;
  return ['input', 'queryName', 'displayName', 'recordType'].every((key) => typeof query[key] === 'string')
    && ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR', 'SRV'].includes(String(query.recordType))
    && ['service', 'protocol', 'domain'].every((key) => query[key] === null || typeof query[key] === 'string')
    && ['records', 'answer', 'authority', 'additional'].every((key) => records(value[key]))
    && strings(value.warnings) && object(value.dnssec) && object(value.raw)
    && Array.isArray(value.diagnostics) && value.diagnostics.every((item) => object(item) && typeof item.id === 'string'
      && ['status', 'message'].every((key) => item[key] === undefined || typeof item[key] === 'string')
      && (item.mechanismDetails === undefined || (Array.isArray(item.mechanismDetails) && item.mechanismDetails.every(isDnsSpfMechanism))));
}

export function isDnsCheckResult(value: unknown): value is DnsCheckResult {
  if (!diagnostic(value) || !object(value) || 'error' in value || !object(value.cache)
    || typeof value.cache.fromCache !== 'boolean' || value.cache.cacheScope !== 'site') return false;
  const cache = value.cache;
  if (!['cacheTtlSeconds', 'cacheAgeSeconds', 'cacheExpiresInSeconds'].every((key) => cache[key] === undefined
    || (typeof cache[key] === 'number' && Number.isFinite(cache[key]) && cache[key] >= 0))) return false;
  if (value.mode === 'single') return summary(value.provider) && summary(value.resolver) && value.providers === undefined;
  return value.provider === null && object(value.resolver) && typeof value.resolver.group === 'string'
    && Array.isArray(value.resolver.providers) && value.resolver.providers.every(summary)
    && Array.isArray(value.providers) && value.providers.length > 0 && value.providers.every((provider) => diagnostic(provider) && summary(provider.provider) && summary(provider.resolver));
}

export function parseDnsCheckResponse(value: unknown): DnsCheckResponse {
  if (object(value) && value.ok === false && object(value.error) && typeof value.error.code === 'string'
    && typeof value.error.message === 'string' && value.error.message.trim()) {
    return { ok: false, error: { code: value.error.code, message: value.error.message } };
  }
  if (isDnsCheckResult(value)) return value;
  return { ok: false, error: { code: 'DNS_CHECK_FAILED', message: 'DNS check returned an unexpected response. Please try again.' } };
}

export async function fetchDnsCheck(payload: DnsCheckPayload) {
  const response = await fetch('/api/tools/dns-check', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });
  const body = parseDnsCheckResponse(await response.json().catch(() => null));

  return { response, body };
}
