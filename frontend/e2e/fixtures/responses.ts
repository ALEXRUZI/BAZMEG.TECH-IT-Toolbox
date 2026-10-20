import type { DnsCheckSuccess } from '../../src/tools/dns-checker/dnsTypes';
import type { HttpHeaderCheckSuccess } from '../../src/tools/http-header-checker/httpHeaderTypes';
import type { TlsCertificateDetail, TlsCheckSuccess } from '../../src/tools/tls-certificate-checker/tlsTypes';

// Synthetic data, with the envelopes emitted by the existing backend tools.
const records = [{ name: 'example.com', type: 'A', ttl: 300, address: '93.184.216.34' }];
const provider = { id: 'cloudflare', name: 'Cloudflare DNS' };
export const dnsResponse: DnsCheckSuccess = {
  ok: true, mode: 'single',
  query: { input: 'example.com', queryName: 'example.com', displayName: 'example.com', recordType: 'A', service: null, protocol: null, domain: null },
  resolver: provider, provider, responseCode: 'NOERROR', durationMs: 12, status: 'ok',
  records, answer: records, authority: [], additional: [],
  diagnostics: [{ id: 'dnssec_deep_checks', status: 'info', doFlagSent: true, adFlag: false, dsRecords: 0, dnskeyRecords: 0, rrsigPresent: false, nsecPresent: false }], warnings: [],
  dnssec: { requested: true, doFlagSent: true, adFlag: false, rrsigPresent: false, nsecPresent: false, deepChecksDisabled: false, dsRecords: [], dnskeyRecords: [], dsPresent: false, dnskeyPresent: false },
  raw: { id: 1234, responseCode: 'NOERROR', flags: { qr: true, rd: true, ra: true, ad: false }, question: [{ name: 'example.com', type: 'A' }], answer: records, authority: [], additional: [] },
  cache: { fromCache: false, cacheScope: 'site', cacheTtlSeconds: 60, cacheAgeSeconds: 0, cacheExpiresInSeconds: 60 },
};

export const httpResponse: HttpHeaderCheckSuccess = {
  ok: true, input: { original: 'example.com', cleanHost: 'example.com', protocolMode: 'auto' },
  budget: { checksRequested: 1, freshChecks: 1, cachedChecks: 0, tokensConsumed: 1 },
  cache: { ttlSeconds: 60 }, redirectLimit: 2,
  checks: [{
    ok: true, protocol: 'auto', port: 80, cached: false,
    cacheTtlSeconds: 60, cacheAgeSeconds: 0, cacheExpiresInSeconds: 60,
    startUrl: 'http://example.com/', finalUrl: 'https://example.com/', finalCheckedUrl: 'https://example.com/', status: 200, statusText: 'OK',
    redirectsFollowed: 1, chainDisplay: 'http://example.com/ --> https://example.com/',
    redirects: [{ from: 'http://example.com/', to: 'https://example.com/', status: 301, statusText: 'Moved Permanently', location: 'https://example.com/' }],
    blockedRedirect: null, durationMs: 15,
    headers: [{ name: 'content-type', value: 'text/html; charset=utf-8' }, { name: 'server', value: 'fixture-server' }],
    interestingHeaders: [{ name: 'server', category: 'Server information', explanation: 'Identifies server software.', values: ['fixture-server'] }],
    findings: [{ severity: 'warning', code: 'MISSING_HSTS', title: 'Missing HSTS', detail: 'The HTTPS response did not include Strict-Transport-Security.', recommendation: 'Add HSTS after confirming the site is ready to require HTTPS.' }],
  }],
};

// Matches findings emitted by the backend for these observed HTTPS headers.
export const httpSecurityResponse: HttpHeaderCheckSuccess = {
  ...httpResponse,
  checks: [{
    ...httpResponse.checks[0],
    headers: [
      { name: 'strict-transport-security', value: 'max-age=0; includeSubDomains' },
      { name: 'access-control-allow-origin', value: '*' },
      { name: 'access-control-allow-credentials', value: 'true' },
      { name: 'content-security-policy', value: "default-src 'self'; frame-ancestors 'none'" },
      { name: 'x-content-type-options', value: 'nosniff' },
      { name: 'referrer-policy', value: 'no-referrer' },
      { name: 'cache-control', value: 'no-store' },
    ],
    interestingHeaders: [
      { name: 'strict-transport-security', category: 'Security headers', explanation: 'Advertises an HSTS policy over HTTPS; valid max-age=0 removes the cached policy for this host.', values: ['max-age=0; includeSubDomains'] },
      { name: 'content-security-policy', category: 'Security headers', explanation: 'Controls which resources the browser may load or execute.', values: ["default-src 'self'; frame-ancestors 'none'"] },
      { name: 'x-content-type-options', category: 'Security headers', explanation: 'nosniff prevents some MIME sniffing behavior.', values: ['nosniff'] },
      { name: 'referrer-policy', category: 'Security headers', explanation: 'Controls how much referrer information browsers send.', values: ['no-referrer'] },
      { name: 'cache-control', category: 'Cache', explanation: 'Primary HTTP caching directive.', values: ['no-store'] },
      { name: 'access-control-allow-origin', category: 'CORS', explanation: 'Advertises origins for browser CORS access; other CORS checks also apply.', values: ['*'] },
      { name: 'access-control-allow-credentials', category: 'CORS', explanation: 'Advertises credential support for browser CORS access; a compatible allowed origin is also required.', values: ['true'] },
    ],
    findings: [
      {
        severity: 'warning', code: 'HSTS_DISABLED', title: 'HSTS policy disabled',
        detail: 'The first Strict-Transport-Security field has max-age=0, instructing browsers to remove the cached HSTS policy for this host. includeSubDomains does not make this zero-age policy protective; inherited or preloaded policies are not assessed.',
        recommendation: 'If disabling HSTS is unintended, send a positive max-age over HTTPS after confirming HTTPS readiness.',
      },
      {
        severity: 'warning', code: 'CORS_WILDCARD_WITH_CREDENTIALS', title: 'Incompatible credentialed CORS configuration',
        detail: 'The response combines a wildcard allowed origin with credential support. Browsers block credentialed JavaScript access to this response; this does not by itself demonstrate credential exposure.',
        recommendation: "Use an explicitly permitted origin for credentialed cross-origin access, or omit credential support if it is unnecessary. Review the endpoint's intended CORS policy.",
      },
    ],
  }],
};

const certificate: TlsCertificateDetail = {
  type: 'server', subject: { CN: 'example.com' }, issuer: { CN: 'Fixture Intermediate CA', O: 'Fixture Trust' },
  validFrom: '2026-10-01T00:00:00.000Z', validTo: '2026-10-15T00:00:00.000Z', daysRemaining: 7,
  expiresAt: Date.parse('2026-10-15T00:00:00.000Z'), expirationState: 'expiring-soon', ca: false, selfIssued: false, selfSigned: false,
  signatureAlgorithmOid: '1.2.840.113549.1.1.11', signatureStrength: 'not-known-weak', namedCurve: null,
  serialNumber: '0123456789', fingerprint256: Array(32).fill('AB').join(':'), subjectAltName: 'DNS:example.com, DNS:www.example.com',
  signatureAlgorithm: 'sha256WithRSAEncryption', publicKeyAlgorithm: 'rsa', modulusLength: 2048, bits: 2048,
};
const intermediate: TlsCertificateDetail = {
  ...certificate, type: 'intermediate', subject: { CN: 'Fixture Intermediate CA' }, issuer: { CN: 'Fixture Root CA' },
  fingerprint256: Array(32).fill('CD').join(':'),
  validTo: '2030-10-01T00:00:00.000Z', daysRemaining: 1454, subjectAltName: null, signatureAlgorithm: 'sha1WithRSAEncryption',
  expiresAt: Date.parse('2030-10-01T00:00:00.000Z'), expirationState: 'valid', ca: true, signatureStrength: 'weak', signatureAlgorithmOid: '1.2.840.113549.1.1.5',
};
export const tlsResponse: TlsCheckSuccess = {
  ok: true, host: 'example.com', port: 443, resolvedAddresses: ['93.184.216.34'],
  tls: { authorized: true, authorizationError: null, protocol: 'TLSv1.3', cipher: 'TLS_AES_256_GCM_SHA384' },
  certificate, certificateType: 'DV', certificateTypeConfidence: 'policy-oid', certificateTypeReason: 'CA/Browser Forum DV policy OID.', certificatePolicyOids: ['2.23.140.1.2.1'],
  warnings: ['The server certificate expires within 30 days.', 'The chain certificate 2 uses a weak signature algorithm: sha1WithRSAEncryption.'],
  summary: { resolves: true, trusted: true, hostnameMatches: true, notExpired: true, chainProvided: null },
  checks: [
    { id: 'dns_resolves', status: 'pass', message: 'example.com resolves to 93.184.216.34' },
    { id: 'certificate_trusted', status: 'pass', message: 'The certificate is trusted by the default trust store.' },
    { id: 'hostname_match', status: 'pass', message: 'The hostname is correctly listed in the certificate.' },
    { id: 'certificate_expiry', status: 'warn', message: 'The certificate expires in 7 days.' },
    { id: 'certificate_chain', status: 'warn', message: 'Issuer chain entries shown: 2. Server-provided certificates: unknown. Chain completeness is unverified.' },
    { id: 'weak_signature', status: 'warn', message: 'At least one certificate uses a weak signature algorithm.' },
  ],
  chain: [certificate, intermediate], serverProvidedCertificateCount: null, issuerChainComplete: null,
  issuerChain: [
    { level: 'leaf', source: 'peer', ca: false, selfIssued: false, selfSigned: false, subject: 'CN: example.com', issuer: 'CN: Fixture Intermediate CA, O: Fixture Trust', validFrom: certificate.validFrom, validTo: certificate.validTo, fingerprint256: certificate.fingerprint256, signatureAlgorithm: certificate.signatureAlgorithm, publicKeyAlgorithm: certificate.publicKeyAlgorithm, modulusLength: 2048, namedCurve: null },
    { level: 'intermediate', source: 'inferred', ca: true, selfIssued: false, selfSigned: false, subject: 'CN: Fixture Intermediate CA', issuer: 'CN: Fixture Root CA', validFrom: intermediate.validFrom, validTo: intermediate.validTo, fingerprint256: intermediate.fingerprint256, signatureAlgorithm: intermediate.signatureAlgorithm, publicKeyAlgorithm: intermediate.publicKeyAlgorithm, modulusLength: 2048, namedCurve: null },
  ],
  issuerChainNote: 'Exact certificates transmitted by the server cannot be determined from this inspection. Issuer origin and chain completeness are unverified; TLS authorization is reported separately.',
};

export const dnsFailure = { ok: false, error: { code: 'RATE_LIMITED', message: 'Too many live DNS checks were made recently. Please try again later.' } };
export const httpFailure = { ok: false, error: { code: 'REQUEST_TIMEOUT', message: 'HTTP header request timed out.' } };
export const tlsFailure = { ok: false, error: { code: 'TLS_CONNECTION_FAILED', message: 'TLS connection failed.' } };
