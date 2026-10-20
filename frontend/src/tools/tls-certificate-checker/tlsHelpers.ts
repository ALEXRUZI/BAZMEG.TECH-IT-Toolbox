import type { TlsCertificateDetail, TlsCertificateTypeConfidence, TlsCheckStatus, TlsCheckSuccess, TlsIssuerChainEntry } from './tlsTypes';

export const tlsIssuerProvenanceNote = 'Exact certificates transmitted by the server cannot be determined from this inspection. Issuer origin and chain completeness are unverified; TLS authorization is reported separately.';

export function getTlsExpirationPresentation(certificate: TlsCertificateDetail) {
  const { daysRemaining, expirationState, expiresAt } = certificate;
  if (!['expired', 'expiring-soon', 'valid'].includes(expirationState) || daysRemaining === null || !Number.isFinite(daysRemaining) || expiresAt === null || !Number.isFinite(expiresAt)) {
    return {
      badge: 'Unknown',
      label: 'Expiration date unavailable',
      daysText: '-',
      className: 'border-amber-300/35 bg-amber-400/10 text-amber-100',
    };
  }

  if (expirationState === 'expired') {
    const daysExpired = Math.abs(daysRemaining);

    return {
      badge: 'Expired',
      label: daysExpired === 0 ? 'Expired (less than one day ago or at expiration)' : `Expired ${daysExpired} day${daysExpired === 1 ? '' : 's'} ago`,
      daysText: String(daysRemaining),
      className: 'border-red-300/35 bg-red-500/10 text-red-100',
    };
  }

  if (expirationState === 'expiring-soon') {
    return {
      badge: 'Expiring soon',
      label: `Expires in ${daysRemaining} day${daysRemaining === 1 ? '' : 's'}`,
      daysText: String(daysRemaining),
      className: 'border-amber-300/35 bg-amber-400/10 text-amber-100',
    };
  }

  return {
    badge: 'Valid',
    label: `Expires in ${daysRemaining} days`,
    daysText: String(daysRemaining),
    className: 'border-emerald-400/35 bg-emerald-500/10 text-emerald-100',
  };
}

export function getTlsIssuerChain(result: TlsCheckSuccess): TlsIssuerChainEntry[] {
  if (Array.isArray(result.issuerChain) && result.issuerChain.length > 0) {
    return result.issuerChain.map((entry, index) => normalizeTlsIssuerChainEntry(entry, index));
  }

  return result.chain.map((certificate, index) => ({
    level: index === 0 ? 'leaf' : certificate.ca === true && certificate.selfSigned === true ? 'self-signed-ca' : certificate.selfIssued === true ? 'self-issued' : certificate.ca === true ? 'intermediate' : 'unknown',
    source: index === 0 ? 'peer' : 'inferred',
    ca: certificate.ca,
    selfIssued: certificate.selfIssued,
    selfSigned: certificate.selfSigned,
    signatureAlgorithm: certificate.signatureAlgorithm,
    publicKeyAlgorithm: certificate.publicKeyAlgorithm,
    modulusLength: certificate.modulusLength,
    namedCurve: certificate.namedCurve,
    subject: formatDistinguishedName(certificate.subject) || certificate.subject.CN || 'Unavailable',
    issuer: formatDistinguishedName(certificate.issuer) || certificate.issuer.CN || 'Unavailable',
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    fingerprint256: certificate.fingerprint256,
  }));
}

export function normalizeTlsIssuerChainEntry(entry: TlsIssuerChainEntry, index: number): TlsIssuerChainEntry {
  return {
    ...entry,
    level: isTlsIssuerLevel(entry.level) ? entry.level : index === 0 ? 'leaf' : 'unknown',
    source: isTlsIssuerSource(entry.source) ? entry.source : 'unavailable',
  };
}

export function getTlsServerProvidedCertificateCount(result: TlsCheckSuccess) {
  if (
    typeof result.serverProvidedCertificateCount === 'number' &&
    Number.isSafeInteger(result.serverProvidedCertificateCount) &&
    result.serverProvidedCertificateCount >= 1
  ) {
    return result.serverProvidedCertificateCount;
  }

  return null;
}

export function hasCompleteTlsIssuerChain(result: TlsCheckSuccess) {
  return result.issuerChainComplete ?? null;
}

export function getTlsSummaryChecks(
  result: TlsCheckSuccess,
  serverProvidedCertificateCount = getTlsServerProvidedCertificateCount(result),
  issuerChainEntriesShown = getTlsIssuerChain(result).length,
) {
  return result.checks.map((check) => {
    if (check.id === 'certificate_chain' || /server provided \d+ certificates?/i.test(check.message)) {
      return {
        ...check,
        status: serverProvidedCertificateCount === null || hasCompleteTlsIssuerChain(result) !== true ? 'warn' as const : check.status,
        message: `Issuer chain entries shown: ${issuerChainEntriesShown}. Server-provided certificates: ${serverProvidedCertificateCount ?? 'unknown'}. Chain completeness is ${hasCompleteTlsIssuerChain(result) === true ? 'verified' : hasCompleteTlsIssuerChain(result) === false ? 'incomplete' : 'unverified'}.`,
      };
    }

    return check;
  });
}

export function getTlsIssuerCertificateTitle(entry: TlsIssuerChainEntry, index: number) {
  if (entry.level === 'leaf' || index === 0) {
    return 'Leaf Certificate';
  }

  if (entry.level === 'self-signed-ca') {
    return 'Self-signed CA Certificate (trust unverified)';
  }
  if (entry.level === 'self-issued') return 'Self-issued Certificate';

  if (entry.level === 'intermediate') {
    return 'Intermediate Certificate';
  }

  return 'Issuer Certificate (CA status unknown)';
}

export function isTlsIssuerSource(value: unknown): value is TlsIssuerChainEntry['source'] {
  return value === 'peer' ||
    value === 'server-provided' ||
    value === 'local-trust-store' ||
    value === 'inferred' ||
    value === 'unavailable';
}

export function isTlsIssuerLevel(value: unknown): value is TlsIssuerChainEntry['level'] {
  return value === 'leaf' || value === 'intermediate' || value === 'self-signed-ca' || value === 'self-issued' || value === 'unknown';
}

export function getCertificateTypeConfidenceLabel(confidence?: TlsCertificateTypeConfidence) {
  if (confidence === 'policy-oid') {
    return 'policy OID';
  }

  if (confidence === 'heuristic') {
    return 'heuristic';
  }

  return null;
}

export function normalizeTlsHostInput(value: string): string {
  const trimmed = value.trim();

  if (!trimmed) {
    return '';
  }

  try {
    const withScheme = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
    const parsed = new URL(withScheme);

    return parsed.hostname.toLowerCase();
  } catch {
    return trimmed
      .replace(/^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//, '')
      .split(/[/?#]/)[0]
      .trim()
      .toLowerCase();
  }
}

export function formatOptionalNumber(value: number | null) {
  return value === null ? null : String(value);
}

export function formatDistinguishedName(value: Record<string, string | undefined>) {
  const entries = Object.entries(value).filter(([, entryValue]) => entryValue);

  return entries.length > 0 ? entries.map(([key, entryValue]) => `${key}: ${entryValue}`).join('\n') : null;
}

export function parseSubjectAltNames(value: string | null) {
  if (!value) {
    return [];
  }

  return value
    .split(/,\s*/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}
