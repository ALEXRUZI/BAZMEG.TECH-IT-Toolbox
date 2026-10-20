export type TlsCheckStatus = 'pass' | 'warn' | 'fail';

export type TlsCertificateValidationType = 'DV' | 'OV' | 'EV' | 'IV' | 'Unknown';

export type TlsCertificateTypeConfidence = 'policy-oid' | 'heuristic' | 'unknown';

export type TlsCertificateDetail = {
  type: 'server' | 'intermediate' | 'self-signed-ca' | 'self-issued' | 'chain';
  subject: Record<string, string | undefined>;
  issuer: Record<string, string | undefined>;
  validFrom: string | null;
  validTo: string | null;
  daysRemaining: number | null;
  expiresAt: number | null;
  expirationState: 'valid' | 'expiring-soon' | 'expired' | 'unknown';
  ca: boolean | null;
  selfIssued: boolean | null;
  selfSigned: boolean | null;
  signatureAlgorithmOid: string | null;
  signatureStrength: 'weak' | 'not-known-weak' | 'unknown';
  namedCurve: string | null;
  serialNumber: string | null;
  fingerprint256: string | null;
  subjectAltName: string | null;
  signatureAlgorithm: string | null;
  publicKeyAlgorithm: string | null;
  modulusLength: number | null;
  bits: number | null;
};

export type TlsIssuerChainEntry = {
  level: 'leaf' | 'intermediate' | 'self-signed-ca' | 'self-issued' | 'unknown';
  source: 'peer' | 'server-provided' | 'local-trust-store' | 'inferred' | 'unavailable';
  ca?: boolean | null;
  selfIssued?: boolean | null;
  selfSigned?: boolean | null;
  signatureAlgorithm?: string | null;
  publicKeyAlgorithm?: string | null;
  modulusLength?: number | null;
  namedCurve?: string | null;
  subject: string;
  issuer: string;
  validFrom?: string | null;
  validTo?: string | null;
  fingerprint256?: string | null;
};

export type TlsCheckSuccess = {
  ok: true;
  host: string;
  port: number;
  resolvedAddresses: string[];
  tls: {
    authorized: boolean;
    authorizationError: string | null;
    protocol: string | null;
    cipher: string | null;
  };
  certificate: TlsCertificateDetail;
  certificateType?: TlsCertificateValidationType;
  certificateTypeConfidence?: TlsCertificateTypeConfidence;
  certificateTypeReason?: string | null;
  certificatePolicyOids?: string[];
  warnings: string[];
  summary: {
    resolves: boolean;
    trusted: boolean;
    hostnameMatches: boolean;
    notExpired: boolean | null;
    chainProvided: boolean | null;
  };
  checks: Array<{
    id: string;
    status: TlsCheckStatus;
    message: string;
  }>;
  chain: TlsCertificateDetail[];
  serverProvidedCertificateCount?: number | null;
  issuerChain?: TlsIssuerChainEntry[];
  issuerChainComplete?: boolean | null;
  issuerChainNote?: string;
};

export type TlsCheckErrorResponse = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

export type TlsCheckResponse = TlsCheckSuccess | TlsCheckErrorResponse;
