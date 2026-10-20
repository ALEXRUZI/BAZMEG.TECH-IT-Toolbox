export type HttpHeaderProtocolMode = 'auto' | 'https' | 'http' | 'both';

export type HttpHeaderView = 'simple' | 'advanced' | 'raw';

export type HttpHeaderFindingSeverity = 'pass' | 'info' | 'warning' | 'critical';

export type HttpHeaderCspPrivateIpReference = {
  header: string;
  value: string;
  privateIps: string[];
};

export type HttpHeaderFinding = {
  severity: HttpHeaderFindingSeverity;
  code: string;
  title: string;
  detail: string;
  recommendation: string;
  metadata?: {
    privateIps?: string[];
    references?: HttpHeaderCspPrivateIpReference[];
  };
};

export type HttpHeaderRedirect = {
  from: string;
  to: string;
  status: number;
  statusText: string | null;
  location?: string | null;
};

export type HttpHeaderEntry = {
  name: string;
  value: string;
};

export type HttpHeaderInteresting = {
  name: string;
  category: string;
  explanation: string;
  values: string[];
};

export type HttpHeaderCheck = {
  ok?: boolean;
  protocol: 'auto' | 'http' | 'https';
  port: number;
  cached: boolean;
  cacheTtlSeconds?: number;
  cacheAgeSeconds?: number;
  cacheExpiresInSeconds?: number;
  startUrl: string;
  finalUrl?: string;
  finalCheckedUrl?: string;
  status: number | null;
  statusText: string | null;
  redirectsFollowed: number;
  chainDisplay: string;
  redirects?: HttpHeaderRedirect[];
  blockedRedirect: {
    from: string;
    status: number | null;
    location: string | null;
  } | null;
  durationMs: number;
  headers: HttpHeaderEntry[];
  interestingHeaders: HttpHeaderInteresting[];
  findings: HttpHeaderFinding[];
};

export type HttpHeaderCheckSuccess = {
  ok: boolean;
  input: {
    original: string;
    cleanHost: string;
    protocolMode: HttpHeaderProtocolMode;
  };
  budget: {
    checksRequested: number;
    freshChecks: number;
    cachedChecks: number;
    tokensConsumed: number;
  };
  cache: {
    ttlSeconds: number;
  };
  redirectLimit: number;
  checks: HttpHeaderCheck[];
};

export type HttpHeaderCheckErrorResponse = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

export type HttpHeaderCheckResponse = HttpHeaderCheckSuccess | HttpHeaderCheckErrorResponse;
