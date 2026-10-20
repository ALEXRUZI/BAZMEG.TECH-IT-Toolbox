export type DnsMode = 'single' | 'burst';

export type DnsRecordType = 'A' | 'AAAA' | 'CNAME' | 'MX' | 'TXT' | 'NS' | 'SOA' | 'CAA' | 'PTR' | 'SRV';

export type DnsResponseView = 'simple' | 'advanced' | 'raw';

export type DnsTxtHelper = 'normal' | 'spf' | 'dkim' | 'dmarc' | 'acme';

export type DnsProviderSummary = {
  id: string;
  name: string;
  profile?: string;
  category?: string;
};

export type DnsRecord = {
  name: string;
  type: string;
  ttl?: number;
  address?: string;
  target?: string;
  host?: string;
  value?: string;
  chunks?: string[];
  preference?: number;
  exchange?: string;
  resolvedA?: string[];
  resolvedAAAA?: string[];
  priority?: number;
  weight?: number;
  port?: number;
  flags?: number;
  tag?: string;
  [key: string]: unknown;
};

export type DnsQuery = {
  input: string;
  queryName: string;
  displayName: string;
  recordType: DnsRecordType;
  service: string | null;
  protocol: string | null;
  domain: string | null;
};

export type DnsDiagnostic = {
  id: string;
  status?: string;
  message?: string;
  [key: string]: unknown;
};

export type DnsSpfMechanism = {
  token: string;
  qualifier?: string | null;
  result?: string | null;
  mechanism?: string | null;
  value?: string | null;
  prefix?: string | null;
  modifier?: boolean;
  valid?: boolean;
  [key: string]: unknown;
};

export type DnsCacheMetadata = {
  fromCache: boolean;
  cacheScope: 'site';
  cacheTtlSeconds?: number;
  cacheAgeSeconds?: number;
  cacheExpiresInSeconds?: number;
};

export type DnsProviderResult = {
  ok: boolean;
  mode: DnsMode;
  query: DnsQuery;
  resolver: DnsProviderSummary;
  provider: DnsProviderSummary;
  responseCode: string | null;
  durationMs: number;
  status: string;
  records: DnsRecord[];
  answer: DnsRecord[];
  authority: DnsRecord[];
  additional: DnsRecord[];
  diagnostics: DnsDiagnostic[];
  warnings: string[];
  dnssec: Record<string, unknown>;
  raw: Record<string, unknown>;
};

type DnsCheckResultBase = Omit<DnsProviderResult, 'ok' | 'resolver' | 'provider'> & {
  cache: DnsCacheMetadata;
  resolver: DnsProviderSummary | {
    group: string;
    providers: DnsProviderSummary[];
  };
  provider: DnsProviderSummary | null;
  providers?: DnsProviderResult[];
};

export type DnsCheckSuccess = DnsCheckResultBase & { ok: true };
export type DnsCheckDiagnosticFailure = DnsCheckResultBase & { ok: false; error?: never };
export type DnsCheckResult = DnsCheckSuccess | DnsCheckDiagnosticFailure;

export type DnsCheckErrorResponse = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

export type DnsCheckResponse = DnsCheckResult | DnsCheckErrorResponse;

export type DnsCheckPayload = {
  mode: DnsMode;
  recordType: DnsRecordType;
  resolverId?: string;
  dnssec?: boolean;
  service?: string;
  protocol?: 'tcp' | 'udp';
  domain?: string;
  query?: string;
};
