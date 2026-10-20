import type { DnsCheckPayload, DnsCheckResult, DnsDiagnostic, DnsMode, DnsProviderResult, DnsProviderSummary, DnsRecord, DnsRecordType, DnsSpfMechanism, DnsTxtHelper } from './dnsTypes';

export const dnsStatusLabels: Record<string, string> = {
  ok: 'OK',
  'different-answer': 'Different answer',
  'no-record': 'No record',
  nxdomain: 'NXDOMAIN',
  servfail: 'SERVFAIL',
  refused: 'REFUSED',
  timeout: 'Timeout',
  'possible-filtering': 'Possible filtering',
  'possible-sinkhole': 'Possible sinkhole',
  'possible-dnssec-failure': 'Possible DNSSEC issue',
  'resolver-error': 'Resolver error',
  incomplete: 'Incomplete (truncated UDP response)',
  'partial-failure': 'Incomplete provider comparison',
  formerr: 'FORMERR (query format error)',
  notimp: 'NOTIMP (not implemented)',
  'rcode-error': 'Unsuccessful DNS response',
};

export function buildDnsPayload({
  mode,
  recordType,
  resolverId,
  queryInput,
  txtHelper,
  dkimSelector,
  srvService,
  srvProtocol,
  srvDomain,
  dnssec,
}: {
  mode: DnsMode;
  recordType: DnsRecordType;
  resolverId: string;
  queryInput: string;
  txtHelper: DnsTxtHelper;
  dkimSelector: string;
  srvService: string;
  srvProtocol: 'tcp' | 'udp';
  srvDomain: string;
  dnssec: boolean;
}): DnsCheckPayload {
  const payload: DnsCheckPayload = {
    mode,
    recordType,
  };

  if (mode === 'single') {
    payload.resolverId = resolverId;
    payload.dnssec = dnssec;
  }

  if (recordType === 'SRV') {
    payload.service = srvService.trim();
    payload.protocol = srvProtocol;
    payload.domain = srvDomain.trim();
    return payload;
  }

  payload.query = getDnsQueryInput(recordType, queryInput, txtHelper, dkimSelector);
  return payload;
}

export function getDnsQueryInput(recordType: DnsRecordType, queryInput: string, txtHelper: DnsTxtHelper, dkimSelector: string) {
  const value = queryInput.trim();

  if (recordType !== 'TXT') {
    return value;
  }

  if (txtHelper === 'dkim') {
    if (value.toLowerCase().includes('._domainkey.')) return value;
    return `${dkimSelector.trim()}._domainkey.${value}`;
  }

  if (txtHelper === 'dmarc') {
    return value.toLowerCase().startsWith('_dmarc.') ? value : `_dmarc.${value}`;
  }

  if (txtHelper === 'acme') {
    return value.toLowerCase().startsWith('_acme-challenge.') ? value : `_acme-challenge.${value}`;
  }

  return value;
}

export function getDnsPreviewName(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvProtocol: 'tcp' | 'udp',
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    const service = srvService.trim().replace(/^_/, '');
    const domain = srvDomain.trim();

    return service && domain ? `_${service}._${srvProtocol}.${domain}` : '';
  }

  if (recordType === 'TXT' && txtHelper !== 'normal' && txtHelper !== 'spf') {
    return getDnsQueryInput(recordType, queryInput, txtHelper, dkimSelector);
  }

  return '';
}

export function validateDnsForm(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    if (!srvService.trim() || !srvDomain.trim()) {
      return 'Service and domain are required for SRV checks.';
    }

    if (!/^[A-Za-z0-9][A-Za-z0-9-]{0,61}$/.test(srvService.trim().replace(/^_/, '')) || srvService.trim().endsWith('-')) {
      return 'Use a valid SRV service such as sip or xmpp-server.';
    }

    const name = `_${srvService.trim().replace(/^_/, '')}._tcp.${normalizeDnsFormName(srvDomain) || ''}`;
    return isLikelyDnsName(srvDomain) && name.length <= 253 ? '' : 'Enter a valid public domain for SRV checks.';
  }

  if (!queryInput.trim()) {
    return recordType === 'PTR' ? 'IP address is required.' : 'Domain/FQDN is required.';
  }

  if (recordType === 'PTR') {
    return isAllowedDnsPtrAddress(queryInput.trim()) ? '' : 'Enter a valid public IPv4 or IPv6 address.';
  }

  if (recordType === 'TXT' && txtHelper === 'dkim' && !queryInput.toLowerCase().includes('._domainkey.')) {
    if (!dkimSelector.trim()) {
      return 'Selector is required for DKIM TXT checks.';
    }

    if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$/.test(dkimSelector.trim())) {
      return 'Use a valid DKIM selector.';
    }
  }

  const name = getDnsQueryInput(recordType, queryInput, txtHelper, dkimSelector);
  return isLikelyDnsName(name, recordType === 'TXT') ? '' : 'Enter a valid public domain or FQDN.';
}

export function shouldShowDnsValidationError(
  recordType: DnsRecordType,
  queryInput: string,
  txtHelper: DnsTxtHelper,
  dkimSelector: string,
  srvService: string,
  srvDomain: string,
) {
  if (recordType === 'SRV') {
    return Boolean(srvService.trim() || srvDomain.trim());
  }

  if (recordType === 'TXT' && txtHelper === 'dkim') {
    return Boolean(queryInput.trim() || dkimSelector.trim());
  }

  return Boolean(queryInput.trim());
}

function normalizeDnsFormName(value: string) {
  const name = value.trim().replace(/\.$/, '').toLowerCase();
  if (!/^[\p{L}\p{M}\p{N}._-]+$/u.test(name)) return null;
  try {
    return new URL(`http://${name}`).hostname;
  } catch {
    return null;
  }
}

export function isLikelyDnsName(value: string, allowOwnerLabels = false) {
  const normalizedValue = normalizeDnsFormName(value);
  if (!normalizedValue || normalizedValue === 'localhost' ||
    /\.(localhost|local|internal|lan|home|home\.arpa)$/.test(normalizedValue) ||
    isValidIpv4Address(normalizedValue)) return false;

  return (
    normalizedValue.length > 0 &&
    normalizedValue.length <= 253 &&
    normalizedValue.includes('.') &&
    !normalizedValue.includes('..') &&
    !/[:/?#@[\]\\\s]/.test(normalizedValue) &&
    normalizedValue.split('.').every((label) => (allowOwnerLabels
      ? /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/
      : /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/).test(label))
  );
}

export function isAllowedDnsPtrAddress(value: string) {
  if (!isValidIpAddress(value)) {
    return false;
  }

  return isValidIpv4Address(value) ? !isBlockedDnsPtrIpv4Address(value) : !isBlockedDnsPtrIpv6Address(value);
}

export function isBlockedDnsPtrIpv4Address(value: string) {
  const address = ipv4AddressToNumber(value);
  const blockedRanges: Array<[string, number]> = [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4],
    ['255.255.255.255', 32],
    ['169.254.169.254', 32],
  ];

  return blockedRanges.some(([range, prefix]) => ipv4NumberInCidr(address, ipv4AddressToNumber(range), prefix));
}

export function ipv4AddressToNumber(value: string) {
  return value.split('.').reduce((address, octet) => ((address << 8) + Number(octet)) >>> 0, 0);
}

export function ipv4NumberInCidr(address: number, range: number, prefix: number) {
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;

  return (address & mask) === (range & mask);
}

export function isBlockedDnsPtrIpv6Address(value: string) {
  const address = parseIpAddress(value);
  const blockedRanges: Array<[string, number]> = [
    ['::', 128],
    ['::1', 128],
    ['100::', 64],
    ['2001:db8::', 32],
    ['fc00::', 7],
    ['fe80::', 10],
    ['ff00::', 8],
  ];

  return blockedRanges.some(([range, prefix]) => ipv6AddressInPrefix(address, parseIpAddress(range), prefix));
}

export function ipv6AddressInPrefix(address: Uint8Array, range: Uint8Array, prefix: number) {
  const fullBytes = Math.floor(prefix / 8);
  const partialBits = prefix % 8;

  for (let index = 0; index < fullBytes; index += 1) {
    if (address[index] !== range[index]) {
      return false;
    }
  }

  if (partialBits === 0) {
    return true;
  }

  const mask = (0xff << (8 - partialBits)) & 0xff;

  return (address[fullBytes] & mask) === (range[fullBytes] & mask);
}

export function formatDnsResolver(result: DnsCheckResult) {
  if (result.provider) {
    return result.provider.name;
  }

  if (result.resolver && 'providers' in result.resolver) {
    const providers = Array.isArray(result.resolver.providers) ? result.resolver.providers : [];

    return `${providers.length} predefined providers`;
  }

  return (result.resolver as DnsProviderSummary | null | undefined)?.name || 'Unknown provider';
}

export function getDnsExportTarget(result: DnsCheckResult) {
  return result.query?.displayName || result.query?.queryName || result.query?.input || '-';
}

export function formatDnsStatus(status: string | null | undefined) {
  return status ? (Object.prototype.hasOwnProperty.call(dnsStatusLabels, status) ? dnsStatusLabels[status] : status) : null;
}

export function formatDnsTtls(records: DnsRecord[] | null | undefined) {
  const ttls = Array.from(new Set(asDnsRecords(records).map((record) => record.ttl).filter((ttl): ttl is number => typeof ttl === 'number')));

  return ttls.length ? ttls.join(', ') : '-';
}

export function formatDnsLowestTtl(records: DnsRecord[] | null | undefined) {
  const ttls = asDnsRecords(records)
    .map((record) => record.ttl)
    .filter((ttl): ttl is number => typeof ttl === 'number' && Number.isFinite(ttl));

  if (ttls.length === 0) {
    return '-';
  }

  return `${Math.min(...ttls)} seconds`;
}

export function formatDnsRecordValues(records: DnsRecord[] | null | undefined) {
  const safeRecords = asDnsRecords(records);

  if (safeRecords.length === 0) {
    return '-';
  }

  return safeRecords.map(formatDnsRecord).join('; ');
}

export function formatDnsRecord(record: DnsRecord) {
  if (record.type === 'A' || record.type === 'AAAA') {
    return record.address || '-';
  }

  if (record.type === 'CNAME') {
    return record.target || '-';
  }

  if (record.type === 'NS' || record.type === 'PTR') {
    return record.host || '-';
  }

  if (record.type === 'TXT') {
    return record.value || record.chunks?.join('') || '-';
  }

  if (record.type === 'MX') {
    return `${record.preference ?? '-'} ${record.exchange || '-'}`;
  }

  if (record.type === 'SOA') {
    return `mname=${formatUnknown(record.mname)} rname=${formatUnknown(record.rname)} serial=${formatUnknown(record.serial)}`;
  }

  if (record.type === 'SRV') {
    return `${formatUnknown(record.priority)} ${formatUnknown(record.weight)} ${formatUnknown(record.port)} ${formatUnknown(record.target)}`;
  }

  if (record.type === 'CAA') {
    return `${formatUnknown(record.flags)} ${formatUnknown(record.tag)} ${formatUnknown(record.value)}`;
  }

  return JSON.stringify(record);
}

export function asDnsRecords(records: DnsRecord[] | null | undefined) {
  return Array.isArray(records) ? records : [];
}

export function asDnsDiagnostics(diagnostics: DnsDiagnostic[] | null | undefined) {
  return Array.isArray(diagnostics) ? diagnostics : [];
}

export function asDnsProviders(providers: DnsProviderResult[] | null | undefined) {
  return Array.isArray(providers) ? providers : [];
}

export function asDnsStrings(values: string[] | null | undefined) {
  return Array.isArray(values) ? values.filter((value): value is string => typeof value === 'string') : [];
}

export function getDnsDiagnosticId(diagnostic: DnsDiagnostic) {
  return typeof diagnostic.id === 'string' && diagnostic.id ? diagnostic.id : 'diagnostic';
}

export function getDnsTxtDiagnostics(diagnostics: DnsDiagnostic[]) {
  return diagnostics.filter((diagnostic) => [
    'spf',
    'dkim',
    'dmarc',
    'microsoft_365_verification',
    'google_verification',
    'acme_challenge',
  ].includes(getDnsDiagnosticId(diagnostic)));
}

export function getDnsSpfDiagnostics(diagnostics: DnsDiagnostic[] | null | undefined) {
  return asDnsDiagnostics(diagnostics).filter((diagnostic) => getDnsDiagnosticId(diagnostic) === 'spf');
}

export function getDnsSpfMechanisms(diagnostic: DnsDiagnostic) {
  const detailed = Array.isArray(diagnostic.mechanismDetails) ? diagnostic.mechanismDetails : [];
  const structured = detailed.filter(isDnsSpfMechanism);

  if (structured.length > 0) {
    return structured;
  }

  return Array.isArray(diagnostic.mechanisms)
    ? diagnostic.mechanisms.filter((token): token is string => typeof token === 'string').map(parseDnsSpfToken)
    : [];
}

export function isDnsSpfMechanism(value: unknown): value is DnsSpfMechanism {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Record<string, unknown>;
  return typeof item.token === 'string'
    && ['qualifier', 'result', 'mechanism', 'value', 'prefix'].every((key) => item[key] === undefined || item[key] === null || typeof item[key] === 'string')
    && ['modifier', 'valid'].every((key) => item[key] === undefined || typeof item[key] === 'boolean');
}

export function parseDnsSpfToken(token: string): DnsSpfMechanism {
  const qualifier = /^[+?~-]/.test(token) ? token[0] : '+';
  const body = qualifier === token[0] ? token.slice(1) : token;
  const modifierMatch = body.match(/^(redirect|exp)=(.+)$/i);

  if (modifierMatch) {
    return {
      token,
      qualifier: null,
      result: null,
      mechanism: modifierMatch[1].toLowerCase(),
      value: modifierMatch[2],
      modifier: true,
      valid: true,
    };
  }

  const mechanismMatch = body.match(/^([a-z0-9]+)(?::([^/]+))?(?:\/(.+))?$/i);

  return {
    token,
    qualifier,
    result: ({ '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' } as Record<string, string>)[qualifier] || 'pass',
    mechanism: mechanismMatch?.[1]?.toLowerCase() || 'unknown',
    value: mechanismMatch?.[2] || null,
    prefix: mechanismMatch?.[3] || null,
    modifier: false,
    valid: Boolean(mechanismMatch),
  };
}

export function getDnsSpfTtl(records: DnsRecord[] | null | undefined, spfValue: string) {
  const txtRecords = asDnsRecords(records).filter((record) => record.type === 'TXT');
  const matchingRecord = txtRecords.find((record) => {
    const value = record.value || record.chunks?.join('') || '';

    return value === spfValue || value.toLowerCase().startsWith('v=spf1');
  });

  return typeof matchingRecord?.ttl === 'number' && Number.isFinite(matchingRecord.ttl) ? matchingRecord.ttl : null;
}

export function formatDnsTtlShort(seconds: number) {
  if (seconds % 3600 === 0) {
    return `${seconds / 3600}h`;
  }

  if (seconds % 60 === 0) {
    return `${seconds / 60}m`;
  }

  return `${seconds}s`;
}

export function describeDnsSpfMechanism(mechanism: DnsSpfMechanism, defaultDomain: string | null, isFirst: boolean) {
  const kind = String(mechanism.mechanism || 'unknown').toLowerCase();
  const value = typeof mechanism.value === 'string' && mechanism.value ? mechanism.value : null;
  const prefix = typeof mechanism.prefix === 'string' && mechanism.prefix ? mechanism.prefix : null;
  const domain = value || defaultDomain || 'this domain';
  const lead = isFirst ? '' : 'Or else, ';
  const sentenceVerb = (verb: string) => (isFirst ? `${verb.charAt(0).toUpperCase()}${verb.slice(1)}` : `${lead}${verb}`);

  if (kind === 'redirect') {
    return `${sentenceVerb('redirect')} SPF evaluation to ${domain} if no previous rule matches.`;
  }

  if (kind === 'exp') {
    return `${sentenceVerb('use')} ${domain} for SPF failure explanation text.`;
  }

  if (kind === 'all') {
    return `${lead}${describeDnsSpfAllResult(mechanism)}.`;
  }

  if (!mechanism.valid || kind === 'unknown') {
    return 'Unknown or unsupported SPF mechanism.';
  }

  const result = getDnsSpfResultPhrase(mechanism, isFirst);

  if (kind === 'include') {
    return `${sentenceVerb('include')} the SPF record at ${domain} and ${getDnsSpfResultPhrase(mechanism, false)} if it matches the sender's IP.`;
  }

  if (kind === 'a') {
    return `${lead}${result} if the email sender's IP is in the A or AAAA records of ${domain}${formatDnsSpfPrefix(prefix)}.`;
  }

  if (kind === 'mx') {
    return `${lead}${result} if the email sender's IP is in the MX records of ${domain}${formatDnsSpfPrefix(prefix)}.`;
  }

  if (kind === 'ip4') {
    return prefix
      ? `${lead}${result} if the email sender's IP matches the IPv4 range ${domain}/${prefix}.`
      : `${lead}${result} if the email sender's IP is ${domain}.`;
  }

  if (kind === 'ip6') {
    return prefix
      ? `${lead}${result} if the email sender's IP matches the IPv6 range ${domain}/${prefix}.`
      : `${lead}${result} if the email sender's IP is ${domain}.`;
  }

  if (kind === 'exists') {
    return `${lead}${result} if ${domain} resolves in DNS.`;
  }

  if (kind === 'ptr') {
    return `${lead}${result} if reverse DNS validates against ${domain}.`;
  }

  return 'Unknown or unsupported SPF mechanism.';
}

export function describeDnsSpfAllResult(mechanism: DnsSpfMechanism) {
  const result = String(mechanism.result || 'pass').toLowerCase();

  if (result === 'fail') {
    return 'mark the email as fail';
  }

  if (result === 'softfail') {
    return 'mark the email as soft fail';
  }

  if (result === 'neutral') {
    return 'return neutral';
  }

  return 'pass all senders';
}

export function getDnsSpfResultPhrase(mechanism: DnsSpfMechanism, isFirst: boolean) {
  const result = String(mechanism.result || 'pass').toLowerCase();

  if (result === 'fail') {
    return isFirst ? 'Fail' : 'fail';
  }

  if (result === 'softfail') {
    return isFirst ? 'Soft fail' : 'soft fail';
  }

  if (result === 'neutral') {
    return isFirst ? 'Return neutral' : 'return neutral';
  }

  return isFirst ? 'Pass' : 'pass';
}

export function formatDnsSpfPrefix(prefix: string | null) {
  return prefix ? ` within prefix /${prefix}` : '';
}

export function getDnsSpfMechanismWarning(mechanism: DnsSpfMechanism) {
  const kind = String(mechanism.mechanism || 'unknown').toLowerCase();
  const qualifier = mechanism.qualifier || '+';

  if (kind === 'all' && qualifier === '+') {
    return 'Dangerous/permissive: this passes all senders.';
  }

  if (kind === 'ptr') {
    return 'Deprecated: ptr mechanisms are slow and unreliable.';
  }

  if (mechanism.valid === false || kind === 'unknown') {
    return 'Invalid-looking or unsupported mechanism.';
  }

  return null;
}

export function formatSeconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} seconds` : null;
}

export function formatMilliseconds(value: unknown) {
  return typeof value === 'number' && Number.isFinite(value) ? `${value} ms` : null;
}

export function formatUnknown(value: unknown) {
  if (value === null || value === undefined || value === '') {
    return null;
  }

  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

export function formatDiagnosticName(value: string) {
  if (value.toLowerCase() === 'dnssec_deep_checks') {
    return 'DNSSEC deep checks';
  }

  return value.replace(/_/g, ' ').replace(/\b\w/g, (character) => character.toUpperCase());
}

export function isValidIpAddress(value: string) {
  return isValidIpv4Address(value) || isValidIpv6Address(value);
}

export function isValidIpv4Address(value: string) {
  const octets = value.split('.');

  return (
    octets.length === 4 &&
    octets.every((octet) => /^\d{1,3}$/.test(octet) && Number(octet) >= 0 && Number(octet) <= 255)
  );
}

export function isValidIpv6Address(value: string) {
  if (!value.includes(':')) {
    return false;
  }

  const normalizedValue = value.toLowerCase();

  if (!/^[0-9a-f:.]+$/.test(normalizedValue)) {
    return false;
  }

  const parts = normalizedValue.split('::');

  if (parts.length > 2) {
    return false;
  }

  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const groups = [...left, ...right];
  const hasValidGroups = groups.every((group) => /^[0-9a-f]{1,4}$/.test(group));

  return hasValidGroups && (parts.length === 2 ? groups.length < 8 : groups.length === 8);
}

export function parseIpAddress(value: string) {
  if (isValidIpv4Address(value)) {
    return new Uint8Array(value.split('.').map((octet) => Number(octet)));
  }

  const parts = value.toLowerCase().split('::');
  const left = parts[0] ? parts[0].split(':') : [];
  const right = parts[1] ? parts[1].split(':') : [];
  const missingGroupCount = 8 - left.length - right.length;
  const groups = [...left, ...Array(Math.max(missingGroupCount, 0)).fill('0'), ...right].map((group) =>
    parseInt(group, 16)
  );
  const bytes = new Uint8Array(16);

  groups.forEach((group, index) => {
    bytes[index * 2] = group >> 8;
    bytes[index * 2 + 1] = group & 255;
  });

  return bytes;
}
