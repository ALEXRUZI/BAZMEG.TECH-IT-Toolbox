import type { RegistrationResult } from '../../src/tools/rdap-whois/rdapTypes';

export const registrationFixture: RegistrationResult = {
  ok: true, input: { original: 'example.com', canonical: 'example.com', kind: 'domain', protocolMode: 'auto' },
  protocol: 'rdap', source: 'https://registry.example.org/domain/example.com', timestamp: '2026-10-14T12:00:00Z', outcome: 'record',
  normalized: { outcome: 'record', fields: { Domain: ['example.com'], Registrar: ['Fixture Registrar'], 'Registrar organization': ['Fixture Registrar Ltd'], 'Registrar code': ['1234 (IANA ID)'], 'Registrar email': ['registration@example.org'], 'Registrant name': ['Redacted'], 'Registrant organization': ['Fixture Holder'], 'Registrant organization ID': ['ORG-42 (Organization ID)'], 'Registrant phone': ['tel:+1-555-0100'], 'Registrant email': ['owner@example.org', 'other@example.org'], Expires: ['2030-01-01T00:00:00Z'], Nameservers: ['ns1.example.com'], Status: ['active'], 'Published country': ['SK'] },
    details: { contacts: [{ roles: ['registrant'], values: { fn: ['REDACTED FOR PRIVACY'] } }], events: [], notices: [{ description: ['<script>untrusted notice</script>'] }], dnssec: { delegationSigned: true, dsData: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest: 'C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A' }] }, links: [{ href: 'javascript:alert(1)' }] }, unknown: {}, conflicts: [] },
  discovery: { source: 'https://data.iana.org/rdap/dns.json', fetchedAt: '2026-10-14T11:00:00Z', ageSeconds: 3600, fresh: true, expiresAt: '2026-10-15T11:00:00Z', publication: '2026-10-01T00:00:00Z' },
  attempts: [{ protocol: 'rdap', phase: 'discovery', source: 'https://data.iana.org/rdap/dns.json', timestamp: '2026-10-14T12:00:00Z', outcome: 'completed', status: null }, { protocol: 'rdap', phase: 'query', source: 'https://registry.example.org/domain/example.com', timestamp: '2026-10-14T12:00:00Z', outcome: 'record', status: 200 }],
  rawResponses: [{ protocol: 'rdap', phase: 'query', source: 'https://registry.example.org/domain/example.com', timestamp: '2026-10-14T12:00:00Z', text: '{"objectClassName":"domain","ldhName":"example.com","untrusted":"<script>not executable</script>"}' }],
  fallbackReason: null, cache: { cached: false, ageSeconds: 0, ttlSeconds: 60 },
  warnings: ['Registration data does not establish purchase availability, physical geolocation, or live DNSSEC validation.'],
};

export function mixedRoleFixture(roles: string[]): RegistrationResult {
  const vcardArray = ['vcard', [['fn', {}, 'text', 'Shared Name'], ['org', {}, 'text', 'Shared Org'], ['email', {}, 'text', 'shared@example.org'], ['tel', {}, 'uri', 'tel:+1-555-0999']]];
  const publicIds = [{ type: 'IANA Registrar ID', identifier: '1234' }];
  return { ...registrationFixture,
    normalized: { ...registrationFixture.normalized, fields: { Domain: ['example.com'], 'Registered holder': ['Shared Org', 'Known Holder'], 'Registrant name': ['Known Holder'], 'Registrant email': ['holder@example.org'], Registrar: ['Known Registrar'], 'Registrar email': ['registrar@example.org'], 'Registrar code': ['1234 (IANA ID)'] },
      details: { contacts: [{ handle: 'SHARED-HANDLE', roles, publicIds, vcardArray, redacted: [], values: { fn: ['Shared Name'], org: ['Shared Org'], email: ['shared@example.org'], tel: ['tel:+1-555-0999'] } },
        ...(['registrant', 'registrar'] as const).map((role) => {
          const name = role === 'registrant' ? 'Known Holder' : 'Known Registrar', email = role === 'registrant' ? 'holder@example.org' : 'registrar@example.org';
          return { handle: null, roles: [role], publicIds: [], redacted: [], vcardArray: ['vcard', [['fn', {}, 'text', name], ['email', {}, 'text', email]]], values: { fn: [name], email: [email] } };
        })] }, conflicts: ['Registered holder'] },
    rawResponses: [{ ...registrationFixture.rawResponses[0], text: JSON.stringify({ objectClassName: 'domain', ldhName: 'example.com', entities: [{ roles, handle: 'SHARED-HANDLE', publicIds, vcardArray },
      ...(['registrant', 'registrar'] as const).map((role) => ({ roles: [role], vcardArray: ['vcard', [['fn', {}, 'text', role === 'registrant' ? 'Known Holder' : 'Known Registrar'], ['email', {}, 'text', role === 'registrant' ? 'holder@example.org' : 'registrar@example.org']]] }))] }) }],
  };
}

export function resourceFixture(kind: 'ipv4' | 'ipv6' | 'asn', known = true): RegistrationResult {
  const canonical = kind === 'asn' ? 'AS13335' : kind === 'ipv6' ? '2606:4700::1111' : '8.8.8.8';
  const base = 'https://rdap.arin.net/registry/';
  const source = `${base}${kind === 'asn' ? 'autnum/13335' : `ip/${canonical}`}`;
  return { ...registrationFixture, input: { original: canonical, canonical, kind, protocolMode: 'auto' },
    source,
    discovery: { ...registrationFixture.discovery, source: `https://data.iana.org/rdap/${kind}.json` },
    attempts: [{ ...registrationFixture.attempts[1], source }],
    rawResponses: [{ ...registrationFixture.rawResponses[0], source, text: JSON.stringify({ objectClassName: kind === 'asn' ? 'autnum' : 'ip network', handle: 'Fixture resource', custom: 'preserved' }) }],
    normalized: { outcome: 'record', fields: { ...(known ? { 'Registry / RIR': ['ARIN'] } : {}), 'Registered holder': ['Fixture Holder', 'Conflicting Holder'] },
      details: { contacts: [], registryEvidence: { name: known ? 'ARIN' : null, service: known ? base : null, source: `https://data.iana.org/rdap/${kind}.json` } }, unknown: { custom: ['preserved'] }, conflicts: ['Registered holder'] } };
}
