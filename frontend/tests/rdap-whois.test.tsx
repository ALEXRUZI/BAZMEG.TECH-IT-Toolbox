import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { classifyRegistration, expirationRemaining, normalizedExport, downloadRegistration, registrationStatusExplanation, publishedDnssec, registrationContactFields, lookupTimestamp } from '../src/tools/rdap-whois/rdapHelpers';
import type { JsonValue } from '../src/tools/rdap-whois/rdapTypes';
import { validateRegistrationResponse, fetchRegistration } from '../src/tools/rdap-whois/rdapApi';
import { RdapLookup } from '../src/tools/rdap-whois/RdapLookup';
import { registrationFixture as fixture, resourceFixture, mixedRoleFixture } from '../e2e/fixtures/rdap';
import { RegistrationOverview } from '../src/tools/rdap-whois/RdapResults';
import { registrationOverviewFields } from '../src/tools/rdap-whois/rdapHelpers';

afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
describe('registration input and contracts', () => {
  it.each(['ipv4', 'ipv6', 'asn'] as const)('presents %s fields, missing values and registry evidence without domain placeholders', (kind) => {
    const result = resourceFixture(kind);
    const fields = registrationOverviewFields(result);
    expect(fields['Registry / RIR']).toBe('ARIN');
    expect(fields[kind === 'asn' ? 'ASN name' : 'Network name']).toBe('Unavailable');
    expect(fields.Contacts).toBe('Unavailable');
    expect(fields).not.toHaveProperty('Registrar'); expect(fields).not.toHaveProperty('Nameservers');
    expect(registrationOverviewFields(resourceFixture(kind, false))['Registry / RIR']).toBe('Unavailable / unknown');
    const { container } = render(<RegistrationOverview result={result} calculatedAt={0} image />);
    expect(container).not.toHaveTextContent('Expiration remaining');
    expect(container).toHaveTextContent(result.source); expect(container).toHaveTextContent(lookupTimestamp(result.timestamp));
    expect(container).toHaveTextContent('Conflicting / ambiguous; see detailed evidence'); expect(container).not.toHaveTextContent('preserved');
    expect(container.querySelector('pre, details')).toBeNull();
    expect(normalizedExport(result).normalized.details.registryEvidence).toEqual(result.normalized.details.registryEvidence);
    expect(normalizedExport(result)).not.toHaveProperty('rawResponses');
  });
  it('domain headline contains only the domain and expiration date', () => {
    const fields = registrationOverviewFields(fixture);
    expect(fields).toEqual({ 'Domain name': 'example.com', 'Expiration date': '2030-01-01T00:00:00Z' });
  });
  it.each([
    ['BÜCHER.de.', 'xn--bcher-kva.de', 'domain'], ['as00013335', 'AS13335', 'asn'], ['8.8.8.8', '8.8.8.8', 'ipv4'],
    ['2606:4700:0:0:0:0:0:1111', '2606:4700::1111', 'ipv6'], ['127.0.0.1', '127.0.0.1', 'ipv4'],
  ])('classifies %s without treating queried IP as a destination', (value, canonical, kind) => expect(classifyRegistration(value)).toEqual({ canonical, kind }));
  it.each(['https://example.com', 'example.com:43', 'a.com\nb.com', 'a.com,b.com', 'a.com\u200b', '8.8.8.8/24', 'AS0', 'AS4294967296', '10.00.0.1', '[::1]', 'fe80::1%eth0', '12345', 'example.com/path', 'localhost'])('rejects %s', (value) => expect(() => classifyRegistration(value)).toThrow());
  it('validates every used API contract rather than only asserting a type', () => {
    expect(validateRegistrationResponse(fixture)).toEqual(fixture);
    for (const patch of [{ input: null }, { attempts: [{}] }, { rawResponses: [{ text: 'a' }] }, { normalized: { ...fixture.normalized, fields: { Domain: 123 } } }, { normalized: { ...fixture.normalized, conflicts: [3] } }, { cache: { cached: true, ageSeconds: NaN, ttlSeconds: 60 } }, { discovery: null }, { protocol: 'http' }, { warnings: 'oops' }]) expect(() => validateRegistrationResponse({ ...fixture, ...patch })).toThrow();
    for (const patch of [{ input: { ...fixture.input, kind: ['domain'] } }, { input: { ...fixture.input, protocolMode: ['auto'] } }, { outcome: ['record'], normalized: { ...fixture.normalized, outcome: ['record'] } }]) expect(() => validateRegistrationResponse({ ...fixture, ...patch })).toThrow();
    expect(validateRegistrationResponse({ ok: false, error: { code: 'RATE_LIMITED', message: 'Wait.' }, attempts: [], rawResponses: [] }).ok).toBe(false);
  });
  it('computes expiration at a fixed instant and refuses ambiguous, absent or conflicting dates', () => {
    const expiration = Date.parse('2030-01-01T00:00:00Z');
    expect(expirationRemaining(fixture, expiration)).toBe('Expires at this instant');
    expect(expirationRemaining(fixture, expiration + 1)).toBe('Expired');
    expect(expirationRemaining(fixture, expiration - 86400000)).toContain('1.00 days');
    expect(expirationRemaining({ ...fixture, normalized: { ...fixture.normalized, fields: { Expires: ['2030-01-01'] } } }, expiration)).toContain('Calendar date only');
    expect(expirationRemaining({ ...fixture, normalized: { ...fixture.normalized, fields: { Expires: ['2030-01-01T00:00:00Z', '2031-01-01T00:00:00Z'] } } }, expiration)).toContain('Conflicting');
    expect(expirationRemaining({ ...fixture, normalized: { ...fixture.normalized, fields: {} } }, expiration)).toBe('Unavailable');
    expect(expirationRemaining({ ...fixture, normalized: { ...fixture.normalized, fields: { Expires: ['2030-02-30T00:00:00Z'] } } }, expiration)).toContain('Invalid expiration');
  });
  it('keeps normalized exports attributed without duplicating raw data', () => {
    const exported = normalizedExport(fixture); expect(exported.source).toBe(fixture.source); expect(exported.protocol).toBe('rdap'); expect(exported.timestamp).toBe(fixture.timestamp); expect(exported.input.canonical).toBe('example.com'); expect(exported).not.toHaveProperty('rawResponses');
  });
  it('explains known EPP and RDAP states without inventing meanings for unknown codes', () => {
    expect(registrationStatusExplanation('clientTransferProhibited https://icann.org/epp')).toBe(registrationStatusExplanation('client transfer prohibited'));
    expect(registrationStatusExplanation('active')).toBe(registrationStatusExplanation('ok'));
    expect(registrationStatusExplanation('private status')).toContain('no interpretation');
    expect(registrationStatusExplanation('constructor')).toContain('no interpretation');
  });
  it('downloads only on explicit action and revokes the object URL', async () => {
    const create = vi.fn(() => 'blob:fixture'), revoke = vi.fn();
    class FixtureURL extends URL { static createObjectURL = create; static revokeObjectURL = revoke; }
    vi.stubGlobal('URL', FixtureURL);
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    downloadRegistration('{}', 'registration.json', 'application/json'); expect(create).toHaveBeenCalledOnce();
    await waitFor(() => expect(revoke).toHaveBeenCalledWith('blob:fixture'));
  });
  it('uses relative API, includes mode, and forwards cancellation', async () => {
    const fetch = vi.fn(async () => ({ ok: true, text: async () => JSON.stringify(fixture) })); vi.stubGlobal('fetch', fetch);
    const controller = new AbortController(); await fetchRegistration('example.com', 'auto', controller.signal);
    expect(fetch).toHaveBeenCalledWith('/api/tools/rdap-lookup', expect.objectContaining({ signal: controller.signal, body: '{"target":"example.com","protocolMode":"auto"}' }));
  });
});

describe('registration overview v3', () => {
  it.each(['rdap', 'whois'] as const)('replaces empty domain cards for %s negatives and unknowns on screen and image', (protocol) => {
    for (const outcome of ['not_found', 'unknown'] as const) for (const image of [false, true]) {
      const result = { ...fixture, protocol, outcome, normalized: { ...fixture.normalized, outcome, fields: {}, details: { diagnostic: 'Preserved evidence' } } };
      const view = render(<RegistrationOverview result={result} calculatedAt={0} image={image} />);
      expect(screen.getByRole('heading', { name: outcome === 'not_found' ? 'No registration record found' : 'Registration status could not be determined' })).toBeInTheDocument();
      for (const name of ['Registration overview', 'Domain registrant', 'Registrar', 'Additional information']) expect(screen.queryByRole('heading', { name })).toBeNull();
      expect(view.container).not.toHaveTextContent('Unavailable');
      expect(view.container).toHaveTextContent(result.input.canonical); expect(view.container).toHaveTextContent(result.source);
      if (outcome === 'not_found') expect(view.container).toHaveTextContent('A missing registration record does not guarantee domain purchase or registration availability.');
      if (image) expect(view.container.querySelector('pre, details, button')).toBeNull();
      else expect(screen.getByText('All published fields and registry evidence')).toBeInTheDocument();
      expect(normalizedExport(result).normalized.details).toEqual(result.normalized.details);
      view.unmount();
    }
  });
  it.each(['ipv4', 'ipv6', 'asn'] as const)('does not alter %s negative or unknown presentation', (kind) => {
    for (const outcome of ['not_found', 'unknown'] as const) {
      const result = resourceFixture(kind);
      result.outcome = outcome; result.normalized.outcome = outcome;
      const view = render(<RegistrationOverview result={result} calculatedAt={0} />);
      expect(screen.getByRole('heading', { name: 'Registration overview' })).toBeInTheDocument();
      expect(screen.queryByRole('heading', { name: 'No registration record found' })).toBeNull();
      view.unmount();
    }
  });
  const section = (title: string) => within(screen.getByRole('heading', { name: title }).closest('section')!);
  const withDnssec = (dnssec: JsonValue) => ({ ...fixture, normalized: { ...fixture.normalized, details: { ...fixture.normalized.details, dnssec } } });
  it('orders compact lookup metadata above the domain overview and never adds per-field controls', () => {
    const result = { ...fixture, input: { ...fixture.input, protocolMode: 'whois' as const }, protocol: 'whois' as const, source: 'whois://registry.example.org:43', fallbackReason: 'UNSUPPORTED_DISCOVERY', cache: { cached: true, ageSeconds: 12, ttlSeconds: 60 } };
    const { container } = render(<RegistrationOverview result={result} calculatedAt={Date.parse('2029-12-31T00:00:00Z')} />);
    expect(screen.getAllByRole('heading').slice(0, 5).map((h) => h.textContent)).toEqual(['Lookup metadata', 'Registration overview', 'Domain registrant', 'Registrar', 'Additional information']);
    const metadata = section('Lookup metadata');
    for (const value of ['WHOIS-only', 'WHOIS', result.source, '2026-10-14 12:00:00.000 UTC', 'Cached result · 12.0 seconds old; TTL 60s', 'UNSUPPORTED_DISCOVERY', 'Registration record']) expect(metadata.getByText(value, { exact: true })).toBeInTheDocument();
    expect(section('Registration overview').queryByText('Selected mode')).toBeNull();
    expect(section('Registration overview').getByText('1.00 days remaining (display rounded)')).toBeInTheDocument();
    expect(container.querySelectorAll('button')).toHaveLength(0);
    expect(container).not.toHaveTextContent('Expiration calculated at');
    expect(section('Domain registrant').getByText('Redacted')).toBeInTheDocument();
    for (const value of ['Fixture Holder', 'ORG-42 (Organization ID)', 'tel:+1-555-0100', 'owner@example.org', 'other@example.org']) expect(section('Domain registrant').getByText(value)).toBeInTheDocument();
    expect(section('Registrar').getByText('1234 (IANA ID)')).toBeInTheDocument();
    expect(section('Registrar').getByText('Unavailable')).toBeInTheDocument();
  });
  it('keeps conflicting registrar codes in evidence without treating a handle or abuse contact as a substitute', () => {
    const result = { ...fixture, normalized: { ...fixture.normalized, conflicts: ['Registrar', 'Registrar code'], fields: { Registrar: ['One', 'Two'], 'Registrar code': ['1234 (IANA ID)', '5678 (IANA ID)', 'REG-9 (Registry Registrar ID)'], 'Abuse email': ['abuse@example.org'] }, details: { contacts: [{ handle: 'NOT-AN-ORG-ID', roles: ['registrant'] }] } } };
    const fields = registrationContactFields(result, 'registrar');
    expect(fields['Registrar code']).toEqual(['Conflicting / ambiguous; see detailed evidence']); expect(fields.Email).toEqual([]);
    render(<RegistrationOverview result={result} calculatedAt={0} />);
    expect(section('Registrar').queryByText('One')).toBeNull(); expect(section('Registrar').queryByText('1234 (IANA ID)')).toBeNull();
    expect(section('Registrar').getAllByText('Conflicting / ambiguous; see detailed evidence')).toHaveLength(2);
    expect(section('Domain registrant').getAllByText('Unavailable')).toHaveLength(5);
    expect(section('Domain registrant').queryByText('Redacted')).toBeNull();
  });
  it.each([['registrant', 'registrar'], ['registrant', 'registrar', 'abuse'], ['registrar', 'technical', 'registrant'], ['registrant', 'registrar', 'abuse', 'technical']])('keeps mixed-role evidence out of both cards (%j)', (...roles) => {
    const result = mixedRoleFixture(roles);
    const view = render(<RegistrationOverview result={result} calculatedAt={0} />);
    for (const image of [false, true]) {
      view.rerender(<RegistrationOverview result={result} calculatedAt={0} image={image} />);
      for (const title of ['Domain registrant', 'Registrar']) {
        const card = section(title);
        for (const value of ['Shared Name', 'Shared Org', 'shared@example.org', 'tel:+1-555-0999']) expect(card.queryByText(value)).toBeNull();
        expect(card.getByText(title === 'Registrar' ? 'Known Registrar' : 'Known Holder')).toBeInTheDocument();
        expect(card.getByText(title === 'Registrar' ? 'registrar@example.org' : 'holder@example.org')).toBeInTheDocument();
      }
      expect(section('Registrar').getByText('1234 (IANA ID)')).toBeInTheDocument();
      if (image) expect(view.container).not.toHaveTextContent('shared@example.org');
    }
    expect(normalizedExport(result).normalized.details.contacts).toEqual(result.normalized.details.contacts);
    expect(result.rawResponses[0].text).toContain('shared@example.org');
  });
  it('renders every DS record in source order with known names, unknown codes and complete digests', () => {
    const digest = 'C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A';
    const result = withDnssec({ delegationSigned: true, dsData: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest }, { keyTag: 99, algorithm: 250, digestType: 251, digest: 'ABCD' }] });
    render(<RegistrationOverview result={result} calculatedAt={0} />);
    const info = section('Additional information');
    expect(info.getByText('Signed delegation reported')).toBeInTheDocument();
    expect(info.getAllByRole('heading').map((h) => h.textContent)).toEqual(['Additional information', 'Published DNSSEC', 'DS Record #1', 'DS Record #2']);
    for (const value of [digest, '13 — ECDSA P-256 / SHA-256', '2 — SHA-256', '250', '251']) expect(info.getByText(value, { exact: true })).toBeInTheDocument();
    expect(info.getByText(digest)).toHaveClass('[overflow-wrap:anywhere]');
    expect(info.getByText(/live DNSSEC chain has not been validated/)).toBeInTheDocument();
  });
  it.each([[1, 20], [2, 32], [3, 32], [4, 48]])('validates exact digest length for type %i without altering evidence', (digestType, bytes) => {
    for (const length of [0, bytes - 1, bytes, bytes + 1]) {
      const digest = 'aB'.repeat(length);
      const data = { dsData: [{ keyTag: 2371, algorithm: 13, digestType, digest }] };
      const result = withDnssec(data), before = structuredClone(result);
      const parsed = publishedDnssec(result);
      expect(parsed?.malformed).toBe(length !== bytes);
      expect(parsed?.records[0]?.Digest).toBe(digest);
      expect(result).toEqual(before);
      expect(normalizedExport(result).normalized.details.dnssec).toEqual(data);
    }
  });
  it.each(['AB', 'aBcD', 'AB'.repeat(64)])('does not assume a digest length for unknown types (%s)', (digest) => {
    const result = withDnssec({ dsData: [{ keyTag: 1, algorithm: 250, digestType: 251, digest }] });
    expect(publishedDnssec(result)).toMatchObject({ malformed: false, records: [{ 'Digest type': '251', Digest: digest }] });
  });
  it.each(['ABC', 'GG', 'AB '.repeat(32)])('still rejects invalid hex digests for unknown types (%s)', (digest) => {
    expect(publishedDnssec(withDnssec({ dsData: [{ keyTag: 1, algorithm: 250, digestType: 251, digest }] }))?.malformed).toBe(true);
  });
  it('flags a short known digest on screen and image while preserving every record and exported evidence', () => {
    const data = { delegationSigned: true, dsData: [{ keyTag: 1, algorithm: 13, digestType: 2, digest: 'aBcD' }, { keyTag: 2, algorithm: 250, digestType: 251, digest: '1234' }] };
    const result = withDnssec(data);
    const view = render(<RegistrationOverview result={result} calculatedAt={0} />);
    for (const image of [false, true]) {
      view.rerender(<RegistrationOverview result={result} calculatedAt={0} image={image} />);
      const info = section('Additional information');
      expect(info.getByText(/Unrecognized or malformed DNSSEC/)).toBeInTheDocument();
      expect(info.getAllByRole('heading', { name: /DS Record/ })).toHaveLength(2);
      expect(info.getByText('aBcD', { exact: true })).toBeInTheDocument();
      expect(info.getByText('1234', { exact: true })).toBeInTheDocument();
    }
    expect(normalizedExport(result).normalized.details.dnssec).toEqual(data);
  });
  it.each([null, {}])('hides absent DNSSEC (%j) and reports unavailable nameservers', (data) => {
    const result = withDnssec(data);
    result.normalized.fields = {};
    render(<RegistrationOverview result={result} calculatedAt={0} />);
    expect(screen.queryByRole('heading', { name: 'Published DNSSEC' })).toBeNull();
    expect(section('Additional information').getAllByText('Unavailable')).toHaveLength(3);
  });
  it('distinguishes unsigned and WHOIS status-only metadata without inventing records', () => {
    expect(publishedDnssec(withDnssec({ delegationSigned: false }))?.status).toBe('Unsigned delegation reported');
    const result = withDnssec(null); result.normalized.fields = { 'Published DNSSEC': ['signedDelegation', 'unknown upstream status'] };
    render(<RegistrationOverview result={result} calculatedAt={0} />);
    expect(section('Additional information').getByText('signedDelegation')).toBeInTheDocument();
    expect(section('Additional information').queryByText('Signed delegation reported')).toBeNull();
    expect(screen.queryByRole('heading', { name: /DS Record/ })).toBeNull();
  });
  it('does not turn null, primitive or empty DS entries into records, or hide out-of-range numeric identifiers', () => {
    const result = withDnssec({ dsData: [null, {}, 123, { keyTag: 9, algorithm: 999, digestType: 888, digest: 'ABCD' }] });
    render(<RegistrationOverview result={result} calculatedAt={0} />);
    const info = section('Additional information');
    expect(info.queryByRole('heading', { name: 'DS Record #1' })).toBeNull();
    expect(info.queryByRole('heading', { name: 'DS Record #2' })).toBeNull();
    expect(info.queryByRole('heading', { name: 'DS Record #3' })).toBeNull();
    expect(info.getByRole('heading', { name: 'DS Record #4' })).toBeInTheDocument();
    expect(info.getByText('999 (unrecognized format)')).toBeInTheDocument();
    expect(info.getByText('888 (unrecognized format)')).toBeInTheDocument();
  });
  it.each<JsonValue>([false, 'signed', { delegationSigned: 'false', dsData: {} }, { dsData: [null, { algorithm: '13', digest: '<script>bad</script>' }] }])('safely reports malformed DNSSEC %j without coercing values', (data) => {
    const result = withDnssec(data);
    const { container } = render(<RegistrationOverview result={result} calculatedAt={0} />);
    expect(section('Additional information').getByText(/Unrecognized or malformed DNSSEC/)).toBeInTheDocument();
    expect(section('Additional information').queryByText('Signed delegation reported')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
  });
  it('gives screen and image identical meaningful overview content without buttons', () => {
    const view = render(<RegistrationOverview result={fixture} calculatedAt={0} />);
    const content = section('Registration overview').getByText('example.com').closest('section')!.textContent;
    view.rerender(<RegistrationOverview result={fixture} calculatedAt={0} image />);
    expect(section('Registration overview').getByText('example.com').closest('section')!.textContent).toBe(content);
    expect(screen.queryByRole('button')).toBeNull();
    expect(lookupTimestamp('not a date')).toBe('Unavailable');
  });
  it('ends the branded image after overview warnings while retaining expandable technical details on screen', () => {
    const result = { ...fixture, normalized: { ...fixture.normalized, conflicts: ['Expires'] } };
    const before = structuredClone(result);
    const view = render(<RegistrationOverview result={result} calculatedAt={0} image />);
    for (const title of ['Lookup metadata', 'Registration overview', 'Domain registrant', 'Registrar', 'Additional information', 'Published DNSSEC', 'DS Record #1']) expect(screen.getByRole('heading', { name: title })).toBeInTheDocument();
    for (const value of ['BAZMEG.TECH IT Toolbox', 'toolbox.bazmeg.tech', 'ns1.example.com', fixture.warnings[0], 'Conflicting fields: Expires. No value was selected as authoritative.']) expect(view.container).toHaveTextContent(value);
    for (const value of ['Detailed information', 'All published fields and registry evidence', 'Registration status codes and explanations', 'Discovery and protocol attempts', 'Contacts, events, DNSSEC, notices and unknown fields', 'Protocol attempts', 'Raw responses', 'untrusted notice', 'objectClassName']) expect(view.container).not.toHaveTextContent(value);
    expect(view.container.querySelector('pre, details, summary, button')).toBeNull();
    expect(view.container.firstElementChild?.lastElementChild).toHaveTextContent('Conflicting fields: Expires.');
    view.rerender(<RegistrationOverview result={result} calculatedAt={0} />);
    expect(screen.getByRole('heading', { name: 'Detailed information' })).toBeInTheDocument();
    for (const title of ['All published fields and registry evidence', 'Registration status codes and explanations']) {
      const summary = screen.getByText(title);
      expect(summary.closest('details')).not.toHaveAttribute('open');
      fireEvent.click(summary);
      expect(summary.closest('details')).toHaveAttribute('open');
    }
    expect(view.container).toHaveTextContent(registrationStatusExplanation('active'));
    expect(result).toEqual(before);
  });
});

describe('registration UI lifecycle and untrusted data', () => {
  it('renders safe text, preserves structured/raw views and supports reset', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(Date.parse('2029-12-31T00:00:00Z'));
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, text: async () => JSON.stringify(fixture) })));
    const { container } = render(<RdapLookup />);
    expect(screen.getByRole('combobox', { name: 'Protocol mode' })).toHaveValue('auto');
    fireEvent.change(screen.getByRole('textbox', { name: 'Registration identifier' }), { target: { value: 'https://example.com' } }); expect(screen.getByRole('button', { name: 'Lookup' })).toBeDisabled();
    fireEvent.change(screen.getByRole('textbox', { name: 'Registration identifier' }), { target: { value: 'example.com' } }); fireEvent.click(screen.getByRole('button', { name: 'Lookup' }));
    await screen.findByRole('button', { name: 'Download normalized JSON' }); expect(container.querySelector('script')).toBeNull(); expect(container.querySelector('a[href^="javascript:"]')).toBeNull();
    expect(screen.queryByRole('button', { name: 'Calculate expiration remaining' })).toBeNull();
    expect(screen.getAllByText('1.00 days remaining (display rounded)')).toHaveLength(2);
    expect(screen.getByRole('button', { name: 'Copy structured result' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy result image' })).toBeInTheDocument();
    expect(screen.getByText('Raw responses')).toBeInTheDocument(); expect(screen.getAllByText('Fixture Registrar').length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: 'Reset' })); expect(screen.queryByRole('button', { name: 'Download normalized JSON' })).toBeNull();
  });
  it('cancels, ignores stale completion and permits retry', async () => {
    let resolveOld: ((value: unknown) => void) | undefined;
    const fetch = vi.fn().mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve; })).mockResolvedValue({ ok: true, text: async () => JSON.stringify(fixture) }); vi.stubGlobal('fetch', fetch);
    render(<RdapLookup />); fireEvent.change(screen.getByRole('textbox', { name: 'Registration identifier' }), { target: { value: 'example.com' } }); fireEvent.click(screen.getByRole('button', { name: 'Lookup' }));
    fireEvent.click(screen.getByRole('button', { name: 'Cancel lookup' })); expect((fetch.mock.calls[0][1] as RequestInit).signal?.aborted).toBe(true);
    expect(screen.getByRole('alert')).toHaveTextContent('cancelled'); fireEvent.click(screen.getByRole('button', { name: 'Lookup' }));
    await screen.findByRole('button', { name: 'Download normalized JSON' });
    resolveOld?.({ ok: false, text: async () => JSON.stringify({ ok: false, error: { code: 'FAILED', message: 'Stale' }, attempts: [], rawResponses: [] }) });
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull());
  });
  it('aborts on unmount', () => {
    const fetch = vi.fn((..._args: unknown[]) => new Promise(() => {})); vi.stubGlobal('fetch', fetch);
    const view = render(<RdapLookup />); fireEvent.change(screen.getByRole('textbox', { name: 'Registration identifier' }), { target: { value: 'example.com' } }); fireEvent.click(screen.getByRole('button', { name: 'Lookup' })); view.unmount();
    expect((fetch.mock.calls[0]?.[1] as RequestInit).signal?.aborted).toBe(true);
  });
});
