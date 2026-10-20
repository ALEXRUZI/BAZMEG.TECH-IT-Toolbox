import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createDnsContractFixtures, normalizeFixtureRequest } from '../../backend/test/fixtures/dns-contracts.mjs';
import { DnsChecker } from '../src/tools/dns-checker/DnsChecker';
import { isDnsCheckResult, parseDnsCheckResponse } from '../src/tools/dns-checker/dnsApi';
import { buildDnsPayload, getDnsQueryInput, validateDnsForm } from '../src/tools/dns-checker/dnsHelpers';
import type { DnsCheckResult, DnsRecordType, DnsTxtHelper } from '../src/tools/dns-checker/dnsTypes';

let fixtures: Record<string, DnsCheckResult>;
beforeAll(async () => {
  const generated = await createDnsContractFixtures();
  fixtures = Object.fromEntries(Object.entries(generated).map(([key, value]) => {
    if (!isDnsCheckResult(value)) throw new Error(`Invalid backend fixture: ${key}`);
    return [key, value];
  }));
});
afterEach(() => vi.unstubAllGlobals());

function run() {
  render(<DnsChecker />);
  const input = screen.getByRole('textbox', { name: 'Domain/FQDN' });
  fireEvent.focus(input);
  fireEvent.change(input, { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Run DNS Check' }));
}

describe('DNS response contracts from real offline backend outputs', () => {
  it.each(['timeout', 'resolverError', 'incomplete', 'formerr', 'notimp', 'nxdomain'])('keeps %s inspectable in simple, raw and image views, and permits retry', async (key) => {
    const fixture = fixtures[key];
    const fetch = vi.fn().mockResolvedValueOnce(new Response(JSON.stringify(fixture)))
      .mockResolvedValueOnce(new Response(JSON.stringify(fixtures.success)));
    vi.stubGlobal('fetch', fetch);
    run();
    await screen.findByRole('heading', { name: 'Main records' });
    expect(screen.getByRole('button', { name: 'Run DNS Check' })).toBeEnabled();
    for (const warning of fixture.warnings) expect(screen.getAllByText(warning, { exact: true }).length).toBeGreaterThan(0);
    expect(screen.getAllByText('Cloudflare DNS', { exact: true }).length).toBeGreaterThan(0);
    if (!fixture.ok) expect(screen.getByRole('alert')).toHaveTextContent('does not establish a complete successful lookup');
    const capture = document.querySelector('[aria-hidden="true"]') as HTMLElement;
    // The image capture includes the same explicit status and warnings as the UI.
    expect(screen.getByRole('button', { name: 'Copy result image' })).toBeInTheDocument();
    expect(capture).not.toBeNull();
    expect(capture.textContent).not.toContain('Overall resultOK');
    for (const warning of fixture.warnings) expect(capture.textContent).toContain(warning);
    fireEvent.click(screen.getByRole('button', { name: 'raw' }));
    expect(document.querySelector('pre')?.textContent).toBe(JSON.stringify(fixture, null, 2));
    fireEvent.click(screen.getByRole('button', { name: 'Run DNS Check' }));
    fireEvent.click(screen.getByRole('button', { name: 'simple' }));
    await screen.findByRole('heading', { name: 'Main records' });
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('keeps every burst provider, its warnings and non-success badge in UI and export', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(fixtures.burst))));
    run();
    const comparison = await screen.findByRole('heading', { name: 'Provider comparison' });
    const section = comparison.parentElement!;
    expect(within(section).getAllByRole('article')).toHaveLength(10);
    for (const failed of fixtures.burst.providers!.filter((provider) => !provider.ok)) {
      expect(within(section).getByText(failed.warnings[0], { exact: true })).toBeVisible();
    }
    const badges = section.querySelectorAll('span.w-fit');
    expect(badges[0].className).toContain('text-amber-100');
    expect(badges[1].className).toContain('text-amber-100');
    expect(document.querySelectorAll('span.w-fit.text-amber-100')).toHaveLength(4);
  });

  it.each([
    [400, 'INVALID_QUERY', 'Enter a valid public DNS name.'],
    [429, 'RATE_LIMITED', 'Too many live DNS checks were made recently. Please try again later.'],
    [503, 'DNS_CAPACITY_EXHAUSTED', 'DNS checks are busy. Please try again later.'],
    [504, 'DNS_DIAGNOSTIC_TIMEOUT', 'DNS diagnostic timed out.'],
  ])('renders structured HTTP %s API errors separately', async (status, code, message) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ok: false, error: { code, message } }), { status })));
    run();
    expect(await screen.findByText(code === 'RATE_LIMITED' ? /Rate limit reached/ : message)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run DNS Check' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: 'Copy result image' })).not.toBeInTheDocument();
  });

  it.each([null, {}, { ok: false }, { ok: false, error: null }, { ok: false, error: { code: 'X', message: {} } }, { ok: true, records: [] }])('rejects malformed envelopes safely: %j', async (body) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(body))));
    run();
    expect(await screen.findByText('DNS check returned an unexpected response. Please try again.')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Run DNS Check' })).toBeEnabled();
  });

  it.each(['future-status', 'toString', '__proto__'])('rejects malformed nested records/providers and renders unknown status %s safely', async (status) => {
    for (const bad of [
      { ...fixtures.success, records: [null] },
      { ...fixtures.success, records: [{ name: 'example.com', type: 'TXT', chunks: {} }] },
      { ...fixtures.success, diagnostics: [{ id: 'x', status: {} }] },
      { ...fixtures.success, diagnostics: [{ id: 'spf', mechanismDetails: [{ token: 'a', mechanism: { toString: null } }] }] },
      { ...fixtures.success, records: [{ name: 'example.com', type: 'SOA', mname: { toString: null } }] },
      { ...fixtures.burst, providers: [null] },
      { ...fixtures.success, query: { queryName: {} } },
    ]) expect(parseDnsCheckResponse(bad)).toHaveProperty('error.code', 'DNS_CHECK_FAILED');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({ ...fixtures.timeout, status }))));
    run();
    expect(await screen.findByRole('alert')).toHaveTextContent(status);
  });

  it.each(['non-JSON', 'network failure'])('clears loading and shows a safe error for %s', async (failure) => {
    vi.stubGlobal('fetch', failure === 'non-JSON'
      ? vi.fn().mockResolvedValue(new Response('<html>private upstream detail</html>', { status: 502 }))
      : vi.fn().mockRejectedValue(new Error('private upstream detail')));
    run();
    expect(await screen.findByRole('alert')).toHaveTextContent(failure === 'non-JSON'
      ? 'DNS check returned an unexpected response. Please try again.' : 'DNS check failed.');
    expect(screen.getByRole('button', { name: 'Run DNS Check' })).toBeEnabled();
    expect(screen.queryByText(/private upstream detail/)).not.toBeInTheDocument();
  });
});

describe('TXT helper and backend normalization agreement', () => {
  const input = (queryInput: string, txtHelper: DnsTxtHelper, dkimSelector = 'selector_name', recordType: DnsRecordType = 'TXT') => ({
    mode: 'single' as const, resolverId: 'cloudflare', recordType, queryInput, txtHelper, dkimSelector,
    srvService: 'sip', srvProtocol: 'tcp' as const, srvDomain: 'example.com', dnssec: false,
  });
  it.each([
    ['normal', 'example.com', 'example.com'], ['spf', 'example.com', 'example.com'],
    ['dmarc', 'example.com', '_dmarc.example.com'], ['dkim', 'example.com', 'selector_name._domainkey.example.com'],
    ['acme', 'example.com', '_acme-challenge.example.com'], ['normal', '_dmarc.example.com', '_dmarc.example.com'],
    ['normal', 'selector_name._domainkey.example.com', 'selector_name._domainkey.example.com'],
    ['dmarc', '_dmarc.example.com', '_dmarc.example.com'], ['acme', '_acme-challenge.example.com', '_acme-challenge.example.com'],
    ['dkim', 'selector_name._domainkey.example.com', 'selector_name._domainkey.example.com'],
    ['dmarc', 'bücher.example', '_dmarc.xn--bcher-kva.example'],
  ] as const)('%s helper accepts %s and produces backend-normalizable payloads', (helper, name, expected) => {
    expect(validateDnsForm('TXT', name, helper, 'selector_name', '', '')).toBe('');
    const payload = buildDnsPayload(input(name, helper));
    expect(normalizeFixtureRequest(payload).query.queryName).toBe(expected);
    expect(getDnsQueryInput('TXT', name, helper, 'selector_name')).not.toContain('_dmarc._dmarc.');
  });
  it.each(['bad..example.com', '-bad.example.com', 'bad-.example.com', 'bad!name.example.com', 'bad name.example.com', 'bad\tname.example.com', '\ud800.example.com', '_dmarc.local', '_dmarc.internal', '_dmarc.home.arpa', 'a'.repeat(64) + '.example.com'])('rejects invalid owner %s on both sides', (name) => {
    expect(validateDnsForm('TXT', name, 'normal', '', '', '')).not.toBe('');
    expect(() => normalizeFixtureRequest(buildDnsPayload(input(name, 'normal')))).toThrow();
  });
  it('checks generated wire length, IDN length and restrictive non-TXT/SRV names', () => {
    const maximum = [63, 63, 63, 61].map((n) => 'a'.repeat(n)).join('.');
    expect(validateDnsForm('TXT', maximum, 'normal', '', '', '')).toBe('');
    expect(normalizeFixtureRequest(buildDnsPayload(input(maximum, 'normal'))).query.queryName).toHaveLength(253);
    expect(validateDnsForm('TXT', maximum, 'dmarc', '', '', '')).not.toBe('');
    expect(() => normalizeFixtureRequest(buildDnsPayload(input(maximum, 'dmarc')))).toThrow();
    expect(validateDnsForm('TXT', 'é'.repeat(60) + '.example.com', 'normal', '', '', '')).not.toBe('');
    for (const type of ['A', 'AAAA', 'MX', 'CNAME', 'NS', 'SOA', 'CAA'] as const) {
      expect(validateDnsForm(type, '_dmarc.example.com', 'normal', '', '', '')).not.toBe('');
    }
    expect(validateDnsForm('SRV', '', 'normal', '', 'sip-', 'example.com')).not.toBe('');
  });
});
