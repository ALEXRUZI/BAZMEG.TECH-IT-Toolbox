import { fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TlsCertificateChecker } from '../src/tools/tls-certificate-checker/TlsCertificateChecker';
import { getTlsExpirationPresentation, getTlsIssuerChain, getTlsIssuerCertificateTitle, getTlsServerProvidedCertificateCount, getTlsSummaryChecks, hasCompleteTlsIssuerChain } from '../src/tools/tls-certificate-checker/tlsHelpers';
import { tlsResponse } from '../e2e/fixtures/responses';
import type { TlsCertificateDetail, TlsCheckSuccess } from '../src/tools/tls-certificate-checker/tlsTypes';

afterEach(() => vi.unstubAllGlobals());

describe('TLS certificate evidence presentation', () => {
  it.each([
    ['expired', 0, 'Expired'], ['expired', -3, 'Expired'],
    ['expiring-soon', 1, 'Expiring soon'], ['expiring-soon', 30, 'Expiring soon'],
    ['valid', 31, 'Valid'], ['unknown', null, 'Unknown'],
  ] as const)('uses backend exact state %s, not rounded days %s', (expirationState, daysRemaining, badge) => {
    const certificate = { ...tlsResponse.certificate, expirationState, daysRemaining };
    expect(getTlsExpirationPresentation(certificate).badge).toBe(badge);
  });

  it('missing state is unknown and never falls back to a rounded validity claim', () => {
    const { expirationState: _, ...legacy } = tlsResponse.certificate;
    expect(getTlsExpirationPresentation(legacy as TlsCertificateDetail).badge).toBe('Unknown');
    expect(getTlsExpirationPresentation({ ...tlsResponse.certificate, expirationState: 'valid', expiresAt: null, validTo: null }).badge).toBe('Unknown');
  });

  it('never invents transmitted counts, completeness or roots from fallback entries', () => {
    const result: TlsCheckSuccess = { ...tlsResponse, issuerChain: undefined, issuerChainComplete: undefined, serverProvidedCertificateCount: undefined };
    const entries = getTlsIssuerChain(result);
    expect(entries.map((entry) => entry.source)).toEqual(['peer', 'inferred']);
    expect(getTlsServerProvidedCertificateCount(result)).toBeNull();
    expect(hasCompleteTlsIssuerChain(result)).toBeNull();
    expect(getTlsSummaryChecks(result).find((check) => check.id === 'certificate_chain')?.message).toContain('Server-provided certificates: unknown');
    expect(getTlsServerProvidedCertificateCount({ ...result, serverProvidedCertificateCount: 2 })).toBe(2);
    expect(getTlsServerProvidedCertificateCount({ ...result, issuerChain: result.chain.map((_, index) => ({ ...entries[index], source: 'server-provided' })) })).toBeNull();
    const selfIssued = { ...tlsResponse.certificate, issuer: tlsResponse.certificate.subject, ca: false, selfIssued: true, selfSigned: true };
    const selfEntries = getTlsIssuerChain({ ...result, chain: [selfIssued] });
    expect(selfEntries[0].level).toBe('leaf');
    expect(getTlsIssuerCertificateTitle(selfEntries[0], 0)).toBe('Leaf Certificate');
    expect(hasCompleteTlsIssuerChain({ ...result, issuerChain: [{ ...selfEntries[0], level: 'self-signed-ca', ca: true }] })).toBeNull();
  });

  it.each([
    ['expired', 0, 'Expired'], ['unknown', null, 'Unknown'], ['expiring-soon', 30, 'Expiring soon'],
  ] as const)('main UI and image capture agree for %s, independently of authorization', async (expirationState, daysRemaining, badge) => {
    const certificate = { ...tlsResponse.certificate, issuer: tlsResponse.certificate.subject, expirationState, daysRemaining, ca: false, selfIssued: true, selfSigned: true, expiresAt: expirationState === 'unknown' ? null : tlsResponse.certificate.expiresAt, validTo: expirationState === 'unknown' ? null : tlsResponse.certificate.validTo };
    const result: TlsCheckSuccess = {
      ...tlsResponse, certificate, chain: [certificate, tlsResponse.chain[1]], issuerChain: undefined,
      tls: { ...tlsResponse.tls, authorized: false, authorizationError: 'CERT_HAS_EXPIRED' },
      summary: { ...tlsResponse.summary, trusted: false, notExpired: expirationState === 'unknown' ? null : expirationState !== 'expired' },
      checks: tlsResponse.checks.map((check) => check.id === 'certificate_trusted' ? { ...check, status: 'fail', message: 'The certificate is not trusted: CERT_HAS_EXPIRED' } : check.id === 'certificate_expiry' ? { ...check, status: expirationState === 'expired' ? 'fail' : 'warn', message: expirationState === 'expired' ? 'The certificate has expired.' : expirationState === 'unknown' ? 'The certificate expiration date could not be read.' : 'The certificate expires in 30 days.' } : check),
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(result), { status: 200 })));
    const { container } = render(<TlsCertificateChecker />);
    fireEvent.change(screen.getByRole('textbox', { name: 'Hostname' }), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Check certificate' }));
    await screen.findAllByText(badge, { exact: true });
    const image = container.querySelector('[aria-hidden="true"][style]') as HTMLElement;
    expect(within(image).getAllByText(badge, { exact: true }).length).toBeGreaterThan(0);
    expect(screen.getAllByText(badge, { exact: true }).some((element) => !image.contains(element))).toBe(true);
    expect(within(image).getAllByText('Unknown', { exact: true }).length).toBeGreaterThan(0);
    expect(image.textContent).toContain('Exact certificates transmitted by the server cannot be determined');
    expect(image.textContent).toContain('ORIGIN UNVERIFIED');
    expect(image.textContent).toContain('sha256WithRSAEncryption');
    expect(image.textContent).toContain('rsa / 2048 modulus bits');
    expect(image.textContent).not.toContain('Root Certificate');
    expect(image.textContent).toContain('weak signature algorithm');
    expect(screen.getAllByText('CERT_HAS_EXPIRED', { exact: true })[0]).toBeVisible();
  });
});
