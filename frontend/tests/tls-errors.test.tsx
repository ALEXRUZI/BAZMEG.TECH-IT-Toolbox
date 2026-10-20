import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TlsCertificateChecker } from '../src/tools/tls-certificate-checker/TlsCertificateChecker';
import { tlsResponse } from '../e2e/fixtures/responses';

afterEach(() => vi.unstubAllGlobals());

describe('TLS resource-budget error contract', () => {
  it.each([
    [429, 'RATE_LIMITED', 'Too many TLS checks were requested recently. Try again later.'],
    [503, 'TLS_CAPACITY_EXHAUSTED', 'TLS checker is busy. Try again later.'],
    [504, 'TLS_DIAGNOSTIC_TIMEOUT', 'TLS diagnostic timed out.'],
  ])('displays HTTP %s %s and recovers on retry', async (status, code, message) => {
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: false, error: { code, message } }), { status }))
      .mockResolvedValueOnce(new Response(JSON.stringify(tlsResponse), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    render(<TlsCertificateChecker />);
    fireEvent.change(screen.getByRole('textbox', { name: 'Hostname' }), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Check certificate' }));
    expect(await screen.findByText(code, { exact: true })).toBeVisible();
    expect(screen.getByText(message, { exact: true })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Check certificate' })).toBeEnabled();
    expect(fetch).toHaveBeenCalledWith('/api/tools/tls-check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ host: 'example.com', port: 443 }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Check certificate' }));
    await waitFor(() => expect(screen.getAllByText('TLSv1.3', { exact: true }).length).toBeGreaterThan(0));
    expect(screen.queryByText(code, { exact: true })).not.toBeInTheDocument();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
