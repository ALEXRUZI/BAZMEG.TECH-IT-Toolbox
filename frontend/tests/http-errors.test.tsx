import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpHeaderChecker } from '../src/tools/http-header-checker/HttpHeaderChecker';
import { httpResponse, httpSecurityResponse } from '../e2e/fixtures/responses';

afterEach(() => vi.unstubAllGlobals());

it('renders backend CORS and disabled HSTS warnings without upgrading severity', async () => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify(httpSecurityResponse))));
  render(<HttpHeaderChecker />);
  fireEvent.change(screen.getByRole('textbox', { name: 'Target' }), { target: { value: 'example.com' } });
  fireEvent.click(screen.getByRole('button', { name: 'Check headers' }));
  await screen.findByRole('heading', { name: 'HSTS policy disabled' });
  for (const view of ['simple', 'advanced'] as const) {
    fireEvent.click(screen.getByRole('button', { name: view }));
    for (const finding of httpSecurityResponse.checks[0].findings) {
      const heading = screen.getByRole('heading', { name: finding.title });
      expect(heading.closest('article')).toHaveClass('border-amber-300/35');
      expect(screen.getByText(finding.detail, { exact: true })).toBeVisible();
      expect(screen.getByText(finding.recommendation, { exact: true })).toBeVisible();
    }
    expect(screen.queryByText('critical', { exact: true })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'HSTS does not include subdomains' })).not.toBeInTheDocument();
  }
  fireEvent.click(screen.getByRole('button', { name: 'raw' }));
  const { budget: _budget, ...publicResponse } = httpSecurityResponse;
  expect(screen.getByText(JSON.stringify(publicResponse, null, 2), { normalizer: (text) => text })).toBeVisible();
});

describe('HTTP resource-budget error contract', () => {
  it.each([
    [429, 'RATE_LIMITED', 'Too many HTTP header checks were requested recently. Try again later, or wait for the cached result to expire.'],
    [503, 'HTTP_CAPACITY_EXHAUSTED', 'HTTP header checks are busy. Try again later.'],
    [504, 'HTTP_DIAGNOSTIC_TIMEOUT', 'HTTP header diagnostic timed out.'],
  ])('displays HTTP %s %s, clears loading and recovers on retry', async (status, code, message) => {
    const displayedMessage = code === 'RATE_LIMITED'
      ? 'Rate limit reached. Too many HTTP header checks were requested recently. Try again later.' : message;
    const fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ ok: false, error: { code, message } }), { status }))
      .mockResolvedValueOnce(new Response(JSON.stringify(httpResponse), { status: 200 }));
    vi.stubGlobal('fetch', fetch);
    render(<HttpHeaderChecker />);
    fireEvent.change(screen.getByPlaceholderText('example.com, https://example.com'), { target: { value: 'example.com' } });
    fireEvent.click(screen.getByRole('button', { name: 'Check headers' }));
    expect(screen.getByRole('button', { name: 'Checking...' })).toBeDisabled();
    expect(await screen.findByText(displayedMessage, { exact: true })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Check headers' })).toBeEnabled();
    expect(fetch).toHaveBeenCalledWith('/api/tools/http-header-check', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: 'example.com', protocolMode: 'auto' }),
    });
    fireEvent.click(screen.getByRole('button', { name: 'Check headers' }));
    expect(await screen.findByRole('heading', { name: 'Missing HSTS' })).toBeVisible();
    expect(screen.queryByText(displayedMessage, { exact: true })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Check headers' })).toBeEnabled();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
