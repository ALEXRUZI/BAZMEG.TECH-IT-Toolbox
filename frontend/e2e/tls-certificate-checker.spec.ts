import { test, expect, openTool, mockApi } from './fixtures/test';
import { tlsFailure, tlsResponse } from './fixtures/responses';

const payload = { host: 'example.com', port: 443 };

for (const [expirationState, daysRemaining, badge] of [
  ['expired', 0, 'Expired'], ['unknown', null, 'Unknown'],
] as const) {
  test(`TLS ${expirationState} state is consistent in UI and image export with unknown wire provenance`, async ({ page }) => {
    const certificate = { ...tlsResponse.certificate, issuer: tlsResponse.certificate.subject, expirationState, daysRemaining, selfIssued: true, selfSigned: true, ca: false, expiresAt: expirationState === 'unknown' ? null : tlsResponse.certificate.expiresAt, validTo: expirationState === 'unknown' ? null : tlsResponse.certificate.validTo };
    await mockApi(page, '/api/tools/tls-check', {
      ...tlsResponse, certificate, chain: [certificate, tlsResponse.chain[1]], issuerChain: undefined,
      tls: { ...tlsResponse.tls, authorized: false, authorizationError: 'CERT_HAS_EXPIRED' },
      summary: { ...tlsResponse.summary, trusted: false, notExpired: expirationState === 'unknown' ? null : false },
      checks: tlsResponse.checks.map((check) => check.id === 'certificate_trusted' ? { ...check, status: 'fail', message: 'The certificate is not trusted: CERT_HAS_EXPIRED' } : check.id === 'certificate_expiry' ? { ...check, status: expirationState === 'expired' ? 'fail' : 'warn', message: expirationState === 'expired' ? 'The certificate has expired.' : 'The certificate expiration date could not be read.' } : check),
    }, payload);
    const tool = await openTool(page, 'TLS cert checker', 'TLS/SSL certificate checker');
    await tool.getByRole('textbox', { name: 'Hostname' }).fill('example.com');
    await tool.getByRole('button', { name: 'Check certificate' }).click();
    await expect(tool.getByText(badge, { exact: true }).first()).toBeVisible();
    const image = tool.locator('[aria-hidden="true"][style]');
    await expect(image.getByText(badge, { exact: true }).first()).toBeAttached();
    await expect(image.getByText('Unknown', { exact: true }).first()).toBeAttached();
    await expect(image).toContainText('Exact certificates transmitted by the server cannot be determined');
    await expect(image).toContainText('ORIGIN UNVERIFIED');
    await expect(image).toContainText('sha256WithRSAEncryption');
    await expect(image).toContainText('rsa / 2048 modulus bits');
    await expect(image.getByText('Root Certificate', { exact: true })).toHaveCount(0);
    await expect(tool.getByText('CERT_HAS_EXPIRED', { exact: true }).first()).toBeVisible();
    if (expirationState === 'expired') {
      await tool.getByRole('button', { name: 'Copy result image' }).click();
      await expect(tool.getByText('Copied TLS certificate result image to clipboard.', { exact: true })).toBeVisible({ timeout: 15000 });
      const png = await page.evaluate(async () => {
        const items = await navigator.clipboard.read();
        const item = items.find((entry) => entry.types.includes('image/png'));
        if (!item) throw new Error('TLS clipboard contains no PNG');
        const blob = await item.getType('image/png');
        const bitmap = await createImageBitmap(blob);
        const details = { size: blob.size, width: bitmap.width, height: bitmap.height };
        bitmap.close();
        await navigator.clipboard.writeText('');
        return details;
      });
      expect(png.size).toBeGreaterThan(0);
      expect(png.width).toBeGreaterThan(0);
      expect(png.height).toBeGreaterThan(0);
    }
  });
}

test('TLS normalizes the host and renders issuer, expiry, trust and warnings', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/tls-check', tlsResponse, payload);
  const tool = await openTool(page, 'TLS cert checker', 'TLS/SSL certificate checker');
  await expect(tool.getByRole('button', { name: 'Check certificate' })).toBeDisabled();
  await tool.getByRole('textbox', { name: 'Hostname' }).fill('https://EXAMPLE.com/path');
  await tool.getByRole('button', { name: 'Check certificate' }).click();
  await expect(tool.getByRole('textbox', { name: 'Hostname' })).toHaveValue('example.com');
  await expect(tool.getByText('The certificate is trusted by the default trust store.', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('The certificate expires in 7 days.', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('Fixture Intermediate CA', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('2026-10-15T00:00:00.000Z', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('TLSv1.3', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('The chain certificate 2 uses a weak signature algorithm: sha1WithRSAEncryption.', { exact: true }).first()).toBeVisible();
  expect(requests).toEqual([payload]);
});

test('TLS displays backend error code and message', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/tls-check', tlsFailure, payload, 502);
  const tool = await openTool(page, 'TLS cert checker', 'TLS/SSL certificate checker');
  await tool.getByRole('textbox', { name: 'Hostname' }).fill('example.com');
  await tool.getByRole('button', { name: 'Check certificate' }).click();
  await expect(tool.getByText(tlsFailure.error.code, { exact: true })).toBeVisible();
  await expect(tool.getByText(tlsFailure.error.message, { exact: true })).toBeVisible();
  await expect(tool.getByRole('button', { name: 'Check certificate' })).toBeEnabled();
  expect(requests).toEqual([payload]);
});

for (const failure of [
  { status: 429, code: 'RATE_LIMITED', message: 'Too many TLS checks were requested recently. Try again later.' },
  { status: 503, code: 'TLS_CAPACITY_EXHAUSTED', message: 'TLS checker is busy. Try again later.' },
  { status: 504, code: 'TLS_DIAGNOSTIC_TIMEOUT', message: 'TLS diagnostic timed out.' },
]) {
  test(`TLS displays ${failure.code} and recovers on retry`, async ({ page }) => {
    await mockApi(page, '/api/tools/tls-check', {
      ok: false, error: { code: failure.code, message: failure.message },
    }, payload, failure.status);
    const tool = await openTool(page, 'TLS cert checker', 'TLS/SSL certificate checker');
    await tool.getByRole('textbox', { name: 'Hostname' }).fill('example.com');
    await tool.getByRole('button', { name: 'Check certificate' }).click();
    await expect(tool.getByText(failure.code, { exact: true })).toBeVisible();
    await expect(tool.getByText(failure.message, { exact: true })).toBeVisible();
    await expect(tool.getByRole('button', { name: 'Check certificate' })).toBeEnabled();
    await mockApi(page, '/api/tools/tls-check', tlsResponse, payload);
    await tool.getByRole('button', { name: 'Check certificate' }).click();
    await expect(tool.getByText(failure.code, { exact: true })).toHaveCount(0);
    await expect(tool.getByText('TLSv1.3', { exact: true }).first()).toBeVisible();
  });
}
