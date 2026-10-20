import { test, expect, openTool, field, mockApi, copyText } from './fixtures/test';
import { httpFailure, httpResponse, httpSecurityResponse } from './fixtures/responses';

const payload = { target: 'example.com', protocolMode: 'auto' };

test('HTTP headers, redirect chain and local result views', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/http-header-check', httpResponse, payload);
  const tool = await openTool(page, 'HTTP Header Checker');
  await expect(tool.getByRole('button', { name: 'Check headers' })).toBeDisabled();
  await field(tool, 'Target').fill('example.com');
  await tool.getByRole('button', { name: 'Check headers' }).click();
  await expect(tool.getByRole('heading', { name: 'Missing HSTS', exact: true })).toBeVisible();
  await expect(tool.getByText('301 Moved Permanently', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('https://example.com/', { exact: true }).first()).toBeVisible();
  await tool.getByRole('button', { name: 'advanced', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Raw headers', exact: true })).toBeVisible();
  await expect(tool.locator('pre:visible')).toHaveText('content-type: text/html; charset=utf-8\nserver: fixture-server');
  await copyText(page, tool, 'content-type: text/html; charset=utf-8\nserver: fixture-server');
  await tool.getByRole('button', { name: 'raw', exact: true }).click();
  const { budget: _budget, ...publicResponse } = httpResponse;
  await expect(tool.locator('pre:visible')).toHaveText(JSON.stringify(publicResponse, null, 2));
  await tool.getByRole('button', { name: 'simple', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Security findings', exact: true })).toBeVisible();
  expect(requests).toEqual([payload]);
});

test('HTTP security warnings retain accurate wording and severity in every view', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/http-header-check', httpSecurityResponse, payload);
  const tool = await openTool(page, 'HTTP Header Checker');
  await field(tool, 'Target').fill('example.com');
  await tool.getByRole('button', { name: 'Check headers' }).click();
  for (const view of ['simple', 'advanced'] as const) {
    await tool.getByRole('button', { name: view, exact: true }).click();
    for (const finding of httpSecurityResponse.checks[0].findings) {
      const article = tool.getByRole('article').filter({ has: page.getByRole('heading', { name: finding.title, exact: true }) });
      await expect(article.getByText('warning', { exact: true })).toBeVisible();
      await expect(article).toHaveClass(/border-amber-300/);
      await expect(article).not.toHaveClass(/border-red-300/);
      await expect(article.getByText(finding.detail, { exact: true })).toBeVisible();
      await expect(article.getByText(finding.recommendation, { exact: true })).toBeVisible();
    }
    await expect(tool.getByText('critical', { exact: true })).toHaveCount(0);
    await expect(tool.getByRole('heading', { name: 'HSTS does not include subdomains', exact: true })).toHaveCount(0);
  }
  await tool.getByRole('button', { name: 'raw', exact: true }).click();
  const { budget: _budget, ...publicResponse } = httpSecurityResponse;
  await expect(tool.locator('pre:visible')).toHaveText(JSON.stringify(publicResponse, null, 2));
  expect(requests).toEqual([payload]);
});

test('HTTP checker displays backend failures', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/http-header-check', httpFailure, payload, 502);
  const tool = await openTool(page, 'HTTP Header Checker');
  await field(tool, 'Target').fill('example.com');
  await tool.getByRole('button', { name: 'Check headers' }).click();
  await expect(tool.getByText(httpFailure.error.message, { exact: true })).toBeVisible();
  await expect(tool.getByRole('button', { name: 'Check headers' })).toBeEnabled();
  expect(requests).toEqual([payload]);
});

for (const [status, code, message] of [
  [429, 'RATE_LIMITED', 'Too many HTTP header checks were requested recently. Try again later, or wait for the cached result to expire.'],
  [503, 'HTTP_CAPACITY_EXHAUSTED', 'HTTP header checks are busy. Try again later.'],
  [504, 'HTTP_DIAGNOSTIC_TIMEOUT', 'HTTP header diagnostic timed out.'],
] as const) {
  test(`HTTP ${status} clears loading and permits successful retry`, async ({ page }) => {
    const displayedMessage = code === 'RATE_LIMITED'
      ? 'Rate limit reached. Too many HTTP header checks were requested recently. Try again later.' : message;
    let calls = 0;
    await page.route('**/api/tools/http-header-check', async (route) => {
      expect(route.request().postDataJSON()).toEqual(payload);
      calls++;
      await route.fulfill({ status: calls === 1 ? status : 200,
        json: calls === 1 ? { ok: false, error: { code, message } } : httpResponse });
    });
    const tool = await openTool(page, 'HTTP Header Checker');
    await field(tool, 'Target').fill('example.com');
    await tool.getByRole('button', { name: 'Check headers' }).click();
    await expect(tool.getByText(displayedMessage, { exact: true })).toBeVisible();
    await expect(tool.getByRole('button', { name: 'Check headers' })).toBeEnabled();
    await tool.getByRole('button', { name: 'Check headers' }).click();
    await expect(tool.getByRole('heading', { name: 'Missing HSTS', exact: true })).toBeVisible();
    await expect(tool.getByText(displayedMessage, { exact: true })).toHaveCount(0);
    await expect(tool.getByRole('button', { name: 'Check headers' })).toBeEnabled();
    expect(calls).toBe(2);
  });
}
