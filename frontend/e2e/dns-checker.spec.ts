import { test, expect, openTool, field, mockApi, copyText } from './fixtures/test';
import { dnsFailure, dnsResponse } from './fixtures/responses';
import { createDnsContractFixtures, createTxtContractFixture, normalizeFixtureRequest } from '../../backend/test/fixtures/dns-contracts.mjs';

const payload = { mode: 'single', recordType: 'A', resolverId: 'cloudflare', dnssec: true, query: 'example.com' };

test('DNS submits the real payload and switches views without another request', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/dns-check', dnsResponse, payload);
  const tool = await openTool(page, 'DNS checker');
  await expect(tool.getByRole('button', { name: 'Run DNS Check' })).toBeDisabled();
  await field(tool, 'Domain/FQDN').fill('example.com');
  await tool.getByRole('button', { name: 'Run DNS Check' }).click();
  await expect(tool.getByRole('heading', { name: 'Main records', exact: true })).toBeVisible();
  await expect(tool.getByText('93.184.216.34', { exact: false }).first()).toBeVisible();
  await tool.getByRole('button', { name: 'advanced', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Query', exact: true })).toBeVisible();
  await tool.getByRole('button', { name: 'raw', exact: true }).click();
  await expect(tool.locator('pre:visible')).toHaveText(JSON.stringify(dnsResponse, null, 2));
  await copyText(page, tool, JSON.stringify(dnsResponse, null, 2));
  await tool.getByRole('button', { name: 'simple', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Main records', exact: true })).toBeVisible();
  expect(requests).toEqual([payload]);
});

test('DNS displays backend failures and allows retry', async ({ page }) => {
  const requests = await mockApi(page, '/api/tools/dns-check', dnsFailure, payload, 429);
  const tool = await openTool(page, 'DNS checker');
  await field(tool, 'Domain/FQDN').fill('example.com');
  await tool.getByRole('button', { name: 'Run DNS Check' }).click();
  await expect(tool.getByText('Rate limit reached. Too many live DNS checks were made recently. Please try again later. Cached DNS results may still be available for repeated checks.', { exact: true })).toBeVisible();
  await expect(tool.getByRole('button', { name: 'Run DNS Check' })).toBeEnabled();
  await expect(tool.getByRole('button', { name: 'Copy result image' })).toHaveCount(0);
  expect(requests).toEqual([payload]);
});

for (const [code, status, message] of [
  ['INVALID_QUERY', 400, 'Enter a valid public DNS name.'],
  ['DNS_CAPACITY_EXHAUSTED', 503, 'DNS checks are busy. Please try again later.'],
  ['DNS_DIAGNOSTIC_TIMEOUT', 504, 'DNS diagnostic timed out.'],
  ['DNS_CHECK_CANCELLED', 499, 'DNS check was cancelled.'],
] as const) {
  test(`DNS recovers from ${code} without staying in loading state`, async ({ page }) => {
    let attempts = 0;
    await page.route('**/api/tools/dns-check', async (route) => {
      expect(route.request().postDataJSON()).toEqual(payload);
      attempts++;
      await route.fulfill({ status: attempts === 1 ? status : 200, contentType: 'application/json',
        body: JSON.stringify(attempts === 1 ? { ok: false, error: { code, message } } : dnsResponse) });
    });
    const tool = await openTool(page, 'DNS checker');
    await field(tool, 'Domain/FQDN').fill('example.com');
    const run = tool.getByRole('button', { name: 'Run DNS Check' });
    await run.click();
    await expect(tool.getByText(message, { exact: true })).toBeVisible();
    await expect(run).toBeEnabled();
    await run.click();
    await expect(tool.getByRole('heading', { name: 'Main records', exact: true })).toBeVisible();
    await expect(run).toBeEnabled();
    expect(attempts).toBe(2);
  });
}

for (const [key, label] of [
  ['timeout', 'Timeout'], ['resolverError', 'Resolver error'], ['incomplete', 'Incomplete (truncated UDP response)'],
  ['formerr', 'FORMERR (query format error)'], ['notimp', 'NOTIMP (not implemented)'], ['nxdomain', 'NXDOMAIN'],
] as const) {
  test(`DNS displays actual backend ${key} diagnostic, raw response and image summary then retries`, async ({ page }) => {
    const fixtures = await createDnsContractFixtures();
    let attempts = 0;
    await page.route('**/api/tools/dns-check', async (route) => {
      expect(route.request().postDataJSON()).toEqual(payload);
      await route.fulfill({ json: ++attempts === 1 ? fixtures[key] : fixtures.success });
    });
    const tool = await openTool(page, 'DNS checker');
    await tool.getByRole('textbox', { name: 'Domain/FQDN' }).fill('example.com');
    const run = tool.getByRole('button', { name: 'Run DNS Check' });
    await run.click();
    await expect(tool.getByText(label, { exact: true }).first()).toBeVisible();
    await expect(run).toBeEnabled();
    const image = tool.locator('[aria-hidden="true"]');
    await expect(image.getByText(label, { exact: true })).toHaveCount(key === 'nxdomain' ? 2 : 1);
    await tool.getByRole('button', { name: 'advanced', exact: true }).click();
    await expect(tool.getByRole('heading', { name: 'Resolver metadata' })).toBeVisible();
    await tool.getByRole('button', { name: 'raw', exact: true }).click();
    await expect(tool.locator('pre:visible')).toHaveText(JSON.stringify(fixtures[key], null, 2));
    await run.click();
    await tool.getByRole('button', { name: 'simple', exact: true }).click();
    await expect(tool.getByText('OK', { exact: true }).first()).toBeVisible();
    expect(attempts).toBe(2);
  });
}

test('DNS burst keeps failed and incomplete providers visible with accurate export badges', async ({ page }) => {
  const fixtures = await createDnsContractFixtures();
  await mockApi(page, '/api/tools/dns-check', fixtures.burst, { mode: 'burst', recordType: 'A', query: 'example.com' });
  const tool = await openTool(page, 'DNS checker');
  await tool.getByRole('button', { name: 'Burst / Multi-Provider DNS Comparison' }).click();
  await tool.getByRole('textbox', { name: 'Domain/FQDN' }).fill('example.com');
  await tool.getByRole('button', { name: 'Run DNS Check' }).click();
  await expect(tool.getByText('Incomplete provider comparison', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('The resolver returned an error.', { exact: true }).first()).toBeVisible();
  await expect(tool.getByRole('heading', { name: 'Provider comparison' }).locator('..').getByRole('article')).toHaveCount(10);
  await expect(tool.locator('span.w-fit.text-amber-100')).toHaveCount(4);
});

for (const [helper, input, expected] of [
  ['normal', '_dmarc.example.com', '_dmarc.example.com'], ['spf', 'example.com', 'example.com'],
  ['dmarc', 'example.com', '_dmarc.example.com'], ['dmarc', '_dmarc.example.com', '_dmarc.example.com'],
  ['dkim', 'example.com', 'selector_name._domainkey.example.com'],
  ['acme', '_acme-challenge.example.com', '_acme-challenge.example.com'],
] as const) {
  test(`DNS ${helper} TXT helper input ${input} submits ${expected} accepted by the backend`, async ({ page }) => {
    const tool = await openTool(page, 'DNS checker');
    await tool.getByRole('combobox', { name: 'Record type' }).selectOption('TXT');
    await tool.getByRole('combobox', { name: 'TXT helper' }).selectOption(helper);
    await tool.getByRole('textbox', { name: helper === 'dkim' ? 'Domain' : 'Domain/FQDN', exact: true }).fill(input);
    if (helper === 'dkim') await tool.getByRole('textbox', { name: 'Selector' }).fill('selector_name');
    let requests = 0;
    await page.route('**/api/tools/dns-check', async (route) => {
      const request = route.request().postDataJSON();
      expect(request).toEqual({ ...payload, recordType: 'TXT', query: expected });
      expect(normalizeFixtureRequest(request).query.queryName).toBe(expected);
      requests++;
      await route.fulfill({ json: await createTxtContractFixture(request) });
    });
    await tool.getByRole('button', { name: 'Run DNS Check' }).click();
    await expect(tool.getByText('offline TXT fixture', { exact: true }).first()).toBeVisible();
    expect(requests).toBe(1);
  });
}

test('DNS malformed payload reports a safe error and recovers on retry', async ({ page }) => {
  let attempts = 0;
  await page.route('**/api/tools/dns-check', async (route) => {
    await route.fulfill({ json: ++attempts === 1 ? { ok: false, error: { message: {} } } : dnsResponse });
  });
  const tool = await openTool(page, 'DNS checker');
  await tool.getByRole('textbox', { name: 'Domain/FQDN' }).fill('example.com');
  const run = tool.getByRole('button', { name: 'Run DNS Check' });
  await run.click();
  await expect(tool.getByText('DNS check returned an unexpected response. Please try again.')).toBeVisible();
  await expect(run).toBeEnabled();
  await run.click();
  await expect(tool.getByRole('heading', { name: 'Main records' })).toBeVisible();
});
