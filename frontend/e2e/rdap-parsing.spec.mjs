import { test, expect, openTool, field, mockApi } from './fixtures/test.ts';
import { registrationFixture } from './fixtures/rdap.ts';
import { readFileSync } from 'node:fs';
import { parseWhois } from '../../backend/src/tools/registration-parse.mjs';

const raw = readFileSync(new URL('../../backend/test/fixtures/registration/sknic-whois.txt', import.meta.url), 'utf8');
function parsedResult(text = raw, canonical = 'example.sk', source = 'whois://whois.sk-nic.sk:43') {
  const normalized = parseWhois(text, { kind: 'domain', canonical }, source);
  return { ...structuredClone(registrationFixture), input: { original: canonical, canonical, kind: 'domain', protocolMode: 'auto' }, protocol: 'whois', source,
    outcome: normalized.outcome, normalized, fallbackReason: 'UNSUPPORTED_DISCOVERY',
    attempts: [{ protocol: 'whois', phase: 'query', source, timestamp: registrationFixture.timestamp, outcome: normalized.outcome, status: 200 }],
    rawResponses: [{ protocol: 'whois', phase: 'query', source, timestamp: registrationFixture.timestamp, text }] };
}

test('hostile CZ.NIC NSSET fields stay out of the overview and PNG export while nameservers and raw evidence survive', async ({ page }) => {
  const text = readFileSync(new URL('../../backend/test/fixtures/registration/cznic-auxiliary-adversarial-whois.txt', import.meta.url), 'utf8');
  const result = parsedResult(text, 'example.cz', 'whois://whois.nic.cz:43');
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.cz', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('example.cz'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  const capture = tool.locator('[aria-hidden="true"][style]');
  await expect(capture).toContainText('Fixture Holder'); await expect(capture).toContainText('REG-TEST (Registry registrar ID)');
  await expect(capture).toContainText('ns1.example.test'); await expect(capture).toContainText('ns2.example.test');
  await expect(capture).toContainText('2030-01-01 (calendar date)');
  await expect(capture).not.toContainText(/Auxiliary|AUXILIARY|Keyset|KEYSET|9999|1997-/);
  await expect(tool.getByText('Conflicting fields:', { exact: false })).toHaveCount(0);
  await expect(tool.getByRole('heading', { name: 'Published DNSSEC', exact: true })).toHaveCount(0);
  await expect(capture.locator('button, pre, details')).toHaveCount(0);
  await tool.getByRole('button', { name: 'Copy result image', exact: true }).click();
  await expect(tool.getByText('Copied registration result image.', { exact: true })).toBeVisible({ timeout: 15000 });
  await tool.getByText('Raw responses', { exact: true }).click();
  await expect(tool.locator('pre:visible').last()).toHaveText(text);
});

test('actual SK-NIC parser output retains approved layout, calendar dates, role evidence and concise image export', async ({ page }) => {
  const result = parsedResult();
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.sk', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('example.sk'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByText('2003-06-10 (calendar date)', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('2027-06-10 (calendar date)', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('Calendar date only; exact expiration time and timezone unpublished', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('REG-TEST (Registry registrar ID)', { exact: true }).first()).toBeVisible();
  await expect(tool.getByRole('heading', { name: 'Domain registrant' })).toBeVisible();
  const capture = tool.locator('[aria-hidden="true"][style]');
  await expect(capture).toContainText('2003-06-10 (calendar date)'); await expect(capture).not.toContainText('2017-09-01');
  await expect(capture.locator('button, pre, details')).toHaveCount(0);
  await tool.getByText('All published fields and registry evidence', { exact: true }).click();
  await expect(tool.locator('details[open] pre').first()).toContainText('line:2');
  await expect(capture).not.toContainText('whois:0');
  await tool.getByRole('button', { name: 'Copy result image', exact: true }).click();
  await expect(tool.getByText('Copied registration result image.', { exact: true })).toBeVisible({ timeout: 15000 });
  await tool.getByText('Raw responses', { exact: true }).click();
  await expect(tool.locator('pre:visible').last()).toHaveText(raw);
});

test('conflicting SK-NIC expiration stays in raw evidence and never appears as a selected primary date or countdown', async ({ page }) => {
  const result = parsedResult(raw.replace('Valid Until:                  2027-06-10', 'Valid Until:                  2027-06-10\nValid Until:                  2030-06-10'));
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.sk', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('example.sk'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Registration status could not be determined', exact: true })).toBeVisible();
  await expect(tool.getByRole('heading', { name: 'Registration overview', exact: true })).toHaveCount(0);
  const capture = tool.locator('[aria-hidden="true"][style]');
  await expect(capture).not.toContainText('2030-06-10');
  await expect(capture).toContainText('Registration status could not be determined');
  await expect(capture).toContainText('Conflicting fields: Expires');
  await expect(capture.locator('button, pre, details')).toHaveCount(0);
  await tool.getByText('All published fields and registry evidence', { exact: true }).click();
  await expect(tool.locator('details[open] pre').first()).toContainText('2030-06-10');
  await tool.getByText('Raw responses', { exact: true }).click();
  await expect(tool.locator('pre:visible').last()).toHaveText(result.rawResponses[0].text);
});

test('actual SK-NIC exact negative parser output produces the domain not-found presentation', async ({ page }) => {
  const result = parsedResult('Domain not found.\r\n', 'notregistered.sk');
  expect(result.outcome).toBe('not_found');
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'notregistered.sk', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('notregistered.sk'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'No registration record found', exact: true })).toBeVisible();
  await expect(tool.locator('[aria-hidden="true"][style]')).toContainText('No registration record found');
  await tool.getByText('Raw responses', { exact: true }).click();
  await expect(tool.locator('pre:visible').last()).toHaveText('Domain not found.\r\n');
});
