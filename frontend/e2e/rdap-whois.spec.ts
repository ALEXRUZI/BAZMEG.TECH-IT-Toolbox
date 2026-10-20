import { test, expect, openTool, field, mockApi } from './fixtures/test';
import { registrationFixture as fixture, resourceFixture, mixedRoleFixture } from './fixtures/rdap';
import { readFile } from 'node:fs/promises';
import { normalizedExport } from '../src/tools/rdap-whois/rdapHelpers';
import type { JsonValue } from '../src/tools/rdap-whois/rdapTypes';
import type { Locator } from '@playwright/test';

const section = (tool: Locator, title: string, includeHidden = false) => tool.locator('section').filter({ has: tool.page().getByRole('heading', { name: title, exact: true, includeHidden }) }).last();

for (const kind of ['ipv4', 'ipv6', 'asn'] as const) for (const known of [true, false]) test(`${kind} overview preserves ${known ? 'known' : 'unknown'} registry evidence and kind-specific image export`, async ({ page }) => {
  const result = resourceFixture(kind, known);
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: result.input.canonical, protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill(result.input.canonical); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(section(tool, 'Registration overview')).toContainText(known ? 'ARIN' : 'Unavailable / unknown');
  await expect(tool.getByRole('button', { name: 'Copy Registrar', exact: true })).toHaveCount(0);
  await expect(tool.getByRole('button', { name: 'Copy Nameservers', exact: true })).toHaveCount(0);
  await expect(section(tool, 'Registration overview')).toContainText(kind === 'asn' ? 'ASN name' : 'Network name');
  await expect(section(tool, 'Registration overview').getByRole('button')).toHaveCount(0);
  await expect(tool.getByRole('heading', { name: /Domain registrant|^Registrar$|Additional information/ })).toHaveCount(0);
  const capture = tool.locator('[aria-hidden="true"][style]');
  for (const value of [known ? 'ARIN' : 'Unavailable / unknown', result.source, '2026-10-14 12:00:00.000 UTC', 'Conflicting / ambiguous; see detailed evidence']) await expect(capture).toContainText(value);
  await expect(capture).not.toContainText('preserved');
  await expect(capture.locator('pre, details')).toHaveCount(0);
  await tool.getByText('Raw responses', { exact: true }).click(); await expect(tool.locator('pre:visible').last()).toHaveText(result.rawResponses[0].text);
  const download = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download normalized JSON' }).click(); expect((await download).suggestedFilename()).toBe('registration-normalized.json');
});

test('activated registration tool validates IDN and displays structured, safely rendered raw results', async ({ page }) => {
  const payload = { target: 'example.com', protocolMode: 'auto' };
  const requests = await mockApi(page, '/api/tools/rdap-lookup', fixture, payload);
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await expect(field(tool, 'Protocol mode', 'combobox')).toHaveValue('auto');
  await field(tool, 'Registration identifier').fill('https://example.com'); await expect(tool.getByRole('button', { name: 'Lookup', exact: true })).toBeDisabled();
  await field(tool, 'Registration identifier').fill('bücher.de'); await expect(tool.getByText('domain: xn--bcher-kva.de', { exact: true })).toBeVisible();
  await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByText('Fixture Registrar', { exact: true }).first()).toBeVisible();
  await expect(tool.getByRole('button', { name: 'Copy result image' })).toBeVisible();
  await tool.getByText('Contacts, events, DNSSEC, notices and unknown fields', { exact: true }).and(tool.locator('summary')).click();
  await expect(tool.locator('pre:visible').first()).toContainText('<script>untrusted notice</script>');
  await expect(tool.locator('script')).toHaveCount(0); await expect(tool.locator('a[href^="javascript:"]')).toHaveCount(0);
  await tool.getByText('Raw responses', { exact: true }).click(); await expect(tool.locator('pre:visible').last()).toHaveText(fixture.rawResponses[0].text);
  const rawDownload = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download raw RDAP', exact: true }).click(); expect((await rawDownload).suggestedFilename()).toBe('registration-1.json');
  const normalizedDownload = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download normalized JSON' }).click(); expect((await normalizedDownload).suggestedFilename()).toBe('registration-normalized.json');
  const metadataDownload = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download raw with metadata' }).click(); expect((await metadataDownload).suggestedFilename()).toBe('registration-raw-with-metadata.json');
  await tool.getByRole('button', { name: 'Reset', exact: true }).click(); await expect(tool.getByRole('button', { name: 'Download normalized JSON' })).toHaveCount(0); expect(requests).toEqual([payload]);
});
for (const protocolMode of ['rdap', 'whois'] as const) test(`forced ${protocolMode} submits only the selected mode and displays actual protocol`, async ({ page }) => {
  const result = { ...fixture, input: { ...fixture.input, protocolMode }, protocol: protocolMode,
    ...(protocolMode === 'whois' ? { source: 'whois://registry.example.org:43/', rawResponses: [{ ...fixture.rawResponses[0], protocol: 'whois', text: 'Domain Name: EXAMPLE.COM\r\nRegistrar: Fixture Registrar\r\n' }] } : {}) };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await field(tool, 'Protocol mode', 'combobox').selectOption(protocolMode);
  await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(section(tool, 'Lookup metadata').getByText(protocolMode === 'rdap' ? 'RDAP-only' : 'WHOIS-only', { exact: true })).toBeVisible();
  await expect(section(tool, 'Lookup metadata').getByText(protocolMode.toUpperCase(), { exact: true })).toBeVisible();
  await tool.getByText('Raw responses', { exact: true }).click(); await expect(tool.locator('pre:visible').last()).toHaveText(result.rawResponses[0].text);
});
for (const [status, code] of [[429, 'UPSTREAM_RATE_LIMITED'], [504, 'DEADLINE_EXHAUSTED'], [400, 'SECURITY_REJECTION'], [502, 'MALFORMED_REPLY']] as const) test(`${code} preserves attempted protocol diagnostics and allows retry`, async ({ page }) => {
  let calls = 0;
  await page.route('**/api/tools/rdap-lookup', async (route) => { calls++; await route.fulfill({ status: calls === 1 ? status : 200, json: calls === 1 ? { ok: false, error: { code, message: 'Fixture registration failure.' }, attempts: [{ ...fixture.attempts[1], outcome: code }], rawResponses: [] } : fixture }); });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('alert')).toContainText(code); await tool.getByText('Protocol attempts', { exact: true }).click(); await expect(tool.locator('pre:visible')).toContainText(code);
  await tool.getByRole('button', { name: 'Lookup', exact: true }).click(); await expect(tool.getByRole('button', { name: 'Download normalized JSON' })).toBeVisible(); await expect(tool.getByRole('alert')).toHaveCount(0);
});
test('fallback, cache age, valid not-found and unfamiliar WHOIS replies stay distinct', async ({ page }) => {
  let calls = 0;
  await page.route('**/api/tools/rdap-lookup', async (route) => { calls++; await route.fulfill({ json: { ...fixture, protocol: 'whois', fallbackReason: 'UNSUPPORTED_DISCOVERY', cache: { cached: true, ageSeconds: 12, ttlSeconds: 60 }, outcome: calls === 1 ? 'not_found' : 'unknown', normalized: { ...fixture.normalized, outcome: calls === 1 ? 'not_found' : 'unknown', fields: {} } } }); });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByText('No matching registration record (not purchase availability)', { exact: true }).first()).toBeVisible(); await expect(tool.getByText('Cached result · 12.0 seconds old; TTL 60s', { exact: true }).first()).toBeVisible();
  await expect(tool.getByText('UNSUPPORTED_DISCOVERY', { exact: true }).first()).toBeVisible();
  await tool.getByRole('button', { name: 'Lookup', exact: true }).click(); await expect(tool.getByText('Unrecognized or conflicting WHOIS reply; inspect raw text', { exact: true }).first()).toBeVisible();
  await expect(tool.getByRole('heading', { name: 'Registration status could not be determined', exact: true })).toBeVisible();
  await expect(tool.getByRole('heading', { name: 'Registration overview', exact: true })).toHaveCount(0);
});

for (const protocol of ['rdap', 'whois'] as const) test(`${protocol} domain negative preserves diagnostics, global exports and a concise real PNG`, async ({ page }) => {
  const rawText = protocol === 'whois' ? 'Domain not found.\r\n' : '{"errorCode":404,"description":["No domain record"]}';
  const source = protocol === 'whois' ? 'whois://whois.sk-nic.sk:43' : 'https://registry.example.org/domain/notregistered.sk';
  const result = { ...fixture, protocol, source, outcome: 'not_found' as const, input: { ...fixture.input, canonical: 'notregistered.sk' },
    normalized: { ...fixture.normalized, outcome: 'not_found' as const, fields: {}, details: { unparsed: [rawText] }, conflicts: [] },
    rawResponses: [{ ...fixture.rawResponses[0], protocol: 'whois' as const, phase: 'discovery', source: 'whois://whois.iana.org:43', text: 'domain: SK\nwhois: whois.sk-nic.sk\n' }, { ...fixture.rawResponses[0], protocol, source, text: rawText }] };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'notregistered.sk', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('notregistered.sk'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'No registration record found', exact: true })).toBeVisible();
  for (const title of ['Registration overview', 'Domain registrant', 'Registrar', 'Additional information']) await expect(tool.getByRole('heading', { name: title, exact: true })).toHaveCount(0);
  const capture = tool.locator('[aria-hidden="true"][style]');
  for (const root of [tool, capture]) {
    await expect(root).toContainText('A missing registration record does not guarantee domain purchase or registration availability.');
    await expect(root).toContainText(source); await expect(root).not.toContainText('Unavailable');
  }
  await expect(capture).toContainText('No registration record found'); await expect(capture).toContainText('BAZMEG.TECH IT Toolbox');
  await expect(capture.locator('pre, details, button')).toHaveCount(0);
  await tool.getByText('Contacts, events, DNSSEC, notices and unknown fields', { exact: true }).and(tool.locator('summary')).click();
  await expect(tool.locator('pre:visible').first()).toContainText('unparsed');
  await tool.getByText('Raw responses', { exact: true }).click(); await expect(tool.locator('pre:visible').last()).toHaveText(rawText);
  for (const [button, expected] of [['Download normalized JSON', normalizedExport(result)], ['Download raw with metadata', result]] as const) {
    const pending = page.waitForEvent('download'); await tool.getByRole('button', { name: button, exact: true }).click();
    const path = await (await pending).path(); const downloaded = JSON.parse(await readFile(path!, 'utf8'));
    if (button === 'Download normalized JSON') expect(downloaded).toEqual(expected);
    else expect(downloaded.rawResponses).toEqual(result.rawResponses);
  }
  const pending = page.waitForEvent('download'); await tool.getByRole('button', { name: `Download raw ${protocol.toUpperCase()}`, exact: true }).last().click();
  expect(await readFile((await (await pending).path())!, 'utf8')).toBe(rawText);
  try {
    await tool.getByRole('button', { name: 'Copy structured result', exact: true }).click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify(normalizedExport(result), null, 2));
    await tool.getByRole('button', { name: 'Copy result image', exact: true }).click();
    await expect(tool.getByText('Copied registration result image.', { exact: true })).toBeVisible({ timeout: 15000 });
    const png = await page.evaluate(async () => {
      const item = (await navigator.clipboard.read()).find((value) => value.types.includes('image/png'))!;
      const blob = await item.getType('image/png'); const bitmap = await createImageBitmap(blob);
      const result = { size: blob.size, width: bitmap.width, height: bitmap.height }; bitmap.close(); return result;
    });
    expect(png.size).toBeGreaterThan(0); expect(png.width).toBeGreaterThan(0); expect(png.height).toBeGreaterThan(0);
  } finally { await page.evaluate(() => navigator.clipboard.writeText('')).catch(() => {}); }
});
test('cancellation returns control and permits recovery', async ({ page }) => {
  let calls = 0, release: (() => void) | undefined;
  await page.route('**/api/tools/rdap-lookup', async (route) => { calls++; if (calls === 1) await new Promise<void>((resolve) => { release = resolve; }); await route.fulfill({ json: fixture }).catch(() => {}); });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect.poll(() => calls).toBe(1); await tool.getByRole('button', { name: 'Cancel lookup' }).click(); await expect(tool.getByRole('alert')).toContainText('cancelled'); release?.();
  await tool.getByRole('button', { name: 'Lookup', exact: true }).click(); await expect(tool.getByRole('button', { name: 'Download normalized JSON' })).toBeVisible();
});

test('copies complete structured data but exports only the branded overview and warnings in a real PNG locally', async ({ page }) => {
  await mockApi(page, '/api/tools/rdap-lookup', fixture, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup');
  await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  try {
    await expect(section(tool, 'Registration overview').getByRole('button')).toHaveCount(0);
    await tool.getByRole('button', { name: 'Copy structured result', exact: true }).click();
    await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe(JSON.stringify(normalizedExport(fixture), null, 2));
    const capture = tool.locator('[aria-hidden="true"][style]');
    for (const value of ['BAZMEG.TECH IT Toolbox', 'toolbox.bazmeg.tech', 'Lookup metadata', 'Registration overview', 'Additional information', 'ns1.example.com', fixture.input.canonical, fixture.source, '2026-10-14 12:00:00.000 UTC', 'RDAP', 'Fixture Registrar', 'Domain registrant', 'ORG-42 (Organization ID)', '1234 (IANA ID)', 'DS Record #1', '13 — ECDSA P-256 / SHA-256', '2 — SHA-256', 'C988EC423E3880EB8DD8A46FE06CA230EE23F35B578D64E78B29C3E1C83D245A', fixture.warnings[0]]) await expect(capture).toContainText(value);
    for (const title of ['All published fields and registry evidence', 'Registration status codes and explanations', 'Contacts, events, DNSSEC, notices and unknown fields', 'Discovery freshness and normalized JSON', 'Protocol attempts', 'Raw responses']) {
      const details = tool.locator('details').filter({ has: page.locator('summary').getByText(title, { exact: true }) });
      await details.locator('summary').click();
      await expect(details).toHaveAttribute('open', '');
      await expect(details.locator('pre, dl').first()).toBeVisible();
      await expect(capture).not.toContainText(title);
    }
    for (const value of ['Detailed information', 'Discovery and protocol attempts', 'untrusted notice', 'objectClassName', 'ICANN EPP/RDAP definitions']) await expect(capture).not.toContainText(value);
    await expect(capture.locator('button, pre, details, summary')).toHaveCount(0);
    expect(await capture.evaluate((element) => element.firstElementChild?.firstElementChild?.lastElementChild?.textContent)).toBe(fixture.warnings.join(' '));
    await tool.getByRole('button', { name: 'Copy result image', exact: true }).click();
    await expect(tool.getByText('Copied registration result image.', { exact: true })).toBeVisible({ timeout: 15000 });
    const png = await page.evaluate(async () => {
      const items = await navigator.clipboard.read(); const item = items.find((value) => value.types.includes('image/png'));
      if (!item) throw new Error('Fixture export has no PNG');
      const blob = await item.getType('image/png'); const bitmap = await createImageBitmap(blob);
      const dimensions = { size: blob.size, width: bitmap.width, height: bitmap.height }; bitmap.close(); return dimensions;
    });
    expect(png.size).toBeGreaterThan(0); expect(png.width).toBeGreaterThan(0); expect(png.height).toBeGreaterThan(0);
  } finally { await page.evaluate(() => navigator.clipboard.writeText('')).catch(() => {}); }
});

test('narrow-screen lookup retains labels, long-source wrapping and scrollable raw results', async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 800 });
  const digest = 'ABCD'.repeat(64), nameserver = `${'n'.repeat(63)}.${'s'.repeat(63)}.${'x'.repeat(63)}.example.com`;
  const result = { ...fixture, source: `https://registry.example.org/${'path'.repeat(80)}`, normalized: { ...fixture.normalized, fields: { ...fixture.normalized.fields, Nameservers: [nameserver, 'ns2.example.com'] }, details: { ...fixture.normalized.details, dnssec: { delegationSigned: true, dsData: [{ keyTag: 2371, algorithm: 13, digestType: 2, digest }, { keyTag: 99, algorithm: 250, digestType: 251, digest: 'ABCD' }] } } } };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('button', { name: 'Download normalized JSON' })).toBeVisible();
  const info = section(tool, 'Additional information');
  await expect(info.getByText(digest, { exact: true })).toHaveText(digest);
  await expect(info.getByText(nameserver, { exact: true })).toBeVisible();
  await expect(info.getByText('DS Record #2', { exact: true })).toBeVisible();
  await expect(info.getByText('250', { exact: true })).toBeVisible();
  expect(await info.getByText(digest, { exact: true }).evaluate((element) => element.scrollWidth <= element.clientWidth)).toBe(true);
  await tool.getByText('Raw responses', { exact: true }).click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
});

test('metadata precedes the overview and expiration is automatic and fixed at lookup completion without extra requests', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2029-12-31T00:00:00Z'));
  const requests = await mockApi(page, '/api/tools/rdap-lookup', fixture, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  const metadata = section(tool, 'Lookup metadata'), overview = section(tool, 'Registration overview');
  for (const value of ['Auto', 'RDAP', fixture.source, '2026-10-14 12:00:00.000 UTC', 'Fresh lookup', 'None', 'Registration record']) await expect(metadata.getByText(value, { exact: true })).toBeVisible();
  expect(await metadata.evaluate((element) => element.nextElementSibling?.querySelector('h4')?.textContent)).toBe('Registration overview');
  await expect(overview.getByText('1.00 days remaining (display rounded)', { exact: true })).toBeVisible();
  await expect(tool.getByRole('button', { name: 'Calculate expiration remaining' })).toHaveCount(0);
  await expect(tool.getByText('Expiration calculated at', { exact: true })).toHaveCount(0);
  await expect(overview.getByRole('button')).toHaveCount(0);
  await expect(section(tool, 'Domain registrant').getByText('Redacted', { exact: true })).toBeVisible();
  for (const value of ['Fixture Holder', 'ORG-42 (Organization ID)', 'owner@example.org', 'other@example.org']) await expect(section(tool, 'Domain registrant').getByText(value, { exact: true })).toBeVisible();
  await expect(section(tool, 'Registrar').getByText('1234 (IANA ID)', { exact: true })).toBeVisible();
  await expect(section(tool, 'Registrar').getByText('Unavailable', { exact: true })).toBeVisible();
  await page.clock.setFixedTime(new Date('2031-01-01T00:00:00Z'));
  await field(tool, 'Registration identifier').fill('changed.example');
  await expect(overview.getByText('1.00 days remaining (display rounded)', { exact: true })).toBeVisible();
  expect(requests).toHaveLength(1);
});

for (const [label, data, expected] of [
  ['unsigned', { delegationSigned: false }, 'Unsigned delegation reported'],
  ['signed without DS records', { delegationSigned: true }, 'Signed delegation reported'],
  ['absent', null, null],
  ['malformed', { delegationSigned: 'false', dsData: [null] }, 'Unrecognized or malformed DNSSEC fields'],
] as [string, JsonValue, string | null][]) test(`DNSSEC ${label} stays honest`, async ({ page }) => {
  const result = { ...fixture, normalized: { ...fixture.normalized, details: { ...fixture.normalized.details, dnssec: data } } };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  await expect(tool.getByRole('heading', { name: 'Registration overview', exact: true })).toBeVisible();
  const info = section(tool, 'Additional information');
  if (expected) await expect(info).toContainText(expected); else await expect(info.getByRole('heading', { name: 'Published DNSSEC' })).toHaveCount(0);
  await expect(info.getByRole('heading', { name: /DS Record/ })).toHaveCount(0);
});

test('WHOIS contacts and status-only DNSSEC preserve unknowns and conflicting registrar codes', async ({ page }) => {
  const result = { ...fixture, protocol: 'whois', normalized: { ...fixture.normalized, fields: { Domain: ['example.com'], 'Registrant name': ['Redacted'], Registrar: ['Registrar One', 'Registrar Two'], 'Registrar code': ['1234 (IANA ID)', '5678 (IANA ID)', 'REG-9 (Registrar ID; system unspecified)'], 'Abuse email': ['abuse@example.org'], 'Published DNSSEC': ['signedDelegation'] }, details: {} } };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  for (const value of result.normalized.fields['Registrar code']) await expect(section(tool, 'Registrar').getByText(value, { exact: true })).toBeVisible();
  await expect(section(tool, 'Registrar')).not.toContainText('abuse@example.org');
  await expect(section(tool, 'Registrar').getByText('Unavailable', { exact: true })).toHaveCount(3);
  await expect(section(tool, 'Domain registrant').getByText('Unavailable', { exact: true })).toHaveCount(4);
  await expect(section(tool, 'Additional information').getByText('signedDelegation', { exact: true })).toBeVisible();
  await expect(section(tool, 'Additional information').getByRole('heading', { name: /DS Record/ })).toHaveCount(0);
});

for (const [digestType, bytes] of [[1, 20], [2, 32], [3, 32], [4, 48], [251, 2]]) for (const validLength of [true, false]) test(`DNSSEC type ${digestType} retains ${validLength ? 'exact' : 'short'} digest and warns only for known invalid lengths`, async ({ page }) => {
  const digest = 'aB'.repeat(validLength ? bytes : bytes - 1);
  const dnssec = { delegationSigned: true, dsData: [{ keyTag: 1, algorithm: 13, digestType, digest }] };
  const result = { ...fixture, normalized: { ...fixture.normalized, details: { ...fixture.normalized.details, dnssec } } };
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  const info = section(tool, 'Additional information');
  await expect(info.getByText(digest, { exact: true })).toHaveText(digest);
  await expect(info.getByRole('heading', { name: 'DS Record #1', exact: true })).toBeVisible();
  await expect(info.getByText(/Unrecognized or malformed DNSSEC/)).toHaveCount(!validLength && digestType !== 251 ? 1 : 0);
  const capture = tool.locator('[aria-hidden="true"][style]');
  await expect(capture).toContainText(digest);
  const download = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download normalized JSON' }).click();
  const path = await (await download).path();
  expect(JSON.parse(await readFile(path!, 'utf8')).normalized.details.dnssec).toEqual(dnssec);
});

for (const roles of [['registrant', 'registrar'], ['registrant', 'registrar', 'abuse'], ['registrar', 'technical', 'registrant'], ['registrant', 'registrar', 'abuse', 'technical']]) test(`mixed roles ${roles.join('/')} stay in evidence, not both overview cards`, async ({ page }) => {
  const result = mixedRoleFixture(roles);
  await mockApi(page, '/api/tools/rdap-lookup', result, { target: 'example.com', protocolMode: 'auto' });
  const tool = await openTool(page, 'RDAP / WHOIS Lookup'); await field(tool, 'Registration identifier').fill('example.com'); await tool.getByRole('button', { name: 'Lookup', exact: true }).click();
  for (const root of [tool, tool.locator('[aria-hidden="true"][style]')]) for (const title of ['Domain registrant', 'Registrar']) {
    const card = section(root, title, root !== tool);
    for (const value of ['Shared Name', 'Shared Org', 'shared@example.org', 'tel:+1-555-0999']) await expect(card).not.toContainText(value);
    await expect(card).toContainText(title === 'Registrar' ? 'Known Registrar' : 'Known Holder');
    await expect(card).toContainText(title === 'Registrar' ? 'registrar@example.org' : 'holder@example.org');
  }
  const evidence = tool.locator('details').filter({ has: page.getByText('Contacts, events, DNSSEC, notices and unknown fields', { exact: true }).and(page.locator('summary')) });
  await evidence.locator('summary').click();
  await expect(evidence.locator('pre')).toContainText('shared@example.org');
  const raw = tool.locator('details').filter({ has: page.getByText('Raw responses', { exact: true }).and(page.locator('summary')) });
  await raw.locator('summary').click();
  await expect(raw.locator('pre')).toHaveText(result.rawResponses[0].text);
  const download = page.waitForEvent('download'); await tool.getByRole('button', { name: 'Download normalized JSON' }).click();
  const path = await (await download).path();
  expect(JSON.parse(await readFile(path!, 'utf8'))).toEqual(normalizedExport(result));
});
