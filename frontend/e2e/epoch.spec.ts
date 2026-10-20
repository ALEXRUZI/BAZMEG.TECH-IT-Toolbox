import { test as guardedTest, expect, field, openTool, copyText } from './fixtures/test';

const test = guardedTest.extend<{ javascriptErrors: string[] }>({
  javascriptErrors: [async ({ page }, use) => {
    const errors: string[] = [];
    page.on('pageerror', (error) => errors.push(error.message));
    await use(errors);
    expect(errors, 'Timestamp input must not cause unhandled JavaScript exceptions').toEqual([]);
  }, { auto: true }],
});

test.use({ timezoneId: 'UTC' });

for (const { unit, boundary, beyond, minimum, below } of [
  { unit: 'seconds', boundary: '8640000000000', beyond: '8640000000001', minimum: '-8640000000000', below: '-8640000000001' },
  { unit: 'milliseconds', boundary: '8640000000000000', beyond: '8640000000000001', minimum: '-8640000000000000', below: '-8640000000000001' },
]) {
  test(`Epoch handles ${unit} beyond the JavaScript Date range without crashing`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T00:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T00:00:00Z'));
    const panel = await openTool(page, 'Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion');
    await field(panel, 'Unit', 'combobox').selectOption(unit);
    const timestamp = field(panel, 'Unix timestamp');
    await timestamp.fill(boundary);
    await expect(panel.locator('pre').first()).toHaveText('13/09/275760 00:00:00\n+275760-09-13T00:00:00.000Z');
    await timestamp.fill(beyond);
    await expect(panel, 'Invalid timestamp must not unmount the toolbox').toBeVisible();
    const conversion = panel.getByRole('heading', { name: 'Timestamp to local time', exact: true }).locator('..');
    await expect(conversion.getByText('Unix timestamp is outside the supported date range.', { exact: true })).toBeVisible();
    await expect(conversion.locator('pre')).toHaveCount(0);
    await timestamp.fill(minimum);
    await expect(conversion.locator('pre')).toHaveText('20/04/-271821 00:00:00\n-271821-04-20T00:00:00.000Z');
    await timestamp.fill(below);
    await expect(conversion.getByText('Unix timestamp is outside the supported date range.', { exact: true })).toBeVisible();
    await expect(conversion.locator('pre')).toHaveCount(0);
    await timestamp.fill('0');
    await expect(conversion.locator('pre')).toHaveText('01/01/1970 00:00:00\n1970-01-01T00:00:00.000Z');
    await expect(conversion.getByText('Unix timestamp is outside the supported date range.', { exact: true })).toHaveCount(0);
    await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
    await expect(page.getByRole('article').locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
  });
}

for (const unit of ['seconds', 'milliseconds']) {
  test(`Epoch rejects invalid numeric input and recovers in ${unit}`, async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T00:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T00:00:00Z'));
    const panel = await openTool(page, 'Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion');
    await field(panel, 'Unit', 'combobox').selectOption(unit);
    const conversion = panel.getByRole('heading', { name: 'Timestamp to local time', exact: true }).locator('..');
    const timestamp = field(panel, 'Unix timestamp');
    for (const invalid of ['', 'not-a-number', 'NaN', 'Infinity', '-Infinity', '1e309']) {
      await timestamp.fill(invalid);
      await expect(conversion.getByText('Unix timestamp must be a number.', { exact: true })).toBeVisible();
      await expect(conversion.locator('pre')).toHaveCount(0);
      await expect(panel).toBeVisible();
    }
    await timestamp.fill('1e308');
    await expect(conversion.getByText('Unix timestamp is outside the supported date range.', { exact: true })).toBeVisible();
    await expect(conversion.locator('pre')).toHaveCount(0);
    await timestamp.fill(unit === 'seconds' ? '-1' : '-1000');
    await expect(conversion.locator('pre')).toHaveText('31/12/1969 23:59:59\n1969-12-31T23:59:59.000Z');
    await timestamp.fill(unit === 'seconds' ? '1704067200' : '1704067200000');
    await expect(conversion.locator('pre')).toHaveText('01/01/2024 00:00:00\n2024-01-01T00:00:00.000Z');
  });
}

test('Epoch unit switching revalidates, preserving formatting and clipboard results', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-01-01T00:00:00Z') });
  await page.clock.pauseAt(new Date('2026-01-01T00:00:00Z'));
  const panel = await openTool(page, 'Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion');
  const conversion = panel.getByRole('heading', { name: 'Timestamp to local time', exact: true }).locator('..');
  const timestamp = field(panel, 'Unix timestamp');
  const unit = field(panel, 'Unit', 'combobox');
  await timestamp.fill('8640000000000000');
  await expect(conversion.locator('pre')).toHaveCount(0);
  await expect(conversion.getByText('Unix timestamp is outside the supported date range.', { exact: true })).toBeVisible();
  await unit.selectOption('milliseconds');
  await expect(conversion.locator('pre')).toHaveText('13/09/275760 00:00:00\n+275760-09-13T00:00:00.000Z');
  await unit.selectOption('seconds');
  await expect(conversion.locator('pre')).toHaveCount(0);
  await timestamp.fill('1704198896');
  await expect(conversion.locator('pre')).toHaveText('02/01/2024 12:34:56\n2024-01-02T12:34:56.000Z');
  await panel.getByRole('button', { name: 'Use MM/DD/YYYY', exact: true }).click();
  await panel.getByRole('button', { name: 'Use 12-hour time', exact: true }).click();
  const expected = '01/02/2024 12:34:56 PM\n2024-01-02T12:34:56.000Z';
  await expect(conversion.locator('pre')).toHaveText(expected);
  await copyText(page, conversion, expected);
});

test.describe('Epoch local-date conversion in America/New_York', () => {
  test.use({ timezoneId: 'America/New_York' });

  test('leap-day input preserves its instant across display formats and live-clock ticks', async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T00:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T00:00:00Z'));
    const panel = await openTool(page, 'Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion');
    const conversion = panel.getByRole('heading', { name: 'Local time to timestamp', exact: true }).locator('..');
    const date = field(panel, 'Local date and time');
    await date.fill('29/02/2024 12:34:56');
    // EST is UTC-5: the independent expected instant is 2024-02-29T17:34:56Z.
    await expect(conversion.locator('pre')).toHaveText(['1709228096', '1709228096000']);
    await panel.getByRole('button', { name: 'Use MM/DD/YYYY', exact: true }).click();
    await expect(date).toHaveValue('02/29/2024 12:34:56');
    await panel.getByRole('button', { name: 'Use 12-hour time', exact: true }).click();
    await expect(date).toHaveValue('02/29/2024 12:34:56 PM');
    await expect(conversion.locator('pre')).toHaveText(['1709228096', '1709228096000']);
    await copyText(page, conversion.locator('pre').first().locator('..'), '1709228096');
    await page.clock.runFor(1000);
    await expect(panel.getByText('Unix seconds', { exact: true }).locator('..')).toContainText('1767225601');
    await expect(panel.getByText('Current local time', { exact: true }).locator('..')).toContainText('12/31/2025 07:00:01 PM');
  });

  test('rejects a nonexistent DST time and preserves native earlier-offset overlap handling', async ({ page }) => {
    await page.clock.install({ time: new Date('2026-01-01T00:00:00Z') });
    await page.clock.pauseAt(new Date('2026-01-01T00:00:00Z'));
    const panel = await openTool(page, 'Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion');
    const conversion = panel.getByRole('heading', { name: 'Local time to timestamp', exact: true }).locator('..');
    const date = field(panel, 'Local date and time');
    await date.fill('10/03/2024 02:30:00');
    await expect(conversion.getByText('Use DD/MM/YYYY HH:mm:ss.', { exact: true })).toBeVisible();
    await expect(conversion.locator('pre')).toHaveCount(0);
    await date.fill('03/11/2024 01:30:00');
    // Native Date selects the first 01:30 (EDT), corresponding to 05:30Z.
    await expect(conversion.locator('pre')).toHaveText(['1730611800', '1730611800000']);
  });
});
