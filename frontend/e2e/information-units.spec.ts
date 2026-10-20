import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test.use({ locale: 'en-US' });

test('Information Units preserves finite primary results and copies supplementary range limitations', async ({ page }) => {
  const panel = await openTool(page, 'Units of information calculator');
  await field(panel, 'Value').fill('1e300');
  await field(panel, 'From', 'combobox').selectOption('PB');
  await field(panel, 'To', 'combobox').selectOption('PB');
  const value = new Intl.NumberFormat('en-US', { maximumFractionDigits: 8 }).format(1e300);
  await expect(panel.getByText(`${value} PB`, { exact: true })).toBeVisible();
  await expect(panel.getByText(`${value} PB/s`, { exact: true })).toBeVisible();
  const details = `${value} PB\n= ${value} PB\n= Result exceeds the supported numeric range. (bits)`;
  const rateDetails = `${value} PB/s\n= ${value} PB/s\n= Result exceeds the supported numeric range. (bps)`;
  await expect(panel.locator('pre').nth(0)).toHaveText(details);
  await expect(panel.locator('pre').nth(1)).toHaveText(rateDetails);
  await copyText(page, panel.locator('pre').nth(0).locator('..'), details);
  await copyText(page, panel.locator('pre').nth(1).locator('..'), rateDetails);
  await expect(panel).not.toContainText(/NaN|Infinity|\u221e/);
});

test('Information Units reports true overflow and underflow and recovers on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = await openTool(page, 'Units of information calculator');
  await field(panel, 'Value').fill('1e308');
  await field(panel, 'From', 'combobox').selectOption('PB');
  await field(panel, 'To', 'combobox').selectOption('b');
  await expect(panel.getByText('Result exceeds the supported numeric range. (b)', { exact: true })).toBeVisible();
  await field(panel, 'Value').fill('5e-324');
  await field(panel, 'From', 'combobox').selectOption('b');
  await field(panel, 'To', 'combobox').selectOption('PiB');
  await expect(panel.getByText('Result is below the supported numeric range. (PiB)', { exact: true })).toBeVisible();
  await expect(panel).not.toContainText(/NaN|Infinity|\u221e/);
  await field(panel, 'Value').fill('8');
  await field(panel, 'To', 'combobox').selectOption('B');
  await expect(panel.getByText('1 B', { exact: true })).toBeVisible();
  await copyText(page, panel.locator('pre').nth(0).locator('..'), '8 b\n= 1 B\n= 8 bits');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Cron generator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText('0 2 * * * /usr/local/bin/backup.sh');
});
