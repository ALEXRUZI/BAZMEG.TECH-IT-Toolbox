import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test.use({ locale: 'en-US' });

test('Data Transfer preserves finite extreme results, clipboard details and mode switching', async ({ page }) => {
  const panel = await openTool(page, 'Data Transfer Calculator');
  await field(panel, 'File size').fill('1e300');
  await panel.getByRole('combobox').nth(0).selectOption('PB');
  await field(panel, 'Transfer speed').fill('1e300');
  await panel.getByRole('combobox').nth(1).selectOption('Gbps');
  await expect(panel.getByText('92 d 14 h 13 min 20 sec', { exact: true })).toBeVisible();
  const durationDetails = '8,000,000 seconds\n133,333.33 minutes\n2,222.22 hours';
  await expect(panel.locator('pre')).toHaveText(durationDetails);
  await copyText(page, panel, durationDetails);

  await panel.getByRole('button', { name: /Find speed/ }).click();
  await field(panel, 'Transfer time').fill('1e300');
  await panel.getByRole('combobox').nth(1).selectOption('days');
  await expect(panel.locator('pre')).toHaveText('92,592,592,592.59 bps\n92,592.59 Mbps\n11,574.07 MB/s');

  await panel.getByRole('button', { name: /Find size/ }).click();
  await field(panel, 'Transfer time').fill('1');
  await panel.getByRole('combobox').nth(1).selectOption('seconds');
  const expectedGB = new Intl.NumberFormat('en-US', { maximumFractionDigits: 2 }).format(1.25e299);
  await expect(panel.getByText(`${expectedGB} GB`, { exact: true })).toBeVisible();
  await expect(panel).not.toContainText(/NaN|Infinity|\u221e/);
});

test('Data Transfer range limitations recover on mobile without breaking other tools', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = await openTool(page, 'Data Transfer Calculator');
  await field(panel, 'File size').fill('1e308');
  await panel.getByRole('combobox').nth(0).selectOption('PB');
  await field(panel, 'Transfer speed').fill('5e-324');
  await panel.getByRole('combobox').nth(1).selectOption('bps');
  await expect(panel.getByText('Result exceeds the supported numeric range.', { exact: true })).toBeVisible();
  await expect(panel).not.toContainText(/NaN|Infinity|\u221e/);
  const limitedDetails = 'Result exceeds the supported numeric range. (seconds)\nResult exceeds the supported numeric range. (minutes)\nResult exceeds the supported numeric range. (hours)';
  await copyText(page, panel, limitedDetails);
  await field(panel, 'File size').fill('8');
  await panel.getByRole('combobox').nth(0).selectOption('b');
  await field(panel, 'Transfer speed').fill('1');
  await panel.getByRole('combobox').nth(1).selectOption('B/s');
  await expect(panel.getByText('1 sec', { exact: true })).toBeVisible();
  await copyText(page, panel, '1 seconds\n0.02 minutes\n0 hours');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
});
