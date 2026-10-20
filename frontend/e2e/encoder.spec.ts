import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test('Base64 Unicode encode/decode, malformed UTF-8 recovery and copy work', async ({ page }) => {
  const panel = await openTool(page, 'Base64 / URL encode');
  await expect(panel.locator('pre')).toHaveText('SGVsbG8gZnJvbSBJVCBUb29sYm94IQ==');
  const text = '\u017dlu\u0165ou\u010dk\u00fd k\u00f4\u0148 \ud83d\ude00';
  const encoded = 'xb1sdcWlb3XEjWvDvSBrw7TFiCDwn5iA';
  await field(panel, 'Input').fill(text); await expect(panel.locator('pre')).toHaveText(encoded); await copyText(page, panel, encoded);
  await field(panel, 'Mode', 'combobox').selectOption('base64-decode');
  await expect(field(panel, 'Input')).toHaveValue('SGVsbG8gZnJvbSBJVCBUb29sYm94IQ==');
  await field(panel, 'Input').fill('/w=='); await expect(panel.getByText('Input is not valid Base64.')).toBeVisible();
  await expect(panel.locator('pre')).toHaveCount(0);
  await field(panel, 'Input').fill(encoded); await expect(panel.locator('pre')).toHaveText(text); await copyText(page, panel, text);
});

test('URL component semantics, sample restoration, recovery and navigation work on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = await openTool(page, 'Base64 / URL encode');
  await field(panel, 'Mode', 'combobox').selectOption('url-encode');
  await field(panel, 'Input').focus(); await expect(field(panel, 'Input')).toHaveValue('');
  await field(panel, 'Input').blur(); await expect(field(panel, 'Input')).toHaveValue('Hello from IT Toolbox!');
  await field(panel, 'Input').fill('a b?x=1&y=#/%');
  const encoded = 'a%20b%3Fx%3D1%26y%3D%23%2F%25';
  await expect(panel.locator('pre')).toHaveText(encoded); await copyText(page, panel, encoded);
  await field(panel, 'Mode', 'combobox').selectOption('url-decode');
  await field(panel, 'Input').fill('%C3%28'); await expect(panel.getByText('Input is not valid URL-encoded text.')).toBeVisible();
  await field(panel, 'Input').fill('a+b%20c'); await expect(panel.locator('pre')).toHaveText('a+b c'); await copyText(page, panel, 'a+b c');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Cron generator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText('0 2 * * * /usr/local/bin/backup.sh');
});
