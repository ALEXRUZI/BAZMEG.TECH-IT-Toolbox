import { test } from './fixtures/toolRegression';
import { expect, field, openTool, copyText } from './fixtures/test';

test('JSON formatting, indentation, recovery and clipboard preserve actual output', async ({ page }) => {
  const panel = await openTool(page, 'JSON/YAML formatter');
  await expect(panel.locator('pre')).toHaveText('{\n  "name": "it-toolbox",\n  "enabled": true,\n  "tools": [\n    "json",\n    "yaml"\n  ]\n}');
  await field(panel, 'Input').fill('{"id":9007199254740993,"value":1e400,"a":[-0,1e-4000]}');
  const twoSpace = '{\n  "id": 9007199254740993,\n  "value": 1e400,\n  "a": [\n    -0,\n    1e-4000\n  ]\n}';
  await expect(panel.locator('pre')).toHaveText(twoSpace); await copyText(page, panel, twoSpace);
  await field(panel, 'Indent', 'combobox').selectOption('4');
  const expected = '{\n    "id": 9007199254740993,\n    "value": 1e400,\n    "a": [\n        -0,\n        1e-4000\n    ]\n}';
  await expect(panel.locator('pre')).toHaveText(expected); await copyText(page, panel, expected);
  await field(panel, 'Input').fill('{'); await expect(panel.locator('pre')).toHaveCount(0);
  await expect(panel.getByRole('button', { name: /copy/i })).toHaveCount(0);
  await expect(panel.getByText('Fix the JSON input before using the formatted output.')).toBeVisible();
  await field(panel, 'Input').fill('[]'); await expect(panel.locator('pre')).toHaveText('[]');
  await copyText(page, panel, '[]');
});

test('YAML-lite normalizes whitespace, preserves limitations and switches back on mobile', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = await openTool(page, 'JSON/YAML formatter');
  await panel.getByRole('button', { name: 'YAML', exact: true }).click();
  await expect(panel.locator('pre')).toHaveText('name: it-toolbox\nenabled: true\ntools:\n  - json\n  - yaml');
  await field(panel, 'Input').fill('\n---\n # comment  \nroot:\n  child: yes  \n\n\n...\n');
  const expected = '---\n # comment\nroot:\n  child: yes\n\n...';
  await expect(panel.locator('pre')).toHaveText(expected); await copyText(page, panel, expected);
  for (const indicator of ['|', '>']) {
    await field(panel, 'Input').fill(`message: ${indicator}\n  first line  \n\n\n  third line\n`);
    await expect(panel.getByRole('alert')).toContainText('Safe YAML formatting is unavailable');
    await expect(panel.locator('pre')).toHaveCount(0);
    await expect(panel.getByRole('button', { name: /copy/i })).toHaveCount(0);
  }
  await field(panel, 'Input').fill('\tkey: no');
  await expect(panel.getByText('YAML indentation should use spaces, not tabs.')).toBeVisible();
  await field(panel, 'Input').fill('root:\n child: "safe  "');
  await expect(panel.locator('pre')).toHaveText('root:\n child: "safe  "');
  await copyText(page, panel, 'root:\n child: "safe  "');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  await panel.getByRole('button', { name: 'JSON', exact: true }).click();
  await expect(field(panel, 'Indent', 'combobox')).toHaveValue('2');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
  await expect(page.getByRole('article').locator('pre')).toHaveText("chmod 755 -- '/var/www/html'");
});
