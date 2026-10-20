import { test, expect, openTool, field, mockApi } from './fixtures/test';
import { dnsResponse } from './fixtures/responses';

test('real DNS result export writes a nonempty PNG image to the Chromium clipboard', async ({ page }) => {
  await mockApi(page, '/api/tools/dns-check', dnsResponse, {
    mode: 'single', recordType: 'A', resolverId: 'cloudflare', dnssec: true, query: 'example.com',
  });
  const tool = await openTool(page, 'DNS checker');
  await field(tool, 'Domain/FQDN').fill('example.com');
  await tool.getByRole('button', { name: 'Run DNS Check' }).click();
  await tool.getByRole('button', { name: 'Copy result image' }).click();
  await expect(tool.getByText('Copied DNS result image to clipboard.', { exact: true })).toBeVisible({ timeout: 15000 });
  const image = await page.evaluate(async () => {
    const items = await navigator.clipboard.read();
    const item = items.find((entry) => entry.types.includes('image/png'));
    if (!item) throw new Error('Clipboard contains no PNG');
    const blob = await item.getType('image/png');
    const bitmap = await createImageBitmap(blob);
    const result = { type: blob.type, size: blob.size, width: bitmap.width, height: bitmap.height };
    bitmap.close();
    return result;
  });
  expect(image.type).toBe('image/png');
  expect(image.size).toBeGreaterThan(0);
  expect(image.width).toBeGreaterThan(0);
  expect(image.height).toBeGreaterThan(0);
});
