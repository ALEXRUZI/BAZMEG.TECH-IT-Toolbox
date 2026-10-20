import { test, expect, openTool } from './fixtures/test';

test('CommandBlock real clipboard success, denied write, manual selection and retry', async ({ page }) => {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const tool = await openTool(page, 'Cron generator');
  await tool.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(tool.getByRole('button', { name: 'Copied', exact: true })).toBeVisible();
  expect(await page.evaluate(async () => await navigator.clipboard.readText() === document.querySelector('article pre')?.textContent)).toBe(true);
  await page.evaluate(() => {
    const realWrite = navigator.clipboard.writeText.bind(navigator.clipboard);
    let fail = true;
    navigator.clipboard.writeText = (text) => {
      if (fail) {
        fail = false;
        return Promise.reject(new DOMException('Denied', 'NotAllowedError'));
      }
      return realWrite(text);
    };
  });
  await tool.getByRole('button', { name: 'Copied', exact: true }).click();
  await expect(tool.getByRole('status')).toHaveText('Could not copy automatically. Select the text below and copy it manually.');
  await expect(tool.getByRole('button', { name: 'Copy', exact: true })).toBeVisible();
  expect(await tool.locator('pre').evaluate((pre) => {
    const range = document.createRange();
    range.selectNodeContents(pre);
    const selection = window.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    return selection?.toString() === pre.textContent && getComputedStyle(pre).userSelect !== 'none';
  })).toBe(true);
  await tool.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect(tool.getByRole('status')).toHaveText('Copied');
  expect(await page.evaluate(async () => await navigator.clipboard.readText() === document.querySelector('article pre')?.textContent)).toBe(true);
  expect(errors).toEqual([]);
  await page.evaluate(() => navigator.clipboard.writeText(''));
});
