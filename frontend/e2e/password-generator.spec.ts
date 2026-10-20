import { test as guardedTest, expect, openTool } from './fixtures/test';

const test = guardedTest.extend({
  page: async ({ page }, use) => {
    try { await use(page); }
    finally {
      await page.evaluate(() => navigator.clipboard.writeText('')).catch(() => {});
      await page.close();
    }
  },
});
test.use({ trace: 'off', screenshot: 'off', video: 'off' });

for (const recovery of [false, true]) {
  test(`${recovery ? 'Recovery Copy all' : 'Password Copy'} failure supports manual selection and successful retry`, async ({ page }) => {
    let pageErrors = 0;
    page.on('pageerror', () => { pageErrors += 1; });
    const tool = await openTool(page, 'Password / Secret Generator');
    if (recovery) await tool.getByRole('button', { name: 'Recovery codes', exact: true }).click();
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
    const label = recovery ? 'Copy all' : 'Copy';
    await tool.getByRole('button', { name: label, exact: true }).click();
    await expect(tool.getByRole('status')).toHaveText('Could not copy automatically. Select the text below and copy it manually.');
    await expect(tool.getByRole('button', { name: label, exact: true })).toBeVisible();
    expect(await tool.locator('pre').evaluate((pre) => {
      const range = document.createRange();
      range.selectNodeContents(pre);
      const selection = window.getSelection();
      selection?.removeAllRanges();
      selection?.addRange(range);
      return selection?.toString() === pre.textContent && getComputedStyle(pre).userSelect !== 'none';
    })).toBe(true);
    await tool.getByRole('button', { name: label, exact: true }).click();
    await expect(tool.getByRole('status')).toHaveText(recovery ? 'Copied all' : 'Copied');
    await expect.poll(() => page.evaluate(async () => (await navigator.clipboard.readText()).replace(/\r\n/g, '\n') === document.querySelector('article pre')?.textContent?.replace(/\r\n/g, '\n'))).toBe(true);
    await tool.getByRole('button', { name: recovery ? 'Regenerate all' : 'Regenerate', exact: true }).click();
    await expect(tool.getByRole('button', { name: label, exact: true })).toBeVisible();
    await expect(tool.getByRole('status')).toBeEmpty();
    expect(pageErrors).toBe(0);
  });
}

test('password length, categories and real clipboard output', async ({ page }) => {
  const tool = await openTool(page, 'Password / Secret Generator');
  const slider = tool.getByRole('slider');
  await slider.focus();
  await slider.press('Home');
  for (let index = 0; index < 14; index++) await slider.press('ArrowRight');
  await expect(slider).toHaveValue('20');
  await expect(tool.getByText('Length: 20', { exact: true })).toBeVisible();
  for (const name of ['Lowercase', 'Uppercase', 'Symbols']) {
    await tool.getByRole('checkbox', { name, exact: true }).uncheck();
  }
  await tool.getByRole('checkbox', { name: 'Numbers', exact: true }).check();
  expect(await tool.locator('pre').evaluate((pre) => /^\d{20}$/.test(pre.textContent ?? ''))).toBe(true);
  await tool.getByRole('button', { name: 'Copy', exact: true }).click();
  await expect.poll(() => page.evaluate(async () => (await navigator.clipboard.readText()) === document.querySelector('article pre')?.textContent)).toBe(true);
});

test('recovery entropy and rating are per code at every count, with safe copy-all and regeneration', async ({ page }) => {
  const tool = await openTool(page, 'Password / Secret Generator');
  await tool.getByRole('button', { name: 'Recovery codes', exact: true }).click();
  for (const format of ['digits', 'alphanumeric']) {
    await tool.getByLabel('Format', { exact: true }).selectOption(format);
    for (const count of [5, 10, 20]) {
      await tool.getByLabel('Code count').selectOption(String(count));
      await expect(tool.getByText('Entropy per code', { exact: true }).locator('..')).toContainText(format === 'digits' ? '26.6 bits' : '40.0 bits');
      await expect(tool.getByText(format === 'digits' ? 'Very weak per code' : 'Weak per code', { exact: true })).toBeVisible();
      expect(await tool.locator('pre').evaluate((pre, options) => {
        const codes = pre.textContent?.trim().split('\n') ?? [];
        const pattern = options.format === 'digits' ? /^\d{4}-\d{4}$/ : /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}-[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]{4}$/;
        return codes.length === options.count && codes.every((code) => pattern.test(code));
      }, { format, count })).toBe(true);
    }
  }
  await expect(tool.getByText(/individually usable one-time credential/)).toContainText('server-side online attempt limits, single-use enforcement, and secure storage');
  await expect(tool.getByText(/More simultaneously valid codes/)).toContainText('do not strengthen each code');
  await tool.getByRole('button', { name: 'Copy all', exact: true }).click();
  await expect.poll(() => page.evaluate(async () => (await navigator.clipboard.readText()).replace(/\r\n/g, '\n') === document.querySelector('article pre')?.textContent?.replace(/\r\n/g, '\n'))).toBe(true);
  await tool.getByRole('button', { name: 'Clear', exact: true }).click();
  await expect(tool.locator('pre')).toHaveCount(0);
  await tool.getByRole('button', { name: 'Regenerate all', exact: true }).click();
  await expect(tool.locator('pre')).toHaveCount(1);
  await expect(tool.getByText('Entropy per code').locator('..')).toContainText('40.0 bits');
});
