import { test as base, expect, type Locator, type Page } from '@playwright/test';

export const test = base.extend<{ networkGuard: void }>({
  networkGuard: [async ({ context, baseURL }, use) => {
    const unexpected: string[] = [];
    await context.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.origin !== baseURL || url.pathname.startsWith('/api/')) {
        unexpected.push(`${route.request().method()} ${url.origin}${url.pathname}`);
        await route.abort('blockedbyclient');
      } else {
        await route.continue();
      }
    });
    await use();
    expect(unexpected, 'Unexpected API/external requests must not leave the browser').toEqual([]);
  }, { auto: true }],
});
export { expect };

export async function openTool(page: Page, name: string, title = name) {
  await page.goto('/');
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name, exact: true }) }).click();
  return page.getByRole('article').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
}

// Exercise the application's real accessible names, not its visual DOM layout.
export function field(scope: Locator, label: string, role: 'textbox' | 'combobox' = 'textbox') {
  return scope.getByRole(role, { name: new RegExp(`^${label}$`) });
}

export async function copyText(page: Page, scope: Locator, expected: string) {
  await scope.getByRole('button', { name: 'Copy', exact: true }).click();
  // Windows clipboard APIs normalize LF to CRLF; compare logical text on both OSes.
  await expect.poll(async () => (await page.evaluate(() => navigator.clipboard.readText())).replace(/\r\n/g, '\n')).toBe(expected);
}

export async function mockApi(page: Page, endpoint: string, response: unknown, payload: unknown, status = 200) {
  const requests: unknown[] = [];
  await page.route(`**${endpoint}`, async (route) => {
    expect(route.request().method()).toBe('POST');
    expect(route.request().headers()['content-type']).toBe('application/json');
    requests.push(route.request().postDataJSON());
    expect(requests.at(-1)).toEqual(payload);
    await route.fulfill({ status, json: response });
  });
  return requests;
}
