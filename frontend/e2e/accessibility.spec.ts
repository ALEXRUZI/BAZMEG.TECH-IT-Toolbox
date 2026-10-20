import type { Locator } from '@playwright/test';
import { test as guardedTest, expect, openTool } from './fixtures/test';

// The password tool generates secrets on mount. Never retain this page in artifacts.
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

async function checkControls(panel: Locator) {
  const controls = panel.locator('input:visible, select:visible, textarea:visible');
  for (const control of await controls.all()) {
    await expect(control).toHaveAccessibleName(/\S/);
    expect(await control.evaluate((element) => (element as HTMLInputElement).labels?.length ?? 0)).toBeGreaterThan(0);
  }
  // Return only IDs/counts, never field values or generated output.
  expect(await panel.page().evaluate(() => {
    const ids = [...document.querySelectorAll('[id]')].map((element) => element.id);
    return ids.length === new Set(ids).size;
  })).toBe(true);
}

const tools = [
  ['CSR Generator', 'CSR Generator'],
  ['Password / Secret Generator', 'Password / Secret Generator'],
  ['DNS checker', 'DNS checker'],
  ['TLS cert checker', 'TLS/SSL certificate checker'],
  ['HTTP Header Checker', 'HTTP Header Checker'],
  ['JSON/YAML formatter', 'JSON/YAML formatter'],
  ['UFW generator', 'UFW command generator'],
  ['Firewalld generator', 'Firewalld rich-rule generator'],
  ['nftables generator', 'nftables generator'],
  ['chmod calculator', 'chmod calculator'],
  ['Cron generator', 'Cron generator'],
  ['Epoch & Unix timestamp', 'Epoch & Unix timestamp conversion'],
  ['Data Transfer Calculator', 'Data Transfer Calculator'],
  ['Units of information calculator', 'Units of information calculator'],
  ['Base64 / URL encode', 'Base64 / URL encode'],
];

for (const [name, title] of tools) test(`${name}: native controls expose associated accessible names`, async ({ page }) => {
  const panel = await openTool(page, name, title);
  await checkControls(panel);
  const labels = panel.locator('label[for]:visible:not(.sr-only)');
  for (const label of await labels.all()) {
    // Let example-value blur handlers settle before checking a different label.
    await page.evaluate(() => (document.activeElement as HTMLElement)?.blur());
    const focused = await label.getAttribute('for');
    await label.click();
    await expect(page.locator(`[id="${focused}"]`)).toBeFocused();
  }
  if (name === 'Firewalld generator') await checkControls(page.getByRole('article').filter({ has: page.getByRole('heading', { name: 'Firewalld zones', exact: true }) }));
});

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) {
  test(`keyboard workflows and focus at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    const panel = await openTool(page, 'UFW generator', 'UFW command generator');
    const source = panel.getByRole('textbox', { name: 'Source IPv4', exact: true });
    await panel.locator('label', { hasText: /^Source IPv4$/ }).click();
    await expect(source).toBeFocused();
    await source.fill('invalid');
    await expect(source).toHaveAttribute('aria-invalid', 'true');
    await expect(source).toHaveAccessibleDescription(/IPv4/);
    await source.fill('192.0.2.1');
    await expect(source).not.toHaveAttribute('aria-invalid');
    await source.press('Tab');
    const port = panel.getByRole('textbox', { name: 'Destination port', exact: true });
    await expect(port).toBeFocused();
    expect(await port.evaluate((element) => getComputedStyle(element).outlineStyle)).toBe('solid');
    expect(await port.evaluate((element) => getComputedStyle(element).outlineWidth)).toBe('2px');
    await port.press('Tab');
    const protocol = panel.getByRole('combobox', { name: 'Protocol', exact: true });
    await expect(protocol).toBeFocused();
    await protocol.press('Home');
    await protocol.press('ArrowDown');
    await protocol.press('Enter');
    await expect(protocol).toHaveValue('udp');
    const checkbox = panel.getByRole('checkbox', { name: /source port/i });
    await checkbox.focus();
    await checkbox.press('Space');
    const conditional = panel.getByRole('textbox', { name: 'Source port', exact: true });
    await expect(conditional).toBeVisible();
    await checkControls(panel);

    await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
    // Earlier mouse clicks can leave the pointer over help after scrolling.
    // Park it outside the workbench to make this a keyboard-only help workflow.
    await page.mouse.move(0, 0);
    const help = page.getByRole('button', { name: 'Help with ping controls' });
    expect(await help.evaluate((element) => element.matches(':hover'))).toBe(false);
    await page.getByRole('checkbox', { name: /ICMP/i }).last().focus();
    // The trigger is reached by ordinary Tab navigation, not positive tabindex.
    for (let i = 0; i < 12 && !(await help.evaluate((element) => element === document.activeElement)); i++) await page.keyboard.press('Tab');
    await expect(help).toBeFocused();
    await expect(help).toHaveAccessibleDescription(/Controls ping/);
    await expect(help).toHaveAttribute('aria-expanded', 'true');
    const helpText = page.locator(`[id="${await help.getAttribute('aria-controls')}"]`);
    await expect(helpText).toBeVisible();
    expect(await help.evaluate((element) => getComputedStyle(element).outlineWidth)).toBe('2px');
    await help.press('Enter');
    await help.press('Escape');
    await expect(helpText).toBeHidden();
    await expect(help).toBeFocused();
    await help.press('Space');
    await expect(helpText).toBeVisible();
    await help.press('Tab');
    await expect(helpText).toBeHidden();
    await expect(help).toHaveAttribute('aria-expanded', 'false');
  });

  test(`help blur dismisses active pointer hover at ${viewport.width}px`, async ({ page }) => {
    await page.setViewportSize(viewport);
    await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
    const help = page.getByRole('button', { name: 'Help with ping controls' });
    const icmp = page.getByRole('checkbox', { name: 'Configure ICMP', exact: true });
    const helpText = page.locator(`[id="${await help.getAttribute('aria-controls')}"]`);

    // Establish real pointer hover, then reach the trigger with the keyboard
    // without moving the pointer. Shift+Tab returns to the adjacent checkbox,
    // avoiding viewport scrolling that could accidentally end pointer hover.
    await help.hover();
    expect(await help.evaluate((element) => element.matches(':hover'))).toBe(true);
    await expect(helpText).toBeVisible();
    await icmp.focus();
    await page.keyboard.press('Tab');
    await expect(help).toBeFocused();
    expect(await help.evaluate((element) => element.matches(':hover'))).toBe(true);
    await help.press('Enter');
    await help.press('Shift+Tab');
    await expect(icmp).toBeFocused();
    expect(await help.evaluate((element) => element.matches(':hover'))).toBe(true);
    await expect(helpText).toBeHidden();
    await expect(help).toHaveAttribute('aria-expanded', 'false');

    // Dismissal survives a stationary pointer, but a genuine new entry opens.
    await page.mouse.move(0, 0);
    expect(await help.evaluate((element) => element.matches(':hover'))).toBe(false);
    await expect(helpText).toBeHidden();
    await help.hover();
    await expect(helpText).toBeVisible();
    await expect(help).toHaveAttribute('aria-expanded', 'true');
    await page.mouse.move(0, 0);
    await expect(helpText).toBeHidden();

    // Keyboard focus reopens after dismissal; Escape wins over active hover.
    await help.hover();
    await page.keyboard.press('Tab');
    await expect(help).toBeFocused();
    await help.press('Escape');
    await expect(helpText).toBeHidden();
    await expect(help).toBeFocused();
    await expect(help).toHaveAttribute('aria-expanded', 'false');
    await help.press('Space');
    await expect(helpText).toBeVisible();
    await help.press('Shift+Tab');
    await expect(helpText).toBeHidden();
  });
}

test('CSR SAN insertion/removal, radio arrows and conditional password errors', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  await panel.getByRole('button', { name: 'Add SAN' }).focus();
  await page.keyboard.press('Space');
  const first = panel.getByRole('textbox', { name: 'SAN 1', exact: true });
  const second = panel.getByRole('textbox', { name: 'SAN 2', exact: true });
  expect(await first.getAttribute('id')).not.toBe(await second.getAttribute('id'));
  await second.fill('bad..name');
  await expect(second).toHaveAttribute('aria-invalid', 'true');
  await expect(second).toHaveAccessibleDescription(/name|SAN|domain/i);
  await second.fill('www.example.test');
  await expect(second).toHaveAttribute('aria-invalid', 'false');
  await panel.getByRole('button', { name: 'Remove SAN 2' }).press('Enter');
  await expect(second).toHaveCount(0);
  await panel.getByRole('button', { name: /Advanced export format/ }).press('Enter');
  const pem = panel.getByRole('radio', { name: /^PEM \/ PKCS#10/ });
  await pem.focus();
  await pem.press('ArrowDown');
  await expect(panel.getByRole('radio', { name: /^DER \/ PKCS#10/ })).toBeChecked();
  await panel.getByRole('radio', { name: /Encrypted PKCS#8/ }).check();
  const password = panel.getByLabel('Encryption password *');
  await expect(password).toHaveAttribute('type', 'password');
  await expect(password).toHaveAttribute('aria-invalid', 'true');
  await expect(password).toHaveAccessibleDescription(/Password is required/);
  await checkControls(panel);
  // No private keys or passwords are generated/entered here.
});

test('DNS conditional names, validation descriptions and example restoration', async ({ page }) => {
  const panel = await openTool(page, 'DNS checker');
  await panel.getByRole('combobox', { name: 'Record type' }).selectOption('SRV');
  await checkControls(panel);
  const service = panel.getByRole('textbox', { name: 'Service', exact: true });
  await service.focus();
  await expect(service).toHaveValue('');
  await service.fill('bad..service');
  await expect(service).toHaveAttribute('aria-invalid', 'true');
  await expect(service).toHaveAccessibleDescription(/service/i);
  await expect(panel.getByRole('textbox', { name: 'Domain', exact: true })).toHaveAccessibleDescription(/service/i);
  await service.fill('');
  await service.press('Tab');
  await expect(service).toHaveValue('sip');
  await panel.getByRole('combobox', { name: 'Record type' }).selectOption('TXT');
  await panel.getByRole('combobox', { name: 'TXT helper' }).selectOption('dkim');
  await checkControls(panel);
  await expect(panel.getByRole('textbox', { name: 'Selector', exact: true })).toBeVisible();
});

test('password modes retain native range/select/checkbox names', async ({ page }) => {
  const panel = await openTool(page, 'Password / Secret Generator');
  const length = panel.getByRole('slider', { name: /^Length:/ });
  await length.focus();
  await length.press('ArrowRight');
  await expect(length).toHaveAccessibleName(/^Length:/);
  for (const name of ['Passphrase', 'API key / token', 'PIN', 'Recovery codes']) {
    await panel.getByRole('button', { name, exact: true }).click();
    await checkControls(panel);
  }
});

for (const viewport of [{ width: 1280, height: 900 }, { width: 390, height: 844 }]) test.describe(`touch help at ${viewport.width}px`, () => {
  test.use({ viewport, hasTouch: true });
  test('tap reveals help without hover and a second tap dismisses it', async ({ page }) => {
    await openTool(page, 'Firewalld generator', 'Firewalld rich-rule generator');
    const help = page.getByRole('button', { name: 'Help with ping controls' });
    const icmp = page.getByRole('checkbox', { name: 'Configure ICMP', exact: true });
    const helpText = page.locator(`[id="${await help.getAttribute('aria-controls')}"]`);
    await expect(icmp).not.toBeChecked();
    await help.tap();
    await expect(help).toHaveAttribute('aria-expanded', 'true');
    await expect(helpText).toBeVisible();
    await help.tap();
    await expect(help).toHaveAttribute('aria-expanded', 'false');
    await expect(helpText).toBeHidden();
    await expect(icmp).not.toBeChecked();
  });
});
