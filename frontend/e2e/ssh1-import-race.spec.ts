import { randomBytes } from 'node:crypto';
import { test as guardedTest, expect, openTool } from './fixtures/test';
import { historicalEncryptionAcknowledgment } from '../src/tools/ssh-key-generator/sshAlgorithms';
import { requireSafe } from '../tests/ssh/interop';
import { clearClipboardAndClose, observeNavigation, readDownload } from './fixtures/sshSafety';

const test = guardedTest.extend({ page: async ({ page }, use, info) => {
  observeNavigation(page, info);
  try { await use(page); } finally { await clearClipboardAndClose(page); }
} });
test.use({ trace: 'off', screenshot: 'off', video: 'off' });
test.use({ actionTimeout: 10_000, navigationTimeout: 15_000 });

test('SSH-1 pending local file survives passphrase edits', async ({ page }) => {
  await page.addInitScript(() => {
    const nativeRead = File.prototype.arrayBuffer;
    File.prototype.arrayBuffer = async function () {
      const bytes = await nativeRead.call(this);
      await new Promise<void>(resolve => { (window as Window & { releaseSshFile?: () => void }).releaseSshFile = resolve; });
      return bytes;
    };
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete');
  await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa1');
  await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
  const password = randomBytes(24).toString('base64url');
  for (const name of ['Output passphrase', 'Confirm output passphrase']) {
    await page.getByLabel(name, { exact: true }).evaluate((el, value) => {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    }, password);
  }
  await panel.getByLabel(historicalEncryptionAcknowledgment).check();
  await panel.getByRole('button', { name: 'Generate key pair', exact: true }).click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 30_000 });
  const fingerprint = await panel.getByText('Historical MD5 fingerprint (identification only)', { exact: true }).locator('..').locator('p').last().textContent();
  const { bytes } = await readDownload(page, () => panel.getByRole('region', { name: /^SSH-1 binary/ }).getByRole('button', { name: 'Download', exact: true }).click());
  await panel.getByRole('tab', { name: 'Extract public key' }).click();
  await panel.getByLabel('Local private-key file').evaluate((element, bytes) => {
    const transfer = new DataTransfer(); transfer.items.add(new File([new Uint8Array(bytes)], 'disposable.ppk'));
    (element as HTMLInputElement).files = transfer.files; element.dispatchEvent(new Event('change', { bubbles: true }));
  }, Array.from(bytes));
  await page.waitForFunction(() => Boolean((window as Window & { releaseSshFile?: () => void }).releaseSshFile), undefined, { timeout: 5_000 });
  await panel.getByLabel('Import passphrase', { exact: true }).evaluate((el, value) => {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')!.set!.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  await page.evaluate(() => (window as Window & { releaseSshFile?: () => void }).releaseSshFile!());
  await expect(panel.getByText(/Binary SSH-1 file loaded/)).toBeVisible({ timeout: 5_000 });
  await panel.getByRole('button', { name: 'Extract public key', exact: true }).click({ timeout: 5_000 });
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 30_000 });
  requireSafe(await panel.getByText('Historical MD5 fingerprint (identification only)', { exact: true }).locator('..').locator('p').last().textContent() === fingerprint, 'Delayed file import changed identity.');
  await expect(panel.getByRole('region', { name: /^SSH-1 binary/ })).toHaveCount(0);
});
