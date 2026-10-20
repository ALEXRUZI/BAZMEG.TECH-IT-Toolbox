import { randomBytes } from 'node:crypto';
import { unzipSync } from 'fflate';
import type { Locator, Page } from '@playwright/test';
import { test as guardedTest, expect, openTool } from './fixtures/test';
import { independentFixture, independentSsh1Fixture, requireSafe, verifyNative } from '../tests/ssh/interop';
import type { Result } from '../src/tools/ssh-key-generator/sshTypes';
import { historicalEncryptionAcknowledgment } from '../src/tools/ssh-key-generator/sshAlgorithms';
import { bounded, clearClipboardAndClose, copyAndCompare, observeNavigation, readDownload } from './fixtures/sshSafety';

const test = guardedTest.extend({ page: async ({ page }, use, info) => {
  observeNavigation(page, info);
  try { await use(page); }
  finally { await clearClipboardAndClose(page); }
} });
test.use({ trace: 'off', screenshot: 'off', video: 'off' });
test.setTimeout(120_000);
// A disabled control/navigation should identify the blocked action promptly,
// not consume the whole test budget. Worker-result waits keep their own limits.
test.use({ actionTimeout: 10_000, navigationTimeout: 15_000 });

async function secret(page: Page, name: string, value: string) {
  const id = await page.getByLabel(name, { exact: true }).getAttribute('id');
  await page.evaluate(({ id, value }) => {
    const input = document.getElementById(id!) as HTMLInputElement | HTMLTextAreaElement;
    const prototype = input instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(prototype, 'value')?.set?.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, { id, value });
}
async function protect(page: Page, password: string) { await secret(page, 'Output passphrase', password); await secret(page, 'Confirm output passphrase', password); }
async function localFile(panel: Locator, content: string) {
  await panel.getByLabel('Local private-key file', { exact: true }).evaluate((element, content) => {
    const input = element as HTMLInputElement, transfer = new DataTransfer();
    // The misleading extension must not override bounded content detection.
    transfer.items.add(new File([content], 'disposable-fixture.pem', { type: 'text/plain' }));
    input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
  }, content);
}
async function collect(panel: Locator): Promise<Result> {
  await test.step('SSH worker result', () => expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 60_000 }));
  const outputs: Result['outputs'] = [];
  for (const [format, label] of [['public', '(?:authorized_keys public key|RFC 8709 public key|SSH-1 decimal public key)'], ['openssh', 'OpenSSH private key'], ['ppk', 'PuTTY PPK v3 private key'], ['ssh1', 'SSH-1 binary private key']] as const) {
    const section = panel.getByRole('region', { name: new RegExp(`^${label}`) });
    if (!await section.count()) continue;
    if (format === 'ssh1') {
      await expect(section.locator('pre')).toHaveCount(0); await expect(section.getByRole('button', { name: 'Copy text' })).toHaveCount(0);
      const download = await readDownload(panel.page(), () => section.getByRole('button', { name: 'Download', exact: true }).click());
      outputs.push({ format, label, filename: (await section.locator('p').first().textContent())!, private: true, text: '', bytes: download.bytes });
      continue;
    }
    if (format !== 'public') {
      requireSafe(!await section.locator('pre').count(), 'Private output was initially exposed.');
      await section.getByRole('button', { name: 'Reveal private key' }).click();
    }
    outputs.push({ format, label, filename: (await section.locator('p').first().textContent())!, text: (await section.locator('pre').textContent())!, private: format !== 'public' });
  }
  const fingerprint = (await panel.getByText(/^(?:SHA-256 fingerprint|Historical MD5 fingerprint \(identification only\))$/).locator('..').locator('p').last().textContent())!;
  return { outputs, inspector: { fingerprint, algorithm: '', identifier: '', parameters: '', classification: '', comment: '', format: '', encrypted: false, exports: '' } };
}

for (const id of ['ed25519', 'ed448', 'P-256', 'P-384', 'P-521', 'rsa2048', 'rsa3072', 'rsa4096', 'rsa1024', 'rsa512', 'rsa768', 'dsa']) test(`real browser ${id} protected/plain exports independently verify`, async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  for (const protectedOutput of [true, false]) {
    await panel.getByRole('button', { name: 'Reset / discard keys' }).click();
    const legacy = ['rsa1024', 'rsa512', 'rsa768', 'dsa'].includes(id);
    const family = id.startsWith('P-') ? 'ECDSA' : legacy ? 'Legacy / Obsolete' : id.startsWith('rsa') ? 'RSA' : 'EdDSA';
    await panel.getByLabel('Algorithm family', { exact: true }).selectOption(family);
    await panel.getByLabel('Algorithm / curve / key size', { exact: true }).selectOption(id);
    if (legacy) await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
    const password = protectedOutput ? randomBytes(24).toString('base64url') : '';
    await panel.getByLabel('Key comment', { exact: true }).fill('Browser Próba "comment" \\ @test');
    if (protectedOutput) await protect(page, password);
    else { await panel.getByLabel('Protect private keys with a passphrase').uncheck(); await panel.getByLabel('I deliberately choose unencrypted private-key output.').check(); }
    await expect(panel.getByRole('button', { name: 'Generate key pair', exact: true })).toBeEnabled({ timeout: 30_000 });
    const started = performance.now(); await panel.getByRole('button', { name: 'Generate key pair', exact: true }).click();
    const result = await collect(panel);
    if (['rsa512', 'rsa768', 'dsa'].includes(id)) console.info(`${id}: Chromium generation/validation/${protectedOutput ? 'encrypted' : 'plain'} exports ${(performance.now() - started).toFixed(1)} ms`);
    verifyNative(result, password, process.env.SSH_INTEROP === '1');
    const input = result.outputs.find(output => output.format === (id === 'ed448' ? 'ppk' : 'openssh'))!;
    if (id === 'ed448') {
      expect(result.outputs.map(output => output.format)).toEqual(['public', 'ppk']);
      await expect(panel.getByText('Ed448; 57-byte seed; 57-byte public key; ~224-bit security strength', { exact: true })).toBeVisible();
      await expect(panel.getByText('RFC 8709 public key, PuTTY PPK v3', { exact: true })).toBeVisible();
      await expect(panel.getByRole('region', { name: /^OpenSSH private key/ })).toHaveCount(0);
    }
    await panel.getByRole('tab', { name: 'Extract public key' }).click();
    await secret(page, 'Paste private-key text', input.text); await secret(page, 'Import passphrase', password);
    await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    const extracted = await collect(panel);
    requireSafe(extracted.outputs.length === 1 && extracted.inspector.fingerprint === result.inspector.fingerprint, 'Browser extraction identity differs.');
    await panel.getByRole('tab', { name: 'Generate key pair' }).click();
  }
});

test('output format labels and explanations follow algorithm switching and keyboard navigation', async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  const outputs = panel.getByRole('group', { name: 'Selected outputs' });
  const family = panel.getByLabel('Algorithm family'), selection = panel.getByLabel('Algorithm / curve / key size');
  for (const [group, ids] of [['EdDSA', ['ed25519']], ['ECDSA', ['P-256', 'P-384', 'P-521']], ['RSA', ['rsa2048', 'rsa3072', 'rsa4096', 'rsa8192']], ['Legacy / Obsolete', ['rsa512', 'rsa768', 'rsa1024', 'dsa']]] as const) {
    await family.selectOption(group);
    for (const id of ids) {
      await selection.selectOption(id);
      for (const label of ['OpenSSH private', 'PPK v3 private']) {
        await expect(outputs.getByRole('checkbox', { name: label, exact: true })).toBeEnabled();
        await expect(outputs.getByText(label, { exact: true })).not.toHaveCSS('text-decoration-line', 'line-through');
      }
      await expect(outputs.getByText('SSH-1 binary private', { exact: true })).toHaveCSS('text-decoration-line', 'line-through');
    }
  }
  await family.selectOption('EdDSA'); await selection.selectOption('ed448');
  const openssh = outputs.getByRole('checkbox', { name: 'OpenSSH private', exact: true });
  await expect(openssh).toBeDisabled(); await expect(openssh).not.toBeChecked();
  // Deliberately click a disabled option's label; native disabled behavior must win.
  await outputs.getByText('OpenSSH private', { exact: true }).click({ force: true }); await expect(openssh).not.toBeChecked();
  await expect(outputs.getByText('OpenSSH private', { exact: true })).toHaveCSS('text-decoration-line', 'line-through');
  await expect(outputs.getByText('OpenSSH private', { exact: true })).toHaveCSS('opacity', '0.6');
  await expect(outputs.getByRole('checkbox', { name: 'PPK v3 private' })).toBeChecked();
  const info = outputs.getByRole('button', { name: 'Why OpenSSH private is unavailable' });
  await page.mouse.move(0, 0);
  await outputs.getByText('OpenSSH private', { exact: true }).hover();
  await expect(outputs.getByRole('tooltip')).toHaveText('OpenSSH private-key format is not supported for Ed448.');
  await info.hover();
  await expect(outputs.getByRole('tooltip')).toHaveText('OpenSSH private-key format is not supported for Ed448.');
  await outputs.getByRole('tooltip').hover(); await expect(outputs.getByRole('tooltip')).toBeVisible();
  await openssh.hover(); await expect(outputs.getByRole('tooltip')).toBeVisible();
  await page.mouse.move(0, 0); await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  await outputs.getByRole('checkbox', { name: 'RFC 8709 public key' }).focus();
  await page.keyboard.press('Tab'); await expect(info).toBeFocused();
  await expect(info).toHaveAccessibleDescription('OpenSSH private-key format is not supported for Ed448.');
  await page.keyboard.press('Escape'); await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  await page.keyboard.press('Enter'); await expect(outputs.getByRole('tooltip')).toBeVisible();
  await page.keyboard.press('Escape'); await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  await page.keyboard.press('Space'); await expect(outputs.getByRole('tooltip')).toBeVisible();
  await page.keyboard.press('Tab'); await expect(outputs.getByRole('checkbox', { name: 'PPK v3 private' })).toBeFocused();
  await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  await outputs.getByText('OpenSSH private', { exact: true }).hover();
  await expect(outputs.getByRole('tooltip')).toBeVisible();
  await family.selectOption('Legacy / Obsolete'); await selection.selectOption('rsa1');
  await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  for (const [label, explanation] of [['OpenSSH private', 'OpenSSH private-key format is not supported for SSH-1 RSA.'], ['PPK v3 private', 'PuTTY PPK v3 is not supported for SSH-1 RSA.']]) {
    await expect(outputs.getByRole('checkbox', { name: label, exact: true })).toBeDisabled();
    await expect(outputs.getByRole('checkbox', { name: label, exact: true })).not.toBeChecked();
    await expect(outputs.getByText(label, { exact: true })).toHaveCSS('text-decoration-line', 'line-through');
    await outputs.getByText(label, { exact: true }).hover();
    await expect(outputs.getByRole('tooltip')).toHaveText(explanation);
    await outputs.getByText(label, { exact: true }).click({ force: true });
    await expect(outputs.getByRole('checkbox', { name: label, exact: true })).not.toBeChecked();
    await outputs.getByRole('button', { name: `Why ${label} is unavailable` }).hover();
    await expect(outputs.getByRole('tooltip')).toHaveText(explanation);
    await page.mouse.move(0, 0);
  }
  await expect(outputs.getByRole('checkbox', { name: 'SSH-1 binary private' })).toBeEnabled();
  await expect(outputs.getByRole('checkbox', { name: 'SSH-1 binary private' })).toBeChecked();
  await expect(outputs.getByText('SSH-1 binary private', { exact: true })).not.toHaveCSS('text-decoration-line', 'line-through');
  await outputs.getByText('PPK v3 private', { exact: true }).hover();
  await expect(outputs.getByRole('tooltip')).toHaveText('PuTTY PPK v3 is not supported for SSH-1 RSA.');
  await family.selectOption('EdDSA');
  await expect(outputs.getByRole('tooltip')).toHaveCount(0);
  await expect(outputs.getByText('PPK v3 private', { exact: true })).not.toHaveCSS('text-decoration-line', 'line-through');
  await panel.getByRole('tab', { name: 'Convert key formats' }).click();
  await expect(outputs.getByRole('button', { name: /Why .* is unavailable/ })).toHaveCount(0);
  await expect(outputs.getByText('SSH-1 binary private', { exact: true })).not.toHaveCSS('text-decoration-line', 'line-through');
});

test.describe('touch output explanations', () => {
  test.use({ hasTouch: true, viewport: { width: 320, height: 850 } });
  test('information toggles on tap and stays within the narrow viewport', async ({ page }) => {
    const panel = await openTool(page, 'SSH Key Generator & Converter');
    await panel.getByLabel('Algorithm / curve / key size').selectOption('ed448');
    const outputs = panel.getByRole('group', { name: 'Selected outputs' });
    for (const [label, explanation] of [['OpenSSH private', 'OpenSSH private-key format is not supported for Ed448.'], ['SSH-1 binary private', 'SSH-1 private-key format is only available for historical SSH-1 RSA keys.']]) {
      const info = outputs.getByRole('button', { name: `Why ${label} is unavailable` });
      await info.tap();
      const tooltip = outputs.getByRole('tooltip');
      await expect(tooltip).toHaveText(explanation);
      expect(await tooltip.evaluate(element => { const rect = element.getBoundingClientRect(); return rect.left >= 0 && rect.right <= innerWidth && rect.top >= 0 && rect.bottom <= innerHeight; })).toBe(true);
      await expect(outputs.getByRole('checkbox', { name: label, exact: true })).not.toBeChecked();
      await info.tap(); await expect(tooltip).toHaveCount(0);
    }
  });
});

test('defaults, deliberate plaintext choice, legacy reset and unsupported selections', async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await expect(panel.getByLabel('Algorithm / curve / key size')).toHaveValue('ed25519');
  await expect(panel.getByLabel('Protect private keys with a passphrase')).toBeChecked();
  const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
  await expect(generate).toBeDisabled();
  await protect(page, 'disposable-default-test-password');
  await secret(page, 'Confirm output passphrase', 'mismatch'); await expect(generate).toBeDisabled();
  await panel.getByLabel('Protect private keys with a passphrase').uncheck(); await expect(generate).toBeDisabled();
  await panel.getByLabel('I deliberately choose unencrypted private-key output.').check();
  await expect(generate).toBeEnabled({ timeout: 30_000 });
  await panel.getByLabel('Algorithm / curve / key size').selectOption('ed448');
  await expect(panel.getByLabel('I deliberately choose unencrypted private-key output.')).not.toBeChecked();
  await panel.getByLabel('I deliberately choose unencrypted private-key output.').check();
  await expect(generate).toBeEnabled(); await expect(panel.getByText(/Standard OpenSSH does not/)).toBeVisible();
  await expect(panel.getByLabel('OpenSSH private', { exact: true })).toBeDisabled();
  await expect(panel.getByLabel('OpenSSH private', { exact: true })).not.toBeChecked();
  await expect(panel.getByLabel('OpenSSH private', { exact: true })).toHaveAccessibleDescription('OpenSSH private-key format is not supported for Ed448.');
  await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete');
  await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa1024');
  await panel.getByLabel('I deliberately choose unencrypted private-key output.').check();
  const acknowledgment = panel.getByLabel('I understand this algorithm is unsuitable for production use.');
  await expect(acknowledgment).not.toBeChecked(); await expect(generate).toBeDisabled();
  await acknowledgment.check(); await expect(generate).toBeEnabled();
  for (const id of ['rsa512', 'rsa768', 'dsa', 'rsa1']) {
    await panel.getByLabel('Algorithm / curve / key size').selectOption(id);
    await expect(acknowledgment).not.toBeChecked(); await expect(generate).toBeDisabled();
    await acknowledgment.check();
    await panel.getByLabel('I deliberately choose unencrypted private-key output.').check();
    await expect(generate).toBeEnabled();
  }
  await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa1024'); await expect(acknowledgment).not.toBeChecked();
  await panel.getByLabel('Algorithm family').selectOption('RSA'); await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa8192');
  await panel.getByLabel('I deliberately choose unencrypted private-key output.').check(); await expect(generate).toBeEnabled();
  await expect(panel.getByText(/Resource-intensive and generally unnecessary/)).toBeVisible();
  await expect(acknowledgment).toHaveCount(0);
  const generateTab = panel.getByRole('tab', { name: 'Generate key pair' });
  await generateTab.focus(); await generateTab.press('ArrowRight');
  const extractTab = panel.getByRole('tab', { name: 'Extract public key' });
  await expect(extractTab).toBeFocused(); await expect(extractTab).toHaveAttribute('aria-selected', 'true');
  await extractTab.press('End'); await expect(panel.getByRole('tab', { name: 'Convert key formats' })).toBeFocused();
  await panel.getByRole('tab', { name: 'Convert key formats' }).press('Home'); await expect(generateTab).toBeFocused();
});

test('provider rejecting RSA 1024 does not disable modern RSA; size failures never fall back', async ({ page }) => {
  const attempts: number[] = [];
  page.on('console', message => {
    const match = /^AUD-SSH-001 RSA attempt (\d+)$/.exec(message.text());
    if (match) attempts.push(Number(match[1]));
  });
  // Modify only the local test worker's provider boundary; all key operations,
  // worker ownership and validation still run through the real implementation.
  await page.route(/\/ssh\.worker\.ts(?:\?|$)/, async route => {
    if (!new URL(route.request().url()).searchParams.has('worker_file')) { await route.fallback(); return; }
    const response = await route.fetch();
    const injection = `
      const nativeGenerate = crypto.subtle.generateKey.bind(crypto.subtle);
      crypto.subtle.generateKey = (...args) => {
        const params = args[0];
        if (typeof params === 'object' && 'modulusLength' in params) {
          console.info('AUD-SSH-001 RSA attempt ' + params.modulusLength);
          if ([1024, 3072, 8192].includes(params.modulusLength)) return Promise.reject(new DOMException('Test provider rejects this size', 'NotSupportedError'));
        }
        return nativeGenerate(...args);
      };
    `;
    await route.fulfill({ response, body: injection + await response.text() });
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await panel.getByLabel('OpenSSH private', { exact: true }).uncheck();
  await panel.getByLabel('PPK v3 private', { exact: true }).uncheck();
  const family = panel.getByLabel('Algorithm family'), selection = panel.getByLabel('Algorithm / curve / key size');
  const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
  await family.selectOption('RSA');
  for (const id of ['rsa2048', 'rsa3072', 'rsa4096', 'rsa8192']) {
    await selection.selectOption(id);
    await expect(generate).toBeEnabled({ timeout: 30_000 });
  }
  expect(attempts).toEqual([]);
  await selection.selectOption('rsa3072'); await generate.click();
  await expect(panel.getByRole('alert')).toContainText('Unsupported native generation of RSA 3072-bit');
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  expect(attempts).toEqual([3072]);
  await selection.selectOption('rsa8192'); await generate.click();
  await expect(panel.getByRole('alert')).toContainText('Unsupported native generation of RSA 8192-bit');
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  expect(attempts).toEqual([3072, 8192]);
  await selection.selectOption('rsa2048'); await generate.click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 60_000 });
  await expect(panel.getByText('RSA 2048-bit; 2048 bits; exponent 65537', { exact: true })).toBeVisible();
  expect(attempts).toEqual([3072, 8192, 2048]);
  await family.selectOption('Legacy / Obsolete'); await selection.selectOption('rsa1024');
  const acknowledgment = panel.getByLabel('I understand this algorithm is unsuitable for production use.');
  await expect(acknowledgment).not.toBeChecked(); await expect(generate).toBeDisabled();
  expect(attempts).toEqual([3072, 8192, 2048]);
  await acknowledgment.check(); await generate.click();
  await expect(panel.getByRole('alert').filter({ hasText: 'Unsupported native generation' })).toContainText('RSA 1024-bit');
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  expect(attempts).toEqual([3072, 8192, 2048, 1024]);
  await family.selectOption('RSA'); await expect(generate).toBeEnabled();
  await family.selectOption('Legacy / Obsolete'); await selection.selectOption('rsa1024');
  await expect(acknowledgment).not.toBeChecked(); await expect(generate).toBeDisabled();
});

for (const id of ['ed25519', 'ed448', 'rsa512', 'rsa768', 'dsa']) test(`${id}: copy warnings, selected ZIP/downloads, reset/cancellation, narrow screen and no secret persistence/requests`, async ({ page }) => {
  let unsafeRequest = false;
  page.context().on('request', request => {
    const url = new URL(request.url());
    // Vite's local module/worker cache-busting parameters are public assets,
    // not user data. Reject other query fields, bodies and non-GET requests.
    const assetQuery = [...url.searchParams].every(([key, value]) =>
      key === 'v' ? /^[0-9a-f]+$/.test(value) : key === 't' ? /^\d+$/.test(value) : key === 'type' ? value === 'module' : ['worker_file', 'import', 'direct'].includes(key) && value === '');
    if (request.method() !== 'GET' || request.postData() !== null || !assetQuery || url.hash) unsafeRequest = true;
  });
  await page.addInitScript(() => {
    (window as Window & { sshPersistence?: number }).sshPersistence = 0;
    const count = () => { const w = window as Window & { sshPersistence?: number }; w.sshPersistence = (w.sshPersistence ?? 0) + 1; };
    Storage.prototype.setItem = count;
    indexedDB.open = (() => { count(); throw new Error('Persistence blocked by test'); }) as typeof indexedDB.open;
    if ('caches' in window) caches.open = async () => { count(); throw new Error('Cache persistence blocked by test'); };
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  const legacy = ['rsa512', 'rsa768', 'dsa'].includes(id);
  if (legacy) await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete');
  await panel.getByLabel('Algorithm / curve / key size').selectOption(id);
  if (legacy) await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
  await page.setViewportSize({ width: 375, height: 850 });
  const password = randomBytes(24).toString('base64url'); await protect(page, password);
  const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
  await expect(generate).toBeEnabled({ timeout: 30_000 }); await generate.click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 60_000 });
  const privateOutput = panel.getByRole('region', { name: id === 'ed448' ? /^PuTTY PPK v3 private key/ : /^OpenSSH private key/ });
  await expect(privateOutput.locator('pre')).toHaveCount(0); await expect(privateOutput.getByRole('button', { name: 'Copy text' })).toBeDisabled();
  await privateOutput.getByLabel('I understand the clipboard risk for this private key.').check();
  await copyAndCompare(privateOutput, () => privateOutput.getByRole('button', { name: 'Reveal private key' }).click());
  await expect(privateOutput.getByRole('button', { name: 'Copy text' })).toBeDisabled();
  const privateText = (await privateOutput.locator('pre').textContent())!;
  await privateOutput.getByRole('button', { name: 'Hide private key' }).click();
  const publicOutput = panel.getByRole('region', { name: id === 'ed448' ? 'RFC 8709 public key' : 'authorized_keys public key' });
  await copyAndCompare(publicOutput);
  await page.evaluate(() => {
    const w = window as Window & { sshDownloadUrls?: { created: number; revoked: number } };
    const counts = { created: 0, revoked: 0 }; w.sshDownloadUrls = counts;
    const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = blob => { counts.created++; return create(blob); };
    URL.revokeObjectURL = url => { counts.revoked++; revoke(url); };
  });
  await panel.getByLabel(/Include PuTTY PPK/).uncheck();
  const download = await readDownload(page, () => panel.getByRole('button', { name: 'Download all as ZIP' }).click());
  {
    const zip = unzipSync(download.bytes);
    requireSafe(Object.keys(zip).length === (id === 'ed448' ? 1 : 2) && !Object.keys(zip).some(name => name.endsWith('.ppk')), 'ZIP selection differs.');
    if (id === 'ed448') requireSafe(Object.keys(zip)[0] === 'id_ed448.pub' && new TextDecoder().decode(zip['id_ed448.pub']) === await publicOutput.locator('pre').textContent(), 'Ed448 ZIP content differs.');
  }
  if (id === 'ed448') {
    await panel.getByLabel(/Include RFC 8709 public key/).uncheck();
    await panel.getByLabel(/Include PuTTY PPK/).check();
    const ppkZip = await readDownload(page, () => panel.getByRole('button', { name: 'Download all as ZIP' }).click());
    {
      const files = unzipSync(ppkZip.bytes);
      requireSafe(Object.keys(files).length === 1 && files['id_ed448.ppk'] && new TextDecoder().decode(files['id_ed448.ppk']) === privateText, 'Selected PPK ZIP content differs.');
    }
  }
  const single = await readDownload(page, () => privateOutput.getByRole('button', { name: 'Download', exact: true }).click());
  requireSafe(new TextDecoder().decode(single.bytes) === privateText, 'Private download content differs.');
  requireSafe(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Narrow viewport overflows.');
  await panel.getByRole('button', { name: 'Reset / discard keys' }).click(); await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  requireSafe(await page.evaluate(expected => {
    const counts = (window as Window & { sshDownloadUrls?: { created: number; revoked: number } }).sshDownloadUrls;
    return counts?.created === expected && counts.revoked === counts.created;
  }, id === 'ed448' ? 3 : 2), 'Download URLs were not revoked on reset.');
  if (legacy) await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete');
  await panel.getByLabel('Algorithm / curve / key size').selectOption(id);
  if (legacy) await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
  await protect(page, password); await generate.click(); await panel.getByRole('button', { name: 'Cancel and reset' }).click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  requireSafe(!unsafeRequest, 'Unexpected request method, body or non-asset query.');
  requireSafe(await page.evaluate(() => (window as Window & { sshPersistence?: number }).sshPersistence === 0 && !localStorage.length && !sessionStorage.length), 'Unexpected persistence.');
});

const nativeTest = process.env.SSH_INTEROP === '1' ? test : test.skip;
async function binaryFile(panel: Locator, bytes: Uint8Array) {
  await test.step('SSH binary file ready', async () => {
    await panel.getByLabel('Local private-key file', { exact: true }).evaluate((element, bytes) => {
      const input = element as HTMLInputElement, transfer = new DataTransfer();
      transfer.items.add(new File([new Uint8Array(bytes)], 'disposable-misleading.ppk', { type: 'application/octet-stream' }));
      input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
    }, Array.from(bytes));
    // The change event starts File.arrayBuffer(), not a synchronous React update.
    await expect(panel.getByText(/Binary SSH-1 file loaded/)).toBeVisible({ timeout: 10_000 });
  });
}
test('SSH-1 real worker binary exports, historical warnings, confirmations, ZIP integrity and local-only recovery', async ({ page }) => {
  let unsafeRequest = false;
  page.context().on('request', request => {
    const url = new URL(request.url()), assetQuery = [...url.searchParams].every(([key, value]) => key === 'v' ? /^[0-9a-f]+$/.test(value) : key === 't' ? /^\d+$/.test(value) : key === 'type' ? value === 'module' : ['worker_file', 'import', 'direct'].includes(key) && value === '');
    if (request.method() !== 'GET' || request.postData() !== null || url.hash || !assetQuery) unsafeRequest = true;
  });
  await page.addInitScript(() => {
    (window as Window & { sshPersistence?: number }).sshPersistence = 0;
    const count = () => { const w = window as Window & { sshPersistence?: number }; w.sshPersistence = (w.sshPersistence ?? 0) + 1; };
    Storage.prototype.setItem = count;
    indexedDB.open = (() => { count(); throw new Error('Secret persistence attempted'); }) as typeof indexedDB.open;
    if ('caches' in window) caches.open = async () => { count(); throw new Error('Secret persistence attempted'); };
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  let originalFingerprint = '';
  for (const encrypted of [true, false]) await test.step(encrypted ? 'SSH-1 protected round trip' : 'SSH-1 plaintext round trip', async () => {
    await panel.getByRole('button', { name: 'Reset / discard keys' }).click();
    await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete'); await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa1');
    await expect(panel.getByLabel('OpenSSH private', { exact: true })).toBeDisabled(); await expect(panel.getByLabel('PPK v3 private', { exact: true })).toBeDisabled();
    await expect(panel.getByLabel('SSH-1 binary private', { exact: true })).toBeChecked();
    await expect(panel.getByLabel('Protect private keys with a passphrase')).toBeChecked();
    await expect(panel.getByLabel(historicalEncryptionAcknowledgment)).not.toBeChecked();
    await expect(panel.getByText(/Historical SSH-1 RSA 1024 only/)).toBeVisible();
    const password = encrypted ? randomBytes(24).toString('base64url') : '';
    const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
    if (encrypted) await protect(page, password);
    else { await panel.getByLabel('Protect private keys with a passphrase').uncheck(); await panel.getByLabel('I deliberately choose unencrypted private-key output.').check(); }
    await expect(generate).toBeDisabled(); await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
    if (encrypted) { await expect(generate).toBeDisabled(); await panel.getByLabel(historicalEncryptionAcknowledgment).check(); }
    await expect(generate).toBeEnabled({ timeout: 30_000 }); await generate.click();
    const result = await collect(panel); verifyNative(result, password, process.env.SSH_INTEROP === '1');
    originalFingerprint = result.inspector.fingerprint;
    const binary = result.outputs.find(output => output.format === 'ssh1')!;
    requireSafe(binary.bytes && Buffer.from(binary.bytes.slice(0, 33)).equals(Buffer.from('SSH PRIVATE KEY FILE FORMAT 1.1\n\0')) && !binary.text, 'SSH-1 binary download differs.');
    const pub = panel.getByRole('region', { name: 'SSH-1 decimal public key', exact: true });
    await copyAndCompare(pub);
    await panel.getByLabel('Include SSH-1 decimal public key', { exact: true }).uncheck();
    const download = await readDownload(page, () => panel.getByRole('button', { name: 'Download all as ZIP' }).click());
    {
      const files = unzipSync(download.bytes);
      requireSafe(Object.keys(files).length === 1 && Buffer.from(files[binary.filename]).equals(Buffer.from(binary.bytes)), 'SSH-1 ZIP binary integrity differs.');
    }
    await panel.getByRole('tab', { name: 'Convert key formats' }).click(); await binaryFile(panel, binary.bytes);
    await expect(panel.getByText(/Binary SSH-1 file loaded/)).toBeVisible();
    await expect(panel.getByLabel('Paste private-key text')).toHaveValue('');
    await secret(page, 'Import passphrase', encrypted ? 'wrong' : '');
    const next = randomBytes(24).toString('base64url'); await protect(page, next); await panel.getByLabel(historicalEncryptionAcknowledgment).check();
    const convert = panel.getByRole('button', { name: 'Convert key formats', exact: true }); await convert.click();
    if (encrypted) { await expect(panel.getByRole('alert').filter({ hasText: 'Unable to unlock' })).toBeVisible(); await secret(page, 'Import passphrase', password); await convert.click(); }
    const converted = await collect(panel); requireSafe(converted.inspector.fingerprint === originalFingerprint, 'SSH-1 browser conversion changed identity.'); verifyNative(converted, next, process.env.SSH_INTEROP === '1');
    await panel.getByRole('tab', { name: 'Extract public key' }).click(); await binaryFile(panel, converted.outputs[1].bytes!); await secret(page, 'Import passphrase', next);
    await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    const extracted = await collect(panel); requireSafe(extracted.outputs.length === 1 && extracted.inspector.fingerprint === originalFingerprint, 'SSH-1 browser extraction differs.');
    await panel.getByRole('tab', { name: 'Generate key pair' }).click();
  });
  await test.step('SSH-1 cancellation', async () => {
    await panel.getByLabel('Algorithm family').selectOption('Legacy / Obsolete'); await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa1');
    await protect(page, 'disposable-cancellation'); await panel.getByLabel(historicalEncryptionAcknowledgment).check(); await panel.getByLabel('I understand this algorithm is unsuitable for production use.').check();
    await panel.getByRole('button', { name: 'Generate key pair', exact: true }).click(); await panel.getByRole('button', { name: 'Cancel and reset' }).click();
    await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0); await expect(panel.getByLabel('Protect private keys with a passphrase')).toBeChecked();
    requireSafe(!unsafeRequest && await page.evaluate(() => (window as Window & { sshPersistence?: number }).sshPersistence === 0 && !localStorage.length && !sessionStorage.length), 'SSH-1 secret request/persistence detected.');
  });
});

test('stalled browser clipboard read is bounded and cleanup still closes the page', async ({ page }) => {
  await openTool(page, 'SSH Key Generator & Converter');
  await page.evaluate(() => {
    navigator.clipboard.readText = () => new Promise(() => {});
    navigator.clipboard.writeText = () => new Promise(() => {});
  });
  // No key is generated or copied. Exercise actual nonsettling browser promises,
  // not an artificial sleep or a relaxed application worker deadline.
  let readFailed = false;
  try { await bounded(() => page.evaluate(() => navigator.clipboard.readText()), 'SSH clipboard comparison', 100); }
  catch (error) { readFailed = error instanceof Error && error.message === 'SSH clipboard comparison failed or exceeded its 100 ms deadline (details suppressed).'; }
  requireSafe(readFailed, 'Stalled clipboard read did not fail at its bounded checkpoint.');
  await clearClipboardAndClose(page);
  requireSafe(page.isClosed(), 'Clipboard cleanup prevented page closure.');
});

for (const id of ['rsa512', 'rsa768', 'dsa', 'rsa1']) nativeTest(`${id}: native historical fixtures processed in Chromium without identity replacement`, async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  for (const encrypted of [false, true]) {
    await panel.getByRole('tab', { name: 'Convert key formats' }).click();
    const fixture = id === 'rsa1' ? independentSsh1Fixture(encrypted) : independentFixture(id, encrypted, 'ppk');
    if ('bytes' in fixture) await binaryFile(panel, fixture.bytes); else await localFile(panel, fixture.text);
    await secret(page, 'Import passphrase', fixture.passphrase);
    const password = randomBytes(24).toString('base64url'); await protect(page, password);
    if (id === 'rsa1') await panel.getByLabel(historicalEncryptionAcknowledgment).check();
    await panel.getByRole('button', { name: 'Convert key formats', exact: true }).click();
    const result = await collect(panel); verifyNative(result, password);
    const count = id === 'rsa1' ? 3 : 2;
    requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, count).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, count).join(' '), 'Native legacy browser identity differs.');
  }
});
test('Ed448 real worker PPK conversion, change passphrase, wrong password, tampering and recovery', async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await panel.getByLabel('Algorithm / curve / key size').selectOption('ed448');
  const original = randomBytes(24).toString('base64url'); await protect(page, original);
  await panel.getByLabel('Key comment').fill('Browser Próba 🔐');
  await panel.getByRole('button', { name: 'Generate key pair', exact: true }).click();
  const generated = await collect(panel);
  let input = generated.outputs.find(item => item.format === 'ppk')!.text, password = original;
  for (const next of ['', randomBytes(24).toString('base64url')]) {
    await panel.getByRole('tab', { name: 'Convert key formats' }).click();
    await secret(page, 'Paste private-key text', input);
    await expect(panel.getByLabel('OpenSSH private', { exact: true })).toBeDisabled();
    await expect(panel.getByLabel('OpenSSH private', { exact: true })).not.toBeChecked();
    if (next) await protect(page, next);
    else { await panel.getByLabel('Protect private keys with a passphrase').uncheck(); await panel.getByLabel('I deliberately choose unencrypted private-key output.').check(); }
    const convert = panel.getByRole('button', { name: 'Convert key formats', exact: true });
    if (password) {
      await secret(page, 'Import passphrase', 'wrong'); await convert.click();
      await expect(panel.getByRole('alert')).toContainText('Unable to unlock');
      await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
    }
    await secret(page, 'Import passphrase', password); await convert.click();
    const converted = await collect(panel);
    requireSafe(converted.inspector.fingerprint === generated.inspector.fingerprint, 'Ed448 conversion changed fingerprint.');
    expect(converted.outputs.map(item => item.format)).toEqual(['public', 'ppk']);
    verifyNative(converted, next, process.env.SSH_INTEROP === '1');
    await expect(panel.getByText('Browser Próba 🔐', { exact: true })).toBeVisible();
    input = converted.outputs.find(item => item.format === 'ppk')!.text; password = next;
    await panel.getByRole('tab', { name: 'Extract public key' }).click();
    await secret(page, 'Paste private-key text', input.replace('Comment: Browser', 'Comment: Tampered'));
    await secret(page, 'Import passphrase', password); await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    await expect(panel.getByRole('alert')).toContainText('Unable to unlock');
    await secret(page, 'Paste private-key text', input); await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    const extracted = await collect(panel);
    requireSafe(extracted.inspector.fingerprint === generated.inspector.fingerprint && extracted.outputs.length === 1, 'Ed448 extraction changed identity or exposed private output.');
  }
});

nativeTest('Ed448 independent PuTTYgen plaintext/encrypted fixtures convert in the real Chromium worker', async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  for (const encrypted of [false, true]) {
    const fixture = independentFixture('ed448', encrypted, 'ppk');
    await panel.getByRole('tab', { name: 'Convert key formats' }).click();
    await localFile(panel, fixture.text);
    await expect(panel.getByLabel('OpenSSH private', { exact: true })).toBeDisabled();
    await secret(page, 'Import passphrase', fixture.passphrase);
    const next = randomBytes(24).toString('base64url'); await protect(page, next);
    await panel.getByRole('button', { name: 'Convert key formats', exact: true }).click();
    const result = await collect(panel); verifyNative(result, next);
    requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Ed448 native browser fixture identity differs.');
    await expect(panel.getByText('Independent Próba "comment" \\ @test', { exact: true })).toBeVisible();
  }
});

nativeTest('independent PPK/OpenSSH imports, wrong passwords, tampering, conversion/passphrase changes and recovery', async ({ page }) => {
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  for (const format of ['ppk', 'openssh'] as const) {
    const fixture = independentFixture('ed25519', true, format);
    await panel.getByRole('tab', { name: 'Convert key formats' }).click();
    if (format === 'ppk') {
      await localFile(panel, fixture.text);
      await expect.poll(() => panel.getByLabel('Paste private-key text', { exact: true }).evaluate(element => (element as HTMLTextAreaElement).value.length > 0)).toBe(true);
    } else await secret(page, 'Paste private-key text', fixture.text);
    await secret(page, 'Import passphrase', 'wrong');
    const password = randomBytes(24).toString('base64url'); await protect(page, password);
    const convert = panel.getByRole('button', { name: 'Convert key formats', exact: true }); await expect(convert).toBeEnabled({ timeout: 30_000 }); await convert.click();
    await expect(panel.getByRole('alert')).toContainText('Unable to unlock', { timeout: 60_000 });
    await secret(page, 'Import passphrase', fixture.passphrase); await convert.click();
    const result = await collect(panel); verifyNative(result, password);
    requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Browser conversion changed fixture identity.');
    await panel.getByRole('tab', { name: 'Extract public key' }).click();
    await secret(page, 'Paste private-key text', format === 'ppk' ? fixture.text.replace('Comment: Independent', 'Comment: Tampered') : fixture.text.slice(0, -30));
    await secret(page, 'Import passphrase', fixture.passphrase); await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    await expect(panel.getByRole('alert')).toContainText('Unable to unlock', { timeout: 60_000 });
    await secret(page, 'Paste private-key text', 'x'.repeat(65537));
    await expect(panel.getByRole('button', { name: 'Extract public key', exact: true })).toBeDisabled();
    await expect(panel.getByText('Import exceeds the 64 KiB limit.', { exact: true })).toBeVisible();
    await localFile(panel, 'x'.repeat(65537));
    await expect(panel.getByRole('alert')).toContainText('Import exceeds the 64 KiB limit.');
  }
});

test('RSA 8192 stalled provider cancellation/deadline discard output and allow recovery', async ({ page }) => {
  // Simulate an unfinished native search without burning CPU or changing the app's timer.
  await page.route(/\/ssh\.worker\.ts(?:\?|$)/, async route => {
    if (!new URL(route.request().url()).searchParams.has('worker_file')) { await route.fallback(); return; }
    const response = await route.fetch();
    await route.fulfill({ response, body: `
      const nativeGenerate = crypto.subtle.generateKey.bind(crypto.subtle);
      crypto.subtle.generateKey = (...args) => args[0]?.modulusLength === 8192 ? new Promise(() => {}) : nativeGenerate(...args);
    ` + await response.text() });
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await panel.getByLabel('OpenSSH private', { exact: true }).uncheck();
  await panel.getByLabel('PPK v3 private', { exact: true }).uncheck();
  const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
  async function selectLarge() {
    await panel.getByLabel('Algorithm family').selectOption('RSA');
    await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa8192');
    await expect(generate).toBeEnabled({ timeout: 30_000 });
  }
  await selectLarge(); await generate.click();
  await panel.getByRole('button', { name: 'Cancel and reset' }).click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  // Reset restores protected-by-default settings, then explicitly select public-only again.
  await expect(panel.getByLabel('Protect private keys with a passphrase')).toBeChecked();
  await panel.getByLabel('OpenSSH private', { exact: true }).uncheck();
  await panel.getByLabel('PPK v3 private', { exact: true }).uncheck();
  await selectLarge(); await page.clock.install(); await generate.click();
  await page.clock.fastForward(120_000);
  await expect(panel.getByRole('alert')).toContainText('120-second work deadline');
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toHaveCount(0);
  await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa2048'); await generate.click();
  await expect(panel.getByText('RSA 2048-bit; 2048 bits; exponent 65537', { exact: true })).toBeVisible({ timeout: 60_000 });
  await expect(panel.getByRole('alert')).toHaveCount(0);
});

const heavyTest = process.env.SSH_RSA8192 === '1' ? test : test.skip;
heavyTest('real browser RSA 8192 generation, protected/plain conversion, identity and selected exports', async ({ page, browser }) => {
  test.setTimeout(360_000); // Multiple independent operations, not an increased worker deadline.
  console.info(`RSA8192 browser: Chromium ${browser.version()}`);
  let nativeGenerationMs = 0;
  page.on('console', message => {
    const match = /^RSA8192 generation ms ([0-9.]+)$/.exec(message.text());
    if (match) nativeGenerationMs = Number(match[1]);
  });
  await page.route(/\/ssh\.worker\.ts(?:\?|$)/, async route => {
    if (!new URL(route.request().url()).searchParams.has('worker_file')) { await route.fallback(); return; }
    const response = await route.fetch();
    await route.fulfill({ response, body: `
      const nativeGenerate = crypto.subtle.generateKey.bind(crypto.subtle);
      crypto.subtle.generateKey = async (...args) => {
        const start = performance.now(), pair = await nativeGenerate(...args);
        if (args[0]?.modulusLength === 8192) console.info('RSA8192 generation ms ' + (performance.now() - start).toFixed(1));
        return pair;
      };
    ` + await response.text() });
  });
  const panel = await openTool(page, 'SSH Key Generator & Converter');
  await panel.getByLabel('Algorithm family').selectOption('RSA');
  await panel.getByLabel('Algorithm / curve / key size').selectOption('rsa8192');
  await expect(panel.getByLabel('Protect private keys with a passphrase')).toBeChecked();
  await expect(panel.getByLabel('I understand this algorithm is unsuitable for production use.')).toHaveCount(0);
  await panel.getByLabel('Key comment').fill('Browser Próba "8192" \\ @test');
  const password = randomBytes(24).toString('base64url'); await protect(page, password);
  const generate = panel.getByRole('button', { name: 'Generate key pair', exact: true });
  await expect(generate).toBeEnabled({ timeout: 30_000 });
  const start = performance.now(); await generate.click();
  await expect(panel.getByRole('heading', { name: 'Key Inspector' })).toBeVisible({ timeout: 120_000 });
  console.info(`RSA8192 browser generation + validation + encrypted exports: ${(performance.now() - start).toFixed(1)} ms; native generation: ${nativeGenerationMs} ms`);
  requireSafe(nativeGenerationMs > 0 && nativeGenerationMs < 120_000, 'RSA 8192 native generation did not complete within budget.');
  await expect(panel.getByText('RSA 8192-bit; 8192 bits; exponent 65537', { exact: true })).toBeVisible();
  const generated = await collect(panel); verifyNative(generated, password, process.env.SSH_INTEROP === '1');
  const privateOutput = panel.getByRole('region', { name: /^OpenSSH private key/ });
  await expect(privateOutput.getByRole('button', { name: 'Copy text' })).toBeDisabled();
  await privateOutput.getByLabel('I understand the clipboard risk for this private key.').check();
  await copyAndCompare(privateOutput);
  await panel.getByLabel(/Include PuTTY PPK/).uncheck();
  const zipDownload = await readDownload(page, () => panel.getByRole('button', { name: 'Download all as ZIP' }).click());
  {
    const files = unzipSync(zipDownload.bytes);
    requireSafe(Object.keys(files).length === 2 && files.id_rsa8192 && files['id_rsa8192.pub'] && !files['id_rsa8192.ppk'], 'RSA 8192 ZIP selection differs.');
    requireSafe(new TextDecoder().decode(files.id_rsa8192) === generated.outputs.find(item => item.format === 'openssh')!.text, 'RSA 8192 ZIP content differs.');
  }
  const single = await readDownload(page, () => privateOutput.getByRole('button', { name: 'Download', exact: true }).click());
  {
    // Chromium may append .txt for the existing text/plain download MIME type.
    expect(single.filename).toMatch(/^id_rsa8192(?:\.txt)?$/);
    requireSafe(new TextDecoder().decode(single.bytes) === generated.outputs.find(item => item.format === 'openssh')!.text, 'RSA 8192 download content differs.');
  }
  for (const input of generated.outputs.filter(item => item.private)) {
    await panel.getByRole('tab', { name: 'Extract public key' }).click();
    await secret(page, 'Paste private-key text', input.text); await secret(page, 'Import passphrase', password);
    await panel.getByRole('button', { name: 'Extract public key', exact: true }).click();
    const extracted = await collect(panel);
    requireSafe(extracted.outputs.length === 1 && extracted.inspector.fingerprint === generated.inspector.fingerprint, 'RSA 8192 browser extraction differs.');
    await panel.getByRole('tab', { name: 'Convert key formats' }).click();
    await secret(page, 'Paste private-key text', input.text); await secret(page, 'Import passphrase', password);
    await panel.getByLabel('Protect private keys with a passphrase').uncheck();
    await panel.getByLabel('I deliberately choose unencrypted private-key output.').check();
    const convertStart = performance.now(); await panel.getByRole('button', { name: 'Convert key formats', exact: true }).click();
    const converted = await collect(panel);
    console.info(`RSA8192 browser ${input.format} encrypted -> both plain exports: ${(performance.now() - convertStart).toFixed(1)} ms`);
    requireSafe(converted.inspector.fingerprint === generated.inspector.fingerprint, 'RSA 8192 browser conversion differs.');
    verifyNative(converted, '', process.env.SSH_INTEROP === '1');
    // Reimport each plaintext format in the browser and protect the same key again.
    const plainInput = converted.outputs.find(item => item.format === input.format)!;
    await panel.getByRole('button', { name: 'Reset / discard keys' }).click();
    await secret(page, 'Paste private-key text', plainInput.text); await protect(page, password);
    const reprotectStart = performance.now(); await panel.getByRole('button', { name: 'Convert key formats', exact: true }).click();
    const reprotected = await collect(panel);
    console.info(`RSA8192 browser ${input.format} plain -> both encrypted exports: ${(performance.now() - reprotectStart).toFixed(1)} ms`);
    requireSafe(reprotected.inspector.fingerprint === generated.inspector.fingerprint, 'RSA 8192 browser reprotection differs.');
    verifyNative(reprotected, password, process.env.SSH_INTEROP === '1');
  }
});
