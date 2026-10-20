import { readFile } from 'node:fs/promises';
import { test, expect, type Locator, type Page, type TestInfo } from '@playwright/test';
import type { SshCheckpoint } from './sshCheckpoints';

// Fixed titles only: the failure reporter never serializes evaluate arguments,
// DOM snapshots, errors, clipboard text, downloads or arbitrary step titles.
const browserTimeout = 10_000;

export function observeNavigation(page: Page, info: TestInfo) {
  const navigation = { type: 'ssh-navigation-count', description: '0' };
  info.annotations.push(navigation);
  page.on('framenavigated', frame => {
    if (frame !== page.mainFrame()) return;
    navigation.description = String(Number(navigation.description) + 1);
    if (process.env.SSH_E2E_DIAGNOSTICS === '1') console.info(`SSH diagnostic: main-frame navigation ${navigation.description}`);
  });
}

// Locator.evaluate's timeout only bounds finding the element, not its returned
// browser promise. A Node-side timer also works when the page stops scheduling.
export async function bounded<T>(operation: () => Promise<T>, checkpoint: SshCheckpoint, timeout = browserTimeout): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(operation),
      new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('deadline')), timeout); }),
    ]);
  } catch {
    // Browser/library errors can contain secret arguments. Do not retain causes.
    throw new Error(`${checkpoint} failed or exceeded its ${timeout} ms deadline (details suppressed).`);
  } finally { clearTimeout(timer); }
}

export async function clearClipboardAndClose(page: Page) {
  if (page.isClosed()) return;
  try {
    await test.step('SSH clipboard cleanup', () => bounded(async () => {
      await page.bringToFront();
      await page.evaluate(() => navigator.clipboard.writeText(''));
    }, 'SSH clipboard cleanup', 2_000));
  } catch { /* Best effort; a stalled clipboard must never prevent page closure. */ }
  finally { await page.close(); }
}

export async function copyAndCompare(section: Locator, beforeRead?: () => Promise<unknown>) {
  await test.step('SSH clipboard comparison', async () => {
    const page = section.page();
    await bounded(async () => {
      await page.bringToFront();
      await section.getByRole('button', { name: 'Copy text', exact: true }).click({ timeout: browserTimeout });
      // A successful click is not completion of navigator.clipboard.writeText.
      await expect(section.getByText('Copied', { exact: true })).toBeVisible({ timeout: browserTimeout });
      await beforeRead?.();
    }, 'SSH clipboard comparison');
    // Compare inside the browser and return only a boolean, including for
    // hidden private output. Never return clipboard contents to a reporter.
    const equal = await bounded(() => section.locator('pre').evaluate(async element =>
      (await navigator.clipboard.readText()).replace(/\r\n/g, '\n') === element.textContent,
    ), 'SSH clipboard comparison');
    if (!equal) throw new Error('SSH clipboard differs (contents suppressed).');
  });
}

export async function readDownload(page: Page, trigger: () => Promise<unknown>) {
  // Register before the click and observe both rejections immediately.
  const [download] = await test.step('SSH download event', () => bounded(() => Promise.all([
    page.waitForEvent('download', { timeout: browserTimeout }), Promise.resolve().then(trigger),
  ]), 'SSH download event'));
  try {
    const path = await test.step('SSH download completion', () => bounded(() => download.path(), 'SSH download completion'));
    if (!path) throw new Error('SSH download missing (details suppressed).');
    const bytes = await test.step('SSH download file read', () => bounded(() => readFile(path), 'SSH download file read'));
    return { bytes: new Uint8Array(bytes), filename: download.suggestedFilename() };
  } finally {
    await test.step('SSH download cleanup', () => bounded(() => download.delete(), 'SSH download cleanup'));
  }
}
