import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, open, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { test, expect, openTool } from './fixtures/test';
import type { Locator, Page } from '@playwright/test';
import { algorithms } from '../src/tools/hash-calculator/types';
import references from '../tests/fixtures/hash-references.json' with { type: 'json' };

test.use({ screenshot: 'off', trace: 'off', video: 'off' });
test.afterEach(async ({ page }) => {
  await page.evaluate(() => navigator.clipboard.writeText('')).catch(() => {});
  await page.close();
});
const names = algorithms.map(({ label }) => label);
const ids = algorithms.map(({ id }) => id);
const standardIds = ids.filter((id) => !['blake3', 'blake2b256', 'crc32', 'xxhash32'].includes(id));
async function selectAll(panel: Locator) {
  for (const name of names) await panel.getByLabel(name, { exact: true }).check();
  await panel.getByRole('button', { name: 'I understand the risk' }).click();
}
async function expectAdditional(panel: Locator, vector: typeof references[number]) {
  for (const [id, digest] of Object.entries(vector.digests)) {
    const label = algorithms.find((item) => item.id === id)!.label;
    await expect(panel.getByRole('region', { name: `${label} digest`, exact: true }).getByText(digest, { exact: true })).toBeVisible();
  }
}

test('new algorithms hash independent exact-text vectors and verify explicit checksums in the real worker', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  for (const id of ['crc32', 'xxhash32', 'blake2b256']) await panel.getByLabel(algorithms.find((item) => item.id === id)!.label, { exact: true }).check();
  for (const vector of references.filter((item) => item.text !== undefined)) {
    const control = panel.getByLabel('Text to hash');
    await selectText(control, 0, (await control.inputValue()).length);
    await pasteText(control, vector.text!);
    await panel.getByRole('button', { name: 'Calculate hashes' }).click();
    await expectAdditional(panel, vector);
  }
  const vector = references.find((item) => item.text === 'abc')!;
  const control = panel.getByLabel('Text to hash');
  await selectText(control, 0, (await control.inputValue()).length); await pasteText(control, 'abc');
  await panel.getByRole('button', { name: 'Calculate hashes' }).click(); await expectAdditional(panel, vector);
  for (const [id, digest] of Object.entries(vector.digests)) {
    await panel.getByLabel('Checksum algorithm').selectOption('auto');
    await panel.getByLabel('Expected checksum').fill(` ${digest.toUpperCase()} `);
    await expect(panel.getByLabel('Expected checksum')).toHaveAccessibleDescription(/ambiguous/);
    await panel.getByLabel('Checksum algorithm').selectOption(id);
    const label = algorithms.find((item) => item.id === id)!.label;
    await expect(panel.getByText(`${label}: checksum matches.`, { exact: true })).toBeVisible();
    await panel.getByLabel('Expected checksum').fill('f'.repeat(digest.length));
    await expect(panel.getByText(`${label}: checksum does not match.`, { exact: true })).toBeVisible();
    await panel.getByRole('button', { name: `Copy ${label} digest`, exact: true }).click();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(digest);
  }
  await panel.getByLabel('Input mode').selectOption('file');
  await panel.getByLabel('Choose file').setInputFiles({ name: 'empty.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(0) });
  await panel.getByRole('button', { name: 'Calculate hashes' }).click(); await expectAdditional(panel, references[0]);
});

for (const label of ['MD5', 'SHA-1']) test(`${label} security gate, keyboard acknowledgment and transient lifecycle`, async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.addInitScript(() => {
    const writes: string[] = [];
    (window as unknown as { hashStorageWrites: string[] }).hashStorageWrites = writes;
    for (const method of ['setItem', 'removeItem', 'clear'] as const) {
      const original = Storage.prototype[method];
      Object.defineProperty(Storage.prototype, method, { configurable: true, writable: true, value: new Proxy(original, { apply(target, receiver, args) {
        writes.push(method); return Reflect.apply(target, receiver, args);
      } }) });
    }
    indexedDB.open = new Proxy(indexedDB.open, { apply(target, receiver, args) {
      writes.push('indexedDB.open'); return Reflect.apply(target, receiver, args);
    } });
  });
  const panel = await openTool(page, 'Hash Calculator');
  const warning = panel.getByRole('region', { name: 'Legacy algorithm security warning' });
  const yellow = panel.getByText(/MD5 and SHA-1 are cryptographically broken/);
  await expect(yellow).toBeVisible(); await expect(warning).toHaveCount(0);
  await panel.getByLabel('Input mode').selectOption('text'); await pasteText(panel.getByLabel('Text to hash'), 'abc');
  await expect(panel.getByRole('button', { name: 'Calculate hashes' })).toBeEnabled();
  await panel.getByLabel(label, { exact: true }).check();
  await expect(warning.getByRole('heading', { name: `${label} is cryptographically insecure` })).toBeVisible();
  await expect(warning.getByText(label === 'MD5' ? /distinct content with the same MD5 digest/ : /Practical SHA-1 collision attacks/)).toBeVisible();
  await expect(warning.getByRole('link')).toHaveAccessibleName(label === 'MD5' ? 'Read the IETF analysis of MD5 security' : "Read Google's research on SHA-1 collisions");
  const calculate = panel.getByRole('button', { name: 'Calculate hashes' });
  await expect(calculate).toBeDisabled(); await expect(calculate).toHaveAccessibleDescription(/acknowledge/);
  await warning.getByRole('button', { name: 'I understand the risk' }).focus(); await page.keyboard.press('Enter');
  await expect(panel.getByRole('group', { name: 'Algorithms' })).toBeFocused();
  await expect(warning).toHaveCount(0); await expect(yellow).toBeVisible();
  await calculate.click(); await expect(panel.getByText(createHash(label === 'MD5' ? 'md5' : 'sha1').update('abc').digest('hex'), { exact: true })).toBeVisible();
  await panel.getByLabel('Input mode').selectOption('file'); await panel.getByLabel('Input mode').selectOption('text');
  await expect(calculate).toBeEnabled();
  const other = label === 'MD5' ? 'SHA-1' : 'MD5'; await panel.getByLabel(other, { exact: true }).check();
  await expect(warning.getByRole('heading', { name: `${other} is cryptographically insecure` })).toBeVisible(); await expect(calculate).toBeDisabled();
  await warning.getByRole('button', { name: 'I understand the risk' }).click();
  await panel.getByLabel(label, { exact: true }).uncheck(); await panel.getByLabel(label, { exact: true }).check();
  await expect(calculate).toBeDisabled();
  await warning.getByRole('button', { name: 'I understand the risk' }).click();
  await panel.getByRole('button', { name: 'Reset', exact: true }).click(); await panel.getByLabel(label, { exact: true }).check();
  await expect(calculate).toBeDisabled();
  await warning.getByRole('button', { name: 'I understand the risk' }).click();
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Hash Calculator', exact: true }) }).click();
  await panel.getByLabel('Input mode').selectOption('text'); await panel.getByLabel(label, { exact: true }).check(); await expect(calculate).toBeDisabled();
  expect(await page.evaluate(() => (window as unknown as { hashStorageWrites: string[] }).hashStorageWrites)).toEqual([]);
  expect(await page.evaluate(() => document.cookie)).toBe('');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
});

test('consolidated warning switches only legacy selections, clears results and checksum status without recalculating', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text'); await pasteText(panel.getByLabel('Text to hash'), 'abc');
  await panel.getByLabel('SHA-256', { exact: true }).uncheck(); await panel.getByLabel('CRC32 (IEEE)', { exact: true }).check();
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  const digest = references.find((item) => item.text === 'abc')!.digests.crc32;
  await expect(panel.getByText(digest, { exact: true })).toBeVisible();
  await panel.getByLabel('Expected checksum').fill(digest); await panel.getByLabel('Checksum algorithm').selectOption('crc32');
  await expect(panel.getByText('CRC32 (IEEE): checksum matches.', { exact: true })).toBeVisible();
  await panel.getByLabel('MD5', { exact: true }).check(); await panel.getByLabel('SHA-1', { exact: true }).check();
  const warning = panel.getByRole('region', { name: 'Legacy algorithm security warning' });
  await expect(warning).toHaveCount(1); await expect(warning.getByRole('heading')).toHaveCount(2); await expect(warning.getByRole('button')).toHaveCount(2);
  await warning.getByRole('button', { name: 'Switch to SHA-256' }).focus(); await page.keyboard.press('Space');
  await expect(panel.getByRole('group', { name: 'Algorithms' })).toBeFocused();
  await expect(panel.getByLabel('MD5', { exact: true })).not.toBeChecked(); await expect(panel.getByLabel('SHA-1', { exact: true })).not.toBeChecked();
  await expect(panel.getByLabel('SHA-256', { exact: true })).toBeChecked(); await expect(panel.getByLabel('CRC32 (IEEE)', { exact: true })).toBeChecked();
  await expect(warning).toHaveCount(0); await expect(panel.getByRole('region', { name: /digest$/ })).toHaveCount(0);
  await expect(panel.getByText(/Calculate CRC32/)).toBeVisible(); await expect(panel.getByText(/MD5 and SHA-1 are cryptographically broken/)).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Calculate hashes' })).toBeEnabled();
});

async function pasteText(control: Locator, text: string) {
  await control.evaluate((node, pasted) => {
    const clipboardData = new DataTransfer(); clipboardData.setData('text/plain', pasted);
    node.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
  }, text);
}
async function selectText(control: Locator, start: number, end = start) {
  await control.focus();
  await control.evaluate((node, range) => (node as HTMLTextAreaElement).setSelectionRange(range.start, range.end), { start, end });
}
async function observeWorkerInputs(page: Page) {
  await page.addInitScript(() => {
    const state = window as unknown as { hashInputs: string[] };
    state.hashInputs = [];
    window.Worker = new Proxy(window.Worker, { construct(target, args) {
      const worker = Reflect.construct(target, args) as Worker;
      worker.postMessage = new Proxy(worker.postMessage, { apply(send, receiver, messages) {
        const request = messages[0] as { input?: unknown };
        if (typeof request?.input === 'string') state.hashInputs.push(request.input);
        return Reflect.apply(send, receiver, messages);
      } });
      return worker;
    } });
  });
}
async function expectRawHash(page: Page, panel: Locator, raw: string) {
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText(createHash('sha256').update(raw, 'utf8').digest('hex'), { exact: true })).toBeVisible();
  expect(await page.evaluate(() => (window as unknown as { hashInputs: string[] }).hashInputs.at(-1))).toBe(raw);
}

test('CR/LF boundary edits fail closed, invalidate digests and recover without changing worker bytes', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  const cases = [
    { raw: 'A\r', start: 2, end: 2, key: 'Enter' },
    { raw: '\rX\n', start: 1, end: 1, key: 'Delete' },
    { raw: '\rX\n', start: 2, end: 2, key: 'Backspace' },
    { raw: '\rX\n', start: 1, end: 2, key: 'Enter' },
    { raw: 'A\r', start: 2, end: 2, paste: '\n' },
    { raw: 'X\n', start: 0, end: 1, paste: '\r' },
    { raw: '\rX\n', start: 1, end: 2, paste: '' },
  ];
  for (const item of cases) {
    await panel.getByRole('button', { name: 'Reset', exact: true }).click();
    await pasteText(control, item.raw);
    await expectRawHash(page, panel, item.raw);
    await selectText(control, item.start, item.end);
    if (item.key) await page.keyboard.press(item.key);
    else await pasteText(control, item.paste!);
    await expect(control).toHaveValue(item.raw.replace(/\r\n?/g, '\n'));
    await expect(control).toHaveAttribute('aria-invalid', 'true');
    await expect(control).toHaveAccessibleDescription(/edit was not applied/);
    await expect(panel.getByRole('region', { name: 'SHA-256 digest', exact: true })).toHaveCount(0);
    await expectRawHash(page, panel, item.raw);
    await selectText(control, item.start, item.end);
    await page.keyboard.insertText('雪');
    const offset = (position: number) => {
      let index = 0;
      for (let i = 0; i < position; i++) index += item.raw[index] === '\r' && item.raw[index + 1] === '\n' ? 2 : 1;
      return index;
    };
    const recovered = item.raw.slice(0, offset(item.start)) + '雪' + item.raw.slice(offset(item.end));
    await expect(control).not.toHaveAttribute('aria-invalid', 'true');
    await expectRawHash(page, panel, recovered);
    await control.focus(); await page.keyboard.press('Control+z');
    await expectRawHash(page, panel, item.raw);
    await control.focus(); await page.keyboard.press('Control+Shift+z');
    await expectRawHash(page, panel, recovered);
  }
});

test('composition boundary input events are rejected and can recover', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  await pasteText(control, 'A\r'); await expectRawHash(page, panel, 'A\r');
  await selectText(control, 2);
  // Chromium CDP cannot complete the newline-composition command. Exercise the
  // native event path explicitly; the existing Unicode CDP test remains intact.
  await control.evaluate((element) => {
    const node = element as HTMLTextAreaElement;
    node.dispatchEvent(new CompositionEvent('compositionstart', { bubbles: true }));
    node.dispatchEvent(new InputEvent('beforeinput', { inputType: 'insertCompositionText', bubbles: true }));
    node.value = 'A\n\n';
    node.dispatchEvent(new InputEvent('input', { inputType: 'insertCompositionText', bubbles: true }));
    node.dispatchEvent(new CompositionEvent('compositionend', { bubbles: true }));
  });
  await expect(control).toHaveValue('A\n');
  await expect(control).toHaveAccessibleDescription(/edit was not applied/);
  await expectRawHash(page, panel, 'A\r');
  await selectText(control, 2); await page.keyboard.insertText('雪');
  await expectRawHash(page, panel, 'A\r雪');
});

test('exact mixed-newline deletion uses real pre-edit ranges and worker bytes', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  await pasteText(control, '\n\r\n');
  await expectRawHash(page, panel, '\n\r\n');
  await selectText(control, 0); await page.keyboard.press('Delete');
  await expect(panel.getByRole('region', { name: 'SHA-256 digest', exact: true })).toHaveCount(0);
  await expectRawHash(page, panel, '\r\n');
  await expect(panel.getByText('7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6', { exact: true })).toBeVisible();
  await expect(panel.getByText('01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b', { exact: true })).toHaveCount(0);
  for (const key of ['Delete', 'Backspace']) for (const position of [0, 1, 2]) {
    await selectText(control, 0, (await control.inputValue()).length);
    await pasteText(control, '\n\r\n\r');
    await selectText(control, key === 'Delete' ? position : position + 1);
    await page.keyboard.press(key);
    await expectRawHash(page, panel, ['\r\n\r', '\n\r', '\n\r\n'][position]);
  }
  await selectText(control, 0, (await control.inputValue()).length);
  await pasteText(control, '\n\r\n');
  await selectText(control, 1, 2); await page.keyboard.press('Enter');
  await expectRawHash(page, panel, '\n\n');
  await control.focus(); await page.keyboard.press('Control+z');
  await expectRawHash(page, panel, '\n\r\n');
});

test('cursor edits, selection replacement, repeated Unicode lines, paste and undo/redo preserve raw bytes', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  await pasteText(control, '😀same\r\nsame\nsame\r');
  await selectText(control, 7, 12); await page.keyboard.press('Delete');
  await expectRawHash(page, panel, '😀same\r\nsame\r');
  await selectText(control, 2); await page.keyboard.insertText('雪');
  await expectRawHash(page, panel, '😀雪same\r\nsame\r');
  await selectText(control, 3, 7); await page.keyboard.insertText('界');
  await expectRawHash(page, panel, '😀雪界\r\nsame\r');
  await selectText(control, 4, 5); await pasteText(control, '\n\r\n\r');
  const replaced = '😀雪界\n\r\n\rsame\r';
  await expectRawHash(page, panel, replaced);
  await control.focus(); await page.keyboard.press('Control+z');
  await expectRawHash(page, panel, '😀雪界\r\nsame\r');
  await control.focus(); await page.keyboard.press('Control+Shift+z');
  await expectRawHash(page, panel, replaced);
  await selectText(control, 0); await page.keyboard.press('Enter');
  await expectRawHash(page, panel, '\n' + replaced);
  await control.focus(); await page.keyboard.press('Control+z');
  await control.focus(); await page.keyboard.press('Control+z');
  await control.focus(); await page.keyboard.press('Control+z');
  await expectRawHash(page, panel, '😀雪same\r\nsame\r');
});

test('Chromium composition replacement and commit preserve surrounding raw newlines', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  await pasteText(control, '\n\r\n雪\r');
  await selectText(control, 2, 3);
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Input.imeSetComposition', { text: 'に', selectionStart: 1, selectionEnd: 1 });
  await expect(panel.getByRole('button', { name: 'Calculate hashes' })).toBeDisabled();
  await cdp.send('Input.imeSetComposition', { text: '日本😀', selectionStart: 4, selectionEnd: 4 });
  await cdp.send('Input.insertText', { text: '日本😀' });
  await expect(control).not.toHaveAttribute('aria-invalid', 'true');
  await expectRawHash(page, panel, '\n\r\n日本😀\r');
  await control.focus(); await page.keyboard.press('Control+z');
  await expectRawHash(page, panel, '\n\r\n雪\r');
  await cdp.detach();
});

test('unsupported range-less edits are rejected and cancelable native undo uses raw history', async ({ page }) => {
  await observeWorkerInputs(page);
  const panel = await openTool(page, 'Hash Calculator');
  await panel.getByLabel('Input mode').selectOption('text');
  const control = panel.getByLabel('Text to hash');
  await pasteText(control, '\n\r\n');
  await control.evaluate((node) => {
    (node as HTMLTextAreaElement).value = '\n';
    node.dispatchEvent(new InputEvent('input', { inputType: 'insertText', bubbles: true }));
  });
  await expect(control).toHaveValue('\n\n');
  await expect(control).toHaveAccessibleDescription(/edit was not applied/);
  await expectRawHash(page, panel, '\n\r\n');
  await selectText(control, 0); await page.keyboard.press('Delete');
  await expectRawHash(page, panel, '\r\n');
  await control.evaluate((node) => {
    const applied = node.dispatchEvent(new InputEvent('beforeinput', { inputType: 'historyUndo', bubbles: true, cancelable: true }));
    if (applied) throw new Error('Native history must be intercepted');
  });
  await expectRawHash(page, panel, '\n\r\n');
  await panel.getByRole('button', { name: 'Reset', exact: true }).click();
  await control.focus(); await page.keyboard.press('Control+z');
  await expectRawHash(page, panel, '');
});

test('real worker hashes exact Unicode text, empty input and verifies/copies digests locally', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  await expect(panel.getByLabel('SHA-256', { exact: true })).toBeChecked();
  await panel.getByLabel('Input mode').selectOption('text');
  const input = ' \t雪😀e\u0301\n ';
  await panel.getByLabel('Text to hash').fill(input);
  await selectAll(panel);
  const workerStarted = page.waitForEvent('worker');
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  const worker = await workerStarted;
  expect(worker.url()).toContain('hash.worker');
  await expect(panel.getByText('Hashing complete.', { exact: true })).toBeVisible();
  for (let i = 0; i < ids.length; i++) {
    if (!standardIds.includes(ids[i])) continue;
    const digest = createHash(ids[i]).update(input).digest('hex');
    const result = panel.getByRole('region', { name: `${names[i]} digest`, exact: true });
    await expect(result.getByText(digest, { exact: true })).toBeVisible();
    await result.getByRole('button', { name: `Copy ${names[i]} digest` }).click();
    await expect(result.getByText('Copied', { exact: true }).first()).toBeVisible();
    expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(digest);
  }
  const digest = createHash('sha256').update(input).digest('hex');
  await panel.getByLabel('Expected checksum').fill(' \n' + digest.toUpperCase() + ' ');
  await expect(panel.getByText(/64 hex characters are ambiguous/)).toBeVisible();
  await panel.getByLabel('Checksum algorithm').selectOption('sha256');
  await expect(panel.getByText('SHA-256: checksum matches.', { exact: true })).toBeVisible();
  await panel.getByLabel('Expected checksum').fill('0'.repeat(64));
  await expect(panel.getByText('SHA-256: checksum does not match.', { exact: true })).toBeVisible();
  await panel.getByLabel('Expected checksum').fill('xyz');
  await expect(panel.getByLabel('Expected checksum')).toHaveAttribute('aria-invalid', 'true');
  await panel.getByLabel('Text to hash').fill('');
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText('af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262', { exact: true })).toBeVisible();
  await expectAdditional(panel, references[0]);
  await expect(panel.getByRole('progressbar', { name: 'Hashing progress' })).toHaveAttribute('value', '100');
});

test('picker and drag/drop read exact binary bytes through a real worker', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  const bytes = Buffer.from(Array.from({ length: 4 * 1024 * 1024 + 17 }, (_, i) => i % 251));
  await selectAll(panel);
  await panel.getByLabel('Choose file').setInputFiles({ name: 'boundary.bin', mimeType: 'application/octet-stream', buffer: bytes });
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText('Hashing complete.', { exact: true })).toBeVisible();
  for (const id of standardIds) await expect(panel.getByText(createHash(id).update(bytes).digest('hex'), { exact: true })).toBeVisible();
  await expectAdditional(panel, references.find((vector) => vector.length === bytes.length)!);
  // Independently calculated with @noble/hashes 2.0.1, not hash-wasm.
  await expect(panel.getByText('6c2d4abf04c9bb2828873834efaf40a76f15ab2f74457683062cc754c4c0d1b2', { exact: true })).toBeVisible();
  // Official BLAKE3 vector input: 0..250 repeating, 102400 bytes.
  const transfer = await page.evaluateHandle(() => {
    const data = new DataTransfer();
    data.items.add(new File([Uint8Array.from({ length: 102400 }, (_, i) => i % 251)], 'vector.bin'));
    return data;
  });
  await panel.getByLabel('Choose file').dispatchEvent('drop', { dataTransfer: transfer });
  await transfer.dispose();
  await expect(panel.getByText('Hashing complete.', { exact: true })).not.toBeVisible();
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText('bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085', { exact: true })).toBeVisible();
});

test('real-worker cancellation, restart, replacement, reset and navigation stop old work', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  const transfer = await page.evaluateHandle(() => {
    const chunk = new Uint8Array(1024 * 1024);
    const data = new DataTransfer();
    data.items.add(new File(Array.from({ length: 256 }, () => chunk), 'cancel.bin'));
    return data;
  });
  await panel.getByLabel('Choose file').dispatchEvent('drop', { dataTransfer: transfer });
  await transfer.dispose();
  await selectAll(panel);
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await panel.getByRole('button', { name: 'Cancel', exact: true }).click();
  await expect(panel.getByText(/Hashing cancelled/)).toBeVisible();
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await panel.getByRole('button', { name: 'Restart calculation' }).click();
  await panel.getByLabel('Choose file').setInputFiles({ name: 'replacement.bin', mimeType: 'application/octet-stream', buffer: Buffer.from('abc') });
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText(createHash('sha256').update('abc').digest('hex'), { exact: true })).toBeVisible();
  await panel.getByRole('button', { name: 'Reset', exact: true }).click();
  await expect(panel.getByRole('region', { name: 'SHA-256 digest', exact: true })).toHaveCount(0);
  await panel.getByLabel('Choose file').setInputFiles({ name: 'empty.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(0) });
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await expect(panel.getByText(createHash('sha256').digest('hex'), { exact: true })).toBeVisible();
  // Unmount with active work rather than merely navigating after completion.
  const secondTransfer = await page.evaluateHandle(() => {
    const data = new DataTransfer(); const chunk = new Uint8Array(1024 * 1024);
    data.items.add(new File(Array.from({ length: 256 }, () => chunk), 'unmount.bin'));
    return data;
  });
  await panel.getByLabel('Choose file').dispatchEvent('drop', { dataTransfer: secondTransfer });
  await secondTransfer.dispose();
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'chmod calculator', exact: true }) }).click();
  await page.getByRole('button').filter({ has: page.getByRole('heading', { name: 'Hash Calculator', exact: true }) }).click();
  await expect(panel.getByRole('region', { name: 'SHA-256 digest', exact: true })).toHaveCount(0);
});

test('mobile keyboard, CRLF paste/edit, invalid selection and clipboard failure recover', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const panel = await openTool(page, 'Hash Calculator');
  for (const control of await panel.locator('input, select, textarea').all()) await expect(control).toHaveAccessibleName(/\S/);
  await panel.getByLabel('SHA-256', { exact: true }).focus();
  await page.keyboard.press('Space');
  await expect(panel.getByRole('button', { name: 'Calculate hashes' })).toBeDisabled();
  await page.keyboard.press('Space');
  await panel.getByLabel('Input mode').selectOption('text');
  const text = ' 雪😀\r\nline\r ';
  await panel.getByLabel('Text to hash').evaluate((control, pasted) => {
    const clipboardData = new DataTransfer(); clipboardData.setData('text/plain', pasted);
    control.dispatchEvent(new ClipboardEvent('paste', { clipboardData, bubbles: true, cancelable: true }));
  }, text);
  await panel.getByLabel('Text to hash').focus();
  await page.keyboard.press('Control+End'); await page.keyboard.type('!');
  await panel.getByRole('button', { name: 'Calculate hashes' }).click();
  const digest = createHash('sha256').update(text + '!').digest('hex');
  await expect(panel.getByText(digest, { exact: true })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.evaluate(() => { Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: async () => { throw new Error('denied'); } }); });
  await panel.getByRole('button', { name: 'Copy SHA-256 digest' }).click();
  await expect(panel.getByText(/Could not copy automatically/)).toBeVisible();
  await page.evaluate(() => { delete (navigator.clipboard as Partial<Clipboard>).writeText; });
  await panel.getByRole('button', { name: 'Copy SHA-256 digest' }).click();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(digest);
});

test('rejects multi-file and directory drops without hashing', async ({ page }) => {
  const panel = await openTool(page, 'Hash Calculator');
  const transfer = await page.evaluateHandle(() => {
    const data = new DataTransfer(); data.items.add(new File(['a'], 'a')); data.items.add(new File(['b'], 'b')); return data;
  });
  await panel.getByLabel('Choose file').dispatchEvent('drop', { dataTransfer: transfer });
  await transfer.dispose();
  await expect(panel.getByLabel('Choose file')).toHaveAccessibleDescription(/Choose exactly one file/);
  await panel.getByLabel('Choose file').evaluate((control) => {
    const data = new DataTransfer(); data.items.add(new File([], 'directory'));
    Object.defineProperty(data, 'items', { value: [{ webkitGetAsEntry: () => ({ isDirectory: true }) }] });
    control.dispatchEvent(new DragEvent('drop', { dataTransfer: data, bubbles: true, cancelable: true }));
  });
  await expect(panel.getByLabel('Choose file')).toHaveAccessibleDescription(/Directories are not supported/);
  await expect(panel.getByRole('button', { name: 'Calculate hashes' })).toBeDisabled();
});

for (const size of [100 * 1024 ** 2, 1024 ** 3, 2 * 1024 ** 3 + 17]) {
  test(`large local file ${size} bytes matches independent streaming reference`, async ({ page, browser }) => {
    test.skip(process.env.HASH_LARGE_TESTS !== '1', 'Opt in with HASH_LARGE_TESTS=1; uses local disk and CPU only.');
    test.setTimeout(180_000);
    const directory = await mkdtemp('/tmp/opencode/hash-test-');
    try {
      const path = join(directory, 'zeros.bin');
      const handle = await open(path, 'w');
      await handle.truncate(size); await handle.close(); // Sparse, disk-backed file, not an in-memory whole-file fixture.
      const referenceIds = size === 100 * 1024 ** 2 ? standardIds : ['sha256'];
      const hashStates = referenceIds.map((id) => ({ id, hash: createHash(id) }));
      for await (const chunk of createReadStream(path)) for (const { hash } of hashStates) hash.update(chunk);
      const expected = hashStates.map(({ id, hash }) => ({ id, digest: hash.digest('hex') }));
      const panel = await openTool(page, 'Hash Calculator');
      if (size === 100 * 1024 ** 2) await selectAll(panel);
      await panel.getByLabel('Choose file').setInputFiles(path);
      const cdp = await browser.newBrowserCDPSession();
      async function rss() {
        const { processInfo } = await cdp.send('SystemInfo.getProcessInfo');
        const values = await Promise.all(processInfo.map(async ({ id }) => {
          try { return Number((await readFile(`/proc/${id}/status`, 'utf8')).match(/^VmRSS:\s+(\d+)/m)?.[1] ?? 0); } catch { return 0; }
        }));
        return values.reduce((sum, value) => sum + value, 0) / 1024;
      }
      const baselineMiB = await rss(); let peakMiB = baselineMiB;
      const interval = setInterval(() => { void rss().then((value) => { peakMiB = Math.max(peakMiB, value); }).catch(() => {}); }, 100);
      await page.evaluate(() => { (window as unknown as { hashTicks: number }).hashTicks = 0; setInterval(() => { (window as unknown as { hashTicks: number }).hashTicks++; }, 50); });
      const started = performance.now();
      try {
        await panel.getByRole('button', { name: 'Calculate hashes' }).click();
        await expect(panel.getByText('Hashing complete.', { exact: true })).toBeVisible({ timeout: 120_000 });
      } finally { clearInterval(interval); }
      const elapsedSeconds = (performance.now() - started) / 1000;
      for (const { digest } of expected) await expect(panel.getByText(digest, { exact: true })).toBeVisible();
      if (size === 100 * 1024 ** 2) await expect(panel.getByText('3b66b313c1481abbe678cc31e692937404b855a7a37803ee0759905f7e6fa53b', { exact: true })).toBeVisible();
      if (size === 100 * 1024 ** 2) await expectAdditional(panel, references.find((vector) => vector.zeros)!);
      const ticks = await page.evaluate(() => (window as unknown as { hashTicks: number }).hashTicks);
      expect(ticks).toBeGreaterThan(0);
      console.log('HASH_MEASUREMENT', JSON.stringify({ size, algorithms: size === 100 * 1024 ** 2 ? names : ['SHA-256'], elapsedSeconds, baselineMiB, peakMiB, mainThreadTimerTicks: ticks }));
      // Repeated run must produce the same output, with a fresh worker.
      if (size === 100 * 1024 ** 2) {
        await panel.getByRole('button', { name: 'Calculate hashes' }).click();
        await expect(panel.getByText('Hashing complete.', { exact: true })).toBeVisible({ timeout: 120_000 });
        for (const { digest } of expected) await expect(panel.getByText(digest, { exact: true })).toBeVisible();
        await expectAdditional(panel, references.find((vector) => vector.zeros)!);
      }
      await cdp.detach();
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}
