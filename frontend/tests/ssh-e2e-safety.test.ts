import { afterEach, expect, test, vi } from 'vitest';
import type { Page } from '@playwright/test';
import { bounded, clearClipboardAndClose, readDownload } from '../e2e/fixtures/sshSafety';

vi.mock('@playwright/test', () => ({ test: { step: (_title: string, run: () => unknown) => run() } }));
afterEach(() => vi.useRealTimers());

test('bounded operations suppress secret-bearing errors and clear timers on success/failure', async () => {
  vi.useFakeTimers();
  expect(await bounded(async () => true, 'SSH clipboard comparison')).toBe(true);
  await expect(bounded(async () => { throw new Error('disposable-secret-must-not-leak'); }, 'SSH download file read'))
    .rejects.toThrow('SSH download file read failed or exceeded its 10000 ms deadline (details suppressed).');
  expect(vi.getTimerCount()).toBe(0);
});

for (const checkpoint of ['SSH clipboard comparison', 'SSH download completion', 'SSH download file read', 'SSH download cleanup'] as const) test(`${checkpoint} cannot wait indefinitely`, async () => {
  vi.useFakeTimers();
  const pending = bounded(() => new Promise(() => {}), checkpoint);
  const failed = expect(pending).rejects.toThrow(`${checkpoint} failed or exceeded its 10000 ms deadline (details suppressed).`);
  await vi.advanceTimersByTimeAsync(10_000); await failed;
  expect(vi.getTimerCount()).toBe(0);
});

test('stalled clipboard cleanup still closes the page', async () => {
  vi.useFakeTimers();
  const close = vi.fn().mockResolvedValue(undefined);
  const page = { isClosed: () => false, bringToFront: vi.fn().mockResolvedValue(undefined), evaluate: () => new Promise(() => {}), close } as unknown as Page;
  const cleanup = clearClipboardAndClose(page);
  await vi.advanceTimersByTimeAsync(2_000); await cleanup;
  expect(close).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
});

test('download listener is registered before trigger; missing event has a finite deadline', async () => {
  vi.useFakeTimers();
  const order: string[] = [];
  const waitForEvent = vi.fn(() => { order.push('listen'); return new Promise(() => {}); });
  const page = { waitForEvent } as unknown as Page;
  const pending = readDownload(page, async () => { order.push('click'); });
  const failed = expect(pending).rejects.toThrow('SSH download event failed or exceeded its 10000 ms deadline (details suppressed).');
  await vi.advanceTimersByTimeAsync(10_000); await failed;
  expect(order).toEqual(['listen', 'click']); expect(waitForEvent).toHaveBeenCalledWith('download', { timeout: 10_000 });
});

test('stalled download completion still attempts deletion', async () => {
  vi.useFakeTimers();
  const remove = vi.fn().mockResolvedValue(undefined);
  const download = { path: () => new Promise(() => {}), delete: remove };
  const page = { waitForEvent: async () => download } as unknown as Page;
  const pending = readDownload(page, async () => {});
  const failed = expect(pending).rejects.toThrow('SSH download completion failed or exceeded its 10000 ms deadline (details suppressed).');
  await vi.advanceTimersByTimeAsync(10_000); await failed;
  expect(remove).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
});

test('synchronously failing download trigger still observes the event rejection', async () => {
  let rejectEvent!: (error: Error) => void;
  const page = { waitForEvent: () => new Promise((_, reject) => { rejectEvent = reject; }) } as unknown as Page;
  await expect(readDownload(page, () => { throw new Error('details must not leak'); }))
    .rejects.toThrow('SSH download event failed or exceeded its 10000 ms deadline (details suppressed).');
  // This would be an unhandled rejection if trigger() ran before Promise.all.
  rejectEvent(new Error('event details must not leak'));
});
