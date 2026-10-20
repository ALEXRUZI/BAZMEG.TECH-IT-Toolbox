import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { CommandBlock } from '../src/components/CommandBlock';
import { textCopyError } from '../src/components/useTextClipboard';

function deferred() {
  let resolve!: () => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

describe('text clipboard feedback and lifecycle', () => {
  const writeText = vi.fn();
  const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
  function clipboard(value: unknown) {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value });
  }
  async function clickCopy() {
    await act(async () => { fireEvent.click(screen.getByRole('button')); });
  }
  function notCopied() {
    expect(screen.getByRole('button')).toHaveTextContent(/^Copy$/);
    expect(screen.getByRole('status')).not.toHaveTextContent('Copied');
  }

  beforeEach(() => {
    vi.useFakeTimers();
    writeText.mockReset().mockResolvedValue(undefined);
    clipboard({ writeText });
  });
  afterEach(() => {
    vi.useRealTimers();
    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
    else Reflect.deleteProperty(navigator, 'clipboard');
  });

  it('reports success only after resolution and clears it after 1400ms', async () => {
    const pending = deferred();
    writeText.mockReturnValue(pending.promise);
    render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    expect(writeText).toHaveBeenCalledWith('example command');
    notCopied();
    await act(async () => pending.resolve());
    expect(screen.getByRole('button', { name: 'Copied' })).toBeVisible();
    act(() => vi.advanceTimersByTime(1399));
    expect(screen.getByRole('status')).toHaveTextContent('Copied');
    act(() => vi.advanceTimersByTime(1));
    notCopied();
  });

  it.each(['missing API', 'missing writeText', 'permission denied', 'other rejection', 'synchronous exception'])('handles %s without success and allows retry', async (failure) => {
    if (failure === 'missing API') clipboard(undefined);
    else if (failure === 'missing writeText') clipboard({});
    else if (failure === 'synchronous exception') writeText.mockImplementation(() => { throw new Error('Unavailable'); });
    else writeText.mockRejectedValue(failure === 'permission denied' ? new DOMException('Denied', 'NotAllowedError') : new Error('Failed'));
    render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    expect(screen.getByRole('status')).toHaveTextContent(textCopyError);
    expect(document.querySelector('pre')).toHaveTextContent('example command');
    notCopied();
    clipboard({ writeText });
    writeText.mockResolvedValue(undefined);
    await clickCopy();
    expect(screen.getByRole('button', { name: 'Copied' })).toBeVisible();
    expect(screen.queryByText(textCopyError)).toBeNull();
  });

  it('replaces the success timer on repeated clicks', async () => {
    render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    act(() => vi.advanceTimersByTime(1000));
    await clickCopy();
    expect(writeText).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(1);
    act(() => vi.advanceTimersByTime(400));
    expect(screen.getByRole('button', { name: 'Copied' })).toBeVisible();
    act(() => vi.advanceTimersByTime(1000));
    notCopied();
  });

  it.each(['resolve', 'reject'] as const)('ignores older %s after a newer successful write', async (completion) => {
    const older = deferred();
    const newer = deferred();
    writeText.mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise);
    render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    await clickCopy();
    notCopied();
    await act(async () => newer.resolve());
    await act(async () => completion === 'resolve' ? older.resolve() : older.reject(new Error('Failed')));
    expect(screen.getByRole('button', { name: 'Copied' })).toBeVisible();
    expect(screen.queryByText(textCopyError)).toBeNull();
    expect(vi.getTimerCount()).toBe(1);
  });

  it('does not let older success overwrite a newer failure', async () => {
    const older = deferred();
    writeText.mockReturnValueOnce(older.promise).mockRejectedValueOnce(new Error('Failed'));
    render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    await clickCopy();
    await act(async () => older.resolve());
    expect(screen.getByRole('status')).toHaveTextContent(textCopyError);
    notCopied();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['resolve', 'reject'] as const)('ignores pending %s after unmount', async (completion) => {
    const pending = deferred();
    writeText.mockReturnValue(pending.promise);
    const { unmount } = render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    unmount();
    await act(async () => completion === 'resolve' ? pending.resolve() : pending.reject(new Error('Failed')));
    expect(vi.getTimerCount()).toBe(0);
  });

  it('clears a success timer on unmount', async () => {
    const { unmount } = render(<CommandBlock>example command</CommandBlock>);
    await clickCopy();
    expect(vi.getTimerCount()).toBe(1);
    unmount();
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['resolve', 'reject'] as const)('invalidates pending %s when source changes, even if it changes back', async (completion) => {
    const pending = deferred();
    writeText.mockReturnValueOnce(pending.promise);
    const { rerender } = render(<CommandBlock>first command</CommandBlock>);
    await clickCopy();
    rerender(<CommandBlock>second command</CommandBlock>);
    rerender(<CommandBlock>first command</CommandBlock>);
    await act(async () => completion === 'resolve' ? pending.resolve() : pending.reject(new Error('Failed')));
    notCopied();
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    expect(vi.getTimerCount()).toBe(0);
    await clickCopy();
    expect(screen.getByRole('button', { name: 'Copied' })).toBeVisible();
  });

  it('clears existing success and its timer when source changes', async () => {
    const { rerender } = render(<CommandBlock>first command</CommandBlock>);
    await clickCopy();
    rerender(<CommandBlock>second command</CommandBlock>);
    notCopied();
    expect(vi.getTimerCount()).toBe(0);
  });
});
