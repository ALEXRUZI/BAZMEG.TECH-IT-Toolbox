import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PasswordSecretGenerator } from '../src/tools/password-secret-generator/PasswordSecretGenerator';
import { textCopyError } from '../src/components/useTextClipboard';

describe('secret clipboard integration', () => {
  const originalClipboard = Object.getOwnPropertyDescriptor(navigator, 'clipboard');
  const writeText = vi.fn();
  beforeEach(() => {
    vi.useFakeTimers();
    writeText.mockReset().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: { writeText } });
  });
  afterEach(() => {
    // Do not retain copied disposable secrets in mock call histories.
    writeText.mockReset();
    vi.useRealTimers();
    if (originalClipboard) Object.defineProperty(navigator, 'clipboard', originalClipboard);
    else Reflect.deleteProperty(navigator, 'clipboard');
  });

  it.each([false, true])('handles failure and retry for recovery=%s without exposing values in assertions', async (recovery) => {
    render(<PasswordSecretGenerator />);
    if (recovery) fireEvent.click(screen.getByRole('button', { name: 'Recovery codes' }));
    const copyLabel = recovery ? 'Copy all' : 'Copy';
    const copiedLabel = recovery ? 'Copied all' : 'Copied';
    writeText.mockRejectedValueOnce(new DOMException('Denied', 'NotAllowedError'));
    await act(async () => fireEvent.click(screen.getByRole('button', { name: copyLabel })));
    expect(screen.getByRole('status')).toHaveTextContent(textCopyError);
    expect(screen.queryByRole('button', { name: copiedLabel })).toBeNull();
    await act(async () => fireEvent.click(screen.getByRole('button', { name: copyLabel })));
    // Boolean comparisons keep secret-bearing diffs out of failure output.
    expect(writeText.mock.calls.at(-1)?.[0] === document.querySelector('pre')?.textContent).toBe(true);
    expect(screen.getByRole('button', { name: copiedLabel })).toBeVisible();
    expect(screen.queryByText(textCopyError)).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: recovery ? 'Regenerate all' : 'Regenerate' }));
    expect(screen.getByRole('button', { name: copyLabel })).toBeVisible();
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    expect(vi.getTimerCount()).toBe(0);
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    expect(screen.getByRole('button', { name: copyLabel })).toBeDisabled();
    expect(document.querySelector('pre')).toBeNull();
  });

  it('does not publish success for a secret cleared during a pending write', async () => {
    let resolve!: () => void;
    writeText.mockReturnValue(new Promise<void>((yes) => { resolve = yes; }));
    render(<PasswordSecretGenerator />);
    fireEvent.click(screen.getByRole('button', { name: 'Copy' }));
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    await act(async () => resolve());
    expect(screen.getByRole('status')).toBeEmptyDOMElement();
    expect(screen.getByRole('button', { name: 'Copy' })).toBeDisabled();
    expect(vi.getTimerCount()).toBe(0);
  });
});
