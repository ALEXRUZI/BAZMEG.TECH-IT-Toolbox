import { act, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { HashCalculator } from '../src/tools/hash-calculator/HashCalculator';

class FakeWorker {
  static instances: FakeWorker[] = [];
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onerror: ((event: { preventDefault: () => void }) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  terminate = vi.fn();
  postMessage = vi.fn();
  constructor() { FakeWorker.instances.push(this); }
}
const done = { type: 'done', digests: { sha256: 'a'.repeat(64) }, processed: 3, total: 3, elapsedMs: 12 };
function start() { fireEvent.click(screen.getByRole('button', { name: 'Calculate hashes' })); return FakeWorker.instances.at(-1)!; }
function textMode() { fireEvent.change(screen.getByLabelText('Input mode'), { target: { value: 'text' } }); }
beforeEach(() => { FakeWorker.instances = []; vi.stubGlobal('Worker', FakeWorker); });
afterEach(() => vi.unstubAllGlobals());

describe('hash worker ownership and UI recovery', () => {
  it('defaults to SHA-256 with permanent notice and no security gate', () => {
    render(<HashCalculator />); textMode();
    expect(screen.getByLabelText('SHA-256')).toBeChecked();
    expect(screen.getByText(/MD5 and SHA-1 are cryptographically broken/)).toBeVisible();
    expect(screen.queryByRole('region', { name: 'Legacy algorithm security warning' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Calculate hashes' })).toBeEnabled();
  });
  it.each(['MD5', 'SHA-1'])('%s requires acknowledgment; deselection, reset and remount clear it', (label) => {
    const view = render(<HashCalculator />); textMode();
    fireEvent.click(screen.getByLabelText(label));
    const calculate = screen.getByRole('button', { name: 'Calculate hashes' });
    expect(calculate).toBeDisabled();
    expect(calculate).toHaveAccessibleDescription(/acknowledge/);
    expect(screen.getByRole('heading', { name: `${label} is cryptographically insecure` })).toBeVisible();
    expect(screen.getByRole('link', { name: label === 'MD5' ? 'Read the IETF analysis of MD5 security' : "Read Google's research on SHA-1 collisions" })).toHaveAttribute('href', label === 'MD5' ? 'https://www.rfc-editor.org/rfc/rfc6151.html' : 'https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html');
    fireEvent.click(calculate); expect(FakeWorker.instances).toHaveLength(0);
    fireEvent.click(screen.getByRole('button', { name: 'I understand the risk' }));
    expect(calculate).toBeEnabled();
    expect(screen.getByRole('group', { name: 'Algorithms' })).toHaveFocus();
    expect(screen.getByLabelText(label)).toBeChecked();
    const worker = start();
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(worker.terminate).toHaveBeenCalledOnce();
    expect(calculate).toBeEnabled(); start();
    expect(screen.getByRole('button', { name: 'Restart calculation' })).toBeEnabled();
    fireEvent.click(screen.getByRole('button', { name: 'Restart calculation' }));
    fireEvent.change(screen.getByLabelText('Input mode'), { target: { value: 'file' } }); textMode();
    expect(calculate).toBeEnabled();
    fireEvent.paste(screen.getByLabelText('Text to hash'), { clipboardData: { getData: () => 'abc' } });
    expect(calculate).toBeEnabled();
    fireEvent.click(screen.getByLabelText(label)); fireEvent.click(screen.getByLabelText(label));
    expect(calculate).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'I understand the risk' }));
    fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    fireEvent.click(screen.getByLabelText(label)); expect(calculate).toBeDisabled();
    fireEvent.click(screen.getByRole('button', { name: 'I understand the risk' }));
    view.unmount(); render(<HashCalculator />); textMode(); fireEvent.click(screen.getByLabelText(label));
    expect(screen.getByRole('button', { name: 'Calculate hashes' })).toBeDisabled();
  });
  it('acknowledges per algorithm and consolidates both warnings without duplicate actions', () => {
    render(<HashCalculator />); textMode();
    fireEvent.click(screen.getByLabelText('MD5')); fireEvent.click(screen.getByLabelText('SHA-1'));
    expect(screen.getAllByRole('region', { name: 'Legacy algorithm security warning' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'I understand the risk' })).toHaveLength(1);
    expect(screen.getAllByRole('button', { name: 'Switch to SHA-256' })).toHaveLength(1);
    expect(screen.getAllByRole('heading', { name: /is cryptographically insecure/ })).toHaveLength(2);
    fireEvent.click(screen.getByRole('button', { name: 'I understand the risk' }));
    expect(screen.getByRole('button', { name: 'Calculate hashes' })).toBeEnabled();
    fireEvent.click(screen.getByLabelText('SHA-1')); fireEvent.click(screen.getByLabelText('SHA-1'));
    expect(screen.getByRole('heading', { name: 'SHA-1 is cryptographically insecure' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'MD5 is cryptographically insecure' })).toBeVisible();
    fireEvent.click(screen.getByLabelText('SHA-1'));
    expect(screen.queryByRole('region', { name: 'Legacy algorithm security warning' })).not.toBeInTheDocument();
  });
  it('switch preserves non-legacy choices, invalidates worker results and checksum status without calculating', () => {
    render(<HashCalculator />); textMode();
    fireEvent.click(screen.getByLabelText('SHA-256')); fireEvent.click(screen.getByLabelText('CRC32 (IEEE)'));
    const worker = start(); const queued = worker.onmessage!;
    act(() => queued({ data: { ...done, digests: { crc32: 'cbf43926' } } }));
    fireEvent.change(screen.getByLabelText('Expected checksum'), { target: { value: 'cbf43926' } });
    fireEvent.change(screen.getByLabelText('Checksum algorithm'), { target: { value: 'crc32' } });
    expect(screen.getByText('CRC32 (IEEE): checksum matches.')).toBeVisible();
    fireEvent.click(screen.getByLabelText('MD5')); fireEvent.click(screen.getByLabelText('SHA-1'));
    expect(screen.queryByText('CRC32 (IEEE): checksum matches.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Switch to SHA-256' }));
    act(() => queued({ data: done }));
    expect(screen.getByLabelText('SHA-256')).toBeChecked(); expect(screen.getByLabelText('CRC32 (IEEE)')).toBeChecked();
    expect(screen.getByLabelText('MD5')).not.toBeChecked(); expect(screen.getByLabelText('SHA-1')).not.toBeChecked();
    expect(screen.queryByRole('region', { name: /digest$/ })).not.toBeInTheDocument();
    expect(screen.getByText(/Calculate CRC32/)).toBeVisible();
    expect(FakeWorker.instances).toHaveLength(1);
    expect(screen.getByText(/MD5 and SHA-1 are cryptographically broken/)).toBeVisible();
  });
  it.each(['keyboard', 'paste', 'composition'])('rejected %s boundary edits restore bytes and invalidate stale workers', (kind) => {
    render(<HashCalculator />); textMode();
    const control = screen.getByLabelText('Text to hash') as HTMLTextAreaElement;
    fireEvent.paste(control, { clipboardData: { getData: () => 'A\r' } });
    const old = start(); const queued = old.onmessage!;
    control.setSelectionRange(2, 2);
    if (kind === 'paste') fireEvent.paste(control, { clipboardData: { getData: () => '\n' } });
    else {
      if (kind === 'composition') fireEvent.compositionStart(control);
      const inputType = kind === 'composition' ? 'insertCompositionText' : 'insertLineBreak';
      fireEvent(control, new InputEvent('beforeinput', { bubbles: true, inputType }));
      fireEvent.input(control, { target: { value: 'A\n\n' }, inputType });
      if (kind === 'composition') fireEvent.compositionEnd(control);
    }
    act(() => queued({ data: done }));
    expect(old.terminate).toHaveBeenCalledOnce();
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
    expect(control).toHaveValue('A\n');
    expect(control).toHaveAccessibleDescription(/edit was not applied/);
    expect(start().postMessage).toHaveBeenCalledWith({ input: 'A\r', algorithms: ['sha256'] });
  });
  it('cancels, restarts and ignores queued stale progress/results/errors', () => {
    render(<HashCalculator />); textMode();
    const old = start(); const queued = old.onmessage!;
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(old.terminate).toHaveBeenCalledOnce();
    expect(screen.getByText(/Hashing cancelled/)).toBeInTheDocument();
    const current = start();
    act(() => {
      queued({ data: { type: 'progress', processed: 2, total: 3, elapsedMs: 10 } });
      queued({ data: done });
      queued({ data: { type: 'error', message: 'stale failure' } });
    });
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
    expect(screen.queryByText('stale failure')).not.toBeInTheDocument();
    act(() => current.onmessage!({ data: done }));
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
    expect(current.terminate).toHaveBeenCalledOnce();
    act(() => queued({ data: { type: 'progress', processed: 2, total: 3, elapsedMs: 10 } }));
    expect(screen.getByText('Hashing complete.')).toBeInTheDocument();
  });
  it.each(['reset', 'edit', 'algorithm', 'mode', 'unmount'])('invalidates callbacks on %s', (action) => {
    const view = render(<HashCalculator />); textMode();
    const worker = start(); const queued = worker.onmessage!;
    if (action === 'reset') fireEvent.click(screen.getByRole('button', { name: 'Reset' }));
    if (action === 'edit') fireEvent.input(screen.getByLabelText('Text to hash'), { target: { value: 'replacement' }, inputType: 'insertText' });
    if (action === 'algorithm') fireEvent.click(screen.getByLabelText('MD5'));
    if (action === 'mode') fireEvent.change(screen.getByLabelText('Input mode'), { target: { value: 'file' } });
    if (action === 'unmount') view.unmount();
    act(() => queued({ data: done }));
    expect(worker.terminate).toHaveBeenCalledOnce();
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
  });
  it('terminates processing on file replacement and restarts with the replacement', () => {
    render(<HashCalculator />);
    const choose = screen.getByLabelText('Choose file');
    fireEvent.change(choose, { target: { files: [new File(['a'], 'first.bin')] } });
    const old = start(); const queued = old.onmessage!;
    const replacement = new File(['b'], 'second.bin');
    fireEvent.change(choose, { target: { files: [replacement] } });
    const current = start();
    act(() => queued({ data: done }));
    expect(old.terminate).toHaveBeenCalledOnce();
    expect(current.postMessage).toHaveBeenCalledWith({ input: replacement, algorithms: ['sha256'] });
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
  });
  it.each(['error', 'messageerror', 'wasm'])('shows %s failure and permits retry', (kind) => {
    render(<HashCalculator />); textMode(); const worker = start();
    act(() => {
      if (kind === 'error') worker.onerror!({ preventDefault: vi.fn() });
      if (kind === 'messageerror') worker.onmessageerror!();
      if (kind === 'wasm') worker.onmessage!({ data: { type: 'error', message: 'Could not initialize local WebAssembly hashing.' } });
    });
    expect(screen.getByText(/failed|Could not initialize/)).toBeInTheDocument();
    expect(worker.terminate).toHaveBeenCalledOnce();
    start(); expect(FakeWorker.instances).toHaveLength(2);
  });
  it('handles worker construction failure', () => {
    vi.stubGlobal('Worker', class { constructor() { throw new Error('private error'); } });
    render(<HashCalculator />); textMode(); start();
    expect(screen.getByText(/Could not start the local hash worker/)).toBeInTheDocument();
    expect(screen.queryByText('private error')).not.toBeInTheDocument();
  });
  it('preserves pasted CRLF and Unicode in the worker request', () => {
    render(<HashCalculator />); textMode();
    fireEvent.paste(screen.getByLabelText('Text to hash'), { clipboardData: { getData: () => ' 😀\r\n ' } });
    expect(start().postMessage).toHaveBeenCalledWith({ input: ' 😀\r\n ', algorithms: ['sha256'] });
  });
  it('selection-anchored edits clear completed digests and invalidate queued worker callbacks', () => {
    render(<HashCalculator />); textMode();
    const control = screen.getByLabelText('Text to hash') as HTMLTextAreaElement;
    fireEvent.paste(control, { clipboardData: { getData: () => '\n\r\n' } });
    const first = start(); const queued = first.onmessage!;
    act(() => queued({ data: done }));
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument();
    control.setSelectionRange(0, 0);
    fireEvent(control, new InputEvent('beforeinput', { bubbles: true, inputType: 'deleteContentForward' }));
    fireEvent.input(control, { target: { value: '\n' }, inputType: 'deleteContentForward' });
    act(() => queued({ data: done }));
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
    const active = start(); const stale = active.onmessage!;
    expect(active.postMessage).toHaveBeenCalledWith({ input: '\r\n', algorithms: ['sha256'] });
    control.setSelectionRange(0, 0);
    fireEvent(control, new InputEvent('beforeinput', { bubbles: true, inputType: 'insertText' }));
    fireEvent.input(control, { target: { value: 'x\n' }, inputType: 'insertText' });
    act(() => stale({ data: done }));
    expect(active.terminate).toHaveBeenCalledOnce();
    expect(screen.queryByText('a'.repeat(64))).not.toBeInTheDocument();
    expect(start().postMessage).toHaveBeenCalledWith({ input: 'x\r\n', algorithms: ['sha256'] });
  });
  it('rejects ambiguous input without beforeinput and keeps original worker bytes', () => {
    render(<HashCalculator />); textMode();
    const control = screen.getByLabelText('Text to hash');
    fireEvent.paste(control, { clipboardData: { getData: () => '\n\r\n' } });
    fireEvent.input(control, { target: { value: '\n' }, inputType: 'insertText' });
    expect(control).toHaveValue('\n\n');
    expect(control).toHaveAccessibleDescription(/edit was not applied/);
    expect(start().postMessage).toHaveBeenCalledWith({ input: '\n\r\n', algorithms: ['sha256'] });
  });
  it('equal-byte paste restores its caret without leaving a stale selection for the next edit', () => {
    render(<HashCalculator />); textMode();
    const control = screen.getByLabelText('Text to hash') as HTMLTextAreaElement;
    fireEvent.paste(control, { clipboardData: { getData: () => '😀\n\r\n' } });
    control.setSelectionRange(3, 4);
    fireEvent.paste(control, { clipboardData: { getData: () => '\r\n' } });
    expect(control.selectionStart).toBe(4);
    control.setSelectionRange(2, 2);
    fireEvent(control, new InputEvent('beforeinput', { bubbles: true, inputType: 'insertText' }));
    fireEvent.input(control, { target: { value: '😀x\n\n', selectionStart: 3, selectionEnd: 3 }, inputType: 'insertText' });
    expect(control.selectionStart).toBe(3);
    expect(start().postMessage).toHaveBeenCalledWith({ input: '😀x\n\r\n', algorithms: ['sha256'] });
  });
  it('does not reuse a cancelled beforeinput range for a later range-less edit', async () => {
    render(<HashCalculator />); textMode();
    const control = screen.getByLabelText('Text to hash') as HTMLTextAreaElement;
    fireEvent.paste(control, { clipboardData: { getData: () => '\n\r\n' } });
    control.setSelectionRange(0, 0);
    fireEvent(control, new InputEvent('beforeinput', { bubbles: true, inputType: 'deleteContentForward' }));
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); }); // No paired input event.
    fireEvent.input(control, { target: { value: '\n' }, inputType: 'deleteContentForward' });
    expect(control).toHaveValue('\n\n');
    expect(control).toHaveAccessibleDescription(/edit was not applied/);
    expect(start().postMessage).toHaveBeenCalledWith({ input: '\n\r\n', algorithms: ['sha256'] });
  });
});
