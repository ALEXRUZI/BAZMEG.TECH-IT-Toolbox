import { act, fireEvent, render, renderHook, screen } from '@testing-library/react';
import { afterEach, expect, test, vi } from 'vitest';
import { webcrypto } from 'node:crypto';
import { StrictMode } from 'react';
import { useSshWorker } from '../src/tools/ssh-key-generator/useSshWorker';
import { SshKeyGenerator } from '../src/tools/ssh-key-generator/SshKeyGenerator';
import type { Request, Result } from '../src/tools/ssh-key-generator/sshTypes';
import { historicalEncryptionAcknowledgment, legacyAcknowledgment } from '../src/tools/ssh-key-generator/sshAlgorithms';

class WorkerStub {
  static instances: WorkerStub[] = [];
  private handler: ((event: MessageEvent) => void) | null = null;
  queued: ((event: MessageEvent) => void) | null = null;
  get onmessage() { return this.handler; }
  set onmessage(value: ((event: MessageEvent) => void) | null) { this.handler = value; if (value) this.queued = value; }
  onerror: ((event: Event) => void) | null = null;
  onmessageerror: (() => void) | null = null;
  terminate = vi.fn(); postMessage = vi.fn();
  constructor() { WorkerStub.instances.push(this); }
}
const request: Request = { operation: 'generate', algorithm: 'ed25519', comment: '', legacyAcknowledged: false, options: { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public'] } };
const result: Result = { inspector: { algorithm: 'test', identifier: '', parameters: '', classification: '', comment: '', fingerprint: 'test', format: '', encrypted: false, exports: '' }, outputs: [] };
function setup() { WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto); return renderHook(useSshWorker); }
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
test('StrictMode probe cleanup ignores queued callbacks from the replaced probe', () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const hook = renderHook(useSshWorker, { wrapper: StrictMode });
  const [old, current] = WorkerStub.instances;
  act(() => current.onmessage?.(new MessageEvent('message', { data: { supported: ['ed25519'] } })));
  act(() => old.queued?.(new MessageEvent('message', { data: { supported: [] } })));
  expect(hook.result.current.capabilities).toEqual(['ed25519']); hook.unmount();
});
test('replacement, cancel, completion and unmount terminate workers; queued stale results cannot publish', () => {
  const hook = setup();
  const probe = WorkerStub.instances[0]; act(() => probe.onmessage?.(new MessageEvent('message', { data: { supported: ['ed25519'] } })));
  expect(probe.terminate).toHaveBeenCalledOnce();
  act(() => hook.result.current.run(request)); const first = WorkerStub.instances[1], queued = first.onmessage!;
  act(() => hook.result.current.run(request)); expect(first.terminate).toHaveBeenCalledOnce();
  act(() => queued(new MessageEvent('message', { data: { result } })));
  expect(hook.result.current.result).toBeNull(); expect(hook.result.current.busy).toBe(true);
  const second = WorkerStub.instances[2], late = second.onmessage!;
  act(() => hook.result.current.clear()); expect(second.terminate).toHaveBeenCalledOnce();
  act(() => late(new MessageEvent('message', { data: { result } }))); expect(hook.result.current.result).toBeNull();
  act(() => hook.result.current.run(request)); const third = WorkerStub.instances[3];
  act(() => third.onmessage?.(new MessageEvent('message', { data: { result } })));
  expect(third.terminate).toHaveBeenCalledOnce(); expect(hook.result.current.result?.inspector.fingerprint).toBe('test'); expect(hook.result.current.busy).toBe(false);
  act(() => hook.result.current.run(request)); const fourth = WorkerStub.instances[4]; hook.unmount(); expect(fourth.terminate).toHaveBeenCalledOnce();
});
test('work deadline, worker errors and unsupported secure context fail closed', () => {
  vi.useFakeTimers(); const hook = setup();
  act(() => hook.result.current.run(request)); const worker = WorkerStub.instances[1];
  act(() => vi.advanceTimersByTime(120_001)); expect(worker.terminate).toHaveBeenCalledOnce(); expect(hook.result.current.result).toBeNull(); expect(hook.result.current.error).toContain('work deadline');
  act(() => hook.result.current.run(request)); const failed = WorkerStub.instances[2];
  act(() => failed.onerror?.(new Event('error'))); expect(failed.terminate).toHaveBeenCalledOnce(); expect(hook.result.current.error).toContain('worker failed');
  hook.unmount(); vi.stubGlobal('isSecureContext', false);
  const blocked = renderHook(useSshWorker); expect(blocked.result.current.capabilities).toEqual([]); blocked.unmount();
});

test('lazy RSA readiness enables each modern size without RSA 1024 capability and preserves the legacy UI guard', () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const view = render(<SshKeyGenerator />);
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['rsa-lazy'] } })));
  fireEvent.click(screen.getByLabelText('OpenSSH private'));
  fireEvent.click(screen.getByLabelText('PPK v3 private'));
  const family = screen.getByLabelText('Algorithm family'), selection = screen.getByLabelText('Algorithm / curve / key size');
  const generate = screen.getByRole('button', { name: 'Generate key pair' });
  fireEvent.change(family, { target: { value: 'RSA' } });
  for (const id of ['rsa2048', 'rsa3072', 'rsa4096', 'rsa8192']) {
    fireEvent.change(selection, { target: { value: id } });
    expect(generate).toBeEnabled();
  }
  expect(screen.getByText(/Resource-intensive and generally unnecessary/)).toBeVisible();
  expect(screen.queryByLabelText('I understand this algorithm is unsuitable for production use.')).toBeNull();
  fireEvent.change(family, { target: { value: 'Legacy / Obsolete' } });
  fireEvent.change(selection, { target: { value: 'rsa1024' } });
  const acknowledgment = screen.getByLabelText('I understand this algorithm is unsuitable for production use.');
  expect(acknowledgment).not.toBeChecked(); expect(generate).toBeDisabled();
  fireEvent.click(acknowledgment); expect(generate).toBeEnabled();
  fireEvent.change(family, { target: { value: 'RSA' } });
  fireEvent.change(family, { target: { value: 'Legacy / Obsolete' } });
  fireEvent.change(selection, { target: { value: 'rsa1024' } });
  expect(screen.getByLabelText('I understand this algorithm is unsuitable for production use.')).not.toBeChecked(); expect(generate).toBeDisabled();
  view.unmount();
});

for (const algorithm of ['rsa8192', 'ed448', 'rsa512', 'rsa768', 'dsa', 'rsa1']) test(`${algorithm} cancel/timeout discard late callbacks and a subsequent operation succeeds`, () => {
  vi.useFakeTimers(); const hook = setup();
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['rsa-lazy', 'ed448'] } })));
  const large: Request = { ...request, algorithm };
  act(() => hook.result.current.run(large));
  const cancelled = WorkerStub.instances[1], lateCancel = cancelled.queued!;
  expect(cancelled.postMessage).toHaveBeenCalledWith(large);
  act(() => hook.result.current.clear());
  expect(cancelled.terminate).toHaveBeenCalledOnce();
  act(() => hook.result.current.run(large));
  const expired = WorkerStub.instances[2], lateTimeout = expired.queued!;
  act(() => vi.advanceTimersByTime(119_999));
  expect(hook.result.current.busy).toBe(true);
  act(() => vi.advanceTimersByTime(1));
  expect(expired.terminate).toHaveBeenCalledOnce();
  expect(hook.result.current.error).toContain('120-second work deadline');
  act(() => hook.result.current.run({ ...request, algorithm: 'rsa2048' }));
  act(() => { lateCancel(new MessageEvent('message', { data: { result } })); lateTimeout(new MessageEvent('message', { data: { result } })); });
  expect(hook.result.current.result).toBeNull(); expect(hook.result.current.busy).toBe(true);
  act(() => WorkerStub.instances[3].onmessage?.(new MessageEvent('message', { data: { result } })));
  expect(hook.result.current.result).toEqual(result); expect(hook.result.current.error).toBe('');
  hook.unmount();
});

test('Ed448 format selection is compatible on switches, header hints and direct worker requests', () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const view = render(<SshKeyGenerator />);
  const selection = screen.getByLabelText('Algorithm / curve / key size');
  fireEvent.change(selection, { target: { value: 'ed448' } });
  expect(screen.getByRole('button', { name: 'Generate key pair' })).toBeDisabled();
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['ed448', 'ed25519'] } })));
  expect(screen.getByLabelText('OpenSSH private')).toBeDisabled();
  expect(screen.getByLabelText('OpenSSH private')).not.toBeChecked();
  expect(screen.getByLabelText('OpenSSH private')).toHaveAccessibleDescription('OpenSSH private-key format is not supported for Ed448.');
  expect(screen.getByLabelText('PPK v3 private')).toBeChecked();
  expect(screen.getByLabelText('Protect private keys with a passphrase')).toBeChecked();
  fireEvent.click(screen.getByLabelText('Protect private keys with a passphrase'));
  fireEvent.click(screen.getByLabelText('I deliberately choose unencrypted private-key output.'));
  fireEvent.click(screen.getByRole('button', { name: 'Generate key pair' }));
  expect(WorkerStub.instances[1].postMessage).toHaveBeenCalledWith(expect.objectContaining({ algorithm: 'ed448', options: expect.objectContaining({ formats: ['public', 'ppk'] }) }));
  fireEvent.click(screen.getByRole('button', { name: 'Cancel and reset' }));
  // An OpenSSH-only selection switches to a useful Ed448 default, not an empty output set.
  fireEvent.click(screen.getByLabelText('authorized_keys')); fireEvent.click(screen.getByLabelText('PPK v3 private'));
  fireEvent.change(selection, { target: { value: 'ed448' } });
  expect(screen.getByLabelText('RFC 8709 public key')).toBeChecked(); expect(screen.getByLabelText('PPK v3 private')).toBeChecked();
  fireEvent.pointerEnter(screen.getByText('OpenSSH private', { exact: true }), { pointerType: 'mouse' });
  expect(screen.getByRole('tooltip')).toHaveTextContent('OpenSSH private-key format is not supported for Ed448.');
  fireEvent.change(selection, { target: { value: 'ed25519' } });
  expect(screen.queryByRole('tooltip')).toBeNull();
  expect(screen.getByText('OpenSSH private', { exact: true })).not.toHaveClass('line-through');
  expect(screen.getByLabelText('OpenSSH private')).toBeEnabled(); expect(screen.getByLabelText('OpenSSH private')).not.toBeChecked();
  fireEvent.click(screen.getByRole('tab', { name: 'Convert key formats' }));
  expect(screen.queryByRole('button', { name: /Why .* is unavailable/ })).toBeNull();
  expect(screen.getByText('SSH-1 binary private', { exact: true })).not.toHaveClass('line-through');
  fireEvent.change(screen.getByLabelText('Paste private-key text'), { target: { value: 'PuTTY-User-Key-File-3: ssh-ed448\n' } });
  expect(screen.getByLabelText('OpenSSH private')).toBeDisabled(); expect(screen.getByLabelText('OpenSSH private')).not.toBeChecked();
  fireEvent.change(screen.getByLabelText('Paste private-key text'), { target: { value: 'PuTTY-User-Key-File-3: ssh-ed25519\n' } });
  expect(screen.getByLabelText('OpenSSH private')).toBeEnabled();
  view.unmount();
});
test('legacy switches reset all security acknowledgments; SSH-1 defaults to binary protected output', () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const view = render(<SshKeyGenerator />);
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['rsa-lazy', 'dsa-lazy'] } })));
  fireEvent.change(screen.getByLabelText('Algorithm family'), { target: { value: 'Legacy / Obsolete' } });
  const selection = screen.getByLabelText('Algorithm / curve / key size'), generate = screen.getByRole('button', { name: 'Generate key pair' });
  for (const id of ['rsa512', 'rsa768', 'dsa', 'rsa1']) {
    fireEvent.change(selection, { target: { value: id } });
    expect(screen.getByLabelText(legacyAcknowledgment)).not.toBeChecked(); expect(generate).toBeDisabled();
    fireEvent.click(screen.getByLabelText(legacyAcknowledgment));
  }
  expect(screen.getByLabelText('SSH-1 binary private')).toBeChecked(); expect(screen.getByLabelText('OpenSSH private')).toBeDisabled(); expect(screen.getByLabelText('PPK v3 private')).toBeDisabled();
  expect(screen.getByLabelText('Protect private keys with a passphrase')).toBeChecked(); expect(screen.getByLabelText(historicalEncryptionAcknowledgment)).not.toBeChecked();
  fireEvent.change(screen.getByLabelText('Output passphrase'), { target: { value: 'disposable' } }); fireEvent.change(screen.getByLabelText('Confirm output passphrase'), { target: { value: 'disposable' } });
  expect(generate).toBeDisabled(); fireEvent.click(screen.getByLabelText(historicalEncryptionAcknowledgment)); expect(generate).toBeEnabled();
  fireEvent.change(selection, { target: { value: 'dsa' } }); fireEvent.change(selection, { target: { value: 'rsa1' } });
  expect(screen.getByLabelText(historicalEncryptionAcknowledgment)).not.toBeChecked(); expect(screen.getByLabelText(legacyAcknowledgment)).not.toBeChecked();
  fireEvent.click(screen.getByLabelText('Protect private keys with a passphrase')); fireEvent.click(screen.getByLabelText('I deliberately choose unencrypted private-key output.'));
  fireEvent.change(selection, { target: { value: 'rsa768' } }); expect(screen.getByLabelText('I deliberately choose unencrypted private-key output.')).not.toBeChecked();
  view.unmount();
});

function pendingFile(name = 'disposable.ppk') {
  // Public format marker only, not private key material; crypto remains worker-owned.
  const bytes = new TextEncoder().encode('SSH PRIVATE KEY FILE FORMAT 1.1\n\0');
  let finish!: (bytes: ArrayBuffer) => void;
  const file = new File([bytes], name);
  Object.defineProperty(file, 'arrayBuffer', { value: () => new Promise<ArrayBuffer>(resolve => { finish = resolve; }) });
  return { file, bytes, finish: () => finish(new Uint8Array(bytes).buffer) };
}

test('pending SSH-1 file read survives passphrase, output and comment edits', async () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const view = render(<SshKeyGenerator />);
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['rsa-lazy'] } })));
  fireEvent.click(screen.getByRole('tab', { name: 'Convert key formats' }));
  const pending = pendingFile();
  fireEvent.change(screen.getByLabelText('Local private-key file'), { target: { files: [pending.file] } });
  fireEvent.change(screen.getByLabelText('Import passphrase'), { target: { value: 'disposable-import' } });
  fireEvent.change(screen.getByLabelText('Output passphrase'), { target: { value: 'disposable-export' } });
  fireEvent.change(screen.getByLabelText('Confirm output passphrase'), { target: { value: 'disposable-export' } });
  fireEvent.click(screen.getByLabelText('Replace imported comment (otherwise preserve it)'));
  fireEvent.change(screen.getByLabelText('Key comment'), { target: { value: 'public comment' } });
  await act(async () => pending.finish());
  expect(screen.getByText(/Binary SSH-1 file loaded/)).toBeVisible();
  // Discovering the profile must still reset its historical protection acknowledgment.
  expect(screen.getByLabelText(historicalEncryptionAcknowledgment)).not.toBeChecked();
  fireEvent.click(screen.getByLabelText(historicalEncryptionAcknowledgment));
  const convert = screen.getByRole('button', { name: 'Convert key formats' });
  expect(convert).toBeEnabled(); fireEvent.click(convert);
  const sent = WorkerStub.instances[1].postMessage.mock.calls[0][0] as Request;
  expect(sent.operation === 'convert' && sent.passphrase === 'disposable-import' && sent.comment === 'public comment').toBe(true);
  expect(sent.options.passphrase === 'disposable-export' && sent.options.confirmation === 'disposable-export').toBe(true);
  expect(sent.options.formats).toEqual(['public', 'ssh1']);
  expect(sent.options.historicalEncryptionAcknowledged).toBe(true);
  expect(sent.operation !== 'generate' && Array.from(sent.bytes ?? []).join() === Array.from(pending.bytes).join()).toBe(true);
  view.unmount();
});

for (const change of ['reset', 'tab', 'paste', 'replacement', 'unmount'] as const) test(`pending file read is discarded on ${change}`, async () => {
  WorkerStub.instances = []; vi.stubGlobal('Worker', WorkerStub); vi.stubGlobal('isSecureContext', true); vi.stubGlobal('crypto', webcrypto);
  const view = render(<SshKeyGenerator />);
  act(() => WorkerStub.instances[0].onmessage?.(new MessageEvent('message', { data: { supported: ['rsa-lazy'] } })));
  fireEvent.click(screen.getByRole('tab', { name: 'Extract public key' }));
  const pending = pendingFile();
  fireEvent.change(screen.getByLabelText('Local private-key file'), { target: { files: [pending.file] } });
  if (change === 'reset') fireEvent.click(screen.getByRole('button', { name: 'Reset / discard keys' }));
  if (change === 'tab') fireEvent.click(screen.getByRole('tab', { name: 'Generate key pair' }));
  if (change === 'paste') fireEvent.change(screen.getByLabelText('Paste private-key text'), { target: { value: 'public replacement marker' } });
  if (change === 'unmount') view.unmount();
  if (change === 'replacement') {
    const replacement = pendingFile('replacement.ppk');
    fireEvent.change(screen.getByLabelText('Local private-key file'), { target: { files: [replacement.file] } });
    await act(async () => replacement.finish());
    expect(screen.getByText(/Binary SSH-1 file loaded/)).toBeVisible();
    // Resolve the old read with incompatible text so a stale publication is observable.
    Object.assign(pending.bytes, new TextEncoder().encode('not SSH-1'));
  }
  await act(async () => pending.finish());
  if (change === 'replacement') expect(screen.getByText(/Binary SSH-1 file loaded/)).toBeVisible();
  else expect(screen.queryByText(/Binary SSH-1 file loaded/)).toBeNull();
  if (change === 'paste') expect(screen.getByLabelText('Paste private-key text')).toHaveValue('public replacement marker');
  view.unmount();
});
