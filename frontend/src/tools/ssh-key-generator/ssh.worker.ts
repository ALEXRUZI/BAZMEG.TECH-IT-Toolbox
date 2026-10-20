import { generateKey, validateKey } from './sshKeys';
import { processKey } from './sshOperations';
import type { Request } from './sshTypes';

self.onmessage = async (event: MessageEvent<Request | { operation: 'capabilities' }>) => {
  if (event.data.operation === 'capabilities') {
    if (typeof WebAssembly !== 'object' || !globalThis.crypto?.subtle) { self.postMessage({ supported: [] }); return; }
    // RSA sizes are attempted only on explicit generation, not probed on mount.
    // This marker means lazy availability, not proof of any RSA size's support.
    const supported: string[] = ['rsa-lazy', 'dsa-lazy'];
    for (const id of ['ed448', 'ed25519', 'P-256', 'P-384', 'P-521']) {
      try { const key = await generateKey(id, ''); if (id === 'ed448') await validateKey(key); supported.push(id); } catch { /* No fallback. */ }
    }
    self.postMessage({ supported }); return;
  }
  try { self.postMessage({ result: await processKey(event.data) }); }
  catch (error) {
    // Never publish exceptions from dependencies, which may contain secret input.
    const message = error instanceof Error && /^(?:Unsupported|PPK v|PKCS#8|Import exceeds|Use a nonempty|Passphrase confirmation|Confirm the risk|Select at least|Legacy generation|Comment must|Unable to unlock|Key consistency|OpenSSH bcrypt work|PPK Argon2 work|Only RSA|Only single-key)/.test(error.message)
      ? error.message : 'Local cryptographic operation failed. This browser may not support the selected algorithm, or the input is invalid. No output was produced.';
    self.postMessage({ error: message });
  }
};
