import { check, equal, MAX_IMPORT, utf8 } from './sshBytes';
import { algorithms } from './sshAlgorithms';
import type { ExportOptions } from './sshTypes';

// Unauthenticated UI hint only. The worker parses, authenticates and validates the actual key.
export function inputAlgorithmHint(value: string, bytes?: Uint8Array): string | undefined {
  const magic = utf8('SSH PRIVATE KEY FILE FORMAT 1.1\n\0');
  if (bytes && equal(bytes.slice(0, magic.length), magic)) return 'rsa1';
  const identifier = /^PuTTY-User-Key-File-3: ([^\r\n]+)/.exec(value.trimStart())?.[1];
  return algorithms.find(item => item.identifier === identifier && !item.bits)?.id;
}

export function detectFormat(value: string, bytes?: Uint8Array): string {
  if (bytes) {
    check(bytes instanceof Uint8Array && bytes.length <= MAX_IMPORT && value === '', 'Import exceeds the 64 KiB limit or mixes binary and text input.');
    if (inputAlgorithmHint('', bytes) === 'rsa1') return 'SSH-1';
    throw new Error('Unsupported binary input format. Supply a historical SSH-1 FORMAT 1.1 file.');
  }
  check(value.length <= MAX_IMPORT && utf8(value).length <= MAX_IMPORT, 'Import exceeds the 64 KiB limit.');
  const content = value.trimStart();
  if (content.startsWith('-----BEGIN OPENSSH PRIVATE KEY-----')) return 'OpenSSH';
  if (content.startsWith('PuTTY-User-Key-File-3: ')) return 'PPK v3';
  if (/^PuTTY-User-Key-File-[12]:/.test(content)) throw new Error('PPK v1/v2 is unsupported; use PuTTYgen locally to upgrade to PPK v3.');
  if (/^-----BEGIN (?:ENCRYPTED |RSA |EC |DSA )?PRIVATE KEY-----/.test(content)) throw new Error('PKCS#8 and traditional PEM imports are not implemented. Convert locally with ssh-keygen or PuTTYgen first.');
  throw new Error('Unsupported input format. Supply OpenSSH/PPK v3 text or use local file input for SSH-1 binary; not certificates, public-only or ssh.com files.');
}
export function validateOptions(options: ExportOptions): void {
  check(options.formats.length > 0 && options.formats.length <= 4 && new Set(options.formats).size === options.formats.length && options.formats.every(format => ['public', 'openssh', 'ppk', 'ssh1'].includes(format)), 'Select at least one supported output.');
  if (!options.formats.some(format => format !== 'public')) return;
  if (options.protected) {
    check(utf8(options.passphrase).length > 0 && utf8(options.passphrase).length <= 1024 && !options.passphrase.includes('\0'), 'Use a nonempty passphrase of at most 1024 UTF-8 bytes without NUL.');
    check(options.passphrase === options.confirmation, 'Passphrase confirmation does not match.');
  } else check(options.unencryptedAcknowledged === true, 'Confirm the risk before producing unencrypted private keys.');
  if (options.protected && options.formats.includes('ssh1')) check(options.historicalEncryptionAcknowledged === true, 'Confirm the risk of obsolete SSH-1 passphrase protection.');
}
