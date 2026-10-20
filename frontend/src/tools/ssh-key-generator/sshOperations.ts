import { algorithm, exportDescription, publicLabel, requireFormat } from './sshAlgorithms';
import { base64, check, utf8, validComment } from './sshBytes';
import { generateKey, validateKey } from './sshKeys';
import { readOpenSsh, writeOpenSsh } from './sshOpenSsh';
import { readPpk, writePpk } from './sshPpk';
import { readSsh1, ssh1Fingerprint, ssh1PublicText, writeSsh1 } from './sshSsh1';
import type { KeyMaterial, OutputFormat, Request, Result } from './sshTypes';
import { detectFormat, validateOptions } from './sshValidation';

export async function processKey(request: Request): Promise<Result> {
  check(request.options && ['generate', 'extract', 'convert'].includes(request.operation));
  if (request.operation !== 'extract') validateOptions(request.options);
  let key: KeyMaterial, format: string, encrypted: boolean;
  if (request.operation === 'generate') {
    const a = algorithm(request.algorithm);
    for (const format of request.options.formats) requireFormat(a.id, format);
    check(!a.legacy || request.legacyAcknowledged === true, 'Legacy generation requires the explicit production-use acknowledgment.');
    key = await generateKey(request.algorithm, request.comment);
    format = 'Generated locally'; encrypted = request.options.protected;
  } else {
    check(request.passphrase.length <= 1024 && utf8(request.passphrase).length <= 1024 && !request.passphrase.includes('\0'), 'Import passphrase exceeds limits or contains NUL.');
    format = detectFormat(request.text, request.bytes);
    let imported;
    try { imported = format === 'SSH-1' ? readSsh1(request.bytes!, request.passphrase) : format === 'OpenSSH' ? await readOpenSsh(request.text, request.passphrase) : await readPpk(request.text.trimStart(), request.passphrase); }
    catch (error) {
      if (error instanceof Error && /(?:exceeds limits|Unsupported|Only single-key|Only RSA)/.test(error.message)) throw error;
      throw new Error('Unable to unlock or validate key: wrong passphrase, malformed data, corruption or inconsistent key material.');
    }
    key = imported.key; encrypted = imported.encrypted;
    if (request.comment !== undefined) { validComment(request.comment); key.comment = request.comment; }
  }
  try { await validateKey(key); }
  catch { throw new Error('Key consistency validation failed; no output was produced.'); }
  const a = algorithm(key.algorithm), fingerprint = a.id === 'rsa1' ? ssh1Fingerprint(key) : `SHA256:${base64(new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(key.publicBlob)))).replace(/=+$/, '')}`;
  const stem = `${a.legacy ? 'legacy-insecure-' : ''}id_${a.id.toLowerCase().replace('-', '')}`;
  const options = request.options, passphrase = options.protected ? options.passphrase : '';
  const formats: OutputFormat[] = request.operation === 'extract' ? ['public'] : options.formats;
  for (const format of formats) requireFormat(a.id, format);
  const outputs: Result['outputs'] = [];
  if (formats.includes('public')) outputs.push({ format: 'public', label: a.id === 'rsa1' || a.id === 'ed448' ? publicLabel(a.id) : 'authorized_keys public key', filename: `${stem}.pub`, private: false, text: a.id === 'rsa1' ? ssh1PublicText(key) : `${a.identifier} ${base64(key.publicBlob)}${key.comment ? ` ${key.comment}` : ''}\n` });
  if (formats.includes('openssh')) outputs.push({ format: 'openssh', label: `OpenSSH private key (${options.protected ? 'encrypted' : 'UNENCRYPTED'})`, filename: stem, private: true, text: await writeOpenSsh(key, passphrase) });
  if (formats.includes('ppk')) outputs.push({ format: 'ppk', label: `PuTTY PPK v3 private key (${options.protected ? 'encrypted' : 'UNENCRYPTED'})`, filename: `${stem}.ppk`, private: true, text: await writePpk(key, passphrase) });
  if (formats.includes('ssh1')) outputs.push({ format: 'ssh1', label: `SSH-1 binary private key (${options.protected ? 'OBSOLETE encryption' : 'UNENCRYPTED'})`, filename: `${stem}.ssh1`, private: true, text: '', bytes: writeSsh1(key, passphrase) });
  return { inspector: { algorithm: a.label, identifier: a.identifier, parameters: a.curve ?? (a.bits ? `${a.bits} bits; exponent 65537` : a.id === 'dsa' ? 'p: 1024 bits; q: 160 bits; historical ssh-dss' : a.id === 'ed448' ? '57-byte seed; 57-byte public key; ~224-bit security strength' : '32-byte Ed25519 seed; 256-bit public encoding'), classification: a.classification, comment: key.comment, fingerprint, format, encrypted, exports: exportDescription(a.id) }, outputs };
}
