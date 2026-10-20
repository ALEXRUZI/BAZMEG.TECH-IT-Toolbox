// @vitest-environment node
import { describe, expect, test } from 'vitest';
import { algorithms, supportedFormats } from '../src/tools/ssh-key-generator/sshAlgorithms';
import { base64, check, concat, equal, lines, random, Reader, string, u32, utf8 } from '../src/tools/ssh-key-generator/sshBytes';
import { generateKey, privateFields, validateKey } from '../src/tools/ssh-key-generator/sshKeys';
import { readOpenSsh, writeOpenSsh } from '../src/tools/ssh-key-generator/sshOpenSsh';
import { readPpk, writePpk } from '../src/tools/ssh-key-generator/sshPpk';
import { processKey } from '../src/tools/ssh-key-generator/sshOperations';
import { detectFormat, validateOptions } from '../src/tools/ssh-key-generator/sshValidation';
import type { ExportOptions } from '../src/tools/ssh-key-generator/sshTypes';

const plain: ExportOptions = { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public', 'openssh', 'ppk'] };
const protect = (password: string): ExportOptions => ({ ...plain, protected: true, passphrase: password, confirmation: password });
function same(actual: Uint8Array, expected: Uint8Array) { check(equal(actual, expected), 'Public key changed.'); }

describe('SSH key material and format contracts (real crypto)', () => {
  test('OpenSSH permits zero padding when private fields already align to a block', async () => {
    const key = await generateKey('ed25519', '');
    while ((8 + privateFields(key, 'openssh').length + string(key.comment).length) % 8) key.comment += 'x';
    const payload = concat(u32(42), u32(42), privateFields(key, 'openssh'), string(key.comment));
    const encoded = concat(utf8('openssh-key-v1\0'), string('none'), string('none'), string(new Uint8Array()), u32(1), string(key.publicBlob), string(payload));
    const imported = await readOpenSsh(`-----BEGIN OPENSSH PRIVATE KEY-----\n${lines(base64(encoded))}\n-----END OPENSSH PRIVATE KEY-----\n`, '');
    await validateKey(imported.key); same(imported.key.publicBlob, key.publicBlob);
  });
  // RSA 8192 real material is qualified once in the opt-in ssh-rsa8192 suite.
  for (const a of algorithms.filter(item => item.supported && item.bits !== 8192 && item.id !== 'rsa1')) test(`${a.id}: protected/plain formats preserve key and comment`, async () => {
    const key = await generateKey(a.id, 'Próba "SSH" \\ key @example.test');
    await validateKey(key);
    const password = Array.from(random(24), n => n.toString(16).padStart(2, '0')).join('');
    for (const passphrase of ['', password]) {
      const importedKeys = [await readPpk(await writePpk(key, passphrase), passphrase)];
      if (supportedFormats(a.id).includes('openssh')) importedKeys.push(await readOpenSsh(await writeOpenSsh(key, passphrase), passphrase));
      for (const imported of importedKeys) {
        await validateKey(imported.key); same(imported.key.publicBlob, key.publicBlob);
        check(imported.key.comment === key.comment && imported.encrypted === Boolean(passphrase), 'Comment or protection changed.');
      }
    }
  }, 60_000);

  test('conversion/passphrase change/extraction preserve fingerprint; no private output in extract', async () => {
    const password = 'disposable-test-only-phrase';
    const generated = await processKey({ operation: 'generate', algorithm: 'ed25519', comment: 'fixture', legacyAcknowledged: false, options: protect(password) });
    for (const format of ['openssh', 'ppk'] as const) {
      const input = generated.outputs.find(item => item.format === format)!;
      const converted = await processKey({ operation: 'convert', text: input.text, passphrase: password, options: protect('new-disposable-test-phrase') });
      check(converted.inspector.fingerprint === generated.inspector.fingerprint && converted.inspector.comment === 'fixture', 'Conversion changed identity/comment.');
      for (const output of converted.outputs.filter(item => item.private)) {
        const extracted = await processKey({ operation: 'extract', text: output.text, passphrase: 'new-disposable-test-phrase', options: plain });
        check(extracted.outputs.length === 1 && !extracted.outputs[0].private && extracted.inspector.fingerprint === generated.inspector.fingerprint, 'Extraction changed identity or exposed a private key.');
      }
    }
  }, 60_000);

  test('wrong passwords, PPK tampering and inconsistent public/private material fail safely', async () => {
    const key = await generateKey('ed25519', 'test');
    const open = await writeOpenSsh(key, 'disposable-password'), ppk = await writePpk(key, 'disposable-password');
    await expect(processKey({ operation: 'extract', text: open, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
    await expect(processKey({ operation: 'extract', text: ppk, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
    await expect(processKey({ operation: 'extract', text: ppk.replace('Comment: test', 'Comment: tampered'), passphrase: 'disposable-password', options: plain })).rejects.toThrow('Unable to unlock');
    key.secret = random(32);
    await expect(validateKey(key)).rejects.toThrow();
    const inconsistent = await writeOpenSsh(key, '');
    await expect(processKey({ operation: 'extract', text: inconsistent, passphrase: '', options: plain })).rejects.toThrow('inconsistent key material');
  }, 60_000);

  test('import, KDF, structure, algorithm and unencrypted/legacy acknowledgment limits', async () => {
    expect(() => detectFormat('x'.repeat(65537))).toThrow('64 KiB');
    for (const input of ['PuTTY-User-Key-File-2: ssh-rsa', '-----BEGIN PRIVATE KEY-----', 'not a key']) expect(() => detectFormat(input)).toThrow();
    expect(() => validateOptions({ ...plain, unencryptedAcknowledged: false })).toThrow('Confirm the risk');
    expect(() => validateOptions({ ...protect('one'), confirmation: 'two' })).toThrow('confirmation');
    expect(() => validateOptions({ ...plain, formats: [] })).toThrow('Select');
    for (const id of algorithms.filter(item => !item.supported).map(item => item.id)) await expect(generateKey(id, '')).rejects.toThrow('Unsupported');
    await expect(processKey({ operation: 'generate', algorithm: 'rsa1024', comment: '', legacyAcknowledged: false, options: plain })).rejects.toThrow('Legacy generation');
    await expect(generateKey('ed25519', 'bad\ncomment')).rejects.toThrow('single line');
    const key = await generateKey('ed25519', 'test'), ppk = await writePpk(key, 'password');
    await expect(readPpk(ppk.replace('Argon2-Memory: 65536', 'Argon2-Memory: 9999999'), 'password')).rejects.toThrow('exceeds limits');
    await expect(readPpk(ppk.replace('Argon2-Passes: 3', 'Argon2-Passes: 32'), 'password')).rejects.toThrow('exceeds limits');
    await expect(readPpk(ppk.replace('Public-Lines: 2', 'Public-Lines: 9999'), 'password')).rejects.toThrow();
    const encoded = concat(u32(0xffffffff), string('short'));
    expect(() => new Reader(encoded).string()).toThrow();
    const truncated = (await writeOpenSsh(key, '')).slice(0, -30);
    await expect(readOpenSsh(truncated, '')).rejects.toThrow();
    const highWork = concat(utf8('openssh-key-v1\0'), string('aes256-ctr'), string('bcrypt'), string(concat(string(random(16)), u32(257))), u32(1), string(key.publicBlob), string(new Uint8Array(16)));
    await expect(readOpenSsh(`-----BEGIN OPENSSH PRIVATE KEY-----\n${lines(base64(highWork))}\n-----END OPENSSH PRIVATE KEY-----\n`, 'password')).rejects.toThrow('exceeds limits');
  }, 60_000);
});
