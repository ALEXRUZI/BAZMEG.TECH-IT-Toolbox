import { cbc } from '@noble/ciphers/aes.js';
import bcrypt from 'bcrypt-pbkdf';
import { base64, check, concat, equal, lines, random, Reader, string, text, u32, unbase64, utf8 } from './sshBytes';
import { privateFields, readPrivate } from './sshKeys';
import type { KeyMaterial } from './sshTypes';

const magic = utf8('openssh-key-v1\0');
export const BCRYPT_ROUNDS = 32;
function derive(passphrase: string, salt: Uint8Array, rounds: number): Uint8Array {
  check(salt.length >= 16 && salt.length <= 64 && rounds >= 1 && rounds <= 256, 'OpenSSH bcrypt work exceeds limits (1–256 rounds, 16–64-byte salt).');
  const password = utf8(passphrase), output = new Uint8Array(48);
  check(password.length > 0 && bcrypt.pbkdf(password, password.length, salt, salt.length, output, 48, rounds) === 0, 'Unable to derive OpenSSH encryption key.');
  return output;
}
async function aesCtr(data: Uint8Array, derived: Uint8Array, operation: 'encrypt' | 'decrypt'): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', new Uint8Array(derived.slice(0, 32)), 'AES-CTR', false, [operation]);
  const parameters = { name: 'AES-CTR', counter: new Uint8Array(derived.slice(32)), length: 128 };
  return new Uint8Array(await crypto.subtle[operation](parameters, key, new Uint8Array(data)));
}
export async function writeOpenSsh(key: KeyMaterial, passphrase: string): Promise<string> {
  const encrypted = Boolean(passphrase), salt = random(16), checkint = random(4);
  const raw = concat(checkint, checkint, privateFields(key, 'openssh'), string(key.comment));
  const padding = (encrypted ? 16 : 8) - raw.length % (encrypted ? 16 : 8);
  let privateBlob = concat(raw, Uint8Array.from({ length: padding }, (_, i) => i + 1));
  if (encrypted) { const derived = derive(passphrase, salt, BCRYPT_ROUNDS); privateBlob = await aesCtr(privateBlob, derived, 'encrypt'); }
  const blob = concat(magic, string(encrypted ? 'aes256-ctr' : 'none'), string(encrypted ? 'bcrypt' : 'none'), string(encrypted ? concat(string(salt), u32(BCRYPT_ROUNDS)) : new Uint8Array()), u32(1), string(key.publicBlob), string(privateBlob));
  return `-----BEGIN OPENSSH PRIVATE KEY-----\n${lines(base64(blob), 70)}\n-----END OPENSSH PRIVATE KEY-----\n`;
}
export async function readOpenSsh(value: string, passphrase: string): Promise<{ key: KeyMaterial; encrypted: boolean }> {
  const match = value.trim().match(/^-----BEGIN OPENSSH PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END OPENSSH PRIVATE KEY-----$/);
  check(match);
  const r = new Reader(unbase64(match[1].replace(/[\r\n]/g, '')));
  check(equal(r.take(magic.length), magic));
  const cipher = r.text(), kdf = r.text(), options = r.string();
  check(r.u32() === 1, 'Only single-key OpenSSH files are supported.');
  const publicBlob = r.string(); let privateBlob = r.string(); r.end();
  const encrypted = cipher !== 'none';
  if (encrypted) {
    check(['aes256-ctr', 'aes256-cbc'].includes(cipher) && kdf === 'bcrypt', 'Unsupported OpenSSH cipher or KDF.');
    const o = new Reader(options), salt = o.string(), rounds = o.u32(); o.end();
    const derived = derive(passphrase, salt, rounds);
    check(privateBlob.length > 0 && privateBlob.length % 16 === 0);
    privateBlob = cipher === 'aes256-ctr' ? await aesCtr(privateBlob, derived, 'decrypt') : cbc(derived.slice(0, 32), derived.slice(32), { disablePadding: true }).decrypt(privateBlob);
  } else check(kdf === 'none' && options.length === 0 && privateBlob.length % 8 === 0);
  const p = new Reader(privateBlob); check(p.u32() === p.u32());
  const key = readPrivate(p, publicBlob, '', 'openssh'); key.comment = text(p.string());
  const padding = p.take(privateBlob.length - p.offset);
  check(padding.length <= (encrypted ? 16 : 8) && padding.every((n, i) => n === i + 1));
  return { key, encrypted };
}
