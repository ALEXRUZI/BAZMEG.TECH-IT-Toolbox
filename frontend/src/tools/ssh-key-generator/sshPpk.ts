import { cbc } from '@noble/ciphers/aes.js';
import { argon2id, argon2i, argon2d } from 'hash-wasm';
import { algorithm } from './sshAlgorithms';
import { base64, check, concat, hex, lines, random, Reader, string, unbase64, unhex } from './sshBytes';
import { privateFields, readPrivate } from './sshKeys';
import type { KeyMaterial } from './sshTypes';

export const ARGON_MEMORY = 65536, ARGON_PASSES = 3;
async function derive(passphrase: string, salt: Uint8Array, memory: number, passes: number, parallelism: number, flavour: string): Promise<Uint8Array> {
  check(Number.isInteger(memory) && memory >= 8 * parallelism && memory <= 65536 && Number.isInteger(passes) && passes >= 1 && passes <= 32 && Number.isInteger(parallelism) && parallelism >= 1 && parallelism <= 4 && memory * passes <= 1048576 && salt.length >= 8 && salt.length <= 64, 'PPK Argon2 work exceeds limits (64 MiB, 32 passes, 4 lanes, 1 GiB-pass total).');
  const kdf = { Argon2id: argon2id, Argon2i: argon2i, Argon2d: argon2d }[flavour];
  check(kdf && passphrase.length > 0, 'Unsupported PPK KDF or missing passphrase.');
  return kdf({ password: passphrase, salt, iterations: passes, parallelism, memorySize: memory, hashLength: 80, outputType: 'binary' });
}
async function mac(key: Uint8Array, data: Uint8Array): Promise<string> {
  // WebCrypto implementations reject a zero-length HMAC key. One SHA-256
  // block of zero bytes is HMAC-equivalent to PPK v3's empty key.
  const nativeKey = await crypto.subtle.importKey('raw', key.length ? new Uint8Array(key) : new Uint8Array(64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return hex(new Uint8Array(await crypto.subtle.sign('HMAC', nativeKey, new Uint8Array(data))));
}
const preimage = (identifier: string, encryption: string, comment: string, pub: Uint8Array, priv: Uint8Array) => concat(string(identifier), string(encryption), string(comment), string(pub), string(priv));
const section = (name: string, data: Uint8Array) => { const encoded = lines(base64(data)); return `${name}-Lines: ${encoded.split('\n').length}\n${encoded}\n`; };
export async function writePpk(key: KeyMaterial, passphrase: string): Promise<string> {
  const identifier = algorithm(key.algorithm).identifier, encrypted = Boolean(passphrase), encryption = encrypted ? 'aes256-cbc' : 'none';
  let privateBlob = privateFields(key, 'ppk'); let derived: Uint8Array = new Uint8Array();
  let kdf = '';
  if (encrypted) {
    const salt = random(16); derived = await derive(passphrase, salt, ARGON_MEMORY, ARGON_PASSES, 1, 'Argon2id');
    privateBlob = concat(privateBlob, random((16 - privateBlob.length % 16) % 16));
    kdf = `Key-Derivation: Argon2id\nArgon2-Memory: ${ARGON_MEMORY}\nArgon2-Passes: ${ARGON_PASSES}\nArgon2-Parallelism: 1\nArgon2-Salt: ${hex(salt)}\n`;
  }
  const signature = await mac(derived.slice(48), preimage(identifier, encryption, key.comment, key.publicBlob, privateBlob));
  const stored = encrypted ? cbc(derived.slice(0, 32), derived.slice(32, 48), { disablePadding: true }).encrypt(privateBlob) : privateBlob;
  return `PuTTY-User-Key-File-3: ${identifier}\nEncryption: ${encryption}\nComment: ${key.comment}\n${section('Public', key.publicBlob)}${kdf}${section('Private', stored)}Private-MAC: ${signature}\n`;
}
export async function readPpk(value: string, passphrase: string): Promise<{ key: KeyMaterial; encrypted: boolean }> {
  const rows = value.replace(/\r\n?/g, '\n').replace(/\n$/, '').split('\n'); let index = 0;
  const header = (name: string) => { const row = rows[index++]; check(row?.startsWith(`${name}: `)); return row.slice(name.length + 2); };
  const identifier = header('PuTTY-User-Key-File-3'), encryption = header('Encryption'), comment = header('Comment');
  check(['none', 'aes256-cbc'].includes(encryption), 'Unsupported PPK encryption.');
  const blob = (name: string) => { const rawCount = header(`${name}-Lines`); check(/^[1-9][0-9]{0,3}$/.test(rawCount)); const count = Number(rawCount); check(count <= 1024 && index + count <= rows.length); const encoded = rows.slice(index, index + count); check(encoded.every(row => row.length > 0 && row.length <= 64)); index += count; return unbase64(encoded.join('')); };
  const publicBlob = blob('Public'), encrypted = encryption !== 'none'; let derived: Uint8Array = new Uint8Array();
  if (encrypted) {
    const flavour = header('Key-Derivation');
    const number = (name: string) => { const raw = header(name); check(/^[1-9][0-9]{0,6}$/.test(raw)); return Number(raw); };
    const memory = number('Argon2-Memory'), passes = number('Argon2-Passes'), parallelism = number('Argon2-Parallelism');
    derived = await derive(passphrase, unhex(header('Argon2-Salt')), memory, passes, parallelism, flavour);
  }
  let privateBlob = blob('Private'); const signature = header('Private-MAC'); check(index === rows.length && /^[a-fA-F0-9]{64}$/.test(signature));
  if (encrypted) { check(privateBlob.length > 0 && privateBlob.length % 16 === 0); privateBlob = cbc(derived.slice(0, 32), derived.slice(32, 48), { disablePadding: true }).decrypt(privateBlob); }
  check(await mac(derived.slice(48), preimage(identifier, encryption, comment, publicBlob, privateBlob)) === signature.toLowerCase());
  const r = new Reader(privateBlob), key = readPrivate(r, publicBlob, comment, 'ppk');
  check(algorithm(key.algorithm).identifier === identifier);
  if (encrypted) check(privateBlob.length - r.offset < 16); else r.end();
  return { key, encrypted };
}
