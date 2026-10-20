import 'node-forge/lib/des.js';
import cipher from 'node-forge/lib/cipher.js';
import util from 'node-forge/lib/util.js';
import { md5 } from '@noble/hashes/legacy.js';
import { requireFormat } from './sshAlgorithms';
import { bigint, check, concat, equal, hex, random, Reader, ssh1int, string, text, u32, unsigned, utf8 } from './sshBytes';
import { ssh1Public, ssh1PublicInfo } from './sshKeys';
import type { KeyMaterial } from './sshTypes';

export const SSH1_MAGIC = utf8('SSH PRIVATE KEY FILE FORMAT 1.1\n\0');
const binary = (bytes: Uint8Array) => String.fromCharCode(...bytes);
function desCbc(data: Uint8Array, key: Uint8Array, decrypt: boolean): Uint8Array {
  check(key.length === 8 && data.length > 0 && data.length % 8 === 0);
  const engine = decrypt ? cipher.createDecipher('DES-CBC', binary(key)) : cipher.createCipher('DES-CBC', binary(key));
  engine.start({ iv: '\0'.repeat(8) }); engine.update(util.createBuffer(binary(data)));
  // FORMAT 1.1 has its own zero padding, never PKCS#7.
  check(engine.finish(() => true));
  const output = Uint8Array.from(engine.output.getBytes(), value => value.charCodeAt(0));
  check(output.length === data.length); return output;
}
function crypt(data: Uint8Array, passphrase: string, decrypt: boolean): Uint8Array {
  // PuTTY pubkey-ssh1.c and des.c: K1/K2/K1, separate zero-IV CBC layers.
  // NOT an outer-chained standard 3DES-CBC cipher.
  const key = md5(utf8(passphrase)), k1 = key.slice(0, 8), k2 = key.slice(8);
  return desCbc(desCbc(desCbc(data, k1, decrypt), k2, !decrypt), k1, decrypt);
}
export function writeSsh1(key: KeyMaterial, passphrase: string): Uint8Array {
  requireFormat(key.algorithm, 'ssh1'); ssh1PublicInfo(key.publicBlob);
  const k = key.rsa!; check(k);
  const checkint = random(2);
  const raw = concat(checkint, checkint, ssh1int(k.d), ssh1int(k.iq), ssh1int(k.q), ssh1int(k.p));
  let secret = concat(raw, new Uint8Array((8 - raw.length % 8) % 8));
  if (passphrase) secret = crypt(secret, passphrase, false);
  return concat(SSH1_MAGIC, new Uint8Array([passphrase ? 3 : 0]), u32(0), u32(1024), ssh1int(k.n), ssh1int(k.e), string(key.comment), secret);
}
export function readSsh1(bytes: Uint8Array, passphrase: string): { key: KeyMaterial; encrypted: boolean } {
  const r = new Reader(bytes); check(equal(r.take(SSH1_MAGIC.length), SSH1_MAGIC));
  const encryption = r.take(1)[0]; check(encryption === 0 || encryption === 3, 'Unsupported SSH-1 encryption identifier.');
  check(r.u32() === 0 && r.u32() === 1024, 'Unsupported SSH-1 structure or size (RSA 1024 only).');
  const n = r.ssh1int(), e = r.ssh1int(), comment = text(r.string());
  let secret = r.take(bytes.length - r.offset); check(secret.length > 0 && secret.length % 8 === 0);
  if (encryption) { check(passphrase.length > 0); secret = crypt(secret, passphrase, true); }
  const p = new Reader(secret), first = p.take(2); check(equal(first, p.take(2)));
  const d = p.ssh1int(), iq = p.ssh1int(), q = p.ssh1int(), prime = p.ssh1int();
  const padding = p.take(secret.length - p.offset); check(padding.length < 8 && padding.every(value => value === 0));
  const rsa = { n, e, d, iq, q, p: prime }, publicBlob = ssh1Public(rsa); ssh1PublicInfo(publicBlob);
  return { key: { algorithm: 'rsa1', comment, rsa, publicBlob, secret: new Uint8Array() }, encrypted: Boolean(encryption) };
}
export function ssh1PublicText(key: KeyMaterial): string {
  const k = ssh1PublicInfo(key.publicBlob);
  return `1024 ${bigint(k.e)} ${bigint(k.n)}${key.comment ? ` ${key.comment}` : ''}\n`;
}
export function ssh1Fingerprint(key: KeyMaterial): string {
  const k = ssh1PublicInfo(key.publicBlob);
  // Historical SSH-1 fingerprint: MD5(minimal unsigned BE n || e), no lengths.
  return `MD5:${hex(md5(concat(unsigned(k.n), unsigned(k.e)))).match(/../g)!.join(':')}`;
}
