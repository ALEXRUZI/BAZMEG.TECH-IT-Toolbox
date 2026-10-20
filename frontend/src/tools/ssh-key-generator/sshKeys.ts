import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { algorithm, algorithms, requireFormat } from './sshAlgorithms';
import { b64url, bigint, check, concat, equal, fromUrl, integer, mpint, random, Reader, ssh1int, string, u32, validComment } from './sshBytes';
import { generateDsa, proveWeakRsa, validateDsa } from './sshLegacyCrypto';
import type { KeyMaterial } from './sshTypes';

const curves = { 'P-256': p256, 'P-384': p384, 'P-521': p521 };
async function nativeKeyPair(a: ReturnType<typeof algorithm>): Promise<CryptoKeyPair> {
  try {
    // Attempt exactly the requested profile; provider failures never trigger fallback.
    if (a.id === 'ed25519') return await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
    return await crypto.subtle.generateKey(a.curve ? { name: 'ECDSA', namedCurve: a.curve } : { name: 'RSASSA-PKCS1-v1_5', modulusLength: a.bits!, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
  } catch {
    // Publish only our profile label, never a potentially sensitive provider exception.
    throw new Error(`Unsupported native generation of ${a.label} in this browser. No output was produced; no other key size or algorithm was attempted.`);
  }
}

export async function generateKey(id: string, comment: string): Promise<KeyMaterial> {
  const a = algorithm(id);
  validComment(comment);
  if (id === 'dsa') {
    const { dsa, secret } = generateDsa();
    return { algorithm: id, comment, dsa, secret, publicBlob: concat(string(a.identifier), ...[dsa.p, dsa.q, dsa.g, dsa.y].map(mpint)) };
  }
  if (id === 'ed448') {
    const secret = random(57);
    return { algorithm: id, comment, secret, publicBlob: concat(string(a.identifier), string(ed448.getPublicKey(secret))) };
  }
  const pair = await nativeKeyPair(a);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  if (id === 'ed25519') {
    // Native Ed25519 is required; no silent browser capability fallback.
    const secret = fromUrl(jwk.d!);
    return { algorithm: id, comment, secret, publicBlob: concat(string(a.identifier), string(ed25519.getPublicKey(secret))) };
  }
  if (a.curve) {
    const secret = fromUrl(jwk.d!);
    return { algorithm: id, comment, secret, publicBlob: concat(string(a.identifier), string(`nistp${a.curve.slice(2)}`), string(curves[a.curve].getPublicKey(secret, false))) };
  }
  const rsa = { n: fromUrl(jwk.n!), e: fromUrl(jwk.e!), d: fromUrl(jwk.d!), p: fromUrl(jwk.p!), q: fromUrl(jwk.q!), iq: fromUrl(jwk.qi!) };
  check(bigint(fromUrl(jwk.dp!)) === bigint(rsa.d) % (bigint(rsa.p) - 1n) && bigint(fromUrl(jwk.dq!)) === bigint(rsa.d) % (bigint(rsa.q) - 1n));
  return { algorithm: id, comment, secret: new Uint8Array(), rsa, publicBlob: id === 'rsa1' ? ssh1Public(rsa) : concat(string(a.identifier), mpint(rsa.e), mpint(rsa.n)) };
}

export function ssh1Public(k: Pick<NonNullable<KeyMaterial['rsa']>, 'n' | 'e'>): Uint8Array { return concat(u32(1024), ssh1int(k.e), ssh1int(k.n)); }
export function ssh1PublicInfo(blob: Uint8Array): ReturnType<typeof publicInfo> & { n: Uint8Array; e: Uint8Array } {
  const r = new Reader(blob); check(r.u32() === 1024); const e = r.ssh1int(), n = r.ssh1int(); r.end();
  check(bigint(n).toString(2).length === 1024 && bigint(e) === 65537n); return { algorithm: 'rsa1', n, e };
}
export function publicInfo(blob: Uint8Array): { algorithm: string; point?: Uint8Array; n?: Uint8Array; e?: Uint8Array; dsa?: NonNullable<KeyMaterial['dsa']> } {
  const r = new Reader(blob), identifier = r.text();
  if (identifier === 'ssh-dss') {
    const dsa = { p: r.mpint(), q: r.mpint(), g: r.mpint(), y: r.mpint() }; r.end();
    check(bigint(dsa.p).toString(2).length === 1024 && bigint(dsa.q).toString(2).length === 160 && dsa.g.length <= 128 && dsa.y.length <= 128);
    return { algorithm: 'dsa', dsa };
  }
  if (identifier === 'ssh-rsa') {
    const e = r.mpint(), n = r.mpint(); r.end();
    const bits = bigint(n).toString(2).length;
    algorithm(`rsa${bits}`);
    check(bigint(e) === 65537n, 'Only RSA exponent 65537 is supported.');
    return { algorithm: `rsa${bits}`, e, n };
  }
  const a = algorithms.find(item => item.identifier === identifier);
  check(a, 'Unsupported SSH key algorithm.');
  algorithm(a.id);
  if (a.curve) check(r.text() === `nistp${a.curve.slice(2)}`);
  const point = r.string(); r.end();
  check(point.length === (a.curve ? 1 + 2 * Math.ceil(Number(a.curve.slice(2)) / 8) : a.id === 'ed448' ? 57 : 32));
  if (a.id === 'ed448') {
    const decoded = ed448.Point.fromBytes(point); // Strict RFC 8032 decoding, not ZIP215.
    check(!decoded.isSmallOrder() && decoded.isTorsionFree());
  }
  return { algorithm: a.id, point };
}

export async function validateKey(key: KeyMaterial): Promise<void> {
  validComment(key.comment);
  const a = algorithm(key.algorithm), pub = key.algorithm === 'rsa1' ? ssh1PublicInfo(key.publicBlob) : publicInfo(key.publicBlob);
  check(pub.algorithm === key.algorithm);
  if (a.id === 'dsa') {
    check(key.dsa && pub.dsa);
    for (const field of ['p', 'q', 'g', 'y'] as const) check(equal(key.dsa[field], pub.dsa[field]));
    validateDsa(key); return;
  }
  if (a.id === 'ed448') {
    check(key.secret.length === 57 && equal(ed448.getPublicKey(key.secret), pub.point!));
    // Pure Ed448, empty context, no prehash (RFC 8709 / RFC 8032).
    const challenge = random(32), context = new Uint8Array();
    const signature = ed448.sign(challenge, key.secret, { context });
    check(signature.length === 114 && ed448.verify(signature, challenge, pub.point!, { context, zip215: false }));
    return;
  }
  if (a.id === 'ed25519') { check(key.secret.length === 32 && equal(ed25519.getPublicKey(key.secret), pub.point!)); return; }
  if (a.curve) {
    check(key.secret.length <= Math.ceil(Number(a.curve.slice(2)) / 8));
    const scalar = new Uint8Array(Math.ceil(Number(a.curve.slice(2)) / 8)); scalar.set(key.secret, scalar.length - key.secret.length);
    check(equal(curves[a.curve].getPublicKey(scalar, false), pub.point!)); key.secret = scalar; return;
  }
  const k = key.rsa!; check(k && equal(k.n, pub.n!) && equal(k.e, pub.e!));
  check(Object.values(k).every(value => value.length > 0 && value.length <= Math.ceil(a.bits! / 8)));
  const n = bigint(k.n), e = bigint(k.e), d = bigint(k.d), p = bigint(k.p), q = bigint(k.q), iq = bigint(k.iq);
  // Validate encoded RSA components and translate CRT fields for native JWK.
  // No RSA key generation, primality testing, signing or inversion is implemented here.
  check(p > 2n && q > 2n && p !== q && p * q === n && d > 0n && d < n && iq > 0n && iq < p && iq * q % p === 1n && e * d % (p - 1n) === 1n && e * d % (q - 1n) === 1n);
  if (a.bits! < 1024) { proveWeakRsa(k); return; }
  const jwk: JsonWebKey = { kty: 'RSA', n: b64url(k.n), e: b64url(k.e), d: b64url(k.d), p: b64url(k.p), q: b64url(k.q), qi: b64url(k.iq), dp: b64url(integer(d % (p - 1n))), dq: b64url(integer(d % (q - 1n))) };
  const params = { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
  const privateKey = await crypto.subtle.importKey('jwk', jwk, params, false, ['sign']);
  const publicKey = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e }, params, false, ['verify']);
  const challenge = random(32);
  const signature = await crypto.subtle.sign(params, privateKey, challenge);
  check(await crypto.subtle.verify(params, publicKey, signature, challenge));
}

export function privateFields(key: KeyMaterial, format: 'openssh' | 'ppk'): Uint8Array {
  const a = algorithm(key.algorithm);
  requireFormat(a.id, format);
  if (key.dsa) return format === 'ppk' ? mpint(key.secret) : concat(key.publicBlob, mpint(key.secret));
  if (key.rsa) {
    const k = key.rsa;
    return format === 'ppk' ? concat(mpint(k.d), mpint(k.p), mpint(k.q), mpint(k.iq)) : concat(string(a.identifier), mpint(k.n), mpint(k.e), mpint(k.d), mpint(k.iq), mpint(k.p), mpint(k.q));
  }
  // PuTTY 0.85 ecc-ssh.c: EdDSA is a fixed unsigned little-endian seed string.
  if (format === 'ppk') return a.curve ? mpint(key.secret) : string(key.secret);
  if (a.curve) return concat(key.publicBlob, mpint(key.secret));
  return concat(key.publicBlob, string(concat(key.secret, ed25519.getPublicKey(key.secret))));
}

export function readPrivate(r: Reader, blob: Uint8Array, comment: string, format: 'openssh' | 'ppk'): KeyMaterial {
  const pub = publicInfo(blob), a = algorithm(pub.algorithm);
  requireFormat(a.id, format);
  const key: KeyMaterial = { algorithm: a.id, comment, publicBlob: blob, secret: new Uint8Array() };
  if (format === 'openssh') check(r.text() === a.identifier);
  if (a.id === 'dsa') {
    key.dsa = pub.dsa;
    if (format === 'openssh') for (const field of ['p', 'q', 'g', 'y'] as const) check(equal(r.mpint(), pub.dsa![field]));
    key.secret = r.mpint(); check(key.secret.length <= 20);
  } else if (a.bits) {
    const n = format === 'openssh' ? r.mpint() : pub.n!;
    const e = format === 'openssh' ? r.mpint() : pub.e!;
    const d = r.mpint();
    const iq = format === 'openssh' ? r.mpint() : undefined;
    const p = r.mpint(), q = r.mpint();
    key.rsa = { n, e, d, p, q, iq: iq ?? r.mpint() };
  } else if (a.curve) {
    if (format === 'openssh') { check(r.text() === `nistp${a.curve.slice(2)}`); check(equal(r.string(), pub.point!)); }
    key.secret = r.mpint();
  } else if (format === 'ppk') {
    key.secret = r.string(); check(key.secret.length === (a.id === 'ed448' ? 57 : 32));
  } else {
    check(equal(r.string(), pub.point!));
    const privateBytes = r.string(); check(privateBytes.length === 64 && equal(privateBytes.slice(32), pub.point!)); key.secret = privateBytes.slice(0, 32);
  }
  return key;
}
