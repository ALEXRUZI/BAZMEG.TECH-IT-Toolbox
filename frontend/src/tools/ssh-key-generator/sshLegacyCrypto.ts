// Isolated legacy-only proofs; never used as a native RSA generation fallback.
import { DSA, genDSAParams } from 'micro-rsa-dsa-dh/dsa.js';
import { isProbablePrime } from 'micro-rsa-dsa-dh/primality.js';
import { PKCS1_SHA256 } from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bigint, check, integer, random } from './sshBytes';
import type { KeyMaterial } from './sshTypes';

export function generateDsa(): { dsa: NonNullable<KeyMaterial['dsa']>; secret: Uint8Array } {
  // Fresh FIPS 186-4 A.1.1.2/A.2.3 domain, exact historical SSH size pair.
  // SHA-256 parameter derivation does not change ssh-dss's SHA-1 wire signature rule.
  const params = genDSAParams(1024, 160, sha256, 1, 256, random), engine = DSA(params);
  const x = engine.randomPrivateKey();
  return { secret: integer(x), dsa: { p: integer(params.p), q: integer(params.q), g: integer(params.g), y: integer(engine.getPublicKey(x)) } };
}
export function validateDsa(key: KeyMaterial): void {
  const k = key.dsa; check(k && key.secret.length > 0 && key.secret.length <= 20);
  check(k.p.length === 128 && k.q.length === 20 && k.g.length <= 128 && k.y.length <= 128);
  const p = bigint(k.p), q = bigint(k.q), g = bigint(k.g), y = bigint(k.y), x = bigint(key.secret);
  check(p.toString(2).length === 1024 && q.toString(2).length === 160);
  // Library checks prime p/q, q|(p-1), generator order, x range, y subgroup.
  const engine = DSA({ p, q, g, hash: sha256 });
  check(engine.getPublicKey(x) === y);
  const challenge = random(32), signature = engine.sign(x, challenge);
  check(signature.length === 40 && engine.verify(y, challenge, signature));
}
export function proveWeakRsa(k: NonNullable<KeyMaterial['rsa']>): void {
  const n = bigint(k.n), e = bigint(k.e), d = bigint(k.d), p = bigint(k.p), q = bigint(k.q);
  check([512, 768].includes(n.toString(2).length));
  check(isProbablePrime(p, 32, random) && isProbablePrime(q, 32, random));
  // Blinded private operation (explicit e), independent of native import policy.
  const challenge = random(32), signature = PKCS1_SHA256.sign({ n, e, d }, challenge);
  check(PKCS1_SHA256.verify({ n, e }, challenge, signature));
}
