// @vitest-environment node
import { checkPrimeSync, createCipheriv, createDecipheriv, createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { expect, test, vi } from 'vitest';
import { DSA } from 'micro-rsa-dsa-dh/dsa.js';
import { PKCS1_SHA256 } from 'micro-rsa-dsa-dh/rsa.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { b64url, bigint, concat, equal, integer, mpint, random, Reader, string, u32, utf8 } from '../src/tools/ssh-key-generator/sshBytes';
import { generateKey, privateFields, publicInfo, validateKey } from '../src/tools/ssh-key-generator/sshKeys';
import { readPpk, writePpk } from '../src/tools/ssh-key-generator/sshPpk';
import { readOpenSsh, writeOpenSsh } from '../src/tools/ssh-key-generator/sshOpenSsh';
import { readSsh1, SSH1_MAGIC, ssh1Fingerprint, writeSsh1 } from '../src/tools/ssh-key-generator/sshSsh1';
import { processKey } from '../src/tools/ssh-key-generator/sshOperations';
import { detectFormat, validateOptions } from '../src/tools/ssh-key-generator/sshValidation';
import { algorithms, operationCompatibility, supportedFormats } from '../src/tools/ssh-key-generator/sshAlgorithms';
import type { ExportOptions, KeyMaterial } from '../src/tools/ssh-key-generator/sshTypes';
import { disposable, independentFixture, independentSsh1Fixture, native, puttygen, requireSafe, verifyModernRejection, verifyNative } from './ssh/interop';

const plain: ExportOptions = { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public', 'openssh', 'ppk'] };
const ssh1plain: ExportOptions = { ...plain, formats: ['public', 'ssh1'] };
const protect = (options: ExportOptions, password: string): ExportOptions => ({ ...options, protected: true, passphrase: password, confirmation: password, historicalEncryptionAcknowledged: true });
function rsaNative(key: KeyMaterial) {
  const k = key.rsa!, d = bigint(k.d);
  return createPrivateKey({ format: 'jwk', key: { kty: 'RSA', n: b64url(k.n), e: b64url(k.e), d: b64url(k.d), p: b64url(k.p), q: b64url(k.q), qi: b64url(k.iq), dp: b64url(integer(d % (bigint(k.p) - 1n))), dq: b64url(integer(d % (bigint(k.q) - 1n))) } });
}
// Test-only traditional DSA DER wrapper for the independent OpenSSL provider.
const der = (tag: number, bytes: Uint8Array) => concat(new Uint8Array([tag]), bytes.length < 128 ? new Uint8Array([bytes.length]) : new Uint8Array([0x82, bytes.length >> 8, bytes.length & 255]), bytes);
function dsaNative(key: KeyMaterial) {
  const k = key.dsa!;
  const ints = [new Uint8Array([0]), k.p, k.q, k.g, k.y, key.secret].map(bytes => der(2, bytes[0] & 128 ? concat(new Uint8Array([0]), bytes) : bytes));
  return createPrivateKey({ key: Buffer.from(der(0x30, concat(...ints))), format: 'der', type: 'pkcs1' });
}
function proveIndependent(key: KeyMaterial) {
  const message = random(32);
  if (key.rsa) {
    const k = key.rsa!, nativeKey = rsaNative(key), pub = createPublicKey(nativeKey);
    requireSafe(checkPrimeSync(k.p, { checks: 64 }) && checkPrimeSync(k.q, { checks: 64 }), 'Independent RSA primality check failed.');
    const signature = PKCS1_SHA256.sign({ n: bigint(k.n), e: bigint(k.e), d: bigint(k.d) }, message);
    requireSafe(verify('sha256', message, pub, signature), 'Independent RSA verification failed.');
    requireSafe(PKCS1_SHA256.verify({ n: bigint(k.n), e: bigint(k.e) }, message, sign('sha256', message, nativeKey)), 'Independent RSA signature failed.');
  } else {
    const k = key.dsa!, nativeKey = dsaNative(key), pub = createPublicKey(nativeKey);
    requireSafe(checkPrimeSync(k.p, { checks: 64 }) && checkPrimeSync(k.q, { checks: 64 }), 'Independent DSA primality check failed.');
    for (const hash of [sha256, sha1]) {
      const engine = DSA({ p: bigint(k.p), q: bigint(k.q), g: bigint(k.g), hash }), name = hash === sha1 ? 'sha1' : 'sha256';
      const signature = engine.sign(bigint(key.secret), message);
      requireSafe(verify(name, message, { key: pub, dsaEncoding: 'ieee-p1363' }, signature), 'Independent DSA verification failed.');
      requireSafe(engine.verify(bigint(k.y), message, sign(name, message, { key: nativeKey, dsaEncoding: 'ieee-p1363' })), 'Independent DSA signature failed.');
      requireSafe(!engine.verify(bigint(k.y), random(32), signature), 'DSA accepted another message.');
    }
  }
}

for (const id of ['rsa512', 'rsa768', 'dsa', 'rsa1']) test(`${id}: exact generation and independent Node/OpenSSL cryptography`, async () => {
  const start = performance.now(), key = await generateKey(id, 'Disposable legacy qualification'); await validateKey(key);
  console.info(`${id}: Node generation + validation ${(performance.now() - start).toFixed(1)} ms`); proveIndependent(key);
  if (key.rsa) { expect(bigint(key.rsa.n).toString(2).length).toBe(id === 'rsa1' ? 1024 : Number(id.slice(3))); expect(bigint(key.rsa.e)).toBe(65537n); }
  else {
    const r = new Reader(key.publicBlob); expect(r.text()).toBe('ssh-dss');
    for (const field of ['p', 'q', 'g', 'y'] as const) requireSafe(equal(r.mpint(), key.dsa![field]), 'DSA field differs.'); r.end();
    const privateReader = new Reader(privateFields(key, 'ppk')); requireSafe(equal(privateReader.mpint(), key.secret), 'DSA private layout differs.'); privateReader.end();
  }
}, 60_000);
test('central operation matrix covers all enabled profiles and distinct SSH-1 formats/fingerprints', () => {
  for (const a of algorithms.filter(item => item.supported)) {
    const matrix = operationCompatibility(a.id);
    expect(matrix.import).toEqual(matrix.privateExport); expect(matrix.publicOutput).toBeTruthy(); expect(matrix.browser).toContain('Secure origin'); expect(matrix.nativeClients).toBeTruthy();
  }
  expect(operationCompatibility('rsa1').binaryFormats).toEqual(['ssh1']); expect(operationCompatibility('rsa1').fingerprint).toContain('Historical MD5');
  expect(operationCompatibility('dsa').nativeClients).toContain('removed DSA'); expect(operationCompatibility('rsa512').nativeClients).toContain('below 1024');
});

for (const id of ['rsa512', 'rsa768']) test(`${id}: validation/import independent of native weak-key acceptance; CRT, exponents, sizes and structures rejected`, async () => {
  const key = await generateKey(id, ''), ppk = await writePpk(key, ''), openssh = await writeOpenSsh(key, '');
  const importKey = vi.spyOn(crypto.subtle, 'importKey').mockRejectedValue(new Error('Provider rejects weak keys'));
  try { await validateKey(key); await validateKey((await readOpenSsh(openssh, '')).key); expect(importKey).not.toHaveBeenCalled(); }
  finally { importKey.mockRestore(); }
  await validateKey((await readPpk(ppk, '')).key);
  for (const field of ['n', 'e', 'd', 'p', 'q', 'iq'] as const) {
    const bad = { ...key, rsa: { ...key.rsa!, [field]: integer(bigint(key.rsa![field]) + 2n) } };
    await expect(validateKey(bad)).rejects.toThrow();
  }
  await expect(validateKey({ ...key, algorithm: id === 'rsa512' ? 'rsa768' : 'rsa512' })).rejects.toThrow();
  expect(() => publicInfo(concat(string('ssh-rsa'), mpint(integer(3n)), mpint(key.rsa!.n)))).toThrow('exponent');
  expect(() => publicInfo(concat(key.publicBlob, mpint(integer(11n))))).toThrow();
  expect(() => publicInfo(key.publicBlob.slice(0, -1))).toThrow();
  const multiPrime = await writePpk(key, '');
  await expect(readPpk(multiPrime.replace('Private-MAC:', 'Extra-Prime: 11\nPrivate-MAC:'), '')).rejects.toThrow();
});

test('DSA rejects alternate size pairs, composites, subgroup/range failures, mismatched x/y and malformed fields', async () => {
  const key = await generateKey('dsa', '');
  for (const secret of [new Uint8Array([0]), key.dsa!.q, random(21), random(20)]) await expect(validateKey({ ...key, secret })).rejects.toThrow();
  for (const [field, value] of [['p', integer(bigint(key.dsa!.p) - 2n)], ['q', integer(bigint(key.dsa!.q) - 2n)], ['g', integer(1n)], ['g', key.dsa!.p], ['y', integer(1n)], ['y', integer(bigint(key.dsa!.y) + 1n)]] as const) {
    const dsa = { ...key.dsa!, [field]: value }, publicBlob = concat(string('ssh-dss'), ...[dsa.p, dsa.q, dsa.g, dsa.y].map(mpint));
    await expect(validateKey({ ...key, dsa, publicBlob })).rejects.toThrow();
  }
  expect(() => publicInfo(concat(string('ssh-dss'), ...[random(256), random(28), random(128), random(128)].map(mpint)))).toThrow();
  expect(() => publicInfo(key.publicBlob.slice(0, -1))).toThrow();
  expect(() => publicInfo(concat(key.publicBlob, string('extra')))).toThrow();
}, 60_000);

for (const id of ['rsa512', 'rsa768', 'dsa']) test(`${id}: encrypted codecs, wrong passwords, MAC corruption, conversion and extraction identity`, async () => {
  const original = await processKey({ operation: 'generate', algorithm: id, comment: 'Disposable Próba', legacyAcknowledged: true, options: protect(plain, 'disposable-original') });
  for (const output of original.outputs.filter(item => item.private)) {
    await expect(processKey({ operation: 'extract', text: output.text, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
    await expect(processKey({ operation: 'extract', text: output.text.slice(0, -20), passphrase: 'disposable-original', options: plain })).rejects.toThrow('Unable to unlock');
    const next = await processKey({ operation: 'convert', text: output.text, passphrase: 'disposable-original', options: plain });
    requireSafe(next.inspector.fingerprint === original.inspector.fingerprint && next.inspector.comment === 'Disposable Próba', 'Legacy conversion changed identity/comment.');
    const extracted = await processKey({ operation: 'extract', text: next.outputs.find(item => item.format === output.format)!.text, passphrase: '', options: plain });
    requireSafe(extracted.outputs.length === 1 && extracted.inspector.fingerprint === original.inspector.fingerprint, 'Legacy extraction differs.');
  }
  const ppk = original.outputs.find(item => item.format === 'ppk')!.text;
  await expect(processKey({ operation: 'extract', text: ppk.replace('Comment: Disposable', 'Comment: Corrupted'), passphrase: 'disposable-original', options: plain })).rejects.toThrow('Unable to unlock');
}, 60_000);

test('SSH-1 genuine binary layout, historical fingerprint, encryption/plain import and reprotection', async () => {
  const original = await processKey({ operation: 'generate', algorithm: 'rsa1', comment: 'Disposable Próba', legacyAcknowledged: true, options: protect(ssh1plain, 'disposable-original') });
  expect(original.outputs.map(item => item.format)).toEqual(['public', 'ssh1']);
  const output = original.outputs[1]; requireSafe(output.bytes && !output.text, 'SSH-1 output is not binary.');
  expect(detectFormat('', output.bytes)).toBe('SSH-1');
  requireSafe(equal(output.bytes.slice(0, SSH1_MAGIC.length), SSH1_MAGIC), 'SSH-1 magic differs.');
  expect(output.bytes[SSH1_MAGIC.length]).toBe(3);
  const key = readSsh1(output.bytes, 'disposable-original').key; await validateKey(key);
  expect(ssh1Fingerprint(key)).toBe(`MD5:${createHash('md5').update(key.rsa!.n).update(key.rsa!.e).digest('hex').match(/../g)!.join(':')}`);
  expect(original.outputs[0].text).toMatch(/^1024 65537 [0-9]+ Disposable Próba\n$/);
  let bytes = output.bytes, password = 'disposable-original';
  for (const nextPassword of ['', 'disposable-Próba-🔐']) {
    const next = await processKey({ operation: 'convert', text: '', bytes, passphrase: password, options: nextPassword ? protect(ssh1plain, nextPassword) : ssh1plain });
    requireSafe(next.inspector.fingerprint === original.inspector.fingerprint && next.outputs[0].text === original.outputs[0].text, 'SSH-1 processing changed identity.');
    bytes = next.outputs[1].bytes!; password = nextPassword;
    const extracted = await processKey({ operation: 'extract', text: '', bytes, passphrase: password, options: plain });
    requireSafe(extracted.outputs.length === 1 && extracted.outputs[0].text === original.outputs[0].text, 'SSH-1 extraction differs.');
  }
  await expect(processKey({ operation: 'extract', text: '', bytes, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
  for (const bad of [bytes.slice(0, -1), concat(bytes, new Uint8Array(8)), new Uint8Array(65537)]) await expect(processKey({ operation: 'extract', text: '', bytes: bad, passphrase: password, options: plain })).rejects.toThrow();
  const unencrypted = writeSsh1(key, ''), r = new Reader(unencrypted); r.take(SSH1_MAGIC.length + 9); r.ssh1int(); r.ssh1int(); r.string();
  for (const offset of [0, SSH1_MAGIC.length, SSH1_MAGIC.length + 4, r.offset, unencrypted.length - 1]) {
    const bad = unencrypted.slice(); bad[offset] ^= 0x80;
    await expect(processKey({ operation: 'extract', text: '', bytes: bad, passphrase: '', options: plain })).rejects.toThrow();
  }
  await expect(processKey({ operation: 'convert', text: '', bytes: output.bytes, passphrase: 'disposable-original', options: plain })).rejects.toThrow('Unsupported openssh');
  await expect(writePpk(key, '')).rejects.toThrow('Unsupported ppk'); await expect(writeOpenSsh(key, '')).rejects.toThrow('Unsupported openssh');
  expect(() => detectFormat('text', output.bytes)).toThrow();
});

test('SSH-1 DES matches independent OpenSSL separate CBC layers, not ordinary outer-CBC 3DES', async () => {
  const key = await generateKey('rsa1', '');
  // Repeating one DES key in OpenSSL EDE3 gives single DES without enabling an
  // obsolete OpenSSL provider. This is independent test code, not application crypto.
  const layer = (data: Uint8Array, desKey: Uint8Array, decrypt: boolean) => {
    const engine = (decrypt ? createDecipheriv : createCipheriv)('des-ede3-cbc', concat(desKey, desKey, desKey), new Uint8Array(8));
    engine.setAutoPadding(false);
    return concat(engine.update(data), engine.final());
  };
  for (const password of ['disposable', 'Próba-🔐', 'x'.repeat(1024)]) {
    for (const comment of ['', 'x', 'Disposable historical review']) {
      const material = { ...key, comment };
      const rng = vi.spyOn(crypto, 'getRandomValues').mockImplementation(array => {
        requireSafe(array instanceof Uint8Array && array.length === 2, 'Unexpected test randomness request.');
        (array as Uint8Array).set([0x12, 0x34]); return array;
      });
      let plainBytes: Uint8Array, encrypted: Uint8Array;
      try { plainBytes = writeSsh1(material, ''); encrypted = writeSsh1(material, password); }
      finally { rng.mockRestore(); }
      const reader = new Reader(plainBytes); reader.take(SSH1_MAGIC.length + 9); reader.ssh1int(); reader.ssh1int(); reader.string();
      const secret = plainBytes.slice(reader.offset), digest = createHash('md5').update(password, 'utf8').digest();
      const k1 = digest.subarray(0, 8), k2 = digest.subarray(8);
      const independent = layer(layer(layer(secret, k1, false), k2, true), k1, false);
      requireSafe(equal(encrypted.slice(reader.offset), independent), 'Historical DES ciphertext differs from OpenSSL.');
      requireSafe(equal(layer(layer(layer(independent, k1, true), k2, false), k1, true), secret), 'Independent DES decrypt differs.');
      const outer = createCipheriv('des-ede3-cbc', concat(k1, k2, k1), new Uint8Array(8)); outer.setAutoPadding(false);
      requireSafe(!equal(independent, concat(outer.update(secret), outer.final())), 'Historical layers became ordinary 3DES.');
      const nativeBytes = encrypted.slice(); nativeBytes.set(independent, reader.offset);
      const imported = readSsh1(nativeBytes, password).key;
      await validateKey(imported);
      requireSafe(equal(imported.publicBlob, key.publicBlob) && imported.comment === comment, 'Independent ciphertext import differs.');
      requireSafe(equal(imported.rsa!.d, key.rsa!.d), 'Independent ciphertext changed private material.');
    }
  }
});

for (const id of ['rsa512', 'rsa768', 'dsa', 'rsa1']) test(`${id}: worker-boundary legacy/plaintext/encryption/format guards execute before generation`, async () => {
  const options = id === 'rsa1' ? ssh1plain : plain;
  const generate = vi.spyOn(crypto.subtle, 'generateKey'), rng = vi.spyOn(crypto, 'getRandomValues');
  try {
    for (const acknowledged of [false, 'true', 1]) await expect(processKey({ operation: 'generate', algorithm: id, comment: '', legacyAcknowledged: acknowledged as boolean, options })).rejects.toThrow('Legacy generation');
    await expect(processKey({ operation: 'generate', algorithm: id, comment: '', legacyAcknowledged: true, options: { ...options, unencryptedAcknowledged: false } })).rejects.toThrow('Confirm the risk');
    await expect(processKey({ operation: 'generate', algorithm: id, comment: '', legacyAcknowledged: true, options: { ...options, formats: [id === 'rsa1' ? 'ppk' : 'ssh1'] } })).rejects.toThrow('Unsupported');
    expect(generate).not.toHaveBeenCalled(); expect(rng).not.toHaveBeenCalled();
  } finally { vi.restoreAllMocks(); }
  expect(supportedFormats(id)).toEqual(id === 'rsa1' ? ['public', 'ssh1'] : ['public', 'openssh', 'ppk']);
  expect(() => validateOptions({ ...protect(ssh1plain, 'disposable'), historicalEncryptionAcknowledged: false })).toThrow('obsolete SSH-1');
});

const interop = process.env.SSH_INTEROP === '1' ? test : test.skip;
for (const id of ['rsa512', 'rsa768', 'dsa']) interop(`${id}: native fixtures, independent cryptography and documented modern OpenSSH policy rejection`, async () => {
  for (const format of ['ppk', 'openssh'] as const) {
    const fixture = independentFixture(id, true, format), imported = format === 'ppk' ? await readPpk(fixture.text, fixture.passphrase) : await readOpenSsh(fixture.text, fixture.passphrase);
    await validateKey(imported.key); proveIndependent(imported.key);
    const converted = await processKey({ operation: 'convert', text: fixture.text, passphrase: fixture.passphrase, options: protect(plain, 'disposable-new') });
    verifyNative(converted, 'disposable-new');
    verifyModernRejection(converted.outputs.find(item => item.format === 'openssh')!.text, 'disposable-new', id === 'dsa' ? 'dsa' : 'weak-rsa');
  }
}, 120_000);
interop('SSH-1 PuTTYgen 0.85 binary fixtures, both protections and native passphrase changes', async () => {
  expect(native(puttygen, ['--version'])).toContain('Release 0.85');
  for (const encrypted of [false, true]) {
    const fixture = independentSsh1Fixture(encrypted), key = readSsh1(fixture.bytes, fixture.passphrase).key;
    await validateKey(key); proveIndependent(key);
    for (const options of [ssh1plain, protect(ssh1plain, 'disposable-Próba-🔐')]) {
      const converted = await processKey({ operation: 'convert', text: '', bytes: fixture.bytes, passphrase: fixture.passphrase, options });
      requireSafe(converted.outputs[0].text === fixture.publicLine, 'SSH-1 fixture identity/comment differs.'); verifyNative(converted, options.passphrase);
      const rewritten = disposable(directory => {
        const source = join(directory, 'key'), target = join(directory, 'rewritten'), old = join(directory, 'old'), next = join(directory, 'next');
        writeFileSync(source, converted.outputs[1].bytes!, { mode: 0o600 }); writeFileSync(old, `${options.passphrase}\n`, { mode: 0o600 }); writeFileSync(next, 'disposable-native-new\n', { mode: 0o600 });
        native(puttygen, [source, '--old-passphrase', old, '--new-passphrase', next, '--reencrypt', '-o', target]);
        return new Uint8Array(readFileSync(target));
      });
      const reimported = readSsh1(rewritten, 'disposable-native-new').key; await validateKey(reimported);
      requireSafe(equal(reimported.publicBlob, key.publicBlob) && reimported.comment === key.comment, 'SSH-1 native reprotection changed identity.');
    }
  }
  for (const options of [ssh1plain, protect(ssh1plain, 'disposable-new')]) verifyNative(await processKey({ operation: 'generate', algorithm: 'rsa1', comment: 'Disposable generated', legacyAcknowledged: true, options }), options.passphrase);
}, 120_000);
