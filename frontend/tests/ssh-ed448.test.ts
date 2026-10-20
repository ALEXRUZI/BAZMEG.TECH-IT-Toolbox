// @vitest-environment node
import { createPrivateKey, createPublicKey, sign, verify, createHash } from 'node:crypto';
import { expect, test } from 'vitest';
import { ed448, ed448ph, ED448_TORSION_SUBGROUP } from '@noble/curves/ed448.js';
import { concat, equal, hex, random, Reader, string, unbase64, u32, utf8, base64, lines } from '../src/tools/ssh-key-generator/sshBytes';
import { generateKey, privateFields, publicInfo, validateKey } from '../src/tools/ssh-key-generator/sshKeys';
import { processKey } from '../src/tools/ssh-key-generator/sshOperations';
import { readOpenSsh, writeOpenSsh } from '../src/tools/ssh-key-generator/sshOpenSsh';
import { readPpk, writePpk } from '../src/tools/ssh-key-generator/sshPpk';
import { supportedFormats } from '../src/tools/ssh-key-generator/sshAlgorithms';
import type { ExportOptions, KeyMaterial } from '../src/tools/ssh-key-generator/sshTypes';
import { disposable, independentFixture, native, puttygen, requireSafe, verifyNative } from './ssh/interop';
import { join } from 'node:path';
import { readFileSync, writeFileSync } from 'node:fs';

// Public, deliberately non-secret RFC 8032 §7.4 vectors. Never use these keys.
const vectors = [
  { name: 'Blank', seed: '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b', public: '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180', message: '', context: '', signature: '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600' },
  { name: '1 octet', seed: 'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e', public: '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480', message: '03', context: '', signature: '26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00' },
  { name: '1 octet (with context)', seed: 'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e', public: '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480', message: '03', context: '666f6f', signature: 'd4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00' },
];
const bytes = (value: string) => new Uint8Array(Buffer.from(value, 'hex'));
const plain: ExportOptions = { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public', 'ppk'] };
const protect = (password: string): ExportOptions => ({ ...plain, protected: true, passphrase: password, confirmation: password });
const material = (seed: Uint8Array, point: Uint8Array): KeyMaterial => ({ algorithm: 'ed448', comment: 'RFC public test vector', secret: seed, publicBlob: concat(string('ssh-ed448'), string(point)) });

for (const vector of vectors) test(`Ed448 RFC 8032 §7.4 ${vector.name}: exact derivation and pure signature`, async () => {
  const seed = bytes(vector.seed), pub = bytes(vector.public), message = bytes(vector.message), context = bytes(vector.context);
  expect(seed.length).toBe(57); expect(pub.length).toBe(57);
  expect(hex(ed448.getPublicKey(seed))).toBe(vector.public);
  await validateKey(material(seed, pub));
  const signature = ed448.sign(message, seed, { context });
  expect(signature.length).toBe(114); expect(hex(signature)).toBe(vector.signature);
  expect(ed448.verify(signature, message, pub, { context, zip215: false })).toBe(true);
  expect(ed448ph.verify(signature, message, pub, { context })).toBe(false);
  expect(ed448.verify(signature, message, pub, { context: utf8('wrong') })).toBe(false);
  expect(() => ed448.verify(signature.slice(0, -1), message, pub)).toThrow();
  signature[0] ^= 1; expect(ed448.verify(signature, message, pub, { context })).toBe(false);
  if (!context.length) {
    // Independent OpenSSL through Node, RFC 8410 test-only PKCS#8 wrapper (not an app export).
    const key = createPrivateKey({ key: Buffer.concat([Buffer.from('3047020100300506032b6571043b0439', 'hex'), Buffer.from(seed)]), type: 'pkcs8', format: 'der' });
    expect(createPublicKey(key).export({ format: 'jwk' }).x).toBe(Buffer.from(pub).toString('base64url'));
    expect(sign(null, message, key).toString('hex')).toBe(vector.signature);
    expect(verify(null, message, createPublicKey(key), bytes(vector.signature))).toBe(true);
  }
});

test('Ed448 generation, RFC 8709 wire blob, fingerprint and unsigned fixed-width PPK seed', async () => {
  const key = await generateKey('ed448', 'Próba 🔐 "comment" \\ @test');
  await validateKey(key);
  requireSafe(key.secret.length === 57 && publicInfo(key.publicBlob).point?.length === 57, 'Ed448 sizes differ.');
  const r = new Reader(privateFields(key, 'ppk')); requireSafe(equal(r.string(), key.secret), 'Ed448 PPK seed changed.'); r.end();
  const result = await processKey({ operation: 'convert', text: await writePpk(key, ''), passphrase: '', options: plain });
  expect(result.outputs.map(output => output.format)).toEqual(['public', 'ppk']);
  expect(result.outputs[0].text.startsWith('ssh-ed448 ')).toBe(true);
  expect(result.inspector.parameters).toContain('57-byte public key; ~224-bit');
  expect(result.inspector.exports).toBe('RFC 8709 public key, PuTTY PPK v3');
  const blob = unbase64(result.outputs[0].text.split(' ')[1]);
  requireSafe(equal(blob, key.publicBlob), 'Public wire blob differs.');
  expect(result.inspector.fingerprint).toBe(`SHA256:${createHash('sha256').update(blob).digest('base64').replace(/=+$/, '')}`);
  expect(result.inspector.fingerprint).not.toBe(`SHA256:${createHash('sha256').update(publicInfo(blob).point!).digest('base64').replace(/=+$/, '')}`);
  // Leading/trailing zeroes and high bytes belong to the seed, not mpint sign padding.
  const seed = random(57); seed[0] = 0x80; seed[56] = 0;
  const special = material(seed, ed448.getPublicKey(seed));
  const imported = await readPpk(await writePpk(special, ''), ''); await validateKey(imported.key);
  requireSafe(equal(imported.key.secret, seed), 'Fixed-width seed bytes changed.');
});

test('Ed448 malformed seeds, invalid/small-order/non-subgroup points and mismatched material fail', async () => {
  const key = await generateKey('ed448', 'test');
  for (const size of [0, 32, 56, 58]) await expect(validateKey({ ...key, secret: random(size) })).rejects.toThrow();
  await expect(validateKey({ ...key, secret: random(57) })).rejects.toThrow();
  const badPoints = [random(56), random(58), new Uint8Array(57).fill(255), ...ED448_TORSION_SUBGROUP.map(bytes), ed448.Point.BASE.add(ed448.Point.fromHex(ED448_TORSION_SUBGROUP[1])).toBytes()];
  const unusedBit = ed448.getPublicKey(key.secret); unusedBit[56] |= 1; badPoints.push(unusedBit);
  for (const point of badPoints) expect(() => publicInfo(material(key.secret, point).publicBlob)).toThrow();
  for (const size of [0, 56, 58]) await expect(processKey({ operation: 'extract', text: await writePpk({ ...key, secret: random(size) }, ''), passphrase: '', options: plain })).rejects.toThrow('Unable to unlock');
  await expect(processKey({ operation: 'extract', text: await writePpk(material(key.secret, new Uint8Array(57).fill(255)), ''), passphrase: '', options: plain })).rejects.toThrow('Unable to unlock');
  await expect(processKey({ operation: 'extract', text: await writePpk({ ...key, secret: random(57) }, ''), passphrase: '', options: plain })).rejects.toThrow('consistency');
});

test('Ed448 encrypted/plain PPK, change passphrase, extraction, MAC failures and export guards', async () => {
  const generated = await processKey({ operation: 'generate', algorithm: 'ed448', comment: 'Próba 🔐', legacyAcknowledged: false, options: protect('disposable-original-phrase') });
  let text = generated.outputs.find(item => item.format === 'ppk')!.text, password = 'disposable-original-phrase';
  for (const next of ['disposable-new-phrase', '', 'disposable-reprotected-phrase']) {
    const converted = await processKey({ operation: 'convert', text, passphrase: password, options: next ? protect(next) : plain });
    requireSafe(converted.inspector.fingerprint === generated.inspector.fingerprint && converted.inspector.comment === 'Próba 🔐', 'Reprotection changed identity/comment.');
    const imported = await readPpk(converted.outputs.find(item => item.format === 'ppk')!.text, next); await validateKey(imported.key);
    expect(imported.encrypted).toBe(Boolean(next));
    text = converted.outputs.find(item => item.format === 'ppk')!.text; password = next;
    const extracted = await processKey({ operation: 'extract', text, passphrase: password, options: { ...plain, formats: ['openssh'] } });
    expect(extracted.outputs.map(item => item.format)).toEqual(['public']);
    requireSafe(extracted.inspector.fingerprint === generated.inspector.fingerprint, 'Extraction changed fingerprint.');
  }
  const badMac = text.replace(/(Private-MAC: )([a-f0-9])/, (_match, prefix: string, digit: string) => `${prefix}${digit === '0' ? '1' : '0'}`);
  for (const value of [text.replace('Comment: Próba', 'Comment: Tampered'), badMac, text.replace(/Private-MAC: [a-f0-9]/, 'Private-MAC: z'), text.slice(0, -20)]) await expect(processKey({ operation: 'extract', text: value, passphrase: password, options: plain })).rejects.toThrow('Unable to unlock');
  await expect(processKey({ operation: 'extract', text, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
  await expect(processKey({ operation: 'convert', text, passphrase: password, options: { ...plain, formats: ['openssh'] } })).rejects.toThrow('Unsupported openssh');
  await expect(processKey({ operation: 'generate', algorithm: 'ed448', comment: '', legacyAcknowledged: false, options: { ...plain, formats: ['openssh'] } })).rejects.toThrow('Unsupported openssh');
  await expect(processKey({ operation: 'generate', algorithm: 'ed448', comment: '', legacyAcknowledged: false, options: { ...plain, unencryptedAcknowledged: false } })).rejects.toThrow('Confirm the risk');
  const key = await generateKey('ed448', '');
  await expect(writeOpenSsh(key, '')).rejects.toThrow('Unsupported openssh');
  // A speculative openssh-key-v1 envelope with an Ed448 blob is explicitly rejected.
  const envelope = concat(utf8('openssh-key-v1\0'), string('none'), string('none'), string(new Uint8Array()), u32(1), string(key.publicBlob), string(new Uint8Array(8)));
  await expect(readOpenSsh(`-----BEGIN OPENSSH PRIVATE KEY-----\n${lines(base64(envelope))}\n-----END OPENSSH PRIVATE KEY-----\n`, '')).rejects.toThrow('Unsupported openssh');
  expect(supportedFormats('ed448')).toEqual(['public', 'ppk']);
}, 30_000);

const interop = process.env.SSH_INTEROP === '1' ? test : test.skip;
interop('Ed448 independent PuTTYgen 0.85 seeds, native re-encryption and Unicode passphrase changes', async () => {
  expect(native(puttygen, ['--version'])).toMatch(/Release 0\.85/);
  for (const encrypted of [false, true]) {
    const fixture = independentFixture('ed448', encrypted, 'ppk');
    const key = (await readPpk(fixture.text, fixture.passphrase)).key; await validateKey(key);
    requireSafe(key.secret.length === 57 && equal(ed448.getPublicKey(key.secret), publicInfo(key.publicBlob).point!), 'Native seed representation differs.');
    for (const passphrase of ['', 'disposable-Próba-🔐-passphrase']) {
      const result = await processKey({ operation: 'convert', text: fixture.text, passphrase: fixture.passphrase, options: passphrase ? protect(passphrase) : plain });
      requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Native fixture identity differs.');
      verifyNative(result, passphrase);
      const rewritten = disposable(directory => {
        const source = join(directory, 'source.ppk'), target = join(directory, 'rewritten.ppk'), old = join(directory, 'old'), next = join(directory, 'next');
        writeFileSync(source, result.outputs.find(item => item.format === 'ppk')!.text, { mode: 0o600 });
        writeFileSync(old, `${passphrase}\n`, { mode: 0o600 }); writeFileSync(next, 'disposable-native-new-phrase\n', { mode: 0o600 });
        native(puttygen, [source, '--old-passphrase', old, '--new-passphrase', next, '--reencrypt', '--ppk-param', 'version=3,kdf=argon2id,memory=65536,passes=3,parallelism=1', '-o', target]);
        return readFileSync(target, 'utf8');
      });
      const reimported = await readPpk(rewritten, 'disposable-native-new-phrase'); await validateKey(reimported.key);
      requireSafe(equal(reimported.key.secret, key.secret) && equal(reimported.key.publicBlob, key.publicBlob) && reimported.key.comment === key.comment, 'Native rewriting changed key/comment.');
    }
  }
}, 120_000);
