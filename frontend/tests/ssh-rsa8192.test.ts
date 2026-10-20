// @vitest-environment node
import { expect, test, vi } from 'vitest';
import { algorithm } from '../src/tools/ssh-key-generator/sshAlgorithms';
import { bigint, check, equal, MAX_IMPORT, utf8 } from '../src/tools/ssh-key-generator/sshBytes';
import { generateKey, publicInfo, validateKey } from '../src/tools/ssh-key-generator/sshKeys';
import { processKey } from '../src/tools/ssh-key-generator/sshOperations';
import { readOpenSsh, writeOpenSsh } from '../src/tools/ssh-key-generator/sshOpenSsh';
import { readPpk, writePpk } from '../src/tools/ssh-key-generator/sshPpk';
import type { ExportOptions, Result } from '../src/tools/ssh-key-generator/sshTypes';
import { detectFormat } from '../src/tools/ssh-key-generator/sshValidation';
import { independentFixture, requireSafe, verifyNative } from './ssh/interop';

const heavy = process.env.SSH_RSA8192 === '1' ? test : test.skip;
const plain: ExportOptions = { protected: false, passphrase: '', confirmation: '', unencryptedAcknowledged: true, formats: ['public', 'openssh', 'ppk'] };
const protectedOptions: ExportOptions = { ...plain, protected: true, passphrase: 'disposable-rsa8192-only', confirmation: 'disposable-rsa8192-only' };
async function measured<T>(label: string, operation: () => Promise<T>): Promise<T> {
  const start = performance.now(), value = await operation(), elapsed = performance.now() - start;
  // Only public operation names/durations are logged, never key material/errors.
  console.info(`RSA8192 Node ${label}: ${elapsed.toFixed(1)} ms`);
  check(elapsed < 120_000, 'RSA 8192 operation exceeded the unchanged worker budget.');
  return value;
}
function sameIdentity(actual: Result, expected: Result) {
  requireSafe(actual.inspector.fingerprint === expected.inspector.fingerprint && actual.inspector.comment === expected.inspector.comment, 'RSA 8192 identity/comment changed.');
}

test('RSA 8192 metadata is supported, modern and resource-intensive without a legacy guard', () => {
  const a = algorithm('rsa8192');
  expect(a.bits).toBe(8192); expect(a.legacy).toBe(false);
  expect(a.classification).toBe('Secure / Resource-intensive');
  expect(a.note).toContain('120-second worker deadline');
});

// One real native generation reused throughout; normal CI does not run large prime searches.
heavy('real RSA 8192 exact generation, CRT proof, both formats/protections, conversions and failures', async () => {
  const generate = vi.spyOn(crypto.subtle, 'generateKey');
  try {
    const key = await measured('generation', () => generateKey('rsa8192', 'Próba "8192" \\ @test'));
    expect(generate).toHaveBeenCalledOnce();
    expect(generate.mock.calls[0]).toEqual([
      { name: 'RSASSA-PKCS1-v1_5', modulusLength: 8192, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
      true, ['sign', 'verify'],
    ]);
    check(bigint(key.rsa!.n).toString(2).length === 8192 && bigint(key.rsa!.e) === 65537n, 'Native RSA size/exponent differs.');
    expect(publicInfo(key.publicBlob).algorithm).toBe('rsa8192');
    await measured('CRT validation + native sign/verify', () => validateKey(key));
    const { d, p, q, n } = key.rsa!;
    check(bigint(p) * bigint(q) === bigint(n) && bigint(d) > 0n, 'RSA components differ.');
    let baseline: Result | undefined;
    for (const options of [plain, protectedOptions]) {
      const password = options.protected ? options.passphrase : '';
      for (const format of ['openssh', 'ppk'] as const) {
        const encoded = await measured(`${format} ${password ? 'encrypted' : 'plain'} export`, () => format === 'openssh' ? writeOpenSsh(key, password) : writePpk(key, password));
        check(utf8(encoded).length < MAX_IMPORT, 'RSA 8192 export exceeds the existing import limit.');
        console.info(`RSA8192 ${format} ${password ? 'encrypted' : 'plain'}: ${utf8(encoded).length} bytes`);
        expect(detectFormat(encoded)).toBe(format === 'openssh' ? 'OpenSSH' : 'PPK v3');
        const imported = await measured(`${format} reimport`, () => format === 'openssh' ? readOpenSsh(encoded, password) : readPpk(encoded, password));
        await validateKey(imported.key);
        check(equal(imported.key.publicBlob, key.publicBlob) && imported.key.comment === key.comment && imported.encrypted === Boolean(password), 'RSA 8192 reimport differs.');
        for (const component of ['n', 'e', 'd', 'p', 'q', 'iq'] as const) check(equal(imported.key.rsa![component], key.rsa![component]), 'RSA CRT component changed.');
        const extracted = await measured(`${format} extraction`, () => processKey({ operation: 'extract', text: encoded, passphrase: password, options: plain }));
        baseline ??= extracted; sameIdentity(extracted, baseline);
        check(extracted.outputs.length === 1 && !extracted.outputs[0].private, 'Extraction exposed private output.');
        // Both directions, plaintext -> protected and protected -> plaintext; no generation.
        const target = password ? plain : protectedOptions;
        const converted = await measured(`${format} conversion to ${target.protected ? 'encrypted' : 'plain'} outputs`, () => processKey({ operation: 'convert', text: encoded, passphrase: password, options: target }));
        sameIdentity(converted, baseline);
        if (process.env.SSH_INTEROP === '1') verifyNative(converted, target.protected ? target.passphrase : '');
        for (const output of converted.outputs.filter(item => item.private)) {
          const roundtrip = await processKey({ operation: 'extract', text: output.text, passphrase: target.protected ? target.passphrase : '', options: plain });
          sameIdentity(roundtrip, baseline);
        }
        if (password) await expect(processKey({ operation: 'extract', text: encoded, passphrase: 'wrong', options: plain })).rejects.toThrow('Unable to unlock');
        const malformed = format === 'ppk' ? encoded.replace('Comment: Próba', 'Comment: Tampered') : encoded.replace(/\n-----END/, '\nAAAA\n-----END');
        await expect(processKey({ operation: 'extract', text: malformed, passphrase: password, options: plain })).rejects.toThrow('Unable to unlock');
      }
    }
    expect(generate).toHaveBeenCalledOnce(); // Imports/conversions never generate.
    const invalid = { ...key, rsa: { ...key.rsa!, iq: new Uint8Array([1]) } };
    await expect(validateKey(invalid)).rejects.toThrow();
    const wrongPublic = { ...key, rsa: { ...key.rsa!, n: key.rsa!.n.slice(1) } };
    await expect(validateKey(wrongPublic)).rejects.toThrow();
  } finally { generate.mockRestore(); }
}, 360_000); // Aggregate of many operations; each measured operation must stay below 120 s.

const nativeHeavy = process.env.SSH_RSA8192 === '1' && process.env.SSH_INTEROP === '1' ? test : test.skip;
nativeHeavy('native OpenSSH-generated and PuTTYgen-serialized RSA 8192 imports preserve identity under both protections', async () => {
  for (const format of ['openssh', 'ppk'] as const) {
    const start = performance.now(), fixture = independentFixture('rsa8192', true, format);
    console.info(`RSA8192 native ${format} fixture generation: ${(performance.now() - start).toFixed(1)} ms`);
    for (const options of [plain, protectedOptions]) {
      const result = await measured(`independent ${format} conversion ${options.protected ? 'encrypted' : 'plain'}`, () => processKey({ operation: 'convert', text: fixture.text, passphrase: fixture.passphrase, options }));
      requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Independent RSA 8192 identity differs.');
      requireSafe(result.inspector.comment === 'Independent Próba "comment" \\ @test', 'Independent RSA 8192 comment differs.');
      expect(result.inspector.parameters).toBe('8192 bits; exponent 65537');
      verifyNative(result, options.protected ? options.passphrase : '');
    }
  }
}, 360_000);
