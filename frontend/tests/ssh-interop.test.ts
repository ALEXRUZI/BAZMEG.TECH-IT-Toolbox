// @vitest-environment node
import { test } from 'vitest';
import { algorithms, supportedFormats } from '../src/tools/ssh-key-generator/sshAlgorithms';
import { processKey } from '../src/tools/ssh-key-generator/sshOperations';
import type { ExportOptions } from '../src/tools/ssh-key-generator/sshTypes';
import { independentFixture, requireSafe, verifyNative } from './ssh/interop';

// Opt-in local interoperability checks require installed native tools, not a backend.
const interop = process.env.SSH_INTEROP === '1' ? test : test.skip;
// Avoid repeatedly generating RSA 8192; its dedicated opt-in suite reuses one key.
for (const a of algorithms.filter(item => item.supported && item.bits !== 8192 && item.id !== 'rsa1')) interop(`${a.id}: independent native imports/exports, both protections`, async () => {
  for (const protectedOutput of [false, true]) {
    const passphrase = protectedOutput ? 'disposable-interop-only-password' : '';
    const options: ExportOptions = { protected: protectedOutput, passphrase, confirmation: passphrase, unencryptedAcknowledged: true, formats: [...supportedFormats(a.id)] };
    const generated = await processKey({ operation: 'generate', algorithm: a.id, comment: 'Generated Próba "comment" \\ @test', legacyAcknowledged: Boolean(a.legacy), options });
    verifyNative(generated, passphrase);
    for (const format of ['openssh', 'ppk'] as const) {
      if (!supportedFormats(a.id).includes(format)) continue;
      const fixture = independentFixture(a.id, protectedOutput, format);
      const imported = await processKey({ operation: 'convert', text: fixture.text, passphrase: fixture.passphrase, options });
      requireSafe(imported.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Independent fixture identity differs.');
      requireSafe(imported.inspector.comment === 'Independent Próba "comment" \\ @test', 'Imported comment differs.');
      verifyNative(imported, passphrase);
    }
  }
}, 120_000);
interop('independent AES-CBC OpenSSH and Argon2d/i/id PPK imports with four lanes', async () => {
  const variants = [
    ['openssh', 'aes256-cbc'],
    ...['argon2d', 'argon2i', 'argon2id'].map(kdf => ['ppk', `version=3,kdf=${kdf},memory=8192,passes=2,parallelism=4`]),
  ];
  for (const [format, variant] of variants) {
    const fixture = independentFixture('ed25519', true, format as 'openssh' | 'ppk', variant);
    const options: ExportOptions = { protected: true, passphrase: 'new-disposable-password', confirmation: 'new-disposable-password', unencryptedAcknowledged: false, formats: ['public', 'openssh', 'ppk'] };
    const result = await processKey({ operation: 'convert', text: fixture.text, passphrase: fixture.passphrase, options });
    requireSafe(result.outputs[0].text.trim().split(/\s+/).slice(0, 2).join(' ') === fixture.publicLine.trim().split(/\s+/).slice(0, 2).join(' '), 'Variant import identity differs.');
    verifyNative(result, options.passphrase);
  }
}, 120_000);
