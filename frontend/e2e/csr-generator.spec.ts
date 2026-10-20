import { createPrivateKey, createPublicKey, randomBytes } from 'node:crypto';
import { BitString, Integer } from 'asn1js';
import { test as guardedTest, expect, field, openTool } from './fixtures/test';
import { decodeOutput, decryptPrivateKey, encryptedParameters, matchPublicKeys, oid, parseCsr, parseDer, requireCondition, sequence, verifyPrivateKey } from '../tests/csr/verification';
import type { Locator } from '@playwright/test';

// CSR-only protection: no recordings, no secret assertion diffs, and no page left
// for Playwright's automatic failure-context DOM snapshot during context teardown.
const test = guardedTest.extend({
  page: async ({ page }, use) => {
    try { await use(page); }
    finally {
      await page.evaluate(() => navigator.clipboard.writeText('')).catch(() => {});
      await page.close();
    }
  },
});
test.use({ trace: 'off', screenshot: 'off', video: 'off' });
test.setTimeout(120_000);

async function generate(panel: Locator) {
  await panel.getByRole('button', { name: 'Generate private key and CSR', exact: true }).click();
  await expect(panel.locator('pre')).toHaveCount(3, { timeout: 60_000 });
  await expect(panel.getByRole('button', { name: 'Generate private key and CSR', exact: true })).toBeEnabled();
  const outputs = await panel.locator('pre').allTextContents();
  requireCondition(outputs.every(Boolean), 'Missing CSR/key output');
  return { csr: outputs[0], privateKey: outputs[1], publicKey: outputs[2] };
}

const profiles = [
  { type: 'rsa', size: '2048', hash: 'SHA-256', signatureOid: '1.2.840.113549.1.1.11', format: 'pkcs8' },
  { type: 'rsa', size: '3072', hash: 'SHA-384', signatureOid: '1.2.840.113549.1.1.12', format: 'rsa' },
  { type: 'rsa', size: '4096', hash: 'SHA-512', signatureOid: '1.2.840.113549.1.1.13', format: 'der' },
  { type: 'ec', size: 'P-256', hash: 'SHA-256', signatureOid: '1.2.840.10045.4.3.2', format: 'pkcs8', curve: 'prime256v1', curveOid: '1.2.840.10045.3.1.7' },
  { type: 'ec', size: 'P-384', hash: 'SHA-384', signatureOid: '1.2.840.10045.4.3.3', format: 'ec', curve: 'secp384r1', curveOid: '1.3.132.0.34' },
  { type: 'ec', size: 'P-521', hash: 'SHA-512', signatureOid: '1.2.840.10045.4.3.4', format: 'der', curve: 'secp521r1', curveOid: '1.3.132.0.35' },
] as const;

for (const profile of profiles) {
  test(`independently verifies ${profile.type} ${profile.size} ${profile.hash} and ${profile.format} export`, async ({ page }) => {
    const panel = await openTool(page, 'CSR Generator');
    await field(panel, 'Key type \\*', 'combobox').selectOption(profile.type);
    await field(panel, 'Key size \\*', 'combobox').selectOption(profile.size);
    await field(panel, 'Signature hash', 'combobox').selectOption(profile.hash);
    await panel.getByRole('button', { name: 'Advanced export format' }).click();
    await expect(panel.getByRole('radio', { name: 'Traditional RSA PEM' })).toBeEnabled({ enabled: profile.type === 'rsa' });
    await expect(panel.getByRole('radio', { name: 'Traditional EC PEM' })).toBeEnabled({ enabled: profile.type === 'ec' });
    if (profile.format === 'rsa') await panel.getByRole('radio', { name: 'Traditional RSA PEM' }).check();
    if (profile.format === 'ec') await panel.getByRole('radio', { name: 'Traditional EC PEM' }).check();
    if (profile.format === 'der') {
      await panel.getByRole('radio', { name: /^PKCS#8 DER/ }).check();
      await panel.getByRole('radio', { name: /^DER \/ PKCS#10/ }).check();
    }
    // Observe real WebCrypto signatures; do not stub keys, signatures or algorithms.
    await page.evaluate(() => {
      const sign = crypto.subtle.sign.bind(crypto.subtle);
      crypto.subtle.sign = async (...args: Parameters<SubtleCrypto['sign']>) => {
        const result = await sign(...args);
        (window as Window & { csrRawSignature?: number[] }).csrRawSignature = Array.from(new Uint8Array(result));
        return result;
      };
    });
    const output = await generate(panel);
    const csr = parseCsr(decodeOutput(output.csr, profile.format === 'der' ? undefined : 'CERTIFICATE REQUEST'));
    expect(csr.signatureOid).toBe(profile.signatureOid);
    expect(csr.subject).toEqual({ '2.5.4.6': { value: 'SK', tag: 19 }, '2.5.4.3': { value: 'app.example.com', tag: 12 } });
    expect(csr.sans.map((san) => ({ tag: san.tag, value: san.bytes.toString('ascii') }))).toEqual([{ tag: 2, value: 'app.example.com' }]);
    matchPublicKeys(csr.publicKey, createPublicKey({ key: decodeOutput(output.publicKey, 'PUBLIC KEY'), format: 'der', type: 'spki' }));
    verifyPrivateKey(output.privateKey, profile.format, csr.publicKey);
    const [spkiAlgorithm, spkiBits] = sequence(csr.spki, 2);
    const spkiParameters = sequence(spkiAlgorithm, 2);
    requireCondition(spkiBits instanceof BitString && spkiBits.valueBlock.unusedBits === 0, 'Invalid SPKI bit string');
    if (profile.type === 'rsa') {
      expect(oid(spkiParameters[0])).toBe('1.2.840.113549.1.1.1');
      expect(csr.publicKey.asymmetricKeyDetails?.modulusLength).toBe(Number(profile.size));
      expect(csr.publicKey.asymmetricKeyDetails?.publicExponent).toBe(65537n);
      const [modulus] = sequence(parseDer(spkiBits.valueBlock.valueHexView), 2);
      requireCondition(modulus instanceof Integer && modulus.valueBlock.valueHexView[0] === 0 && Boolean(modulus.valueBlock.valueHexView[1] & 128), 'RSA modulus must have sign padding');
    } else {
      expect(oid(spkiParameters[0])).toBe('1.2.840.10045.2.1');
      expect(oid(spkiParameters[1])).toBe(profile.curveOid);
      expect(csr.publicKey.asymmetricKeyDetails?.namedCurve).toBe(profile.curve);
      const raw = Buffer.from(await page.evaluate(() => (window as Window & { csrRawSignature?: number[] }).csrRawSignature ?? []));
      const parts = sequence(parseDer(csr.signature), 2);
      parts.forEach((part, index) => {
        requireCondition(part instanceof Integer, 'Missing ECDSA INTEGER');
        const magnitude = raw.subarray(index * raw.length / 2, (index + 1) * raw.length / 2);
        const numeric = (bytes: Uint8Array) => BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
        requireCondition(numeric(part.valueBlock.valueHexView) === numeric(magnitude), 'Raw WebCrypto signature differs from DER ECDSA signature');
      });
      if (profile.size === 'P-521') requireCondition(Boolean(csr.signature[1] & 128), 'P-521 signature must exercise long DER length');
    }
    const badSignature = Buffer.from(csr.signature);
    badSignature[badSignature.length - 1] ^= 1;
    requireCondition(!csr.verifySignature(csr.signed, badSignature), 'Corrupted CSR signature unexpectedly verified');
    const alteredInfo = Buffer.from(csr.signed);
    const nameOffset = alteredInfo.indexOf('app.example.com');
    requireCondition(nameOffset >= 0, 'Cannot locate signed CN');
    alteredInfo[nameOffset] = 'b'.charCodeAt(0);
    requireCondition(!csr.verifySignature(alteredInfo), 'Modified signed CSR contents unexpectedly verified');
  });
}

test('encodes all subject fields and mixed DNS/IPv4/IPv6 SANs', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  await field(panel, 'CN / Common Name \\*').fill('API.example.test');
  await field(panel, 'Country \\*').fill('hu');
  await field(panel, 'Organization').fill('Pr\u00f3ba Labs');
  await field(panel, 'Organizational Unit').fill('Biztons\u00e1g');
  await field(panel, 'State / Province').fill('Pest');
  await field(panel, 'Locality / City').fill('Gy\u0151r');
  await field(panel, 'Email').fill('admin@example.test');
  const extraSans = ['www.example.test', '*.example.test', '192.0.2.10', '2001:db8::1'];
  for (const value of extraSans) {
    await panel.getByRole('button', { name: 'Add SAN', exact: true }).click();
    await panel.getByRole('textbox', { name: /^SAN \d+$/ }).last().fill(value);
  }
  const output = await generate(panel);
  const csr = parseCsr(decodeOutput(output.csr, 'CERTIFICATE REQUEST'));
  expect(csr.subject).toEqual({
    '2.5.4.6': { value: 'HU', tag: 19 }, '2.5.4.8': { value: 'Pest', tag: 12 }, '2.5.4.7': { value: 'Gy\u0151r', tag: 12 },
    '2.5.4.10': { value: 'Pr\u00f3ba Labs', tag: 12 }, '2.5.4.11': { value: 'Biztons\u00e1g', tag: 12 },
    '2.5.4.3': { value: 'API.example.test', tag: 12 }, '1.2.840.113549.1.9.1': { value: 'admin@example.test', tag: 22 },
  });
  expect(csr.sans.map((entry) => ({ tag: entry.tag, hex: entry.bytes.toString('hex') }))).toEqual([
    ...['api.example.test', 'www.example.test', '*.example.test'].map((name) => ({ tag: 2, hex: Buffer.from(name).toString('hex') })),
    { tag: 7, hex: 'c000020a' }, { tag: 7, hex: '20010db8000000000000000000000001' },
  ]);
  verifyPrivateKey(output.privateKey, 'pkcs8', csr.publicKey);
});

for (const keyType of ['rsa', 'ec']) test(`${keyType} encrypted PKCS#8 verifies PBES2 parameters, decryption and fresh salt/IV`, async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  await field(panel, 'Key type \\*', 'combobox').selectOption(keyType);
  await panel.getByRole('button', { name: 'Advanced export format' }).click();
  await panel.getByRole('radio', { name: 'Encrypted PKCS#8 PEM' }).check();
  await expect(panel.getByText('Password is required for encrypted private key export.', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Generate private key and CSR' })).toBeDisabled();
  const password = randomBytes(24).toString('base64url');
  // fill(password) exposes its argument in Playwright reporter step titles.
  // Drive React's real input handler without placing the secret in a step name.
  await page.evaluate((secret) => {
    const input = document.querySelector<HTMLInputElement>('input[type="password"]');
    if (!input) throw new Error('Missing encryption password input');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value')?.set?.call(input, secret);
    input.dispatchEvent(new Event('input', { bubbles: true }));
  }, password);
  const parameters: ReturnType<typeof encryptedParameters>[] = [];
  for (let i = 0; i < 2; i++) {
    const output = await generate(panel);
    const csr = parseCsr(decodeOutput(output.csr, 'CERTIFICATE REQUEST'));
    const bytes = verifyPrivateKey(output.privateKey, 'encrypted', csr.publicKey, password);
    parameters.push(encryptedParameters(bytes));
    decryptPrivateKey(bytes, password, csr.publicKey);
    let failed = false;
    try { createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8', passphrase: randomBytes(24).toString('base64url') }); }
    catch { failed = true; }
    requireCondition(failed, 'Incorrect password unexpectedly decrypted private key');
  }
  requireCondition(!parameters[0].salt.equals(parameters[1].salt) && !parameters[0].iv.equals(parameters[1].iv), 'Encryption reused salt or IV');
});

test('browser smoke, algorithm-specific export options, validation and safe copy checks', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  await generate(panel);
  const blocks = panel.locator('pre');
  for (let i = 0; i < 3; i++) {
    await blocks.nth(i).locator('..').getByRole('button', { name: 'Copy', exact: true }).click();
    // Compare inside the browser and return only a boolean, never clipboard secrets.
    await expect.poll(() => page.evaluate(async (index) => {
      const output = document.querySelectorAll('article pre')[index]?.textContent;
      return (await navigator.clipboard.readText()).replace(/\r\n/g, '\n') === output?.replace(/\r\n/g, '\n');
    }, i)).toBe(true);
  }
  await panel.getByRole('button', { name: 'Advanced export format' }).click();
  await panel.getByRole('radio', { name: 'Traditional RSA PEM' }).check();
  await field(panel, 'Key type \\*', 'combobox').selectOption('ec');
  await expect(panel.getByRole('radio', { name: /^PKCS#8 PEM/ })).toBeChecked();
  await panel.getByRole('radio', { name: 'Traditional EC PEM' }).check();
  const ecOutput = await generate(panel);
  const csr = parseCsr(decodeOutput(ecOutput.csr, 'CERTIFICATE REQUEST'));
  verifyPrivateKey(ecOutput.privateKey, 'ec', csr.publicKey);
  await field(panel, 'Key type \\*', 'combobox').selectOption('rsa');
  await expect(panel.getByRole('radio', { name: /^PKCS#8 PEM/ })).toBeChecked();
  for (const invalid of ['bad..example.test', '256.0.0.1/32', '2001:db8:::1']) {
    await field(panel, 'CN / Common Name \\*').fill(invalid);
    await expect(panel.getByRole('button', { name: 'Generate private key and CSR' })).toBeDisabled();
    await expect(panel.getByText('Use a DNS name, wildcard DNS name, IPv4 address, or IPv6 address.', { exact: true }).first()).toBeVisible();
  }
  await field(panel, 'CN / Common Name \\*').fill('');
  await expect(panel.getByText('Common Name is required.', { exact: true })).toBeVisible();
  await expect(panel.getByText('At least one SAN is required.', { exact: true })).toBeVisible();
  await field(panel, 'CN / Common Name \\*').fill('app.example.test');
  await field(panel, 'Country \\*').fill('1');
  await expect(panel.getByText('Country must be a two-letter ISO code, for example DE or US.', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Generate private key and CSR' })).toBeDisabled();
  await field(panel, 'Country \\*').fill('SK');
  await field(panel, 'Email').fill('invalid');
  await expect(panel.getByText('Enter a valid email address.', { exact: true })).toBeVisible();
  await expect(panel.getByRole('button', { name: 'Generate private key and CSR' })).toBeDisabled();
});

test('SAN count is capped at the existing 100 entries', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  const add = panel.getByRole('button', { name: 'Add SAN', exact: true });
  for (let i = 1; i < 100; i++) await add.click();
  await expect(panel.getByRole('button', { name: /^Remove SAN \d+$/ })).toHaveCount(100);
  await expect(add).toBeDisabled();
  await expect(panel.getByRole('button', { name: 'Remove SAN 1', exact: true })).toBeDisabled();
  const output = await generate(panel);
  expect(parseCsr(decodeOutput(output.csr, 'CERTIFICATE REQUEST')).sans).toHaveLength(100);
});

test('unsupported email identities block generation and ASCII recovery preserves exact IA5 bytes', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  const email = panel.getByLabel('Email', { exact: true });
  const button = panel.getByRole('button', { name: 'Generate private key and CSR' });
  for (const invalid of ['Ł@example.com', 'é@example.com', 'user@exämple.com', '😀@example.com', '\u0141@example.com']) {
    await email.fill(invalid);
    await expect(email).toHaveAttribute('aria-invalid', 'true');
    await expect(panel.getByRole('alert')).toContainText('ASCII');
    await expect(button).toBeDisabled();
    await expect(panel.locator('pre')).toHaveCount(0);
  }
  await field(panel, 'Key type \\*', 'combobox').selectOption('ec');
  for (const valid of ['admin@example.com', 'first.last+tag@example.com', '']) {
    await email.fill(valid);
    await expect(button).toBeEnabled();
    const output = await generate(panel);
    const csr = parseCsr(decodeOutput(output.csr, 'CERTIFICATE REQUEST'));
    if (valid) {
      expect(csr.subject['1.2.840.113549.1.9.1']).toEqual({ value: valid, tag: 0x16 });
      requireCondition(csr.subjectBytes['1.2.840.113549.1.9.1'].equals(Buffer.from(valid, 'ascii')), 'Email bytes differ from accepted input');
    } else expect(csr.subject['1.2.840.113549.1.9.1']).toBeUndefined();
    requireCondition(csr.verifySignature(), 'CSR signature failed');
  }
});

test('invalid inputs cannot produce an initial CSR; example restoration is preserved', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  const generateButton = panel.getByRole('button', { name: 'Generate private key and CSR' });
  const cn = field(panel, 'CN / Common Name \\*');
  await cn.fill('');
  await expect(generateButton).toBeDisabled();
  await expect(panel.locator('pre')).toHaveCount(0);
  await cn.blur();
  await expect(cn).toHaveValue('app.example.com');
  const country = field(panel, 'Country \\*');
  await country.fill('');
  await expect(generateButton).toBeDisabled();
  await country.blur();
  await expect(country).toHaveValue('SK');
  await panel.getByRole('button', { name: 'Add SAN', exact: true }).click();
  const san = panel.getByRole('textbox', { name: 'SAN 2', exact: true });
  for (const invalid of ['', 'bad..name', '192.0.2.-1', '2001::db8::1']) {
    await san.fill(invalid);
    await expect(generateButton).toBeDisabled();
    await expect(panel.locator('pre')).toHaveCount(0);
  }
});

test('real ECDSA output exercises necessary sign padding and unpadded INTEGERs', async ({ page }) => {
  const panel = await openTool(page, 'CSR Generator');
  await field(panel, 'Key type \\*', 'combobox').selectOption('ec');
  let padded = false, unpadded = false;
  // Disposable signatures are random. Sample until both encoding branches are
  // observed, rather than assuming a single random signature has its high bit set.
  for (let i = 0; i < 64 && !(padded && unpadded); i++) {
    const output = await generate(panel);
    const csr = parseCsr(decodeOutput(output.csr, 'CERTIFICATE REQUEST'));
    for (const part of sequence(parseDer(csr.signature), 2)) {
      requireCondition(part instanceof Integer, 'Missing ECDSA INTEGER');
      if (part.valueBlock.valueHexView[0] === 0) padded = true;
      else unpadded = true;
    }
  }
  requireCondition(padded && unpadded, 'Did not observe both ECDSA INTEGER encoding branches');
});
