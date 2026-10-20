// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createCsr } from '../../src/tools/csr-generator/csrCrypto';
import { derIa5String, derName } from '../../src/tools/csr-generator/csrDer';
import { validateCsrEmail } from '../../src/tools/csr-generator/csrValidation';
import type { CreateCsrInput } from '../../src/tools/csr-generator/csrTypes';
import { decodeOutput, parseCsr } from './verification';

const emailOid = '1.2.840.113549.1.9.1';
const input: CreateCsrInput = {
  commonName: 'app.example.com', country: 'SK', organization: 'Próba', organizationalUnit: '',
  locality: '', state: '', email: '', sans: ['app.example.com'], keyType: 'ec', keySize: 'P-256',
  signatureHash: 'SHA-256', csrOutputFormat: 'pem-pkcs10', privateKeyOutputFormat: 'pkcs8-pem',
  privateKeyPassword: '',
};
const invalid = [
  'Ł@example.com', 'é@example.com', 'user@exämple.com', '😀@example.com',
  '\u0141@example.com', '\u0161@example.com', '\ud800@example.com',
  'a\0b@example.com', 'a\x01b@example.com', 'a\x7fb@example.com',
  'a\nb@example.com', 'a\rb@example.com', 'a\tb@example.com', '\nadmin@example.com',
  '\u00a0admin@example.com', 'invalid', '@example.com', 'user@', 'user@example',
  'user@@example.com', 'user@example..com', '.user@example.com', 'user.@example.com',
  'first..last@example.com', 'user name@example.com', 'user@-example.com',
  'user@example_.com', 'user@*.example.com', 'user@example.com.',
  `${'a'.repeat(65)}@example.com`,
];

beforeEach(() => vi.stubGlobal('window', { btoa, atob }));
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

describe('CSR ASCII email identity', () => {
  it.each(['admin@example.com', 'first.last+tag@example.com', '', '  admin@example.com  ', '   '])(
    'independently verifies accepted email %j without identity corruption', async (email) => {
      expect(validateCsrEmail(email)).toBe('');
      const output = await createCsr({ ...input, email });
      const csr = parseCsr(decodeOutput(output.csrOutput, 'CERTIFICATE REQUEST'));
      expect(csr.verifySignature()).toBe(true);
      if (email.trim()) {
        expect(csr.subject[emailOid]).toEqual({ value: email.trim(), tag: 0x16 });
        expect(csr.subjectBytes[emailOid].equals(Buffer.from(email.trim(), 'ascii'))).toBe(true);
      } else expect(csr.subject[emailOid]).toBeUndefined();
      expect(csr.subject['2.5.4.10']).toEqual({ value: 'Próba', tag: 0x0c });
    }
  );

  it.each(invalid)('rejects unsupported email %j before key generation, even without UI validation', async (email) => {
    const generateKey = vi.spyOn(crypto.subtle, 'generateKey');
    expect(validateCsrEmail(email)).not.toBe('');
    await expect(createCsr({ ...input, email })).rejects.toThrow(/email address/);
    expect(generateKey).not.toHaveBeenCalled();
    expect(() => derName([[emailOid, email]])).toThrow();
  });

  it.each(['Ł', 'é', '😀', '\u0141', '\u0161', '\ud800'])('direct IA5String rejects %j instead of truncating', (value) => {
    expect(() => derIa5String(value)).toThrow('IA5String requires ASCII characters.');
  });

  it('direct IA5String preserves exact ASCII bytes and tag', () => {
    const email = 'first.last+tag@example.com';
    expect(derIa5String(email)).toEqual(new Uint8Array([0x16, email.length, ...Buffer.from(email, 'ascii')]));
  });
});
