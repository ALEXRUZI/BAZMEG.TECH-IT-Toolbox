import { describe, expect, it } from 'vitest';
import { decodeOutput, oid, parseCsr, parseDer, sequence } from './verification';

// Public, hand-specified ASN.1 values calibrate the independent verification
// harness, not the production encoders. No keys or passwords are fixtures.
describe('independent CSR verification harness', () => {
  it('decodes an OID and canonical short DER length', () => {
    const fields = sequence(parseDer(Buffer.from('300806062a864886f70d', 'hex')), 1);
    expect(oid(fields[0])).toBe('1.2.840.113549');
  });

  it('accepts a canonical long DER length', () => {
    const bytes = Buffer.concat([Buffer.from('048180', 'hex'), Buffer.alloc(128)]);
    expect(parseDer(bytes).lenBlock.length).toBe(128);
  });

  it.each([
    ['negative INTEGER', '020180'],
    ['redundant sign padding', '02020001'],
    ['non-minimal long length', '04810100'],
    ['indefinite sequence', '30800000'],
    ['trailing sequence data', '3003020100ff'],
    ['truncated contents', '30030201'],
    ['trailing bytes', '02010000'],
  ])('rejects %s', (_name, hex) => {
    expect(() => parseDer(Buffer.from(hex, 'hex'))).toThrow();
  });

  it('accepts necessary positive INTEGER sign padding', () => {
    expect(() => parseDer(Buffer.from('02020080', 'hex'))).not.toThrow();
  });

  it('decodes PEM labels and base64 DER text', () => {
    expect(decodeOutput('-----BEGIN PUBLIC KEY-----\nAgEA\n-----END PUBLIC KEY-----', 'PUBLIC KEY')).toEqual(Buffer.from('020100', 'hex'));
    expect(decodeOutput('Ag\nEA')).toEqual(Buffer.from('020100', 'hex'));
  });

  it.each([
    ['wrong PEM label', '-----BEGIN PRIVATE KEY-----\nAgEA\n-----END PRIVATE KEY-----', 'PUBLIC KEY'],
    ['mismatched PEM end', '-----BEGIN PUBLIC KEY-----\nAgEA\n-----END PRIVATE KEY-----', 'PUBLIC KEY'],
    ['invalid base64', 'not!base64', undefined],
    ['non-canonical base64', 'AB==', undefined],
  ])('rejects %s', (_name, text, label) => {
    expect(() => decodeOutput(text, label)).toThrow();
  });

  it('does not mistake an arbitrary SEQUENCE for PKCS#10', () => {
    expect(() => parseCsr(Buffer.from('3000', 'hex'))).toThrow('field count');
  });
});
