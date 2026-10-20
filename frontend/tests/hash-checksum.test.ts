import { describe, expect, it } from 'vitest';
import { verifyChecksum } from '../src/tools/hash-calculator/checksum';
import { algorithms } from '../src/tools/hash-calculator/types';

describe('checksum verification', () => {
  it.each(algorithms)('verifies $label with whitespace and case normalization', ({ id, length }) => {
    expect(verifyChecksum(` \n${'AB'.repeat(length / 2)}\t `, id, { [id]: 'ab'.repeat(length / 2) }).matches).toBe(true);
    expect(verifyChecksum('ab'.repeat(length / 2), id, { [id]: 'cd'.repeat(length / 2) }).message).toContain('does not match');
  });
  it.each(['abc', '0x' + 'a'.repeat(64), 'g'.repeat(64), 'a'.repeat(63) + ' ', 'ab cd', 'a'.repeat(64) + ' file.iso'])('rejects malformed checksum %j', (input) => {
    expect(verifyChecksum(input, 'auto', {}).error).not.toBe('');
  });
  it.each([8, 64])('requires explicit selection for %i hex ambiguity even if one is calculated', (length) => {
    const candidates = algorithms.filter((item) => item.length === length);
    for (const candidate of candidates) {
      const value = 'a'.repeat(length);
      const result = verifyChecksum(value, 'auto', { [candidate.id]: value });
      expect(result.error).toContain('ambiguous');
      for (const item of candidates) expect(result.error).toContain(item.label);
      expect(verifyChecksum(value, candidate.id, { [candidate.id]: value }).matches).toBe(true);
      expect(verifyChecksum(value, candidate.id, {}).message).toContain(`Calculate ${candidate.label}`);
    }
  });
  it('infers only unambiguous supported lengths, and asks for missing digest', () => {
    expect(verifyChecksum('a'.repeat(96), 'auto', { sha384: 'a'.repeat(96) }).matches).toBe(true);
    expect(verifyChecksum('a'.repeat(40), 'auto', {}).message).toContain('Calculate SHA-1');
    expect(verifyChecksum('a'.repeat(40), 'sha512', {}).error).not.toBe('');
    expect(verifyChecksum(' \t', 'auto', {}).message).toBe('');
  });
});
