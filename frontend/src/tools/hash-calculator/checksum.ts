import { algorithms, type Algorithm, type Digests } from './types';

export function verifyChecksum(input: string, algorithm: Algorithm | 'auto', digests: Digests) {
  const hex = input.trim().toLowerCase();
  if (!hex) return { error: '', message: '', matches: false };
  if (!/^[0-9a-f]+$/.test(hex)) return { error: 'Enter only hexadecimal characters (no filename, prefix, or internal whitespace).', message: '', matches: false };
  const candidates = algorithms.filter((item) => item.length === hex.length && (algorithm === 'auto' || item.id === algorithm));
  const lengths = [...new Set(algorithms.map((item) => item.length))].sort((a, b) => a - b);
  if (!candidates.length) return { error: `Checksum length is not valid for the selected algorithm. Supported hex lengths: ${lengths.join(', ')}.`, message: '', matches: false };
  if (candidates.length > 1) return { error: `${hex.length} hex characters are ambiguous: choose ${candidates.map((item) => item.label).join(' or ')} explicitly. Length alone does not identify an algorithm.`, message: '', matches: false };
  const candidate = candidates[0];
  const digest = digests[candidate.id];
  if (!digest) return { error: '', message: `Calculate ${candidate.label} to verify this checksum. Length is only a hint, not proof of the algorithm.`, matches: false };
  const matches = hex === digest;
  return { error: '', message: `${candidate.label}: checksum ${matches ? 'matches' : 'does not match'}.`, matches, mismatch: !matches };
}
