// @vitest-environment node
import { expect, it, vi } from 'vitest';
vi.mock('hash-wasm', () => {
  const fail = () => Promise.reject(new Error('internal WASM failure'));
  return { createSHA256: fail, createSHA384: vi.fn(), createSHA512: vi.fn(), createSHA1: vi.fn(), createMD5: vi.fn(), createBLAKE3: vi.fn(), createBLAKE2b: fail, createCRC32: fail, createXXHash32: fail };
});
import { calculateHashes } from '../src/tools/hash-calculator/engine';
it.each(['sha256', 'crc32', 'blake2b256', 'xxhash32'] as const)('maps %s WASM initialization failure without exposing internals or falling back', async (id) => {
  await expect(calculateHashes({ input: '', algorithms: [id] }, () => {})).rejects.toThrow('Could not initialize local WebAssembly hashing');
});
