// @vitest-environment node
import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { calculateHashes, CHUNK_BYTES, utf8Size } from '../src/tools/hash-calculator/engine';
import { algorithms, type Algorithm } from '../src/tools/hash-calculator/types';
import { editText, textOffset } from '../src/tools/hash-calculator/text';
import references from './fixtures/hash-references.json';

const standard = algorithms.filter(({ id }) => !['blake3', 'blake2b256', 'crc32', 'xxhash32'].includes(id)).map(({ id }) => id);
describe('incremental hashing against independent Node/OpenSSL implementations', () => {
  it.each(references.filter((vector) => !vector.zeros))('all nine share exact chunks: reference %#', async (vector) => {
    const input = vector.text ?? new Blob([Uint8Array.from({ length: vector.length! }, (_, i) => i % 251)]);
    const slice = typeof input === 'string' ? null : vi.spyOn(input, 'slice');
    for (let run = 0; run < 2; run++) {
      const result = await calculateHashes({ input, algorithms: algorithms.map(({ id }) => id) }, () => {});
      expect(result.digests).toMatchObject(vector.digests);
      expect(Object.keys(result.digests)).toHaveLength(9);
      for (const id of standard) expect(result.digests[id]).toBe(createHash(id).update(typeof input === 'string' ? input : Buffer.from(await input.arrayBuffer())).digest('hex'));
    }
    if (slice) {
      expect(slice).toHaveBeenCalledTimes(2 * Math.ceil(vector.length! / CHUNK_BYTES));
      slice.mock.calls.forEach(([start, end]) => expect(Number(end) - Number(start)).toBeLessThanOrEqual(CHUNK_BYTES));
    }
  });
  it('checks the documented known answers and parameterization, not truncated BLAKE2b-512', async () => {
    const abc = (await calculateHashes({ input: 'abc', algorithms: ['crc32', 'blake2b256', 'xxhash32'] }, () => {})).digests;
    expect(abc.blake2b256).toBe('bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319');
    expect(abc.blake2b256).not.toBe(createHash('blake2b512').update('abc').digest('hex').slice(0, 64));
    expect(abc.xxhash32).toBe('32d153ff');
    expect((await calculateHashes({ input: '123456789', algorithms: ['crc32'] }, () => {})).digests.crc32).toBe('cbf43926');
  });
  it.each(['', 'abc', ' \t雪😀e\u0301\r\n\r\n ', '\ud800x\udfff', '\u0000'])('preserves exact UTF-8 input %j', async (input) => {
    const result = await calculateHashes({ input, algorithms: standard }, () => {});
    for (const id of standard) expect(result.digests[id]).toBe(createHash(id).update(input, 'utf8').digest('hex'));
    expect(result.total).toBe(Buffer.byteLength(input));
    expect(utf8Size(input)).toBe(Buffer.byteLength(input));
  });
  it.each([55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1023, 1024, 1025, CHUNK_BYTES - 1, CHUNK_BYTES, CHUNK_BYTES + 1, CHUNK_BYTES * 2 + 17])('hashes %i raw bytes with one bounded read per chunk', async (length) => {
    const bytes = Uint8Array.from({ length }, (_, i) => i % 251);
    const blob = new Blob([bytes]);
    const slice = vi.spyOn(blob, 'slice');
    const result = await calculateHashes({ input: blob, algorithms: standard }, () => {});
    for (const id of standard) expect(result.digests[id]).toBe(createHash(id).update(bytes).digest('hex'));
    expect(slice).toHaveBeenCalledTimes(Math.ceil(length / CHUNK_BYTES));
    slice.mock.calls.forEach(([start, end]) => expect(Number(end) - Number(start)).toBeLessThanOrEqual(CHUNK_BYTES));
  });
  it('does not split a UTF-16 surrogate pair at an encoding chunk boundary', async () => {
    const input = 'a'.repeat(CHUNK_BYTES / 4 - 1) + '😀雪\r\n';
    const result = await calculateHashes({ input, algorithms: standard }, () => {});
    for (const id of standard) expect(result.digests[id]).toBe(createHash(id).update(input).digest('hex'));
  });
  // BLAKE3 team's official test_vectors.json: repeating bytes i % 251,
  // first 32 bytes of unkeyed extended output. Not generated with hash-wasm.
  it.each([
    [0, 'af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262'],
    [1024, '42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7'],
    [1025, 'd00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444'],
    [102400, 'bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085'],
  ])('matches official BLAKE3 vector %i', async (length, digest) => {
    const input = new Blob([Uint8Array.from({ length: Number(length) }, (_, i) => i % 251)]);
    expect((await calculateHashes({ input, algorithms: ['blake3'] }, () => {})).digests.blake3).toBe(digest);
  });
  it('handles empty files for all algorithms', async () => {
    const result = await calculateHashes({ input: new Blob([]), algorithms: algorithms.map(({ id }) => id) }, () => {});
    for (const id of standard) expect(result.digests[id]).toBe(createHash(id).digest('hex'));
    expect(result.digests).toMatchObject(references[0].digests);
    expect(result.processed).toBe(0);
  });
  it.each([
    [4194303, '6ee7f30ae33570aae744290e3f678050511e72f37e594d7620a9191c7d353dd9'],
    [4194304, '4e94e6f582581a0f3855f3ce504b153e951e65036fe9e2f010b7e25473c54f98'],
    [4194305, '0460893a0170917e0d568bb27c0287984d4f7e9d59eafb95e6fb3c01ec611eab'],
    [8388625, '6cbe97538ff151a60c70079b6290b88cf295f77e99fa34f6da49e1b68e29d580'],
  ])('matches independent @noble/hashes 2.0.1 BLAKE3 chunk-boundary reference %i', async (length, digest) => {
    const input = new Blob([Uint8Array.from({ length: Number(length) }, (_, i) => i % 251)]);
    expect((await calculateHashes({ input, algorithms: ['blake3'] }, () => {})).digests.blake3).toBe(digest);
  });
  it('throttles progress to at most once per 100 ms plus initial notification', async () => {
    const progress = vi.fn();
    let time = 0;
    const result = await calculateHashes({ input: new Blob([new Uint8Array(CHUNK_BYTES * 4)]), algorithms: ['sha256'] }, progress, () => time += 25);
    expect(progress).toHaveBeenCalledTimes(2);
    expect(result.processed).toBe(CHUNK_BYTES * 4);
  });
  it('rejects unsupported or empty algorithm selection', async () => {
    for (const selection of [[], ['unsupported'] as unknown as Algorithm[]]) await expect(calculateHashes({ input: '', algorithms: selection }, () => {})).rejects.toThrow('supported algorithm');
  });
  it('reports interrupted and incomplete file reads safely', async () => {
    const input = new Blob(['abc']);
    vi.spyOn(input, 'slice').mockImplementation(() => ({ arrayBuffer: () => Promise.reject(new Error('private filesystem detail')) }) as Blob);
    await expect(calculateHashes({ input, algorithms: ['sha256'] }, () => {})).rejects.toThrow('Could not read the file');
    vi.spyOn(input, 'slice').mockImplementation(() => new Blob([]));
    await expect(calculateHashes({ input, algorithms: ['sha256'] }, () => {})).rejects.toThrow('incomplete');
  });
});

describe('textarea byte preservation', () => {
  it('preserves CRLF and lone CR outside edited regions', () => {
    expect(editText('a\r\nb\rc', 'a\nb\nc!', { start: 5, end: 5, inputType: 'insertText' })).toBe('a\r\nb\rc!');
    expect(editText('a\r\nb\rc', 'a\nB\nc', { start: 2, end: 3, inputType: 'insertText' })).toBe('a\r\nB\rc');
    expect(editText('a\r\nb', 'ab', { start: 1, end: 1, inputType: 'deleteContentForward' })).toBe('ab');
    expect(textOffset('a\r\nb', 2)).toBe(3);
  });
});
