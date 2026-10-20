export const algorithms = [
  { id: 'sha256', label: 'SHA-256', length: 64 },
  { id: 'sha384', label: 'SHA-384', length: 96 },
  { id: 'sha512', label: 'SHA-512', length: 128 },
  { id: 'blake3', label: 'BLAKE3', length: 64 },
  { id: 'blake2b256', label: 'BLAKE2b-256', length: 64 },
  { id: 'crc32', label: 'CRC32 (IEEE)', length: 8 },
  { id: 'xxhash32', label: 'xxHash32 (seed 0)', length: 8 },
  { id: 'sha1', label: 'SHA-1', length: 40 },
  { id: 'md5', label: 'MD5', length: 32 },
] as const;

export type Algorithm = typeof algorithms[number]['id'];
export type Digests = Partial<Record<Algorithm, string>>;
export type HashRequest = { input: Blob | string; algorithms: Algorithm[] };
export type HashProgress = { processed: number; total: number; elapsedMs: number };
export type HashMessage =
  | ({ type: 'progress' } & HashProgress)
  | ({ type: 'done'; digests: Digests } & HashProgress)
  | { type: 'error'; message: string };
