import { createBLAKE2b, createBLAKE3, createCRC32, createMD5, createSHA1, createSHA256, createSHA384, createSHA512, createXXHash32 } from 'hash-wasm';
import { algorithms, type Algorithm, type Digests, type HashProgress, type HashRequest } from './types';

export const CHUNK_BYTES = 4 * 1024 * 1024;
const TEXT_CHARS = CHUNK_BYTES / 4;
const factories = { sha256: createSHA256, sha384: createSHA384, sha512: createSHA512, sha1: createSHA1, md5: createMD5, blake3: () => createBLAKE3(256), blake2b256: () => createBLAKE2b(256), crc32: () => createCRC32(), xxhash32: () => createXXHash32(0) };

export class HashFailure extends Error {}

export function utf8Size(text: string) {
  let bytes = 0;
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code < 0x80) bytes++;
    else if (code < 0x800) bytes += 2;
    else if (code >= 0xd800 && code <= 0xdbff && text.charCodeAt(i + 1) >= 0xdc00 && text.charCodeAt(i + 1) <= 0xdfff) { bytes += 4; i++; }
    else bytes += 3; // TextEncoder replaces lone surrogates with U+FFFD.
  }
  return bytes;
}

async function* chunks(input: Blob | string) {
  if (typeof input === 'string') {
    const encoder = new TextEncoder();
    for (let offset = 0; offset < input.length;) {
      let end = Math.min(input.length, offset + TEXT_CHARS);
      const last = input.charCodeAt(end - 1);
      if (end < input.length && last >= 0xd800 && last <= 0xdbff) end--;
      yield encoder.encode(input.slice(offset, end));
      offset = end;
    }
  } else {
    for (let offset = 0; offset < input.size; offset += CHUNK_BYTES) {
      let buffer: ArrayBuffer;
      try { buffer = await input.slice(offset, offset + CHUNK_BYTES).arrayBuffer(); }
      catch { throw new HashFailure('Could not read the file. File access may have been interrupted; select it again and retry.'); }
      if (buffer.byteLength !== Math.min(CHUNK_BYTES, input.size - offset)) throw new HashFailure('The file read was incomplete. Select the file again and retry.');
      yield new Uint8Array(buffer);
    }
  }
}

export async function calculateHashes(request: HashRequest, progress: (value: HashProgress) => void, now = () => performance.now()) {
  const selected = [...new Set(request.algorithms)];
  if (!selected.length || selected.some((id) => !algorithms.some((item) => item.id === id))) throw new HashFailure('Select at least one supported algorithm.');
  const started = now();
  const total = typeof request.input === 'string' ? utf8Size(request.input) : request.input.size;
  let states;
  try { states = await Promise.all(selected.map(async (id: Algorithm) => ({ id, hasher: (await factories[id]()).init() }))); }
  catch { throw new HashFailure('Could not initialize local WebAssembly hashing. Your browser or security policy may not allow WASM.'); }
  let processed = 0;
  let lastProgress = started;
  progress({ processed, total, elapsedMs: now() - started });
  for await (const chunk of chunks(request.input)) {
    for (const { hasher } of states) hasher.update(chunk);
    processed += chunk.byteLength;
    const time = now();
    if (time - lastProgress >= 100) {
      progress({ processed, total, elapsedMs: time - started });
      lastProgress = time;
    }
  }
  const digests: Digests = {};
  for (const { id, hasher } of states) digests[id] = hasher.digest('hex');
  return { digests, processed, total, elapsedMs: now() - started };
}
