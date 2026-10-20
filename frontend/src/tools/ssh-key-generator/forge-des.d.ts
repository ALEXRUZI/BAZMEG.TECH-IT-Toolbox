// Narrow declarations for the only Forge primitives imported by this tool.
declare module 'node-forge/lib/util.js' {
  export interface ByteBuffer { getBytes(): string }
  const util: { createBuffer(bytes: string): ByteBuffer };
  export default util;
}
declare module 'node-forge/lib/cipher.js' {
  import type { ByteBuffer } from 'node-forge/lib/util.js';
  interface Cipher { start(options: { iv: string }): void; update(input: ByteBuffer): void; finish(padding: () => boolean): boolean; output: ByteBuffer }
  const cipher: { createCipher(name: string, key: string): Cipher; createDecipher(name: string, key: string): Cipher };
  export default cipher;
}
declare module 'node-forge/lib/des.js';
