export const MAX_IMPORT = 64 * 1024;
export function check(condition: unknown, message = 'Malformed or inconsistent key.'): asserts condition {
  if (!condition) throw new Error(message);
}
export const utf8 = (text: string) => new TextEncoder().encode(text);
export const text = (bytes: Uint8Array) => new TextDecoder('utf-8', { fatal: true }).decode(bytes);
export const random = (length: number) => crypto.getRandomValues(new Uint8Array(length));
export function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}
export function u32(n: number): Uint8Array { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
export function u16(n: number): Uint8Array { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n); return b; }
export function ssh1int(b: Uint8Array): Uint8Array { b = unsigned(b); const bits = bigint(b).toString(2).length; check(bigint(b) > 0n && bits <= 1024); return concat(u16(bits), b); }
export function string(value: Uint8Array | string): Uint8Array { const b = typeof value === 'string' ? utf8(value) : value; return concat(u32(b.length), b); }
export function unsigned(b: Uint8Array): Uint8Array { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; return b.slice(i); }
export function mpint(b: Uint8Array): Uint8Array { b = unsigned(b); return string(b[0] & 128 ? concat(new Uint8Array([0]), b) : b); }
export function base64(b: Uint8Array): string { return btoa(String.fromCharCode(...b)); }
export function unbase64(value: string): Uint8Array {
  check(value.length <= MAX_IMPORT && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value));
  const decoded = Uint8Array.from(atob(value), c => c.charCodeAt(0));
  check(base64(decoded) === value);
  return decoded;
}
export const b64url = (b: Uint8Array) => base64(unsigned(b)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
export function fromUrl(value: string): Uint8Array { return unbase64(value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4)); }
export const hex = (b: Uint8Array) => Array.from(b, n => n.toString(16).padStart(2, '0')).join('');
export function unhex(value: string): Uint8Array { check(/^(?:[0-9a-fA-F]{2})+$/.test(value) && value.length <= 128); return Uint8Array.from(value.match(/../g)!, n => parseInt(n, 16)); }
export const equal = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((n, i) => n === b[i]);
export const bigint = (b: Uint8Array) => BigInt(`0x${hex(b) || '0'}`);
export function integer(n: bigint): Uint8Array { let s = n.toString(16); if (s.length % 2) s = `0${s}`; return Uint8Array.from(s.match(/../g)!, v => parseInt(v, 16)); }
export function lines(value: string, width = 64): string { return value.match(new RegExp(`.{1,${width}}`, 'g'))!.join('\n'); }
export function validComment(value: string): void { check(utf8(value).length <= 256 && !/[\x00-\x1f\x7f]/.test(value), 'Comment must be a single line of at most 256 UTF-8 bytes, without control characters.'); }
export class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) { check(bytes.length <= MAX_IMPORT); }
  take(n: number): Uint8Array { check(n >= 0 && n <= this.bytes.length - this.offset); const b = this.bytes.slice(this.offset, this.offset + n); this.offset += n; return b; }
  u32(): number { return new DataView(this.take(4).buffer).getUint32(0); }
  ssh1int(): Uint8Array { const bits = new DataView(this.take(2).buffer).getUint16(0); check(bits > 0 && bits <= 1024); const b = this.take(Math.ceil(bits / 8)); check(bigint(b).toString(2).length === bits); return b; }
  string(): Uint8Array { return this.take(this.u32()); }
  text(): string { return text(this.string()); }
  mpint(): Uint8Array { const b = this.string(); check(b.length > 0 && b.length <= 1025 && !(b[0] & 128) && !(b.length > 1 && b[0] === 0 && !(b[1] & 128))); return unsigned(b); }
  end(): void { check(this.offset === this.bytes.length); }
}
