export function createSafeFileName(value: string) {
  return (
    value.trim().replace(/^\*\./, 'wildcard.').replace(/[^A-Za-z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') ||
    'request'
  );
}

export function numberToBytes(value: number) {
  const bytes = [];
  let remainingValue = value;

  while (remainingValue > 0) {
    bytes.unshift(remainingValue & 255);
    remainingValue >>= 8;
  }

  return new Uint8Array(bytes.length ? bytes : [0]);
}

export function trimLeadingZeroBytes(value: Uint8Array) {
  let index = 0;

  while (index < value.length - 1 && value[index] === 0) {
    index += 1;
  }

  return value.slice(index);
}

export function concatBytes(...parts: Uint8Array[]) {
  const totalLength = parts.reduce((length, part) => length + part.length, 0);
  const output = new Uint8Array(totalLength);
  let offset = 0;

  parts.forEach((part) => {
    output.set(part, offset);
    offset += part.length;
  });

  return output;
}

export function toArrayBuffer(bytes: Uint8Array) {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function asciiBytes(value: string) {
  return new Uint8Array([...value].map((character) => character.charCodeAt(0)));
}

export function utf8Bytes(value: string) {
  return new TextEncoder().encode(value);
}
