import { isValidIpAddress, parseIpAddress, validateCsrEmail } from './csrValidation';
import { asciiBytes, concatBytes, utf8Bytes, trimLeadingZeroBytes } from './csrHelpers';
import { base64UrlDecode } from './csrPem';
import type { CsrKeyType, CsrSignatureHash } from './csrTypes';

export function derAttributeExtensionRequest(sans: string[]) {
  const generalNames = derSequence(
    ...sans.map((san) =>
      isValidIpAddress(san) ? derRaw(0x87, parseIpAddress(san)) : derRaw(0x82, asciiBytes(san.toLowerCase()))
    )
  );
  const sanExtension = derSequence(derObjectIdentifier('2.5.29.17'), derOctetString(generalNames));
  const extensions = derSequence(sanExtension);

  return derSequence(derObjectIdentifier('1.2.840.113549.1.9.14'), derSet(extensions));
}

export function derRsaPrivateKey(privateJwk: JsonWebKey) {
  const fields = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'] as const;

  return derSequence(
    derInteger(new Uint8Array([0])),
    ...fields.map((field) => derInteger(base64UrlDecode(privateJwk[field] ?? '')))
  );
}

export function derEcPrivateKey(privateJwk: JsonWebKey) {
  const curveOidByName: Record<string, string> = {
    'P-256': '1.2.840.10045.3.1.7',
    'P-384': '1.3.132.0.34',
    'P-521': '1.3.132.0.35',
  };
  const privateKeyBytes = base64UrlDecode(privateJwk.d ?? '');
  const publicPointBytes = concatBytes(new Uint8Array([4]), base64UrlDecode(privateJwk.x ?? ''), base64UrlDecode(privateJwk.y ?? ''));

  return derSequence(
    derInteger(new Uint8Array([1])),
    derOctetString(privateKeyBytes),
    derContext(0, derObjectIdentifier(curveOidByName[privateJwk.crv ?? ''] ?? curveOidByName['P-256'])),
    derContext(1, derBitString(publicPointBytes))
  );
}

export function derName(attributes: string[][]) {
  return derSequence(
    ...attributes
      .filter(([, value]) => value)
      .map(([oid, value]) => derSet(derSequence(derObjectIdentifier(oid), derDirectoryString(oid, value))))
  );
}

function derDirectoryString(oid: string, value: string) {
  if (oid === '1.2.840.113549.1.9.1') {
    const error = validateCsrEmail(value);
    if (error || value !== value.trim()) throw new Error(error || 'Email must be normalized before DER encoding.');
    return derIa5String(value);
  }
  if (oid === '2.5.4.6') {
    return derRaw(0x13, asciiBytes(value));
  }

  return derRaw(0x0c, utf8Bytes(value));
}

export function derIa5String(value: string) {
  if (/[^\x00-\x7f]/.test(value)) throw new Error('IA5String requires ASCII characters.');
  return derRaw(0x16, asciiBytes(value));
}

export function derSignatureAlgorithm(keyType: CsrKeyType, hash: CsrSignatureHash) {
  if (keyType === 'rsa') {
    const oidByHash: Record<CsrSignatureHash, string> = {
      'SHA-256': '1.2.840.113549.1.1.11',
      'SHA-384': '1.2.840.113549.1.1.12',
      'SHA-512': '1.2.840.113549.1.1.13',
    };

    return derSequence(derObjectIdentifier(oidByHash[hash]), derRaw(0x05, new Uint8Array()));
  }

  const oidByHash: Record<CsrSignatureHash, string> = {
    'SHA-256': '1.2.840.10045.4.3.2',
    'SHA-384': '1.2.840.10045.4.3.3',
    'SHA-512': '1.2.840.10045.4.3.4',
  };

  return derSequence(derObjectIdentifier(oidByHash[hash]));
}

export function derEncodeEcdsaSignature(signature: Uint8Array) {
  const halfLength = signature.length / 2;

  return derSequence(derInteger(signature.slice(0, halfLength)), derInteger(signature.slice(halfLength)));
}

export function derSequence(...parts: Uint8Array[]) {
  return derRaw(0x30, concatBytes(...parts));
}

function derSet(...parts: Uint8Array[]) {
  return derRaw(0x31, concatBytes(...parts));
}

export function derContext(index: number, content: Uint8Array) {
  return derRaw(0xa0 + index, content);
}

export function derInteger(value: Uint8Array) {
  let normalizedValue = trimLeadingZeroBytes(value);

  if (normalizedValue.length === 0) {
    normalizedValue = new Uint8Array([0]);
  }

  if (normalizedValue[0] & 0x80) {
    normalizedValue = concatBytes(new Uint8Array([0]), normalizedValue);
  }

  return derRaw(0x02, normalizedValue);
}

export function derBitString(value: Uint8Array) {
  return derRaw(0x03, concatBytes(new Uint8Array([0]), value));
}

export function derOctetString(value: Uint8Array) {
  return derRaw(0x04, value);
}

export function derObjectIdentifier(oid: string) {
  const parts = oid.split('.').map((part) => Number(part));
  const bytes = [parts[0] * 40 + parts[1]];

  for (const part of parts.slice(2)) {
    const stack = [part & 0x7f];
    let value = part >> 7;

    while (value > 0) {
      stack.unshift((value & 0x7f) | 0x80);
      value >>= 7;
    }

    bytes.push(...stack);
  }

  return derRaw(0x06, new Uint8Array(bytes));
}

export function derRaw(tag: number, content: Uint8Array) {
  return concatBytes(new Uint8Array([tag]), derLength(content.length), content);
}

function derLength(length: number) {
  if (length < 128) {
    return new Uint8Array([length]);
  }

  const bytes = [];
  let remainingLength = length;

  while (remainingLength > 0) {
    bytes.unshift(remainingLength & 255);
    remainingLength >>= 8;
  }

  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}
