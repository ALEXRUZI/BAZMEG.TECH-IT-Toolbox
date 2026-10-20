import { constants, createDecipheriv, createPrivateKey, createPublicKey, pbkdf2Sync, sign, verify, type KeyObject } from 'node:crypto';
import * as asn1 from 'asn1js';

// Never include key material in assertion messages or assertion diffs.
export function requireCondition(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

type Block = asn1.AsnType;

function children(block: Block): Block[] {
  requireCondition(block instanceof asn1.Constructed, 'Expected constructed ASN.1 value');
  return block.valueBlock.value;
}

export function sequence(block: Block, count?: number) {
  requireCondition(block instanceof asn1.Sequence, 'Expected ASN.1 SEQUENCE');
  const values = children(block);
  if (count !== undefined) requireCondition(values.length === count, 'Unexpected SEQUENCE field count');
  return values;
}

export function oid(block: Block) {
  requireCondition(block instanceof asn1.ObjectIdentifier, 'Expected OBJECT IDENTIFIER');
  return block.valueBlock.toString();
}

function octets(block: Block) {
  requireCondition(block instanceof asn1.OctetString, 'Expected OCTET STRING');
  return Buffer.from(block.valueBlock.valueHexView);
}

function integer(block: Block) {
  requireCondition(block instanceof asn1.Integer, 'Expected INTEGER');
  return block.valueBlock.valueDec;
}

function encoded(block: Block) {
  return Buffer.from(block.valueBeforeDecodeView);
}

function canonical(block: Block) {
  const raw = encoded(block);
  requireCondition(!block.lenBlock.isIndefiniteForm, 'DER cannot use indefinite lengths');
  requireCondition(raw.length >= 2, 'Truncated DER value');
  const lengthByte = raw[1];
  if (lengthByte & 0x80) {
    const count = lengthByte & 0x7f;
    requireCondition(count > 0 && raw[2] !== 0, 'Non-minimal DER length');
    let length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + raw[2 + i];
    requireCondition(length >= 128 && length === block.lenBlock.length, 'Invalid long DER length');
  } else {
    requireCondition(lengthByte === block.lenBlock.length, 'Invalid short DER length');
  }
  if (block instanceof asn1.Integer) {
    const bytes = block.valueBlock.valueHexView;
    requireCondition(bytes.length > 0 && !(bytes[0] & 0x80), 'Expected positive DER INTEGER');
    requireCondition(bytes.length === 1 || bytes[0] !== 0 || Boolean(bytes[1] & 0x80), 'Unnecessary INTEGER sign padding');
  }
  if (block instanceof asn1.Constructed) children(block).forEach(canonical);
}

export function parseDer(bytes: Uint8Array) {
  const result = asn1.fromBER(bytes);
  requireCondition(result.offset === bytes.length && !result.result.error, 'Invalid ASN.1 or trailing bytes');
  canonical(result.result);
  return result.result;
}

export function decodeOutput(text: string, label?: string) {
  let base64 = text.trim();
  if (label) {
    const lines = base64.split(/\r?\n/);
    requireCondition(lines.shift() === `-----BEGIN ${label}-----`, 'Incorrect PEM BEGIN label');
    requireCondition(lines.pop() === `-----END ${label}-----`, 'Incorrect PEM END label');
    requireCondition(lines.every((line, i) => line.length === 64 || i === lines.length - 1), 'Unexpected PEM wrapping');
    base64 = lines.join('');
  } else base64 = base64.replace(/\s/g, '');
  requireCondition(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(base64) && base64.length > 0, 'Invalid base64');
  const bytes = Buffer.from(base64, 'base64');
  requireCondition(bytes.toString('base64') === base64, 'Non-canonical base64');
  return bytes;
}

const hashes: Record<string, string> = {
  '1.2.840.113549.1.1.11': 'sha256', '1.2.840.113549.1.1.12': 'sha384', '1.2.840.113549.1.1.13': 'sha512',
  '1.2.840.10045.4.3.2': 'sha256', '1.2.840.10045.4.3.3': 'sha384', '1.2.840.10045.4.3.4': 'sha512',
};

export function parseCsr(bytes: Buffer) {
  const [info, algorithm, signatureBlock] = sequence(parseDer(bytes), 3);
  const [version, name, spki, attributes] = sequence(info, 4);
  requireCondition(integer(version) === 0, 'PKCS#10 version must be zero');
  const algorithmFields = sequence(algorithm);
  const signatureOid = oid(algorithmFields[0]);
  requireCondition(Boolean(hashes[signatureOid]), 'Unsupported signature OID');
  const rsa = signatureOid.startsWith('1.2.840.113549.1.1.');
  requireCondition(rsa ? algorithmFields.length === 2 && algorithmFields[1] instanceof asn1.Null : algorithmFields.length === 1, 'Incorrect signature parameters');
  requireCondition(signatureBlock instanceof asn1.BitString && signatureBlock.valueBlock.unusedBits === 0, 'Invalid signature BIT STRING');
  const signature = Buffer.from(signatureBlock.valueBlock.valueHexView);
  if (!rsa) sequence(parseDer(signature), 2).forEach((part) => integer(part));
  const publicKey = createPublicKey({ key: encoded(spki), format: 'der', type: 'spki' });
  const subject: Record<string, { value: string; tag: number }> = {};
  const subjectBytes: Record<string, Buffer> = {};
  for (const rdn of sequence(name)) {
    requireCondition(rdn instanceof asn1.Set && children(rdn).length === 1, 'Invalid subject RDN');
    const [type, value] = sequence(children(rdn)[0], 2);
    requireCondition(value instanceof asn1.Utf8String || value instanceof asn1.PrintableString || value instanceof asn1.IA5String, 'Unexpected subject string');
    requireCondition(!subject[oid(type)], 'Duplicate subject field');
    subject[oid(type)] = { value: value.valueBlock.value, tag: value.idBlock.tagNumber };
    subjectBytes[oid(type)] = Buffer.from(value.valueBlock.valueHexView);
  }
  requireCondition(attributes.idBlock.tagClass === 3 && attributes.idBlock.tagNumber === 0, 'Missing PKCS#10 attributes');
  requireCondition(children(attributes).length === 1, 'Unexpected attribute count');
  const [attributeOid, values] = sequence(children(attributes)[0], 2);
  requireCondition(oid(attributeOid) === '1.2.840.113549.1.9.14', 'Missing PKCS#9 extensionRequest');
  requireCondition(values instanceof asn1.Set && children(values).length === 1, 'Invalid extensionRequest SET');
  const extensions = sequence(children(values)[0], 1);
  const [extensionOid, extensionValue] = sequence(extensions[0], 2);
  requireCondition(oid(extensionOid) === '2.5.29.17', 'Missing subjectAltName extension');
  const sans = sequence(parseDer(octets(extensionValue))).map((entry) => {
    requireCondition(entry instanceof asn1.Primitive && entry.idBlock.tagClass === 3, 'Invalid GeneralName');
    requireCondition(entry.idBlock.tagNumber === 2 || entry.idBlock.tagNumber === 7, 'Incorrect SAN GeneralName type');
    return { tag: entry.idBlock.tagNumber, bytes: Buffer.from(entry.valueBlock.valueHexView) };
  });
  const signed = encoded(info);
  const verifySignature = (data = signed, sig = signature) => verify(hashes[signatureOid], data, {
    key: publicKey, padding: constants.RSA_PKCS1_PADDING, dsaEncoding: 'der',
  }, sig);
  requireCondition(verifySignature(), 'CSR cryptographic signature verification failed');
  return { publicKey, spki, signatureOid, subject, subjectBytes, sans, signature, signed, verifySignature };
}

export function matchPublicKeys(left: KeyObject, right: KeyObject) {
  const exportKey = (key: KeyObject) => key.export({ format: 'der', type: 'spki' });
  requireCondition(exportKey(left).equals(exportKey(right)), 'Exported key does not match CSR public key');
}

function verifyKeyPair(privateKey: KeyObject, publicKey: KeyObject) {
  matchPublicKeys(createPublicKey(privateKey), publicKey);
  // Also prove possession of the private scalar/exponent, rather than trusting
  // a public point carried inside a traditional private-key export.
  const challenge = Buffer.from('Independent CSR exported-private-key proof');
  const signature = sign('sha256', challenge, privateKey);
  requireCondition(verify('sha256', challenge, publicKey, signature), 'Exported private key cannot sign for CSR public key');
}

export function verifyPrivateKey(text: string, format: string, publicKey: KeyObject, password?: string) {
  const labels: Record<string, string> = {
    'pkcs8': 'PRIVATE KEY', encrypted: 'ENCRYPTED PRIVATE KEY', rsa: 'RSA PRIVATE KEY', ec: 'EC PRIVATE KEY',
  };
  const bytes = decodeOutput(text, labels[format]);
  parseDer(bytes);
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: bytes, format: 'der', type: format === 'rsa' ? 'pkcs1' : format === 'ec' ? 'sec1' : 'pkcs8', passphrase: password });
  } catch {
    throw new Error('Independent private key parsing/decryption failed');
  }
  verifyKeyPair(privateKey, publicKey);
  return bytes;
}

export function encryptedParameters(bytes: Buffer) {
  const [algorithm, ciphertext] = sequence(parseDer(bytes), 2);
  const [pbesOid, parameters] = sequence(algorithm, 2);
  requireCondition(oid(pbesOid) === '1.2.840.113549.1.5.13', 'Expected PBES2');
  const [kdf, cipher] = sequence(parameters, 2);
  const [kdfOid, kdfParameters] = sequence(kdf, 2);
  requireCondition(oid(kdfOid) === '1.2.840.113549.1.5.12', 'Expected PBKDF2');
  const [saltBlock, iterations, prf] = sequence(kdfParameters, 3);
  requireCondition(integer(iterations) === 250000, 'Incorrect PBKDF2 iteration count');
  const [prfOid, prfNull] = sequence(prf, 2);
  requireCondition(oid(prfOid) === '1.2.840.113549.2.9' && prfNull instanceof asn1.Null, 'Expected HMAC-SHA256');
  const [cipherOid, ivBlock] = sequence(cipher, 2);
  requireCondition(oid(cipherOid) === '2.16.840.1.101.3.4.1.42', 'Expected AES-256-CBC');
  const salt = octets(saltBlock), iv = octets(ivBlock);
  requireCondition(salt.length === 16 && iv.length === 16 && octets(ciphertext).length % 16 === 0, 'Invalid encryption parameters');
  return { salt, iv, ciphertext: octets(ciphertext) };
}

export function decryptPrivateKey(bytes: Buffer, password: string, publicKey: KeyObject) {
  const { salt, iv, ciphertext } = encryptedParameters(bytes);
  const aesKey = pbkdf2Sync(password, salt, 250000, 32, 'sha256');
  const decipher = createDecipheriv('aes-256-cbc', aesKey, iv);
  let decrypted: Buffer;
  try { decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]); }
  catch { throw new Error('Independent AES-CBC decryption failed'); }
  parseDer(decrypted);
  let privateKey: KeyObject;
  try { privateKey = createPrivateKey({ key: decrypted, format: 'der', type: 'pkcs8' }); }
  catch { throw new Error('Decrypted PKCS#8 parsing failed'); }
  verifyKeyPair(privateKey, publicKey);
}
