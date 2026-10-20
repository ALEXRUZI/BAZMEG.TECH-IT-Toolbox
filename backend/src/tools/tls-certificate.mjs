import { X509Certificate } from "node:crypto";

const MAX_CERTIFICATE_BYTES = 256 * 1024;
const SIGNATURES = new Map([
  ["1.2.840.113549.1.1.4", ["md5WithRSAEncryption", "weak"]],
  ["1.2.840.113549.1.1.5", ["sha1WithRSAEncryption", "weak"]],
  ["1.2.840.113549.1.1.11", ["sha256WithRSAEncryption", "not-known-weak"]],
  ["1.2.840.113549.1.1.12", ["sha384WithRSAEncryption", "not-known-weak"]],
  ["1.2.840.113549.1.1.13", ["sha512WithRSAEncryption", "not-known-weak"]],
  ["1.2.840.113549.1.1.10", ["RSASSA-PSS (hash unverified)", "unknown"]],
  ["1.2.840.10045.4.1", ["ecdsa-with-SHA1", "weak"]],
  ["1.2.840.10045.4.3.1", ["ecdsa-with-SHA224", "not-known-weak"]],
  ["1.2.840.10045.4.3.2", ["ecdsa-with-SHA256", "not-known-weak"]],
  ["1.2.840.10045.4.3.3", ["ecdsa-with-SHA384", "not-known-weak"]],
  ["1.2.840.10045.4.3.4", ["ecdsa-with-SHA512", "not-known-weak"]],
  ["1.3.101.112", ["Ed25519", "not-known-weak"]],
  ["1.3.101.113", ["Ed448", "not-known-weak"]],
  ["1.2.840.10040.4.3", ["dsa-with-SHA1", "weak"]],
]);

// Fixed-depth traversal only. Every read is bounded by its enclosing structure.
function tlv(der, offset, end, tag) {
  if (offset + 2 > end || (der[offset] & 31) === 31) throw new Error("Invalid DER tag");
  const actualTag = der[offset++];
  const first = der[offset++];
  let length = first;
  if (first & 128) {
    const count = first & 127;
    if (!count || count > 4 || offset + count > end || der[offset] === 0) throw new Error("Invalid DER length");
    length = 0;
    for (let i = 0; i < count; i += 1) length = length * 256 + der[offset++];
    if (length < 128) throw new Error("Noncanonical DER length");
  }
  if (offset + length > end || (tag !== undefined && actualTag !== tag)) throw new Error("Invalid DER structure");
  return { tag: actualTag, start: offset, end: offset + length };
}

function oid(der, field) {
  const value = der.subarray(field.start, field.end);
  if (!value.length || value.length > 128) throw new Error("Invalid OID");
  const arcs = [];
  let arc = 0;
  for (let i = 0; i < value.length; i += 1) {
    if (arc === 0 && value[i] === 128) throw new Error("Noncanonical OID");
    arc = arc * 128 + (value[i] & 127);
    if (!Number.isSafeInteger(arc)) throw new Error("Oversized OID");
    if (!(value[i] & 128)) { arcs.push(arc); arc = 0; }
  }
  if (value[value.length - 1] & 128) throw new Error("Truncated OID");
  const first = arcs.shift();
  const a = first >= 80 ? 2 : Math.floor(first / 40);
  return [a, first - a * 40, ...arcs].join(".");
}

function pssHash(der, identifier, algorithm) {
  if (identifier.end === algorithm.end) return null;
  const parameters = tlv(der, identifier.end, algorithm.end, 0x30);
  let hash = "1.3.14.3.2.26"; // RFC 4055 default, only when a parameter SEQUENCE exists.
  let previous = 0x9f;
  for (let offset = parameters.start; offset < parameters.end;) {
    const field = tlv(der, offset, parameters.end);
    if (field.tag <= previous || field.tag < 0xa0 || field.tag > 0xa3) return null;
    previous = field.tag;
    if (field.tag === 0xa0) {
      const hashAlgorithm = tlv(der, field.start, field.end, 0x30);
      if (hashAlgorithm.end !== field.end) return null;
      const hashOid = tlv(der, hashAlgorithm.start, hashAlgorithm.end, 0x06);
      if (hashOid.end < hashAlgorithm.end) {
        const parameter = tlv(der, hashOid.end, hashAlgorithm.end, 0x05);
        if (parameter.start !== parameter.end || parameter.end !== hashAlgorithm.end) return null;
      }
      hash = oid(der, hashOid);
    } else {
      const value = tlv(der, field.start, field.end, field.tag === 0xa1 ? 0x30 : 0x02);
      if (value.end !== field.end || value.start === value.end) return null;
    }
    offset = field.end;
  }
  return new Map([
    ["1.2.840.113549.2.5", "MD5"], ["1.3.14.3.2.26", "SHA1"],
    ["2.16.840.1.101.3.4.2.1", "SHA256"], ["2.16.840.1.101.3.4.2.2", "SHA384"],
    ["2.16.840.1.101.3.4.2.3", "SHA512"],
  ]).get(hash) || null;
}

export function inspectSignature(raw) {
  const unknown = { signatureAlgorithm: null, signatureAlgorithmOid: null, signatureStrength: "unknown" };
  try {
    if (!Buffer.isBuffer(raw) || !raw.length || raw.length > MAX_CERTIFICATE_BYTES) return unknown;
    const cert = tlv(raw, 0, raw.length, 0x30);
    if (cert.end !== raw.length) return unknown;
    const tbs = tlv(raw, cert.start, cert.end, 0x30);
    const algorithm = tlv(raw, tbs.end, cert.end, 0x30);
    const signature = tlv(raw, algorithm.end, cert.end, 0x03);
    if (signature.end !== cert.end || signature.start === signature.end || raw[signature.start] !== 0) return unknown;
    let field = tlv(raw, tbs.start, tbs.end);
    if (field.tag === 0xa0) field = tlv(raw, field.end, tbs.end, 0x02);
    if (field.tag !== 0x02) return unknown;
    const inner = tlv(raw, field.end, tbs.end, 0x30);
    // X.509 requires matching inner and outer AlgorithmIdentifiers, including parameters.
    if (!raw.subarray(inner.start, inner.end).equals(raw.subarray(algorithm.start, algorithm.end))) return unknown;
    const identifier = tlv(raw, algorithm.start, algorithm.end, 0x06);
    if (identifier.end < algorithm.end) {
      const parameters = tlv(raw, identifier.end, algorithm.end);
      if (parameters.end !== algorithm.end) return unknown;
    }
    const signatureAlgorithmOid = oid(raw, identifier);
    let [signatureAlgorithm, signatureStrength] = SIGNATURES.get(signatureAlgorithmOid)
      || [`Unknown algorithm (OID ${signatureAlgorithmOid})`, "unknown"];
    if (signatureAlgorithmOid === "1.2.840.113549.1.1.10") {
      const hash = pssHash(raw, identifier, algorithm);
      if (hash) {
        signatureAlgorithm = `RSASSA-PSS (${hash})`;
        signatureStrength = hash === "SHA1" || hash === "MD5" ? "weak" : "not-known-weak";
      }
    }
    return { signatureAlgorithm, signatureAlgorithmOid, signatureStrength };
  } catch { return unknown; }
}

export function inspectCertificateEvidence(certificate) {
  const result = {
    signatureAlgorithm: null, signatureAlgorithmOid: null, signatureStrength: "unknown", publicKeyAlgorithm: null, modulusLength: null,
    bits: null, namedCurve: null, ca: null, selfIssued: null, selfSigned: null,
  };
  try {
    if (!Buffer.isBuffer(certificate?.raw) || certificate.raw.length > MAX_CERTIFICATE_BYTES) return result;
    const x509 = new X509Certificate(certificate.raw);
    Object.assign(result, inspectSignature(certificate.raw));
    result.ca = x509.ca;
    result.selfIssued = x509.subject === x509.issuer;
    const key = x509.publicKey;
    result.publicKeyAlgorithm = key.asymmetricKeyType || null;
    const details = key.asymmetricKeyDetails;
    if (key.asymmetricKeyType === "rsa" || key.asymmetricKeyType === "rsa-pss") {
      result.modulusLength = details?.modulusLength || null;
      result.bits = result.modulusLength;
    }
    if (key.asymmetricKeyType === "ec") result.namedCurve = details?.namedCurve || null;
    result.selfSigned = result.selfIssued ? x509.verify(key) : false;
  } catch { /* Unsupported key/signature evidence remains explicitly unknown. */ }
  return result;
}

export function getCertificateExpiration(validTo, now) {
  // Accept only timezone-explicit native OpenSSL dates or canonical UTC ISO dates.
  const native = typeof validTo === "string" && /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4} GMT$/.test(validTo);
  const iso = typeof validTo === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(validTo);
  const expiresAt = native || iso ? Date.parse(validTo) : NaN;
  const date = new Date(expiresAt);
  const canonical = Number.isFinite(expiresAt) && (iso
    ? date.toISOString() === validTo.replace(/Z$/, validTo.includes(".") ? "Z" : ".000Z")
    : native && `${date.toUTCString().slice(8, 11)} ${date.getUTCDate()} ${date.toISOString().slice(11, 19)} ${date.getUTCFullYear()} GMT` === validTo.replace(/\s+/g, " "));
  if (!canonical || !Number.isFinite(now)) {
    return { expiresAt: null, expirationState: "unknown", daysRemaining: null };
  }
  const remaining = expiresAt - now;
  return {
    expiresAt, expirationState: remaining <= 0 ? "expired" : remaining <= 30 * 86400000 ? "expiring-soon" : "valid",
    daysRemaining: Math.ceil(remaining / 86400000) || 0,
  };
}
