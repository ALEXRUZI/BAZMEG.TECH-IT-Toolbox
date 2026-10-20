import type { OutputFormat } from './sshTypes';

export const families = ['EdDSA', 'ECDSA', 'RSA', 'Legacy / Obsolete'] as const;
export type Family = typeof families[number];
export interface Algorithm {
  id: string; family: Family; label: string; identifier: string; strength: string;
  classification: string; supported: boolean; legacy?: boolean; curve?: 'P-256' | 'P-384' | 'P-521'; bits?: number; note: string;
}
export const algorithms: Algorithm[] = [
  { id: 'ed25519', family: 'EdDSA', label: 'Ed25519', identifier: 'ssh-ed25519', strength: '~128 bits', classification: 'Recommended', supported: true, note: 'RFC 8709; 32-byte seed/public key. Modern OpenSSH and PuTTY. Not a FIPS-validated implementation.' },
  { id: 'ed448', family: 'EdDSA', label: 'Ed448', identifier: 'ssh-ed448', strength: '~224 bits', classification: 'Limited compatibility', supported: true, note: 'RFC 8709; 57-byte seed/public key, 114-byte signatures. Bundled Noble Ed448; PuTTY PPK v3 supported. Standard OpenSSH does not support Ed448 authentication or private-key import/export. Not a FIPS-validated implementation.' },
  ...(['P-256', 'P-384', 'P-521'] as const).map((curve, i) => ({ id: curve, family: 'ECDSA' as const, label: `NIST ${curve}`, identifier: `ecdsa-sha2-nistp${curve.slice(2)}`, strength: ['~128 bits', '~192 bits', '~256 bits'][i], classification: i === 2 ? 'Secure' : 'Recommended', supported: true, curve, note: 'RFC 5656, NIST standardized curve; modern OpenSSH and PuTTY. Standardization is not FIPS validation. P-521 is usually unnecessary for routine SSH.' })),
  ...[2048, 3072, 4096, 8192, 512, 768, 1024].map(bits => ({ id: `rsa${bits}`, family: (bits < 2048 ? 'Legacy / Obsolete' : 'RSA') as Family, label: `RSA ${bits}-bit`, identifier: 'ssh-rsa', strength: bits < 2048 ? 'Obsolete security margin' : bits === 2048 ? '~112 bits' : bits === 3072 ? '~128 bits' : 'Higher security margin', classification: bits < 2048 ? 'Legacy / Insecure' : bits === 2048 ? 'Caution' : bits === 8192 ? 'Secure / Resource-intensive' : 'Recommended', supported: true, bits, legacy: bits < 2048, note: bits < 1024 ? 'Factorable, unsuitable for production authentication. Native generation only, provider-dependent, with no fallback. PuTTYgen qualifies PPK v3 and OpenSSH encoding; current OpenSSH rejects these sizes by policy (minimum 1024 bits), not an encoding defect.' : bits === 8192 ? 'Exponent 65537, two primes; modern OpenSSH and PuTTY PPK v3. RSA-SHA2 signatures are distinct from the ssh-rsa key encoding. Resource-intensive and generally unnecessary for routine SSH authentication. Qualified in Chromium; other browsers/devices may reject this size or exceed the 120-second worker deadline. No smaller-key or network fallback.' : 'Exponent 65537, two primes; RFC 4253 key encoding. RSA keys support RSA-SHA2 (RFC 8332); ssh-rsa/SHA-1 signatures are deprecated, not a separate key type. RSA 1024 is unsuitable for production; RSA 2048 is not universally broken.' })),
  { id: 'dsa', family: 'Legacy / Obsolete', label: 'DSA 1024-bit', identifier: 'ssh-dss', strength: '~80 bits', classification: 'Legacy / Insecure', supported: true, legacy: true, note: 'Historical 1024/160 DSA profile; ssh-dss authentication uses broken SHA-1. Bundled micro-rsa-dsa-dh generates and validates parameters; variable-time JavaScript. PuTTYgen qualifies PPK v3 and OpenSSH encoding. OpenSSH 10.0 removed DSA: no current OpenSSH authentication compatibility.' },
  { id: 'rsa1', family: 'Legacy / Obsolete', label: 'SSH-1 RSA (rsa1)', identifier: 'SSH-1 RSA', strength: 'Obsolete protocol', bits: 1024, classification: 'Legacy / Insecure', supported: true, legacy: true, note: 'Historical SSH-1 RSA 1024 only; broken protocol, no modern SSH authentication. Actual binary FORMAT 1.1 private file and decimal public text, qualified with PuTTYgen. MD5-derived two-key triple DES with separate CBC layers is obsolete, unsalted and unauthenticated; passphrase protection is NOT modern security.' },
];
export const legacyAcknowledgment = 'I understand this algorithm is unsuitable for production use.';
// Explicit format exceptions, shared by UI and worker. Unavailable profiles have no outputs.
const formatCompatibility: Partial<Record<string, readonly OutputFormat[]>> = { ed448: ['public', 'ppk'], rsa1: ['public', 'ssh1'] };
export const historicalEncryptionAcknowledgment = 'I understand SSH-1 passphrase protection is obsolete and unauthenticated.';
export const ssh1Explanation = 'SSH-1 requires a binary FORMAT 1.1 private file, not OpenSSH or PPK v3. Only RSA 1024 is supported. Historical encryption is MD5-derived, unsalted, separate-layer DES-CBC, without a MAC; it does not provide modern security.';
export function formatExplanation(id: string): string { return id === 'ed448' ? ed448OpenSshExplanation : id === 'rsa1' ? ssh1Explanation : ['rsa512', 'rsa768', 'dsa'].includes(id) ? algorithm(id).note : ''; }
export function publicLabel(id: string): string { return id === 'rsa1' ? 'SSH-1 decimal public key' : id === 'ed448' ? 'RFC 8709 public key' : 'authorized_keys'; }
export function capability(id: string): string { return algorithm(id).bits ? 'rsa-lazy' : id === 'dsa' ? 'dsa-lazy' : id; }
// Operation matrix derived from the same format policy, not React-only assumptions.
export function operationCompatibility(id: string) {
  const a = algorithm(id), formats = supportedFormats(id), privateFormats = formats.filter(format => format !== 'public');
  return {
    generation: id === 'dsa' ? 'Bundled micro-rsa-dsa-dh; fresh 1024/160 parameters' : id === 'ed448' ? 'Bundled Noble; secure random seed' : 'Exact native Web Crypto profile; provider-dependent; no fallback',
    import: privateFormats, privateExport: privateFormats,
    publicOutput: publicLabel(id), binaryFormats: privateFormats.filter(format => format === 'ssh1'),
    encryption: id === 'rsa1' ? 'Obsolete MD5 / separate-layer DES-CBC; additional acknowledgment' : 'OpenSSH bcrypt/AES-256-CTR or PPK v3 Argon2id/AES-256-CBC/HMAC-SHA-256 as available',
    browser: 'Secure origin, local worker, Web Crypto, bundled WASM; Chromium qualified, other browsers unqualified',
    nativeClients: id === 'rsa1' ? 'PuTTYgen 0.85 historical file processing only; no modern SSH authentication' : id === 'dsa' ? 'PuTTYgen 0.85; OpenSSH 10.0+ removed DSA' : a.bits && a.bits < 1024 ? 'PuTTYgen 0.85; current OpenSSH rejects below 1024 bits' : id === 'ed448' ? 'PuTTYgen 0.85; no standard OpenSSH support' : 'OpenSSH 10.2p1 and PuTTYgen 0.85',
    warning: a.note, fingerprint: id === 'rsa1' ? 'Historical MD5(minimal unsigned BE modulus || exponent), identification only' : 'SHA-256(canonical SSH-2 public-key blob)',
  };
}
export const ed448OpenSshExplanation = 'OpenSSH private import/export is unavailable for Ed448. Standard OpenSSH servers cannot authenticate with ssh-ed448; an RFC 8709 public line does not establish OpenSSH compatibility.';
export function supportedFormats(id: string): readonly OutputFormat[] {
  if (!algorithms.find(item => item.id === id)?.supported) return [];
  return formatCompatibility[id] ?? ['public', 'openssh', 'ppk'];
}
// Serialization availability only; native-client authentication policy is separate.
export function unsupportedFormatExplanation(id: string | undefined, format: OutputFormat): string {
  const a = algorithms.find(item => item.id === id);
  if (!a || supportedFormats(a.id).includes(format)) return '';
  if (format === 'ssh1') return 'SSH-1 private-key format is only available for historical SSH-1 RSA keys.';
  const name = format === 'openssh' ? 'OpenSSH private-key format' : format === 'ppk' ? 'PuTTY PPK v3' : 'Public-key output';
  return `${name} is not supported for ${a.id === 'rsa1' ? 'SSH-1 RSA' : a.label}.`;
}
export function compatibleSelection(id: string, selected: OutputFormat[]): OutputFormat[] {
  const available = supportedFormats(id), kept = selected.filter(format => available.includes(format));
  if (!available.length || kept.length === selected.length) return selected;
  if (!kept.length || selected.some(format => format !== 'public') && !kept.some(format => format !== 'public')) return [...available];
  return kept;
}
export function requireFormat(id: string, format: OutputFormat): void {
  if (!supportedFormats(id).includes(format)) throw new Error(`Unsupported ${format} format for ${id}.${id === 'ed448' ? ` ${ed448OpenSshExplanation}` : ''}`);
}
export function exportDescription(id: string): string {
  return supportedFormats(id).map(format => format === 'public' ? publicLabel(id) : format === 'openssh' ? 'OpenSSH private key' : format === 'ssh1' ? 'SSH-1 binary private key' : 'PuTTY PPK v3').join(', ');
}
export function algorithm(id: string): Algorithm {
  const value = algorithms.find(item => item.id === id);
  if (!value?.supported) throw new Error(`Unsupported algorithm or key size.${value ? ` ${value.label}: ${value.note}` : ''}`);
  return value;
}
