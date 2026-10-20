export type OutputFormat = 'public' | 'openssh' | 'ppk' | 'ssh1';
export interface ExportOptions {
  protected: boolean; passphrase: string; confirmation: string; unencryptedAcknowledged: boolean;
  formats: OutputFormat[];
  historicalEncryptionAcknowledged?: boolean;
}
export type Request = { operation: 'generate'; algorithm: string; comment: string; legacyAcknowledged: boolean; options: ExportOptions }
  | { operation: 'extract' | 'convert'; text: string; bytes?: Uint8Array; passphrase: string; comment?: string; options: ExportOptions };
export interface KeyMaterial {
  algorithm: string; comment: string; publicBlob: Uint8Array; secret: Uint8Array;
  rsa?: { n: Uint8Array; e: Uint8Array; d: Uint8Array; p: Uint8Array; q: Uint8Array; iq: Uint8Array };
  dsa?: { p: Uint8Array; q: Uint8Array; g: Uint8Array; y: Uint8Array };
}
// Binary outputs deliberately have no copyable text. Bytes are authoritative.
export type KeyOutput = { format: OutputFormat; label: string; filename: string; private: boolean } &
  ({ text: string; bytes?: never } | { text: ''; bytes: Uint8Array });
export interface Result {
  inspector: { algorithm: string; identifier: string; parameters: string; classification: string; comment: string; fingerprint: string; format: string; encrypted: boolean; exports: string };
  outputs: KeyOutput[];
}
