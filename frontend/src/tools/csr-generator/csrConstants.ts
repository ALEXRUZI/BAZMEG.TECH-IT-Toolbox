import type { CsrSignatureHash, CsrOutputFormat, PrivateKeyOutputFormat, CsrKeyType } from './csrTypes';

export const csrSanLimit = 100;

export const csrExampleDomain = 'app.example.com';

export const csrExampleAdditionalDomain = 'www.example.com';

export const csrExampleCountry = 'SK';

export const csrKeyProfiles = {
  rsa: {
    label: 'RSA',
    sizes: ['2048', '3072', '4096'],
    typical: 'RSA 2048 is the common baseline. RSA 3072 is a stronger long-life choice. RSA 4096 is accepted but slower.',
  },
  ec: {
    label: 'ECDSA',
    sizes: ['P-256', 'P-384', 'P-521'],
    typical: 'ECDSA P-256 is typically used for modern TLS. P-384 is common for higher assurance. P-521 is less common.',
  },
} as const;

export const csrHashOptions: CsrSignatureHash[] = ['SHA-256', 'SHA-384', 'SHA-512'];

const csrKeySizeNotes = {
  rsa: {
    '2048': 'RSA 2048 is the usual public TLS baseline and the most compatible RSA choice.',
    '3072': 'RSA 3072 gives a stronger margin while staying broadly compatible.',
    '4096': 'RSA 4096 is accepted by many systems but generation and handshakes are slower.',
  },
  ec: {
    'P-256': 'P-256 is the normal modern ECDSA choice for public TLS.',
    'P-384': 'P-384 is used when policy asks for a stronger elliptic curve.',
    'P-521': 'P-521 is valid but less commonly deployed and may have compatibility limits.',
  },
} as const;

export const csrSignatureHashNotes: Record<CsrSignatureHash, string> = {
  'SHA-256': 'SHA-256 is the standard default for most CSRs.',
  'SHA-384': 'SHA-384 is commonly paired with stronger policy profiles such as P-384.',
  'SHA-512': 'SHA-512 is available for stricter policies, but it is rarely necessary for normal TLS CSRs.',
};

export const csrOutputFormatLabels: Record<CsrOutputFormat, string> = {
  'pem-pkcs10': 'PEM / PKCS#10',
  'der-pkcs10': 'DER / PKCS#10',
};

export const privateKeyOutputFormatLabels: Record<PrivateKeyOutputFormat, string> = {
  'pkcs8-pem': 'PKCS#8 PEM',
  'encrypted-pkcs8-pem': 'Encrypted PKCS#8 PEM',
  'traditional-rsa-pem': 'Traditional RSA PEM',
  'traditional-ec-pem': 'Traditional EC PEM',
  'pkcs8-der': 'PKCS#8 DER',
};

export function getCsrKeySizeNotes(keyType: CsrKeyType): Record<string, string> {
  return csrKeySizeNotes[keyType];
}
