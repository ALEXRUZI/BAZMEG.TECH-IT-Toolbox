export type CsrKeyType = 'rsa' | 'ec';

export type CsrSignatureHash = 'SHA-256' | 'SHA-384' | 'SHA-512';

export type CsrOutputFormat = 'pem-pkcs10' | 'der-pkcs10';

export type PrivateKeyOutputFormat = 'pkcs8-pem' | 'encrypted-pkcs8-pem' | 'traditional-rsa-pem' | 'traditional-ec-pem' | 'pkcs8-der';

export type CsrSanEntry = {
  id: number;
  value: string;
  isExample: boolean;
};

export type CsrGeneratedOutput = {
  csrOutput: string;
  privateKeyOutput: string;
  publicKeyPem: string;
  csrFileName: string;
  privateKeyFileName: string;
  publicKeyFileName: string;
};

export type CreateCsrInput = {
  commonName: string;
  organization: string;
  organizationalUnit: string;
  email: string;
  country: string;
  locality: string;
  state: string;
  keyType: CsrKeyType;
  keySize: string;
  signatureHash: CsrSignatureHash;
  csrOutputFormat: CsrOutputFormat;
  privateKeyOutputFormat: PrivateKeyOutputFormat;
  privateKeyPassword: string;
  sans: string[];
};
