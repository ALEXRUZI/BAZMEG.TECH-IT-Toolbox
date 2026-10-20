import type { CreateCsrInput, CsrGeneratedOutput } from './csrTypes';
import {
  derSequence,
  derInteger,
  derName,
  derContext,
  derAttributeExtensionRequest,
  derEncodeEcdsaSignature,
  derSignatureAlgorithm,
  derBitString,
  derRsaPrivateKey,
  derEcPrivateKey,
  derObjectIdentifier,
  derOctetString,
  derRaw,
} from './csrDer';
import { createSafeFileName, utf8Bytes, toArrayBuffer, numberToBytes } from './csrHelpers';
import { pemEncode, base64Encode } from './csrPem';
import { validateCsrEmail } from './csrValidation';

export async function createCsr(input: CreateCsrInput): Promise<CsrGeneratedOutput> {
  const emailError = validateCsrEmail(input.email);
  if (emailError) throw new Error(emailError);
  const email = input.email.trim();

  const keyAlgorithm =
    input.keyType === 'rsa'
      ? {
          name: 'RSASSA-PKCS1-v1_5',
          modulusLength: Number(input.keySize),
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: input.signatureHash,
        }
      : {
          name: 'ECDSA',
          namedCurve: input.keySize,
        };
  const signingAlgorithm =
    input.keyType === 'rsa' ? { name: 'RSASSA-PKCS1-v1_5' } : { name: 'ECDSA', hash: input.signatureHash };
  const keyPair = await crypto.subtle.generateKey(keyAlgorithm, true, ['sign', 'verify']);
  const privateKeyDer = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  const publicKeyDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const certificationRequestInfo = derSequence(
    derInteger(new Uint8Array([0])),
    derName([
      ['2.5.4.6', input.country],
      ['2.5.4.8', input.state],
      ['2.5.4.7', input.locality],
      ['2.5.4.10', input.organization],
      ['2.5.4.11', input.organizationalUnit],
      ['2.5.4.3', input.commonName],
      ['1.2.840.113549.1.9.1', email],
    ]),
    publicKeyDer,
    derContext(0, derAttributeExtensionRequest(input.sans))
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign(signingAlgorithm, keyPair.privateKey, certificationRequestInfo)
  );
  const encodedSignature = input.keyType === 'ec' ? derEncodeEcdsaSignature(signature) : signature;
  const csrDer = derSequence(
    certificationRequestInfo,
    derSignatureAlgorithm(input.keyType, input.signatureHash),
    derBitString(encodedSignature)
  );
  const safeCommonName = createSafeFileName(input.commonName);
  const csrOutput = input.csrOutputFormat === 'pem-pkcs10' ? pemEncode('CERTIFICATE REQUEST', csrDer) : base64Encode(csrDer);
  const privateKeyOutput = await formatPrivateKeyOutput(input, privateKeyDer, privateJwk);

  return {
    csrOutput,
    privateKeyOutput,
    publicKeyPem: pemEncode('PUBLIC KEY', publicKeyDer),
    csrFileName: `${safeCommonName}.csr`,
    privateKeyFileName: `${safeCommonName}_private-key.pem`,
    publicKeyFileName: `${safeCommonName}_public-key.pem`,
  };
}

async function formatPrivateKeyOutput(input: CreateCsrInput, privateKeyDer: Uint8Array, privateJwk: JsonWebKey) {
  switch (input.privateKeyOutputFormat) {
    case 'encrypted-pkcs8-pem':
      return pemEncode('ENCRYPTED PRIVATE KEY', await encryptPkcs8PrivateKey(privateKeyDer, input.privateKeyPassword));
    case 'traditional-rsa-pem':
      return pemEncode('RSA PRIVATE KEY', derRsaPrivateKey(privateJwk));
    case 'traditional-ec-pem':
      return pemEncode('EC PRIVATE KEY', derEcPrivateKey(privateJwk));
    case 'pkcs8-der':
      return base64Encode(privateKeyDer);
    case 'pkcs8-pem':
    default:
      return pemEncode('PRIVATE KEY', privateKeyDer);
  }
}

async function encryptPkcs8PrivateKey(privateKeyDer: Uint8Array, password: string) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 250000;
  const passwordKey = await crypto.subtle.importKey('raw', utf8Bytes(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-CBC', length: 256 },
    false,
    ['encrypt']
  );
  const encryptedBytes = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, aesKey, toArrayBuffer(privateKeyDer))
  );
  const pbes2Algorithm = derSequence(
    derObjectIdentifier('1.2.840.113549.1.5.13'),
    derSequence(
      derSequence(
        derObjectIdentifier('1.2.840.113549.1.5.12'),
        derSequence(
          derOctetString(salt),
          derInteger(numberToBytes(iterations)),
          derSequence(derObjectIdentifier('1.2.840.113549.2.9'), derRaw(0x05, new Uint8Array()))
        )
      ),
      derSequence(derObjectIdentifier('2.16.840.1.101.3.4.1.42'), derOctetString(iv))
    )
  );

  return derSequence(pbes2Algorithm, derOctetString(encryptedBytes));
}
