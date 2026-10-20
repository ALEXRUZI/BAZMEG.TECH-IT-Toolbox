# CSR regression contract and verification

Production code is in [src/tools/csr-generator/](../../src/tools/csr-generator/):
[CsrGenerator.tsx](../../src/tools/csr-generator/CsrGenerator.tsx) owns UI state,
[csrCrypto.ts](../../src/tools/csr-generator/csrCrypto.ts) key generation/signing/encryption,
[csrDer.ts](../../src/tools/csr-generator/csrDer.ts) ASN.1,
[csrPem.ts](../../src/tools/csr-generator/csrPem.ts) text encoding, and
[csrValidation.ts](../../src/tools/csr-generator/csrValidation.ts),
[csrHelpers.ts](../../src/tools/csr-generator/csrHelpers.ts),
[csrConstants.ts](../../src/tools/csr-generator/csrConstants.ts), and
[csrTypes.ts](../../src/tools/csr-generator/csrTypes.ts) validation/support/contracts.

[verification.ts](verification.ts) independently parses/verifies browser outputs;
it does not import production encoders. [verification.test.ts](verification.test.ts)
calibrates that verifier with synthetic public ASN.1. [email.test.ts](email.test.ts)
directly exercises production email validation, DER and crypto helpers (AUD-011).
[Browser tests](../../e2e/csr-generator.spec.ts) exercise the actual UI/Web Crypto.

## Current Contract

- Defaults: RSA 2048, SHA-256, PKCS#10 PEM, unencrypted PKCS#8 PEM,
  CN/first SAN `app.example.com`, country `SK`.
- RSA uses WebCrypto RSASSA-PKCS1-v1_5, exponent 65537 and sizes
  2048/3072/4096. ECDSA uses P-256/P-384/P-521. Both expose
  SHA-256/SHA-384/SHA-512 independently of size/curve.
- CSR version is 0. Subject order is C, ST, L, O, OU, CN, email;
  empty optional fields are omitted. Country uses PrintableString,
  email IA5String, and remaining fields UTF8String. Values are trimmed;
  country is uppercased.
- SANs are carried by PKCS#9 extensionRequest (1.2.840.113549.1.9.14),
  containing non-critical subjectAltName (2.5.29.17). DNS uses lowercased
  dNSName [2]; IPv4/IPv6 uses iPAddress [7] with 4/16 bytes.
- RSA signature OIDs end in 11/12/13 under 1.2.840.113549.1.1 and
  include NULL parameters. ECDSA OIDs end in 2/3/4 under
  1.2.840.10045.4.3, with absent parameters. Raw WebCrypto ECDSA r/s
  values become positive, minimally encoded DER INTEGERs.
- PEM labels: CERTIFICATE REQUEST, PUBLIC KEY, PRIVATE KEY,
  ENCRYPTED PRIVATE KEY, RSA PRIVATE KEY, EC PRIVATE KEY.
  Base64 wraps at 64 columns. Both DER UI exports are wrapped base64
  text representing DER bytes, not binary downloads.
- Traditional RSA is PKCS#1 with version 0 and eight JWK key integers.
  Traditional EC is SEC1 with version 1, scalar, explicit named-curve
  OID and public point. Incompatible traditional formats are disabled;
  switching algorithms resets an incompatible selection to PKCS#8 PEM.
- Encrypted PKCS#8 is PBES2 / PBKDF2-HMAC-SHA256, 250,000 iterations,
  16-byte random salt, AES-256-CBC and 16-byte random IV, with WebCrypto
  PKCS#7 padding. Encryption password is required but has no complexity rule.
- Every Generate action creates a new extractable key pair in the browser.
  Outputs appear only after successful generation. Previous outputs remain
  when inputs change. Copy attempts to write the displayed text to the clipboard
  and reports success/failure. Filename labels do not create downloads.
  No application API is called.

## Existing Validation

CN and at least one SAN are required, with a 100-entry SAN cap. CN is
limited to 253 characters. DNS permits single labels, ASCII alphanumeric
labels with interior hyphens, and a leading `*.` wildcard; trailing dots
are rejected. IPv4 octets permit leading zeroes. IPv6 supports hex groups
and `::`, but not IPv4-mapped dotted notation or zone IDs. Country accepts
any two ASCII letters, not an ISO membership lookup. Organization/location fields have no
additional validation. Certain non-public IP ranges and localhost cause warnings,
not rejection. Empty example CN/country/SAN fields are restored on blur.

Numeric dotted names that are not valid IPv4 can still qualify as DNS
names (for example `999.0.0.1`). This is existing validation behavior,
not a strict-IP validator; the SAN warnings are not a comprehensive public-IP/CA
policy check. Validation does not establish that a CA will accept the request.

### ASCII email identity (AUD-011)

Email is optional. Validation rejects non-printable/non-ASCII characters **before
trimming**, including Unicode local parts/domains, controls, DEL, surrogate input,
and non-ASCII whitespace. ASCII spaces surrounding a valid email are trimmed;
empty/all-space input omits the attribute. Accepted addresses use an ASCII dot-atom
local part (at most 64 characters), a dotted non-wildcard DNS-style domain and a
254-character total limit. This is not full RFC email syntax or SMTPUTF8 support;
there is no silent Unicode conversion/truncation.

`createCsr` revalidates email before key generation, independently of UI validation.
Subject DER requires a normalized validated value, and `derIa5String` rejects
non-ASCII. Unit tests check malformed/Unicode/control input rejection before
`generateKey`, exact accepted IA5 bytes/tag, omission and actual CSR signatures.
Browser tests verify visible errors, blocked generation, then ASCII recovery and
independently verified output. Unicode organization/unit/locality values remain
UTF8String and are tested separately.

## Independent Verification

ASN1js is a development-only ASN.1 parser, avoiding a custom parser or
an OpenSSL executable requirement on Windows. The verifier checks complete
consumption, canonical definite lengths and positive INTEGER padding, then
walks PKCS#10, subject, SPKI and extensionRequest structures. Node crypto
independently parses SPKI/private keys and verifies the actual signed bytes
using RSA PKCS#1 v1.5 or DER ECDSA. It checks exported key correspondence,
tampered signatures/subjects, encrypted PKCS#8 interoperability, and also
decrypts PBKDF2/AES-CBC explicitly. Public synthetic unit samples calibrate
the verifier's rejection of malformed encoding; they do not verify production
encoders by themselves.

Browser tests cover six representative size/curve/hash combinations, all
five private-key formats, both encrypted-key algorithms, all subject fields,
UTF-8 organization/unit/city values, and mixed DNS/wildcard/IPv4/IPv6 SANs. Real
WebCrypto signatures are observed without replacing signing, then compared
with decoded DER integers. A bounded sample of real P-256 signatures covers
both sign-padding branches; P-521 covers long signature lengths.

The full 18-way size/hash cross-product, every IPv6 spelling, CA acceptance policy,
and non-Chromium interoperability are not covered. International email is explicitly
unsupported and rejection is tested. Clipboard copying is tested; no download
feature is implemented.

## Privacy and Execution

CSR browser tests reuse the [API/external networking guard](../../e2e/fixtures/test.ts).
Keys and random passwords are disposable, in-memory only. Trace, video and screenshots are
disabled for this spec. Assertions involving secret material return
booleans or generic errors rather than key diffs. Clipboard clearing is best-effort and
the page is closed before context teardown, preventing Playwright failure
DOM snapshots from persisting the output. The [password spec](../../e2e/password-generator.spec.ts)
has equivalent recording/teardown protections; other specs retain normal diagnostics.
Password entry uses a DOM input event because Playwright's `fill()` step
titles would otherwise include its argument in HTML reports. These protections are
not secure memory erasure and cannot protect a compromised browser/device or
OS clipboard monitors. Do not record outputs or reuse production secrets in tests.

Run `npm run test:unit` and `npm run test:e2e` from `frontend`, or focus the
browser checks with `npx playwright test e2e/csr-generator.spec.ts`. See
[setup and CI](../../../README.md#testing-and-ci) for Node 22/Chromium prerequisites.
The independent verifier uses Node crypto/ASN1js; these CSR checks do not require
an OpenSSL executable (separate backend certificate tests do).
