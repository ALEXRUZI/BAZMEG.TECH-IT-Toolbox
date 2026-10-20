# TLS certificate result evidence (Node 22)

## Expiration

`valid_to` is accepted only as a timezone-explicit OpenSSL GMT timestamp or UTC ISO
timestamp, with calendar round-trip validation. Missing, invalid, ambiguous, or
normalized-invalid dates yield `expiresAt: null`, `expirationState: "unknown"`,
`daysRemaining: null`, `summary.notExpired: null`, and a warning check.

All certificates use one wall-clock sample per result. `wallNow` can be injected
through the internal `createTlsChecker()` test seam; it is separate from the
monotonic network-budget clock and is never accepted from request bodies.
At `now >= expiresAt`, the certificate is expired. Otherwise the state is
`expiring-soon` at or within 30 days, or `valid` beyond 30 days. These are
expiration states, not assertions about not-before, trust, or revocation.
`Math.ceil((expiresAt - now) / 86400000)` remains display-only (zero is normalized).
Backend checks, summary and warnings and frontend badges/image exports use the
explicit state, never rounded days or a new browser clock sample.

## Issuer chain and origin

The existing single inspection uses `getPeerCertificate(true)`. Its leaf is the
observed TLS peer certificate (`source: "peer"`), whether or not authorization
succeeds. Subsequent `issuerCertificate` links are certificates available during
Node/OpenSSL chain construction (`source: "inferred"`): **origin unverified**.
They may have been transmitted or locally supplemented. The runtime provides no
trustworthy per-entry wire/store attribution through this API.

Consequently `serverProvidedCertificateCount`, `summary.chainProvided`, and
`issuerChainComplete` are `null`. Neither backend nor frontend counts issuer links
as transmitted certificates. The `certificate_chain` check warns, reporting only
the observed number of entries and the unknown/unverified states. UI and image
export explain: "Exact certificates transmitted by the server cannot be determined
from this inspection." No second connection, trust-store scanning, or revocation
requests are made. Traversal remains bounded to ten entries and stops on cycles.

Leaf classification takes precedence, including self-issued non-CA leaves.
Native `X509Certificate.ca` establishes CA status; native subject/issuer name
equality establishes self-issued status, not self-signature. `x509.verify()` with
the certificate's own public key establishes self-signature when supported.
An issuer with CA and verified self-signature is a `self-signed-ca`, not a trusted
root. Other self-issued issuers are `self-issued`; CA issuers are `intermediate`;
uninspectable authority is `unknown`. No displayed certificate is labeled a
trust anchor, and no root-like entry proves chain completeness or authorization.
`chain` retains detailed certificates; `issuerChain` is a compact display model
with explicit provenance, CA/self-issued/self-signed observations and algorithms.

## Cryptographic metadata

Node 22 has no `X509Certificate.signatureAlgorithm`. A fixed-depth DER parser
reads matching inner/outer certificate AlgorithmIdentifiers from `raw` DER.
It caps input at 256 KiB, bounds every read by its parent, rejects indefinite,
oversized, noncanonical/truncated lengths and unexpected tags, and bounds OID
decoding. Native X.509 construction must also succeed for certificate metadata.
Failures yield unavailable/unknown metadata without a diagnostic crash.

Recognized signatures include RSA SHA-256/384/512, RSA SHA-1/MD5, ECDSA SHA-1 and
SHA-2, Ed25519/Ed448, and RSASSA-PSS. PSS hash claims require a readable parameter
sequence and hash identifier (including its defined SHA-1 default); absent or
unrecognized parameters are reported as hash unverified. This is not a complete
PSS parameter/security assessment. Unrecognized OIDs are preserved in
`signatureAlgorithmOid` and in the displayed unknown-algorithm description.

`X509Certificate.publicKey` supplies `KeyObject.asymmetricKeyType` and
`asymmetricKeyDetails`: RSA/RSA-PSS modulus length and EC named curve, plus native
EdDSA/DSA or other supported key names. `bits` retains the RSA modulus size only;
non-RSA keys never receive an invented modulus size. Public-key type/size is not
the signature's signing-key type/size.

`signatureStrength` is `weak` for recognized SHA-1/MD5 signatures,
`not-known-weak` for the other recognized signature hashes/algorithms, or `unknown`.
"Not known weak" is not a claim of comprehensive cryptographic security.
Every leaf/issuer is evaluated. Weak and unknown observations produce warnings;
names, cipher suites, fingerprints and public-key names are not signature evidence.
Authorization/error, hostname checking, `rejectUnauthorized: false`, and all
network validation, admission, rate, cancellation and socket budgets are unchanged.

## Offline regression checks

From `backend/`:

```sh
node --test test/tls-check.test.mjs test/tls-certificate.test.mjs test/tls-resources.test.mjs
```

Certificate-correctness tests require local OpenSSL,
generate disposable test-only certificates/keys in an isolated temporary directory,
remove them after testing, and use bounded loopback TLS servers only. Nothing
contacts public TLS endpoints or commits private keys. Algorithm and expiration
assertions do not depend on generated certificate fingerprints or current validity.
Frontend unit and guarded Playwright tests cover UI and image-capture wording.
