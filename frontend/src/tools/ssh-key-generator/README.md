# Local SSH key generation and conversion

Keys are generated/imported in fresh browser workers, never uploaded or persisted.
Use a trusted HTTPS browser/device. Clipboard, downloads, browser extensions and
malware are outside this application's control; memory erasure is not guaranteed.

Modern profiles include Ed25519, Ed448, ECDSA and RSA (including resource-intensive
RSA 8192). RSA generation uses the exact requested native size, without smaller-key
or software-prime fallback. Ed448 supports RFC 8709 public lines and PuTTY PPK v3,
not OpenSSH private files or standard OpenSSH server authentication.

Legacy weak RSA, DSA and SSH-1 require explicit risk acknowledgment. Current OpenSSH
does not accept weak RSA and removed DSA in 10.0. Format interoperability does not
establish server acceptance. SSH-1's historical encryption is obsolete and
unauthenticated. Binary SSH-1 private files are download/ZIP only. ZIP is not encrypted.
Keep protected export defaults and deliberate plaintext/clipboard confirmations.

The SSH-1 implementation uses only the six reviewed DES/cipher/util modules from
node-forge 1.4.0. **Its package-level RSA-verifier security advisory remains open.**
This isolated usage and the production bundle guard do not fix the advisory or
constitute acceptance of a security exception. The repository owner must resolve or
explicitly accept the dependency risk before publication.

Run `npm run build` then `npm run check:ssh-bundle` in `frontend/` to inspect the
actual emitted app/worker closure and artifact hashes. Unit tests use independent
Node/OpenSSL proofs; browser tests use Chromium. Native PuTTYgen qualification is
opt-in with `SSH_INTEROP=1` and `SSH_PUTTYGEN`; heavy real RSA 8192 checks additionally
require `SSH_RSA8192=1`. Ordinary CI does not claim all-browser/native qualification.
Third-party notices are in `frontend/public/ssh-key-LICENSES.txt`.
