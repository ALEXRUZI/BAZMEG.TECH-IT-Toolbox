# Hash Calculator

Browser-only, local processing: one regular file or exact UTF-8 text, without
uploads, persistence, telemetry or remote fallback. SHA-256 is selected by default.
Available algorithms are SHA-256/384/512, BLAKE3-256, unkeyed BLAKE2b-256,
CRC32 (IEEE), xxHash32 (seed 0), SHA-1 and MD5. BLAKE2b-256 uses a 32-byte output
parameter, not truncation of BLAKE2b-512. CRC32/xxHash32 are not cryptographic.

`hash-wasm` 4.12.0 and its embedded WASM are bundled in a local worker, never fetched
from a runtime CDN. Files are read in bounded 4 MiB slices shared across selected
algorithm states; whole-file buffering is not used. Text whitespace, Unicode bytes,
CRLF and CR are preserved. Unsupported ambiguous browser edits fail closed rather
than silently changing bytes. Undo history is transient tool memory only.

Each calculation owns a fresh worker terminated on completion, cancellation,
replacement, reset and unmount. Stale callbacks cannot publish results. File
working buffers are bounded, but browser/OS memory usage is not guaranteed constant;
text-input memory scales with text length. No guaranteed memory erasure is claimed.

MD5 and SHA-1 are broken for collision resistance. Their permanent warning remains
visible, and each requires transient acknowledgment before use. Deselect/reset
clears acknowledgment. A matching checksum does not prove authenticity: use a
trusted channel to authenticate expected digests. Auto verification rejects the
64-hex SHA-256/BLAKE3/BLAKE2b ambiguity and 8-hex CRC32/xxHash32 ambiguity even if
only one corresponding result exists. Explicit selection resolves ambiguity.

Run frontend typecheck/build/unit and Chromium E2E checks from the root README.
Independent reference vectors cover exact text/binary bytes, block/chunk boundaries,
empty input, Unicode and interrupted work. Large-file browser checks are opt-in:
`HASH_LARGE_TESTS=1 npx playwright test e2e/hash-calculator.spec.ts`. Ordinary CI
does not run these expensive cases or qualify every browser, IME or low-memory
device. Third-party notices are in `frontend/public/hash-wasm-LICENSE.txt`.
