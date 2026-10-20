"""Offline independent vectors: Python zlib/hashlib and system libxxhash (XXH32).

Run from frontend: python3 tests/fixtures/generate-hash-references.py
Requires Python 3 and libxxhash; neither is an application/test runtime dependency.
XXH32 specification: https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md
BLAKE2 parameters: RFC 7693; CRC32 check value: CRC catalogue CRC-32/ISO-HDLC.
"""
import ctypes
import ctypes.util
import hashlib
import json
from pathlib import Path
import zlib

xx = ctypes.CDLL(ctypes.util.find_library('xxhash'))
xx.XXH32.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32]
xx.XXH32.restype = ctypes.c_uint32
xx.XXH_versionNumber.restype = ctypes.c_uint


def digests(data):
    return dict(crc32=f'{zlib.crc32(data):08x}',
                blake2b256=hashlib.blake2b(data, digest_size=32).hexdigest(),
                xxhash32=f'{xx.XXH32(data, len(data), 0):08x}')


texts = ['', 'abc', '123456789', ' \t雪😀e\u0301\r\n\r ', '\n\r\n', '\x00']
# Fixed small inputs with leading-zero output (searched independently).
for algorithm in ['crc32', 'blake2b256', 'xxhash32']:
    texts.append(next(str(i) for i in range(10000) if digests(str(i).encode())[algorithm].startswith('0')))
vectors = [dict(text=text, digests=digests(text.encode())) for text in texts]
for length in [1, 15, 16, 17, 127, 128, 129, 4194303, 4194304, 4194305, 4194321, 8388625]:
    data = (bytes(range(251)) * ((length + 250) // 251))[:length]
    vectors.append(dict(length=length, digests=digests(data)))
vectors.append(dict(length=104857600, zeros=True, digests=digests(bytes(104857600))))
Path(__file__).with_name('hash-references.json').write_text(json.dumps(vectors, ensure_ascii=False, indent=2) + '\n')
print(f'Python hashlib BLAKE2b-256, zlib {zlib.ZLIB_VERSION}, libxxhash {xx.XXH_versionNumber()}')
