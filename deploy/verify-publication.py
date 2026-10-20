#!/usr/bin/env python3
"""Verify every committed public blob against the deterministic release receipt.

Integrity/drift check, not authorization: protected main and environment reviewers
must establish release approval. Does not inspect the post-test working directory.
"""
import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def verify(root=ROOT, revision='HEAD'):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args])

    files = {}
    receipt = None
    for record in git('ls-tree', '-rz', '--full-tree', revision).split(b'\0'):
        if not record:
            continue
        meta, name = record.split(b'\t', 1)
        mode, kind, oid = meta.decode().split()
        if kind != 'blob' or mode not in ('100644', '100755'):
            raise ValueError('Non-regular publication entry')
        data = git('cat-file', 'blob', oid)
        if name == b'.release/publication.json':
            if mode != '100644':
                raise ValueError('Publication receipt must have regular non-executable mode')
            receipt = data
        else:
            files[name.decode()] = {'mode': mode, 'sha256': hashlib.sha256(data).hexdigest()}
    encoded = (json.dumps(files, sort_keys=True, separators=(',', ':')) + '\n').encode()
    expected = {'schema': 1, 'digest': hashlib.sha256(encoded).hexdigest(), 'files': files}
    canonical = (json.dumps(expected, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if receipt != canonical:
        raise ValueError('Publication receipt missing or committed tree has diverged')


if __name__ == '__main__':
    verify()
