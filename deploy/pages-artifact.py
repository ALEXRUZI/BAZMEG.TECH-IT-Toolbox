#!/usr/bin/env python3
"""Seal/verify the complete Pages payload, including the compiled Function.

The manifest is integrity metadata, not independent authorization. Only the current
run's immutable artifact is accepted by the production workflow.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

MARKER = '.toolbox-artifact.json'


def inventory(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Regular artifact directory required')
    files = {}
    for path in sorted(root.rglob('*')):
        name = path.relative_to(root).as_posix()
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise ValueError('Non-regular artifact entry')
        if name == MARKER:
            continue
        if (not re.fullmatch(r'[A-Za-z0-9_./-]+', name) or
                any(part.startswith('.') for part in path.relative_to(root).parts) or
                name.endswith(('.map', '.ts', '.toml', '.jsonc')) or
                name in ('package.json', 'package-lock.json', 'wrangler.json') or
                name.startswith('functions/')):
            raise ValueError('Configuration/source file in deployment payload')
        if path.is_dir():
            continue
        files[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not {'index.html', '_worker.js/index.js', '_routes.json'} <= files.keys():
        raise ValueError('Static assets or precompiled Pages Function missing')
    routes = json.loads((root / '_routes.json').read_text())
    if routes.get('version') != 1 or '/api/*' not in routes.get('include', []):
        raise ValueError('API Function route missing')
    return files


def process(command, root, sha):
    if not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('Exact public SHA required')
    expected = {'schema': 1, 'sha': sha, 'files': inventory(root)}
    marker = root / MARKER
    if command == 'seal':
        with marker.open('x') as output:
            json.dump(expected, output, sort_keys=True)
    elif command == 'verify':
        if json.loads(marker.read_text()) != expected:
            raise ValueError('Pages artifact drift or SHA mismatch')
        # Metadata is not a public asset. No other bytes are changed.
        marker.unlink()
    else:
        raise ValueError('Unknown artifact operation')


if __name__ == '__main__':
    process(sys.argv[1], Path(sys.argv[2]), sys.argv[3])
