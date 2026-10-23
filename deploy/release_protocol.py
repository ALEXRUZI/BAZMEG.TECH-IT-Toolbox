#!/usr/bin/env python3
"""Canonical production authorization, using OpenSSL Ed25519 (no custom crypto)."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
import time

REPOSITORY = 'ALEXRUZI/BAZMEG.TECH-IT-Toolbox'
WORKFLOW = '.github/workflows/backend-production.yml'
MAX_ARCHIVE = 16 * 1024 * 1024
FIELDS = {'schema', 'repository', 'commit', 'release', 'sequence', 'snapshot',
          'archive', 'size', 'sha256', 'key', 'workflow', 'run', 'attempt',
          'owner', 'environment', 'issued', 'expires', 'algorithm'}


def require_ed25519(der):
    # RFC 8410 SubjectPublicKeyInfo: Ed25519 OID, absent parameters, 32-byte key.
    # Encoding check only; all cryptographic operations remain OpenSSL's responsibility.
    if len(der) != 44 or not der.startswith(bytes.fromhex('302a300506032b6570032100')):
        raise ValueError('Ed25519 key required')


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')


def decode(data):
    if len(data) > 8192:
        raise ValueError('Manifest limit')
    value = json.loads(data)
    if not isinstance(value, dict) or canonical(value) != data or set(value) != FIELDS:
        raise ValueError('Noncanonical manifest/schema')
    return value


def validate(value, now=None):
    now = int(time.time()) if now is None else now
    if set(value) != FIELDS:
        raise ValueError('Manifest fields')
    for field in ('sequence', 'run', 'issued', 'expires', 'size', 'schema', 'attempt'):
        if type(value[field]) is not int or not 0 < value[field] < 2**63:
            raise ValueError('Manifest integer')
    for field, pattern in (('commit', '[0-9a-f]{40}'), ('snapshot', '[0-9a-f]{64}'),
                           ('sha256', '[0-9a-f]{64}'), ('key', '[a-z0-9-]{1,48}')):
        if not isinstance(value[field], str) or not re.fullmatch(pattern, value[field]):
            raise ValueError('Manifest identifier')
    identity = f'production-{value["sequence"]}-{value["run"]}-{value["commit"]}'
    if (value['schema'] != 1 or value['attempt'] != 1 or
            value['repository'] != REPOSITORY or value['workflow'] != WORKFLOW or
            value['owner'] != 'ALEXRUZI' or value['environment'] != 'production' or
            value['algorithm'] != 'Ed25519' or value['release'] != identity or
            value['archive'] != f'backend-{value["commit"]}.tar.gz' or
            value['size'] > MAX_ARCHIVE or
            not 0 < value['expires'] - value['issued'] <= 86400 or
            value['issued'] > now + 60 or value['expires'] <= now):
        raise ValueError('Unsupported, mismatched or stale authorization')
    return value


def verify(data, signature, keys, now=None):
    value = validate(decode(data), now)
    # keys is independently provisioned policy, never supplied by a Release asset.
    policy = keys.get(value['key'])
    if (not policy or policy.get('revoked', False) or
            not policy['first'] <= value['sequence'] <= policy['last'] or len(signature) != 64):
        raise ValueError('Unknown/revoked/out-of-range key')
    require_ed25519(subprocess.check_output(['/usr/bin/openssl', 'pkey', '-pubin',
                    '-in', policy['path'], '-outform', 'DER'], timeout=10, stderr=subprocess.DEVNULL))
    with tempfile.TemporaryDirectory(prefix='toolbox-signature-') as directory:
        manifest = Path(directory) / 'manifest'
        sig = Path(directory) / 'signature'
        manifest.write_bytes(data)
        sig.write_bytes(signature)
        subprocess.run(['/usr/bin/openssl', 'pkeyutl', '-verify', '-pubin',
                        '-inkey', policy['path'], '-rawin', '-in', str(manifest),
                        '-sigfile', str(sig)], check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return value


def archive_matches(value, data):
    if len(data) != value['size'] or hashlib.sha256(data).hexdigest() != value['sha256']:
        raise ValueError('Archive identity mismatch')


def eligible(value, state):
    if state.get('pending'):
        raise ValueError('Interrupted/failed activation requires root operator recovery')
    if value['sequence'] < state['sequence']:
        raise ValueError('Replay/downgrade')
    if value['sequence'] == state['sequence']:
        if state.get('release') != value['release'] or state.get('sha256') != value['sha256']:
            raise ValueError('Conflicting authorization sequence')
        if 'authorization' in state and state['authorization'] != authorization(value, canonical(value)):
            raise ValueError('Conflicting authorization sequence')
        return False
    return True


def authorization(value, manifest):
    """Projection of authenticated canonical bytes; this function grants no trust.

    Decimal sequence text avoids loss of int64 precision in JSON/Actions clients.
    """
    if decode(manifest) != value:
        raise ValueError('Manifest identity mismatch')
    return dict(release=value['release'], sequence=str(value['sequence']),
                commit=value['commit'], archiveSha256=value['sha256'],
                manifestSha256=hashlib.sha256(manifest).hexdigest(), keyId=value['key'])


def publish():
    """Called only after live environment/approval verification in the signing job."""
    sha = os.environ['GITHUB_SHA']
    archive = Path(f'backend-{sha}.tar.gz')
    with os.fdopen(os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARCHIVE:
            raise ValueError('Archive limit/type')
        archive_bytes = source.read(MAX_ARCHIVE + 1)
        if len(archive_bytes) > MAX_ARCHIVE:
            raise ValueError('Archive limit/type')
    now = int(time.time())
    value = dict(schema=1, repository=REPOSITORY, commit=sha,
                 sequence=int(os.environ['GITHUB_RUN_NUMBER']), run=int(os.environ['GITHUB_RUN_ID']),
                 attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), snapshot=os.environ['SNAPSHOT_DIGEST'],
                  archive=archive.name, size=len(archive_bytes),
                  sha256=hashlib.sha256(archive_bytes).hexdigest(),
                 key=os.environ['RELEASE_KEY_ID'], workflow=WORKFLOW, owner='ALEXRUZI',
                 environment='production', issued=now, expires=now + 86400, algorithm='Ed25519')
    value['release'] = f'production-{value["sequence"]}-{value["run"]}-{sha}'
    validate(value)
    with Path('manifest.json').open('xb') as output:
        output.write(canonical(value))
    # Private material is never a release asset; runner temp is removed even on error.
    fd, name = tempfile.mkstemp(prefix='toolbox-signing-', dir=os.environ['RUNNER_TEMP'])
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(os.environ['RELEASE_SIGNING_KEY'])
        require_ed25519(subprocess.check_output(['openssl', 'pkey', '-in', name,
                        '-pubout', '-outform', 'DER'], timeout=10, stderr=subprocess.DEVNULL))
        signature_fd = os.open('manifest.sig', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        os.close(signature_fd)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-inkey', name, '-rawin',
                        '-in', 'manifest.json', '-out', 'manifest.sig'], check=True, timeout=10,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if Path('manifest.sig').stat().st_size != 64:
            raise ValueError('Ed25519 signing key required')
    finally:
        os.unlink(name)
    # Actual signed bytes, not reconstructed GitHub Release metadata.
    identity = authorization(value, Path('manifest.json').read_bytes())
    with open(os.environ['GITHUB_OUTPUT'], 'a') as output:
        for field, content in identity.items():
            output.write(field + '=' + content + '\n')


if __name__ == '__main__':
    publish()
