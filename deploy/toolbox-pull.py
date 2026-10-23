#!/usr/bin/env python3
"""Fixed-path pull orchestration. Network child is toolboxdeploy; root reauthenticates.

No sudo delegation, listener, token on command line, or application secret access.
"""
import argparse
from email.utils import parsedate_to_datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess
from subprocess import Popen
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_protocol import (REPOSITORY, MAX_ARCHIVE, canonical, verify, validate,
                              archive_matches, eligible, authorization)

CONFIG = Path('/etc/toolbox-pull/policy.json')
STATE = Path('/var/lib/toolbox-pull/state.json')
EVIDENCE = Path('/var/lib/toolbox-release/accepted.json')
CACHE = Path('/var/lib/toolbox-deploy/pull-cache.json')
MAX_CACHE = 2 * 1024 * 1024
INCOMING = Path('/var/lib/toolbox-deploy/incoming')
HELPER = Path('/usr/local/sbin/toolbox-backend-deploy')
HELPER_SHA256 = 'e5f973abdc73e886f00f07ea2bed449214f384d8897e13566fe99d9488fe23ac'
API = 'https://api.github.com/repos/' + REPOSITORY + '/releases?per_page=10'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def safe_read(path, limit, root=False):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > limit or
                root and (info.st_uid != 0 or info.st_mode & 0o022)):
            raise ValueError('Unsafe local file')
        data = source.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Local file limit')
        return data


def trusted(path):
    for parent in [path, *path.parents]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Untrusted policy/code/state path')


def secure_lock(path):
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or
            parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX):
        raise ValueError('Unsafe lock directory')
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or
            info.st_nlink != 1):
        os.close(fd)
        raise ValueError('Unsafe lock file')
    return os.fdopen(fd, 'r+')


def restorecon(path):
    subprocess.run(['/usr/sbin/restorecon', str(path)], check=True, timeout=10,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def atomic(path, value, mode=0o600, label=False):
    fd, name = tempfile.mkstemp(prefix='.pull-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as output:
            output.write(canonical(value))
            output.flush()
            os.fchmod(output.fileno(), mode)
            if label:
                # Label the temporary inode BEFORE exposure by rename. Operator
                # fcontext rules must cover the whole evidence directory.
                restorecon(name)
            os.fsync(output.fileno())
        os.replace(name, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_state(state):
    if (not isinstance(state, dict) or type(state.get('sequence')) is not int or
            not 0 <= state['sequence'] < 2**63 or type(state.get('pending')) is not bool):
        raise ValueError('Malformed acceptance state')
    if set(state) == {'sequence', 'pending'} and not state['pending']:
        return state  # Independently provisioned bootstrap/high-water floor.
    fields = {'sequence', 'release', 'sha256', 'pending'}
    if set(state) not in (fields, fields | {'authorization'}):
        raise ValueError('Malformed acceptance state')
    if (not isinstance(state['release'], str) or not re.fullmatch(
            rf'production-{state["sequence"]}-[1-9][0-9]{{0,18}}-[0-9a-f]{{40}}', state['release']) or
            not isinstance(state['sha256'], str) or not re.fullmatch('[0-9a-f]{64}', state['sha256'])):
        raise ValueError('Malformed acceptance state')
    if 'authorization' in state:
        identity = state['authorization']
        if (not isinstance(identity, dict) or set(identity) != {
                'release', 'sequence', 'commit', 'archiveSha256', 'manifestSha256', 'keyId'} or
                identity['release'] != state['release'] or identity['sequence'] != str(state['sequence']) or
                identity['archiveSha256'] != state['sha256'] or
                identity['commit'] != state['release'].rsplit('-', 1)[1] or
                not isinstance(identity['manifestSha256'], str) or
                not re.fullmatch('[0-9a-f]{64}', identity['manifestSha256']) or
                not isinstance(identity['keyId'], str) or not re.fullmatch('[a-z0-9-]{1,48}', identity['keyId'])):
            raise ValueError('Malformed acceptance state')
    return state


def evidence(value):
    # No application or download account may replace a parent or this file.
    trusted(EVIDENCE.parent)
    if EVIDENCE.exists() or EVIDENCE.is_symlink():
        trusted(EVIDENCE)
        safe_read(EVIDENCE, 8192, root=True)
    atomic(EVIDENCE, value, mode=0o644, label=True)


class Network:
    def __init__(self, cache, token=None):
        self.cache = cache
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def get(self, url, limit, conditional=False):
        # No arbitrary hosts, credentials, ports, paths or inherited proxy settings.
        headers = {'User-Agent': 'toolbox-production-pull/1', 'Accept': 'application/vnd.github+json'}
        if conditional:
            etag = self.cache.get('etag', '')
            self.validate_etag(etag)
            if etag:
                headers['If-None-Match'] = etag
        for hop in range(4):
            parsed = urlsplit(url)
            if (parsed.scheme != 'https' or parsed.port not in (None, 443) or
                    parsed.username or parsed.password or parsed.fragment or
                    parsed.hostname not in ('api.github.com', 'github.com', 'release-assets.githubusercontent.com') or
                    re.search(r'[\x00-\x20\x7f]', url)):
                raise ValueError('Download origin rejected')
            if parsed.hostname == 'api.github.com':
                if not parsed.path.startswith('/repos/' + REPOSITORY + '/'):
                    raise ValueError('API repository rejected')
            elif parsed.hostname == 'github.com':
                if not parsed.path.startswith('/' + REPOSITORY + '/releases/download/'):
                    raise ValueError('Release path rejected')
            # Credentials are scoped to the API, never forwarded to asset redirects.
            request_headers = dict(headers)
            if self.token and parsed.hostname == 'api.github.com':
                request_headers['Authorization'] = 'Bearer ' + self.token
            try:
                response = self.opener.open(Request(url, headers=request_headers), timeout=20)
            except HTTPError as error:
                response = error
            with response:
                if response.status in (301, 302, 303, 307, 308):
                    url = response.headers.get('Location', '')
                    continue
                if response.status == 304 and conditional:
                    return None
                if response.status in (403, 429) or response.status == 503 and response.headers.get('Retry-After'):
                    now = int(time.time())
                    try:
                        reset = int(response.headers.get('X-RateLimit-Reset', now))
                        fallback = '60' if response.headers.get('X-RateLimit-Reset') else '3600'
                        retry_after = response.headers.get('Retry-After', fallback)
                        retry = (int(retry_after) + now if retry_after.isdigit() else
                                 int(parsedate_to_datetime(retry_after).timestamp()))
                    except (ValueError, TypeError, OverflowError):
                        reset = retry = now + 3600
                    self.cache['next'] = max(now + 60, min(now + 86400, max(reset, retry)))
                    raise ValueError('GitHub rate limited')
                if response.status != 200:
                    raise ValueError('GitHub HTTP failure')
                if response.headers.get('X-RateLimit-Remaining') == '0':
                    try:
                        reset = int(response.headers.get('X-RateLimit-Reset', int(time.time()) + 3600))
                    except ValueError:
                        reset = int(time.time()) + 3600
                    self.cache['next'] = max(int(time.time()) + 60, min(int(time.time()) + 86400, reset))
                data = response.read(limit + 1)
                if len(data) > limit:
                    raise ValueError('Download limit')
                if conditional:
                    etag = response.headers.get('ETag', '')
                    self.validate_etag(etag)
                    self.cache['etag'] = etag
                return data
        raise ValueError('Redirect limit')

    @staticmethod
    def validate_etag(etag):
        if (not isinstance(etag, str) or len(etag) > 256 or
                etag and not re.fullmatch(r'(?:W/)?"[\x21\x23-\x7e]*"', etag)):
            raise ValueError('Invalid ETag')


def discover(network, keys, state):
    data = network.get(API, 1024 * 1024, conditional=True)
    try:
        releases = json.loads(data) if data is not None else network.cache.get('releases', [])
        if not isinstance(releases, list) or len(releases) > 10:
            raise ValueError('Release listing malformed')
    except Exception:
        network.cache.pop('etag', None)
        network.cache.pop('releases', None)
        raise
    network.cache['releases'] = releases
    metadata = []
    for release in releases:
        tag = release.get('tag_name', '')
        if not isinstance(tag, str) or not tag.startswith('production-'):
            continue
        if not re.fullmatch(r'production-[1-9][0-9]{0,18}-[1-9][0-9]{0,18}-[0-9a-f]{40}', tag):
            raise ValueError('Malformed production release')
        # Old metadata need not cause downloads. It is not an authorization source.
        if int(tag.split('-')[1]) < state['sequence']:
            continue
        if int(tag.split('-')[1]) == state['sequence'] and tag == state.get('release'):
            continue
        metadata.append((int(tag.split('-')[1]), release))
    if len({sequence for sequence, _ in metadata}) != len(metadata):
        raise ValueError('Ambiguous authorization sequence')
    metadata.sort(key=lambda item: item[0], reverse=True)
    # Never let an expired/revoked older, unaccepted release prevent a fresh higher
    # approval. Conversely, never silently fall back if the newest hint is invalid.
    for _, release in metadata[:1]:
        tag = release['tag_name']
        assets = release.get('assets', [])
        names = [asset.get('name') for asset in assets]
        sha = tag.rsplit('-', 1)[1]
        expected = {'manifest.json', 'manifest.sig', f'backend-{sha}.tar.gz'}
        if (release.get('draft') is not False or release.get('prerelease') is not False or
                len(names) != 3 or set(names) != expected):
            raise ValueError('Ambiguous release assets')
        base = f'https://github.com/{REPOSITORY}/releases/download/{tag}/'
        manifest = network.get(base + 'manifest.json', 8192)
        signature = network.get(base + 'manifest.sig', 64)
        value = verify(manifest, signature, keys)
        if value['release'] != tag or value['commit'] != sha:
            raise ValueError('Release identity mismatch')
        if eligible(value, state):
            return value, manifest, signature, base
    return None


def fetch(directory):
    if os.getuid() != pwd.getpwnam('toolboxdeploy').pw_uid:
        raise ValueError('Network phase requires toolboxdeploy')
    policy = json.loads(safe_read(CONFIG, 16384, root=True))
    state = json.loads(safe_read(directory / 'request.json', 8192))
    cache = json.loads(safe_read(CACHE, MAX_CACHE)) if CACHE.exists() else {}
    now = int(time.time())
    if type(cache.get('next', 0)) is not int or not 0 <= cache.get('next', 0) <= now + 86400:
        raise ValueError('Invalid cache/backoff; operator may remove untrusted cache')
    if cache.get('next', 0) > now:
        print('pull: rate/failure backoff active until epoch ' + str(cache['next']))
        return
    token_file = Path('/var/lib/toolbox-deploy/github-read-token')
    token = None
    if token_file.exists():
        info = token_file.lstat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError('Read token requires private ownership/mode')
        token = safe_read(token_file, 1024).decode().strip()
        if not re.fullmatch(r'[A-Za-z0-9_]+', token):
            raise ValueError('Malformed read token')
    network = Network(cache, token)
    try:
        candidate = discover(network, policy['keys'], state)
        if candidate:
            value, manifest, signature, base = candidate
            print('pull: signature authenticated; downloading candidate ' + value['release'])
            archive = network.get(base + value['archive'], value['size'])
            archive_matches(value, archive)
            for name, data in [('manifest.json', manifest), ('manifest.sig', signature), ('archive', archive)]:
                # fresh per-operation directory; root never trusts these names or bytes.
                with (directory / name).open('xb') as output:
                    output.write(data)
        cache['failures'] = 0
        cache['next'] = cache.get('next', 0) if cache.get('next', 0) > now else 0
    except Exception:
        cache['failures'] = min(8, cache.get('failures', 0) + 1)
        cache['next'] = max(cache.get('next', 0), now + min(3600, 60 * 2**cache['failures']))
        raise
    finally:
        # ASCII canonicalization can expand Unicode API metadata. Never persist a
        # cache larger than we can safely read; discard only transport hints, not
        # rate backoff or the separate root acceptance record.
        if len(canonical(cache)) > MAX_CACHE:
            cache.pop('releases', None)
            cache.pop('etag', None)
        atomic(CACHE, cache)


def activate(directory, policy, state, check=False):
    # Freeze all untrusted staging bytes before authentication. No symlinks/FIFOs.
    manifest = safe_read(directory / 'manifest.json', 8192)
    signature = safe_read(directory / 'manifest.sig', 64)
    value = verify(manifest, signature, policy['keys'])
    archive = safe_read(directory / 'archive', MAX_ARCHIVE)
    archive_matches(value, archive)
    if not eligible(value, state):
        print('pull: authorization already accepted; no activation')
        return
    if check:
        print('pull: authenticated candidate; check-only, no activation/state advance')
        return
    trusted(HELPER)
    if hashlib.sha256(safe_read(HELPER, 128 * 1024, root=True)).hexdigest() != HELPER_SHA256:
        raise ValueError('Installed activation helper checksum mismatch')
    # Provision/validate its fixed root lock safely before the unchanged shell
    # helper opens it. Sticky /run/lock cannot let a local user replace root's file.
    with secure_lock(Path('/run/lock/toolbox-backend-deploy.lock')):
        pass
    # Invalidate the old proof durably BEFORE reservation/activation, including
    # same-SHA reauthorization. Interrupted/failed work can never expose old proof.
    evidence(None)
    identity = authorization(value, manifest)  # from root-verified frozen bytes
    # Durable reservation prevents replay even if activation fails or power is lost.
    next_state = dict(sequence=value['sequence'], release=value['release'], sha256=value['sha256'],
                      pending=True, authorization=identity)
    atomic(STATE, next_state)
    # Helper re-freezes and hashes this fixed-name input; a deploy-account race can
    # cause failure, never installation of different bytes. No privileged path open.
    # Anchor writes to an opened real directory. The account owns its home and
    # could rename incoming; never follow a replaced parent symlink as root.
    dirfd = os.open(INCOMING, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.verified-' + os.urandom(16).hex()
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=dirfd)
        with os.fdopen(fd, 'wb') as output:
            output.write(archive)
        os.rename(temporary, value['archive'], src_dir_fd=dirfd, dst_dir_fd=dirfd)
        process = Popen([str(HELPER), value['commit'], value['sha256']],
                        env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin'},
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        start_new_session=True)
        try:
            status = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            # Give the existing helper's TERM trap time to roll back, not SIGKILL.
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=240)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise ValueError('Activation deadline; operator must inspect pending state') from None
        if status:
            raise ValueError('Activation failed; operator must inspect pending state')
    finally:
        try:
            os.unlink(temporary, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        os.close(dirfd)
    validate(value)  # Long activation must not accept an expired authorization.
    next_state['pending'] = False
    atomic(STATE, next_state)
    # Deliberately no automatic reconstruction after interruption: a lost
    # projection stays unknown and requires a fresh higher approval.
    evidence(dict(schema=1, **identity))
    print('pull: accepted ' + value['release'])


def main(check=False):
    if os.geteuid() != 0:
        raise ValueError('Root orchestration required; no sudo delegation')
    for path in (CONFIG, STATE, Path(__file__).resolve(), Path(__file__).resolve().with_name('release_protocol.py')):
        trusted(path)
    policy = json.loads(safe_read(CONFIG, 16384, root=True))
    for key in policy['keys'].values():
        trusted(Path(key['path']))
    # Root lock encloses discovery, freeze, reservation, helper and state commit.
    with secure_lock(STATE.parent / 'operation.lock') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        state = validate_state(json.loads(safe_read(STATE, 8192, root=True)))
        if state['pending']:
            raise ValueError('State invalid or pending; operator recovery required')
        release = state.get('release', 'bootstrap')
        if not isinstance(release, str) or not re.fullmatch(r'[a-zA-Z0-9-]{1,160}', release):
            raise ValueError('Invalid accepted release identity')
        active_path = Path('/opt/toolbox-api/current').resolve(strict=True)
        if active_path.parent != Path('/opt/toolbox-api/releases'):
            raise ValueError('Unexpected active release path')
        active = active_path.name
        if not re.fullmatch(r'(?:[0-9a-f]{40}|legacy-[0-9]{8}T[0-9]{6}Z)', active):
            raise ValueError('Unexpected active release path')
        print(f'pull: last authorization={release} sequence={state["sequence"]} active={active}')
        with tempfile.TemporaryDirectory(prefix='pull-', dir='/var/lib/toolbox-deploy') as temporary:
            directory = Path(temporary)
            directory.chmod(0o755)
            request = directory / 'request.json'
            request.write_bytes(canonical(state))
            request.chmod(0o644)
            account = pwd.getpwnam('toolboxdeploy')
            os.chown(directory, account.pw_uid, account.pw_gid)
            subprocess.run(['/usr/bin/timeout', '--kill-after=5s', '230s',
                            '/usr/sbin/runuser', '-u', 'toolboxdeploy', '--', '/usr/bin/env', '-i',
                            'PATH=/usr/bin:/bin', 'HOME=/var/lib/toolbox-deploy', '/usr/bin/python3',
                            '-I', str(Path(__file__).resolve()), '--fetch', str(directory)],
                           check=True, timeout=240)
            if (directory / 'manifest.json').exists():
                activate(directory, policy, state, check)
            else:
                print('pull: no new authenticated candidate or backoff active')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--fetch', type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        if args.fetch:
            fetch(args.fetch)
        else:
            main(args.check)
    except Exception as error:
        # Do not log token, URLs with signed query parameters, body, or exceptions.
        reasons = {
            'Replay/downgrade', 'Conflicting authorization sequence',
            'Ambiguous authorization sequence', 'Release identity mismatch',
            'Unknown/revoked/out-of-range key', 'Ed25519 key required',
            'Unsupported, mismatched or stale authorization', 'Archive identity mismatch',
            'GitHub rate limited', 'GitHub HTTP failure', 'Download limit',
            'Download origin rejected', 'Installed activation helper checksum mismatch',
            'State invalid or pending; operator recovery required',
            'Activation failed; operator must inspect pending state',
            'Activation deadline; operator must inspect pending state',
            'Root orchestration required; no sudo delegation',
        }
        # Only exact source-controlled messages may reach logs, never raw exceptions.
        reason = str(error) if str(error) in reasons else 'verify local policy, signature, connectivity, backoff and pending state'
        raise SystemExit('pull: failed closed: ' + reason) from None
