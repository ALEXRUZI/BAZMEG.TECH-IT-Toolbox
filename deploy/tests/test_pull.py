"""Offline protocol, HTTP, privilege and state regressions; ephemeral Ed25519 keys."""
import copy
from contextlib import ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy'))
import release_protocol as protocol


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'deploy' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pull = load('toolbox-pull')
wait = load('wait-backend')
SHA = 'a' * 40


class Response(io.BytesIO):
    def __init__(self, data=b'', status=200, headers=None):
        super().__init__(data)
        self.status = status
        self.headers = headers or {}


class PullTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='toolbox-pull-tests-')
        cls.root = Path(cls.temp.name)
        cls.private = cls.root / 'disposable-private'
        cls.public = cls.root / 'public'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(cls.private)],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(cls.private), '-pubout', '-out', str(cls.public)],
                       check=True, capture_output=True)
        cls.keys = {'test-key': dict(path=str(cls.public), first=1, last=100, revoked=False)}

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        now = int(time.time())
        self.archive = b'disposable archive bytes'
        self.value = dict(schema=1, repository=protocol.REPOSITORY, commit=SHA, sequence=7, run=17,
                          attempt=1, snapshot='b' * 64, archive=f'backend-{SHA}.tar.gz',
                          size=len(self.archive), sha256=hashlib.sha256(self.archive).hexdigest(),
                          key='test-key', workflow=protocol.WORKFLOW, owner='ALEXRUZI',
                          environment='production', issued=now, expires=now + 86400, algorithm='Ed25519',
                          release=f'production-7-17-{SHA}')

    def sign(self, value=None, key=None):
        data = protocol.canonical(value or self.value)
        manifest = self.root / 'manifest'
        sig = self.root / 'sig'
        manifest.write_bytes(data)
        subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', str(key or self.private),
                        '-in', str(manifest), '-out', str(sig)], check=True, capture_output=True)
        return data, sig.read_bytes()

    def test_openssl_interoperability_and_canonical_exact_bytes(self):
        data, sig = self.sign()
        self.assertEqual(protocol.verify(data, sig, self.keys), self.value)
        self.assertEqual(self.sign()[1], sig)  # deterministic Ed25519 signatures
        for encoded in (data + b' ', data.replace(b'\n', b'\r\n'),
                        json.dumps(self.value).encode(), data.replace(b'"schema":1', b'"schema":1,"schema":1')):
            with self.subTest(encoded=encoded[:20]), self.assertRaises(ValueError):
                protocol.verify(encoded, sig, self.keys)
        for signature in (b'0' * 64, sig[:-1], bytes([sig[0] ^ 1]) + sig[1:]):
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                protocol.verify(data, signature, self.keys)

    def test_signed_but_wrong_authorization_fields_rejected(self):
        for key, value in [('repository', protocol.REPOSITORY + '-dev'), ('commit', 'main'),
                           ('snapshot', 'not-a-digest'), ('release', 'production-8-17-' + SHA),
                           ('archive', '../archive'), ('schema', 2), ('algorithm', 'Ed448'),
                           ('attempt', 2), ('owner', 'other'), ('environment', 'staging'),
                           ('workflow', 'other.yml'), ('sequence', True), ('size', 2**30),
                           ('expires', int(time.time()) - 1), ('issued', int(time.time()) + 120)]:
            candidate = {**self.value, key: value}
            with self.subTest(field=key), self.assertRaises(ValueError):
                protocol.verify(*self.sign(candidate), self.keys)
        # Altering otherwise valid snapshot/commit bytes without resigning fails.
        data, sig = self.sign()
        for field, value in [('snapshot', 'c' * 64), ('commit', 'c' * 40)]:
            with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                protocol.verify(protocol.canonical({**self.value, field: value}), sig, self.keys)

    def test_rotation_revocation_and_archive_substitution(self):
        data, sig = self.sign()
        for keys in ({}, {'test-key': {**self.keys['test-key'], 'revoked': True}},
                     {'test-key': {**self.keys['test-key'], 'first': 8}},
                     {'test-key': {**self.keys['test-key'], 'last': 6}}):
            with self.assertRaises(ValueError):
                protocol.verify(data, sig, keys)
        rotated = {'test-key': {**self.keys['test-key'], 'last': 7},
                   'next-key': {**self.keys['test-key'], 'first': 8}}
        protocol.verify(data, sig, rotated)
        next_private, next_public = self.root / 'next-private', self.root / 'next-public'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'Ed25519', '-out', str(next_private)],
                       check=True, capture_output=True)
        subprocess.run(['openssl', 'pkey', '-in', str(next_private), '-pubout', '-out', str(next_public)],
                       check=True, capture_output=True)
        rotated['next-key']['path'] = str(next_public)
        next_value = {**self.value, 'sequence': 8, 'key': 'next-key', 'release': f'production-8-17-{SHA}'}
        protocol.verify(*self.sign(next_value, next_private), rotated)
        with self.assertRaises(subprocess.CalledProcessError):
            protocol.verify(*self.sign(next_value), rotated)
        protocol.archive_matches(self.value, self.archive)
        for data in (self.archive + b'x', b'x' * len(self.archive)):
            with self.assertRaises(ValueError):
                protocol.archive_matches(self.value, data)

    def test_publisher_to_pull_verifier_exact_interoperability_and_missing_key(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            (directory / self.value['archive']).write_bytes(self.archive)
            output = directory / 'output'
            environment = dict(GITHUB_SHA=SHA, GITHUB_RUN_NUMBER='7', GITHUB_RUN_ID='17',
                               GITHUB_RUN_ATTEMPT='1', SNAPSHOT_DIGEST='b' * 64,
                               RELEASE_KEY_ID='test-key', RUNNER_TEMP=temp, GITHUB_OUTPUT=str(output),
                               RELEASE_SIGNING_KEY=self.private.read_text())
            previous = Path.cwd()
            try:
                os.chdir(directory)
                with patch.dict(os.environ, environment):
                    protocol.publish()
                value = protocol.verify((directory / 'manifest.json').read_bytes(),
                                        (directory / 'manifest.sig').read_bytes(), self.keys)
                protocol.archive_matches(value, self.archive)
                self.assertEqual(value['release'], self.value['release'])
                self.assertIn('release=' + value['release'], output.read_text())
                outputs = dict(line.split('=', 1) for line in output.read_text().splitlines())
                self.assertEqual(outputs, protocol.authorization(value, (directory / 'manifest.json').read_bytes()))
                self.assertEqual(sorted(p.name for p in directory.iterdir()),
                                 sorted([self.value['archive'], 'manifest.json', 'manifest.sig', 'output']))
                with patch.dict(os.environ, environment), self.assertRaises(FileExistsError):
                    protocol.publish()
                (directory / 'manifest.json').unlink()
                (directory / 'manifest.sig').unlink()
                with patch.dict(os.environ, {**environment, 'RELEASE_SIGNING_KEY': ''}), \
                        self.assertRaises(subprocess.CalledProcessError):
                    protocol.publish()
                self.assertEqual(list(directory.glob('toolbox-signing-*')), [])
                archive = directory / self.value['archive']
                archive.unlink()
                archive.symlink_to(self.private)
                with patch.dict(os.environ, environment), self.assertRaises(OSError):
                    protocol.publish()
                archive.unlink()
                with archive.open('wb') as oversized:
                    oversized.truncate(protocol.MAX_ARCHIVE + 1)
                with patch.dict(os.environ, environment), self.assertRaises(ValueError):
                    protocol.publish()
            finally:
                os.chdir(previous)

    def test_key_algorithm_confusion_rejected(self):
        for der in (b'', bytes.fromhex('302a300506032b6571032100') + b'x' * 32, b'x' * 44):
            with self.assertRaises(ValueError):
                protocol.require_ed25519(der)

    def test_bootstrap_duplicate_replay_conflict_and_pending(self):
        self.assertTrue(protocol.eligible(self.value, {'sequence': 0}))
        self.assertTrue(protocol.eligible(self.value, {'sequence': 6}))
        accepted = dict(sequence=7, release=self.value['release'], sha256=self.value['sha256'])
        self.assertFalse(protocol.eligible(self.value, accepted))
        exact = {**accepted, 'authorization': protocol.authorization(self.value, protocol.canonical(self.value))}
        self.assertFalse(protocol.eligible(self.value, exact))
        with self.assertRaises(ValueError):
            protocol.eligible({**self.value, 'snapshot': 'd' * 64}, exact)
        for state in ({'sequence': 8}, {**accepted, 'sha256': 'c' * 64},
                      {**accepted, 'release': 'wrong'}, {'sequence': 0, 'pending': True}):
            with self.assertRaises(ValueError):
                protocol.eligible(self.value, state)
        # Manual root rollback retains high-water: the old signature stays ineligible.
        with self.assertRaises(ValueError):
            protocol.eligible(self.value, {'sequence': 8, 'release': 'manual-rollback'})

    def network(self, responses, cache=None, token=None):
        network = pull.Network(cache if cache is not None else {}, token)
        network.opener = unittest.mock.Mock()
        network.opener.open.side_effect = responses
        return network

    def test_network_conditional_limits_outages_and_redirects(self):
        network = self.network([Response(b'[]', headers={'ETag': '"fixture"'}), Response(status=304)])
        self.assertEqual(network.get(pull.API, 99, True), b'[]')
        self.assertIsNone(network.get(pull.API, 99, True))
        self.assertEqual(network.opener.open.call_args.args[0].get_header('If-none-match'), '"fixture"')
        for etag in ('bad\nheader', 'unquoted', '"' + 'x' * 300 + '"', [], None):
            network = self.network([], {'etag': etag})
            with self.assertRaises(ValueError):
                network.get(pull.API, 99, True)
            network.opener.open.assert_not_called()
        for response in [Response(status=404), Response(status=500), Response(b'x' * 100),
                         Response(status=302, headers={'Location': 'http://github.com/unsafe'}),
                         Response(status=302, headers={'Location': 'https://evil.example/'}),
                         Response(status=302, headers={'Location': 'https://user:pass@github.com/'}),
                         TimeoutError(), URLError('offline')]:
            network = self.network([response])
            with self.subTest(response=type(response)), self.assertRaises(Exception):
                network.get(pull.API, 99)
        for url in ('https://api.github.com/repos/other/repo/releases', 'https://github.com/other/repo',
                    'https://api.github.com:444/repos/' + protocol.REPOSITORY,
                    'https://api.github.com/\ninjection'):
            network = self.network([])
            with self.assertRaises(ValueError):
                network.get(url, 99)
            network.opener.open.assert_not_called()
        self.assertIsNone(pull.NoRedirect().redirect_request(None, None, None, None, None, None))

    def test_rate_limit_backoff_and_credential_not_forwarded(self):
        for status in (403, 429):
            network = self.network([Response(status=status, headers={'Retry-After': '600'})])
            with self.assertRaises(ValueError):
                network.get(pull.API, 99)
            self.assertGreaterEqual(network.cache['next'], int(time.time()) + 599)
        reset = int(time.time()) + 900
        network = self.network([Response(b'[]', headers={'X-RateLimit-Remaining': '0',
                                                        'X-RateLimit-Reset': str(reset)})])
        network.get(pull.API, 99)
        self.assertEqual(network.cache['next'], reset)
        network = self.network([Response(status=403, headers={'X-RateLimit-Reset': str(reset)})])
        with self.assertRaises(ValueError):
            network.get(pull.API, 99)
        self.assertEqual(network.cache['next'], reset)
        network = self.network([HTTPError(pull.API, 429, 'rate', {'Retry-After': '600'}, io.BytesIO())])
        with self.assertRaises(ValueError):
            network.get(pull.API, 99)
        url = f'https://github.com/{protocol.REPOSITORY}/releases/download/test/manifest.json'
        network = self.network([Response(status=302, headers={'Location': url}), Response(b'{}')], token='disposable-token')
        network.get(pull.API, 99)
        calls = network.opener.open.call_args_list
        self.assertEqual(calls[0].args[0].get_header('Authorization'), 'Bearer disposable-token')
        self.assertIsNone(calls[1].args[0].get_header('Authorization'))

    def listing(self, value=None):
        value = value or self.value
        return {'tag_name': value['release'], 'draft': False, 'prerelease': False,
                'assets': [{'name': name} for name in ('manifest.json', 'manifest.sig', value['archive'])]}

    def test_discovery_valid_empty_304_duplicates_malformed_and_stale(self):
        data, sig = self.sign()
        release = self.listing()
        for initial in (Response(json.dumps([release]).encode()), Response(status=304)):
            network = self.network([initial, Response(data), Response(sig)], {'releases': [release]})
            result = pull.discover(network, self.keys, {'sequence': 0})
            self.assertEqual(result[0], self.value)
            self.assertEqual(network.opener.open.call_count, 3)  # no archive until verified
        self.assertIsNone(pull.discover(self.network([Response(b'[]')]), self.keys, {'sequence': 0}))
        accepted = dict(sequence=7, release=self.value['release'], sha256=self.value['sha256'])
        network = self.network([Response(json.dumps([release]).encode())])
        self.assertIsNone(pull.discover(network, self.keys, accepted))
        self.assertEqual(network.opener.open.call_count, 1)
        for listing in ([{**release, 'assets': []}], [{**release, 'draft': True}], {}, [release] * 11):
            with self.assertRaises(ValueError):
                pull.discover(self.network([Response(json.dumps(listing).encode())]), self.keys, {'sequence': 0})
        with self.assertRaises(json.JSONDecodeError):
            pull.discover(self.network([Response(b'invalid')]), self.keys, {'sequence': 0})
        network = self.network([Response(json.dumps([release, release]).encode()), Response(data),
                                Response(sig), Response(data), Response(sig)])
        with self.assertRaises(ValueError):
            pull.discover(network, self.keys, {'sequence': 0})
        network = self.network([Response(json.dumps([release]).encode())])
        self.assertIsNone(pull.discover(network, self.keys, {'sequence': 8}))

    def test_out_of_order_newest_only_no_expired_fallback_or_archive_download(self):
        older = copy.deepcopy(self.value)
        older.update(sequence=6, release=f'production-6-17-{SHA}',
                     issued=int(time.time()) - 100000, expires=int(time.time()) - 13600)
        data, sig = self.sign()
        releases = [self.listing(older), self.listing()]
        network = self.network([Response(json.dumps(releases).encode()), Response(data), Response(sig)])
        self.assertEqual(pull.discover(network, self.keys, {'sequence': 0})[0], self.value)
        network = self.network([Response(json.dumps([self.listing(older)]).encode()),
                                Response(self.sign(older)[0]), Response(self.sign(older)[1])])
        with self.assertRaises(ValueError):
            pull.discover(network, self.keys, {'sequence': 0})

    def test_failed_network_persists_backoff_and_later_fetch_recovers(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            cache = directory / 'cache'
            config = directory / 'config'
            config.write_text(json.dumps({'keys': self.keys}))
            (directory / 'request.json').write_text('{"sequence":0}')
            account = unittest.mock.Mock(pw_uid=os.getuid())
            original_read = pull.safe_read
            with patch.object(pull, 'CONFIG', config), patch.object(pull, 'CACHE', cache), \
                    patch.object(pull.pwd, 'getpwnam', return_value=account), \
                    patch.object(pull, 'safe_read', side_effect=lambda p, n, root=False: original_read(p, n)), \
                    patch.object(pull.Network, 'get', side_effect=TimeoutError):
                with self.assertRaises(TimeoutError):
                    pull.fetch(directory)
                saved = json.loads(cache.read_text())
                self.assertEqual(saved['failures'], 1)
                self.assertGreaterEqual(saved['next'], int(time.time()) + 119)
            # No network during backoff; after time progresses empty discovery recovers.
            for now, expected in ((saved['next'] - 1, 0), (saved['next'] + 1, 1)):
                with patch.object(pull, 'CONFIG', config), patch.object(pull, 'CACHE', cache), \
                        patch.object(pull.pwd, 'getpwnam', return_value=account), \
                        patch.object(pull, 'safe_read', side_effect=lambda p, n, root=False: original_read(p, n)), \
                        patch.object(pull.time, 'time', return_value=now), \
                        patch.object(pull.Network, 'get', return_value=b'[]') as get:
                    pull.fetch(directory)
                    self.assertEqual(get.call_count, expected)
            self.assertEqual(json.loads(cache.read_text())['failures'], 0)
            # Unicode canonicalization must not write an unreadable oversized cache.
            cache.write_text('{"next":0,"etag":"\\\"fixture\\\""}')
            large_metadata = [{'tag_name': 'notes', 'body': '\x7f' * (pull.MAX_CACHE // 6 + 100)}]
            with patch.object(pull, 'CONFIG', config), patch.object(pull, 'CACHE', cache), \
                    patch.object(pull.pwd, 'getpwnam', return_value=account), \
                    patch.object(pull, 'safe_read', side_effect=lambda p, n, root=False: original_read(p, n)), \
                    patch.object(pull.Network, 'get', return_value=json.dumps(large_metadata, ensure_ascii=False).encode()):
                pull.fetch(directory)
            saved = json.loads(cache.read_text())
            self.assertLessEqual(cache.stat().st_size, pull.MAX_CACHE)
            self.assertNotIn('releases', saved)
            self.assertNotIn('etag', saved)

    def test_state_atomic_write_interruption_preserves_previous_record(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp) / 'state'
            pull.atomic(state, {'sequence': 8})
            before = state.read_bytes()
            with patch.object(pull.os, 'replace', side_effect=OSError), self.assertRaises(OSError):
                pull.atomic(state, {'sequence': 9})
            self.assertEqual(state.read_bytes(), before)
            state.write_bytes(b'{corrupted')
            with self.assertRaises(json.JSONDecodeError):
                json.loads(pull.safe_read(state, 8192))
        pull.validate_state({'sequence': 0, 'pending': False})
        pull.validate_state({'sequence': 7, 'pending': False,
                             'release': self.value['release'], 'sha256': self.value['sha256']})
        for state in ({}, [], {'sequence': True, 'pending': False}, {'sequence': -1, 'pending': False},
                      {'sequence': 0, 'pending': None}, {'sequence': 0, 'pending': False, 'extra': 1},
                      {'sequence': 0, 'pending': True}, {'sequence': 8, 'pending': False,
                       'release': self.value['release'], 'sha256': self.value['sha256']}):
            with self.subTest(state=state), self.assertRaises(ValueError):
                pull.validate_state(state)

    def stage(self, directory):
        data, sig = self.sign()
        (directory / 'manifest.json').write_bytes(data)
        (directory / 'manifest.sig').write_bytes(sig)
        (directory / 'archive').write_bytes(self.archive)

    def test_check_only_signature_reverification_file_races_and_no_activation(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            self.stage(directory)
            with patch.object(pull, 'atomic') as atomic, patch.object(pull, 'Popen') as run:
                pull.activate(directory, {'keys': self.keys}, {'sequence': 0}, check=True)
                atomic.assert_not_called()
                run.assert_not_called()
                (directory / 'archive').write_bytes(b'swapped')
                with self.assertRaises(ValueError):
                    pull.activate(directory, {'keys': self.keys}, {'sequence': 0}, check=True)
                (directory / 'archive').unlink()
                (directory / 'archive').symlink_to(self.private)
                with self.assertRaises(OSError):
                    pull.activate(directory, {'keys': self.keys}, {'sequence': 0}, check=True)
                fifo = directory / 'fifo'
                os.mkfifo(fifo)
                with self.assertRaises(ValueError):
                    pull.safe_read(fifo, 100)

    def test_success_failure_pending_reservation_and_atomic_state(self):
        for status in (0, 1):
            with tempfile.TemporaryDirectory() as temp:
                directory = Path(temp)
                stage = directory / 'stage'
                stage.mkdir()
                self.stage(stage)
                helper = directory / 'helper'
                helper.write_bytes(b'fixture helper')
                state = directory / 'state'
                evidence = directory / 'accepted.json'
                with patch.object(pull, 'trusted'), patch.object(pull, 'HELPER', helper), \
                        patch.object(pull, 'HELPER_SHA256', hashlib.sha256(helper.read_bytes()).hexdigest()), \
                        patch.object(pull, 'STATE', state), patch.object(pull, 'INCOMING', directory), \
                        patch.object(pull, 'EVIDENCE', evidence), \
                        patch.object(pull, 'restorecon') as label, \
                        patch.object(pull, 'secure_lock', return_value=io.StringIO()), \
                        patch.object(pull, 'Popen') as run:
                    run.return_value.wait.return_value = status
                    # Only ownership check is mocked; real signatures, freeze, fsync,
                    # atomic state and anchored staging writes are exercised.
                    original_read = pull.safe_read
                    with patch.object(pull, 'safe_read', side_effect=lambda p, n, root=False: original_read(p, n)):
                        if status:
                            with self.assertRaises(ValueError):
                                pull.activate(stage, {'keys': self.keys}, {'sequence': 0})
                        else:
                            pull.activate(stage, {'keys': self.keys}, {'sequence': 0})
                    saved = json.loads(state.read_bytes())
                    self.assertEqual(saved['sequence'], 7)
                    self.assertEqual(saved['pending'], bool(status))
                    self.assertEqual(state.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(evidence.stat().st_mode & 0o777, 0o644)
                    identity = protocol.authorization(self.value, (stage / 'manifest.json').read_bytes())
                    self.assertEqual(saved['authorization'], identity)
                    pull.validate_state(saved)
                    self.assertEqual(json.loads(evidence.read_bytes()), None if status else dict(schema=1, **identity))
                    self.assertEqual(label.call_count, 1 if status else 2)
                    self.assertEqual((directory / self.value['archive']).read_bytes(), self.archive)

    def test_nonroot_cannot_orchestrate_and_unsafe_trust_path(self):
        with patch.object(pull.os, 'geteuid', return_value=1001), self.assertRaises(ValueError):
            pull.main()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'link'
            path.symlink_to('/etc/passwd')
            with self.assertRaises(ValueError):
                pull.trusted(path)
            path.unlink()
            path.write_bytes(b'x')
            path.chmod(0o666)
            with self.assertRaises(ValueError):
                pull.safe_read(path, 10, root=True)

    def test_old_same_commit_authorization_is_invalidated_and_only_durable_success_exposes_new_proof(self):
        for outcome in ('success', 'failed-rollback', 'interrupted', 'state-commit', 'projection', 'expired'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                directory = Path(temp)
                stage = directory / 'stage'
                stage.mkdir()
                self.stage(stage)
                helper = directory / 'helper'
                helper.write_bytes(b'fixture helper')
                state_path, evidence_path = directory / 'state', directory / 'accepted.json'
                old_value = {**self.value, 'sequence': 6, 'run': 16, 'release': f'production-6-16-{SHA}'}
                old_identity = protocol.authorization(old_value, protocol.canonical(old_value))
                old_state = dict(sequence=6, release=old_value['release'], sha256=self.value['sha256'],
                                 pending=False, authorization=old_identity)
                pull.atomic(state_path, old_state)
                pull.atomic(evidence_path, dict(schema=1, **old_identity), mode=0o644)
                original_atomic, original_read = pull.atomic, pull.safe_read
                def atomic(path, value, **kwargs):
                    if path == state_path and not value['pending'] and outcome == 'state-commit':
                        raise OSError('disposable fsync failure')
                    if path == evidence_path and value is not None and outcome == 'projection':
                        raise OSError('disposable projection failure')
                    return original_atomic(path, value, **kwargs)
                def wait_status(**kwargs):
                    # Helper sees reservation durable and old same-X/Y proof gone.
                    self.assertTrue(json.loads(state_path.read_bytes())['pending'])
                    self.assertIsNone(json.loads(evidence_path.read_bytes()))
                    if outcome == 'interrupted':
                        raise KeyboardInterrupt()
                    return 1 if outcome == 'failed-rollback' else 0
                for name, value in [('trusted', lambda _: None), ('HELPER', helper),
                                    ('HELPER_SHA256', hashlib.sha256(helper.read_bytes()).hexdigest()),
                                    ('STATE', state_path), ('EVIDENCE', evidence_path), ('INCOMING', directory),
                                    ('atomic', atomic), ('restorecon', lambda _: None),
                                    ('safe_read', lambda p, n, root=False: original_read(p, n))]:
                    stack.enter_context(patch.object(pull, name, value))
                stack.enter_context(patch.object(pull, 'secure_lock', return_value=io.StringIO()))
                process = stack.enter_context(patch.object(pull, 'Popen'))
                process.return_value.wait.side_effect = wait_status
                if outcome == 'expired':
                    stack.enter_context(patch.object(pull, 'validate', side_effect=ValueError('expired')))
                if outcome == 'success':
                    pull.activate(stage, {'keys': self.keys}, old_state)
                    saved = json.loads(state_path.read_bytes())
                    self.assertFalse(saved['pending'])
                    new_identity = protocol.authorization(self.value, (stage / 'manifest.json').read_bytes())
                    self.assertEqual(saved['authorization'], new_identity)
                    self.assertEqual(json.loads(evidence_path.read_bytes()), dict(schema=1, **new_identity))
                    self.assertNotEqual(old_identity, new_identity)
                    # Cross-language boundary: feed the real root-writer bytes to
                    # the production Node reader (only UID/ancestor fixture modes
                    # simulated), then enforce the exact workflow expectation.
                    active = directory / SHA
                    (active / 'src').mkdir(parents=True)
                    source = active / 'src' / 'release-info.mjs'
                    source.write_text('// fixture')
                    current = directory / 'current'
                    current.symlink_to(active)
                    script = '''
import * as fs from 'node:fs';
import { pathToFileURL } from 'node:url';
const { acceptedAuthorization } = await import(pathToFileURL(process.argv[1]));
const filesystem = { ...fs,
  lstatSync(p) { const s = fs.lstatSync(p); s.uid = 0; s.mode &= ~0o022; return s; },
  fstatSync(fd) { const s = fs.fstatSync(fd); s.uid = 0; return s; }
};
const identity = acceptedAuthorization(JSON.parse(process.argv[2]), {
  filesystem, evidence: process.argv[3], current: process.argv[4], source: pathToFileURL(process.argv[5]).href
});
console.log(JSON.stringify(identity));
'''
                    actual = json.loads(subprocess.check_output([
                        'node', '--input-type=module', '-e', script, str(ROOT / 'backend/src/release-info.mjs'),
                        json.dumps(dict(revision=SHA, archiveSha256=self.value['sha256'])),
                        str(evidence_path), str(current), str(source)]))
                    self.assertEqual(actual, new_identity)
                    health = load('verify-pages-health')
                    health.validate_identity(actual, SHA, self.value['sha256'], '17')
                else:
                    with self.assertRaises((ValueError, OSError, KeyboardInterrupt)):
                        pull.activate(stage, {'keys': self.keys}, old_state)
                    self.assertIsNone(json.loads(evidence_path.read_bytes()))
                    saved = json.loads(state_path.read_bytes())
                    self.assertEqual(saved['sequence'], 7)  # no anti-replay reset
                    self.assertEqual(saved['pending'], outcome != 'projection')

    def test_evidence_symlink_unsafe_owner_and_label_failure_do_not_publish_success(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            evidence = directory / 'accepted.json'
            target = directory / 'target'
            target.write_text('null\n')
            evidence.symlink_to(target)
            with patch.object(pull, 'EVIDENCE', evidence), patch.object(pull, 'trusted'):
                with self.assertRaises(OSError):
                    pull.evidence({'schema': 1})
            self.assertEqual(target.read_text(), 'null\n')
            evidence.unlink()
            original_read = pull.safe_read
            with patch.object(pull, 'EVIDENCE', evidence), patch.object(pull, 'trusted'), \
                    patch.object(pull, 'restorecon', side_effect=OSError), self.assertRaises(OSError):
                pull.evidence({'schema': 1})
            self.assertFalse(evidence.exists())
            self.assertEqual(list(directory.glob('.pull-*')), [])
            # Real ownership rejection: unprivileged fixtures cannot be authoritative.
            if os.getuid() != 0:
                with self.assertRaises(ValueError):
                    original_read(target, 8192, root=True)

    def test_timer_interval_and_lock_and_installed_helper_compatibility(self):
        timer = (ROOT / 'deploy/toolbox-pull.timer').read_text()
        self.assertIn('OnCalendar=*-*-* *:*:00', timer)
        self.assertIn('OnBootSec=60s', timer)
        self.assertIn('Persistent=false', timer)
        service = (ROOT / 'deploy/toolbox-pull.service').read_text()
        self.assertIn('Type=oneshot', service)
        self.assertNotIn('[Install]', service)
        self.assertEqual(hashlib.sha256((ROOT / 'deploy/toolbox-backend-deploy.sh').read_bytes()).hexdigest(), pull.HELPER_SHA256)
        # Actual flock exclusion, not just a textual test.
        import fcntl
        with tempfile.TemporaryFile() as first, open('/proc/self/fd/' + str(first.fileno()), 'a') as second:
            fcntl.flock(first, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(second, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_secure_lock_precreation_and_helper_deadline_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            lock = directory / 'lock'
            lock.symlink_to('/etc/passwd')
            # Actual nofollow rejection (parent ownership is mocked only for nonroot test runner).
            parent = directory.stat()
            safe_parent = unittest.mock.Mock(st_mode=parent.st_mode, st_uid=0)
            with patch.object(Path, 'lstat', return_value=safe_parent), self.assertRaises(OSError):
                pull.secure_lock(lock)
            lock.unlink()
            lock.write_text('fixture')
            linked = unittest.mock.Mock(st_mode=0o100600, st_uid=0, st_nlink=2)
            with patch.object(Path, 'lstat', return_value=safe_parent), \
                    patch.object(pull.os, 'fstat', return_value=linked), self.assertRaises(ValueError):
                pull.secure_lock(lock)
            lock.unlink()
            self.stage(directory)
            helper = directory / 'helper'
            helper.write_bytes(b'fixture helper')
            state = directory / 'state'
            original_read = pull.safe_read
            with patch.object(pull, 'trusted'), patch.object(pull, 'HELPER', helper), \
                    patch.object(pull, 'HELPER_SHA256', hashlib.sha256(helper.read_bytes()).hexdigest()), \
                    patch.object(pull, 'STATE', state), patch.object(pull, 'INCOMING', directory), \
                    patch.object(pull, 'EVIDENCE', directory / 'accepted.json'), \
                    patch.object(pull, 'restorecon'), \
                    patch.object(pull, 'secure_lock', return_value=io.StringIO()), \
                    patch.object(pull, 'safe_read', side_effect=lambda p, n, root=False: original_read(p, n)), \
                    patch.object(pull, 'Popen') as run, patch.object(pull.os, 'killpg') as kill:
                run.return_value.wait.side_effect = [subprocess.TimeoutExpired('helper', 600), 1]
                with self.assertRaises(ValueError):
                    pull.activate(directory, {'keys': self.keys}, {'sequence': 0})
                self.assertTrue(json.loads(state.read_text())['pending'])
                self.assertIsNone(json.loads((directory / 'accepted.json').read_text()))
                kill.assert_called_once_with(run.return_value.pid, pull.signal.SIGTERM)
                self.assertEqual(run.return_value.wait.call_args_list[-1].kwargs['timeout'], 240)
                self.assertTrue(run.call_args.kwargs['start_new_session'])

    def test_pages_wait_success_timeout_and_no_credential_delivery(self):
        environment = dict(GITHUB_SHA=SHA, GITHUB_RUN_NUMBER='7', GITHUB_RUN_ID='17',
                           EXPECTED_AUTHORIZATION_SEQUENCE='7', EXPECTED_RELEASE_ID=self.value['release'],
                           EXPECTED_BACKEND_DIGEST=self.value['sha256'], EXPECTED_MANIFEST_SHA256='c' * 64,
                           EXPECTED_SIGNING_KEY_ID='test-key')
        with patch.dict(os.environ, environment):
            self.check_wait()
        with patch.dict(os.environ, {**environment, 'EXPECTED_AUTHORIZATION_SEQUENCE': '6'}):
            run = unittest.mock.Mock()
            with self.assertRaises(ValueError):
                wait.wait(run=run)
            run.assert_not_called()

    def check_wait(self):
        run = unittest.mock.Mock(side_effect=[subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)])
        sleep = unittest.mock.Mock()
        wait.wait(run=run, sleep=sleep)
        self.assertEqual(run.call_count, 2)
        sleep.assert_called_once_with(50)
        run = unittest.mock.Mock(return_value=subprocess.CompletedProcess([], 1))
        with self.assertRaises(ValueError):
            wait.wait(run=run, sleep=lambda _: None)
        self.assertEqual(run.call_count, 30)


if __name__ == '__main__':
    unittest.main()
