"""Unprivileged, offline tests. Never execute the installed/root-path script.

Only a disposable COPY has fixed literals substituted. Command doubles have no
network/systemd/root access; the production executable has no test overrides.
"""
import hashlib
import io
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'deploy/toolbox-backend-deploy.sh'
SHA = 'a' * 40
LEGACY = 'legacy-20261014T120000Z'
REQUIRED = [('package.json', b'{"name":"fixture"}'),
            ('package-lock.json', b'{"lockfileVersion":3}'),
            ('src/server.mjs', b'// disposable backend fixture\n')]

# Installed only in each temporary fixture's bin directory.
DOUBLE = r'''#!/usr/bin/python3
import json, os, pathlib, signal, subprocess, sys
command = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
app = root / 'app'
scenario = os.environ.get('SCENARIO', '')
active = (app / 'current').resolve().name
def event(text):
    with (root / 'events').open('a') as log: log.write(text + '\n')
def interrupt(point):
    for sig in ('TERM', 'HUP', 'INT', 'KILL'):
        if scenario == point + '_' + sig:
            os.kill(os.getppid(), getattr(signal, 'SIG' + sig))
if command == 'systemctl':
    if args[0] == 'show':
        prop = args[args.index('-p') + 1]
        print({'User':'toolboxapi', 'Group':'toolboxapi',
               'WorkingDirectory':str(app / 'current'),
               'ExecStart':str(app / 'current/src/server.mjs'),
               'EnvironmentFiles':str(root / 'toolbox-api.env')}[prop])
    elif args[0] == 'restart':
        event('restart:' + active)
        # timeout is also a double, so parent is the shell being tested.
        interrupt('restart')
        if (scenario in ('restart_fail', 'rollback_restart_fail') and active == 'a'*40
                or scenario == 'rollback_restart_fail' and active.startswith('legacy-')):
            sys.exit(1)
    elif args[0] == 'is-active':
        if scenario == 'inactive' and active == 'a'*40: sys.exit(1)
    else: sys.exit('Unexpected systemctl operation')
elif command == 'curl':
    event('health:' + active)
    if (scenario in ('health_fail', 'rollback_health_fail', 'rollback_switch_fail',
                     'second_TERM', 'unexpected_current') and active == 'a'*40
            or scenario == 'rollback_health_fail' and active.startswith('legacy-')):
        sys.exit(22)
    if scenario == 'bad_json' and active == 'a'*40:
        print('{"status":"ok","service":"other"}')
    else: print('{"status":"ok","service":"toolbox-api"}')
elif command == 'stat':
    # UID ownership alone is virtualized; mode/path checks use real fixture files.
    print('root')
elif command == 'find':
    if scenario == 'find_fail': sys.exit(1)
    if '! -user root' in ' '.join(args): sys.exit(0)
    sys.exit(subprocess.call(['/usr/bin/find', *args]))
elif command == 'chown': pass
elif command == 'npm':
    # Discovery only: runuser simulates installation without running npm.
    sys.exit('Unexpected npm execution in offline deployment fixture')
elif command == 'runuser':
    event('install')
    if args[:5] != ['-u', 'toolboxdeploy', '--', 'env', '-i']:
        sys.exit('Dependency environment was not cleared')
    try: os.fstat(9)
    except OSError: pass
    else: sys.exit('Dependency process inherited deployment lock')
    if scenario == 'staging_TERM':
        interrupt('staging')
    build = pathlib.Path(args[-1])
    (build / 'node_modules').mkdir()
    (build / 'node_modules/fixture.js').write_text('// fixture dependency')
    if scenario == 'dependency_external_link':
        (build / 'node_modules/escape.js').symlink_to(root / 'toolbox-api.env')
    if scenario == 'dependency_internal_link':
        (build / 'node_modules/alias.js').symlink_to('fixture.js')
elif command == 'mv':
    destination = pathlib.Path(args[-1])
    if destination == app / 'current' and '.current-next-' in args[-2]:
        if scenario.startswith('before_'):
            interrupt('before')
            sys.exit(1)
        if scenario == 'switch_fail': sys.exit(1)
    if destination == app / 'current' and '.current-rollback-' in args[-2]:
        if scenario == 'rollback_switch_fail': sys.exit(1)
    code = subprocess.call(['/usr/bin/mv', *args])
    if destination == app / 'current' and '.current-next-' in args[-2]:
        # Interrupt immediately after rename, BEFORE Bash can update any state.
        interrupt('after')
        if scenario == 'unexpected_current':
            destination.unlink()
            destination.symlink_to('releases/legacy-20261014T130000Z')
    if destination == app / 'current' and '.current-rollback-' in args[-2]:
        if scenario == 'second_TERM': os.kill(os.getppid(), signal.SIGTERM)
    sys.exit(code)
elif command == 'timeout':
    # Preserve shell parent for deterministic signal injection. No long work.
    os.execv(str(root / 'bin/systemctl'), ['systemctl', *args[3:]])
elif command == 'logger':
    with (root / 'diagnostics').open('a') as log: log.write(args[-1] + '\n')
elif command in ('sleep', 'restorecon'): pass
else: sys.exit('Unexpected command double: ' + command)
'''


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        # Discover the host toolchain before the disposable script restricts PATH.
        node = shutil.which('node')
        self.assertIsNotNone(node, 'Node.js executable not found on host PATH')
        self.node = Path(node).resolve(strict=True)
        self.assertTrue(self.node.is_file() and os.access(self.node, os.X_OK), str(self.node))
        self.addCleanup(os.umask, os.umask(0o022))
        self.temp = tempfile.TemporaryDirectory(prefix='toolbox-deploy-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / 'app'
        self.releases = self.app / 'releases'
        self.previous = self.releases / LEGACY
        self.previous.mkdir(parents=True)
        for directory in (self.app, self.releases, self.previous):
            directory.chmod(0o755)
        (self.previous / 'known-good').write_text('unchanged')
        (self.app / 'current').symlink_to('releases/' + LEGACY)
        self.incoming = self.root / 'incoming'
        self.incoming.mkdir()
        (self.root / 'toolbox-api.env').write_text('DISPOSABLE_FIXTURE=1\n')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for command in ('systemctl', 'curl', 'stat', 'find', 'chown', 'runuser',
                        'mv', 'timeout', 'sleep', 'restorecon', 'logger', 'npm'):
            path = self.bin / command
            path.write_text(DOUBLE)
            path.chmod(0o755)
        # No host PATH fallback: only these utilities intentionally run for real.
        (self.bin / 'node').symlink_to(self.node)
        for command in ('flock', 'python3', 'sha256sum', 'cp', 'rm',
                        'mktemp', 'chmod', 'readlink', 'ln', 'cut', 'cat', 'true'):
            target = Path('/usr/bin') / command
            self.assertTrue(target.is_file() and os.access(target, os.X_OK), str(target))
            (self.bin / command).symlink_to(target)
        source = SCRIPT.read_text()
        # Keep the installed script's fixed Node requirement; adapt only this copy.
        self.assertEqual(source.count('/usr/bin/node'), 4)
        replacements = {
            '/usr/bin/node': str(self.bin / 'node'),
            'app_root=/opt/toolbox-api': 'app_root=' + str(self.app),
            'incoming=/var/lib/toolbox-deploy/incoming': 'incoming=' + str(self.incoming),
            '/run/lock/toolbox-backend-deploy.lock': str(self.root / 'deploy.lock'),
            '/etc/toolbox-api.env': str(self.root / 'toolbox-api.env'),
            'export PATH=/usr/sbin:/usr/bin:/sbin:/bin':
                'export PATH=' + str(self.bin),
            '[[ "$EUID" -eq 0 ]]': '[[ "1" -eq 1 ]]',
        }
        for old, new in replacements.items():
            self.assertIn(old, source)
            source = source.replace(old, new)
        self.assertNotIn('/usr/bin/node', source)
        self.assertEqual(source.count(str(self.bin / 'node')), 4)
        self.script = self.root / 'deploy-copy.sh'
        self.script.write_text(source)
        self.archive()

    def archive(self, members=None):
        self.upload = self.incoming / ('backend-' + SHA + '.tar.gz')
        with tarfile.open(self.upload, 'w:gz', format=tarfile.PAX_FORMAT) as tar:
            for item in REQUIRED if members is None else members:
                if isinstance(item, tarfile.TarInfo):
                    tar.addfile(item)
                else:
                    name, contents = item
                    info = tarfile.TarInfo(name)
                    info.size = len(contents)
                    tar.addfile(info, io.BytesIO(contents))
        self.digest = hashlib.sha256(self.upload.read_bytes()).hexdigest()

    def run_deploy(self, scenario='', sha=SHA, digest=None):
        result = subprocess.run(['bash', str(self.script), sha, digest or self.digest],
                                env={**os.environ, 'FIXTURE_ROOT': str(self.root),
                                     'SCENARIO': scenario}, capture_output=True,
                                text=True, timeout=20)
        self.output = result.stdout + result.stderr
        self.assertEqual((self.previous / 'known-good').read_text(), 'unchanged')
        self.assertEqual((self.root / 'toolbox-api.env').read_text(), 'DISPOSABLE_FIXTURE=1\n')
        return result

    def events(self):
        path = self.root / 'events'
        return path.read_text().splitlines() if path.exists() else []

    def assert_failed_unactivated(self, result):
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertEqual((self.app / 'current').resolve(), self.previous)
        self.assertNotIn('DEPLOYED:', self.output)
        self.assertFalse(any(x.startswith('restart:') for x in self.events()))
        self.assertEqual(list(self.releases.glob('.staging-*')), [])
        self.assertEqual(list(self.releases.glob('.archive-*')), [])

    def assert_rollback(self, scenario, status=1):
        result = self.run_deploy(scenario)
        self.assertEqual(result.returncode, status, self.output)
        self.assertEqual((self.app / 'current').resolve(), self.previous)
        self.assertIn('ROLLBACK SUCCEEDED', self.output)
        self.assertIn('restart:' + LEGACY, self.events())
        self.assertIn('health:' + LEGACY, self.events())
        self.assertNotIn('DEPLOYED:', self.output)
        self.assertTrue((self.releases / SHA).is_dir())
        self.assertFalse((self.app / '.deployment-transaction').exists())

    def test_valid_commit_success(self):
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, self.output)
        self.assertEqual((self.app / 'current').resolve(), self.releases / SHA)
        self.assertIn('DEPLOYED: ' + SHA, self.output)
        self.assertEqual(self.events(), ['install', 'restart:' + SHA, 'health:' + SHA])
        self.assertFalse((self.app / '.deployment-transaction').exists())
        self.assertEqual(list(self.releases.glob('.*')), [])

    def test_node_from_external_toolchain(self):
        toolchain = self.root / 'external-toolchain'
        toolchain.mkdir()
        node = toolchain / 'node'
        shutil.copy2(self.node, node)
        original = SCRIPT.read_bytes()
        # A real executable outside /usr/bin must win host discovery, without
        # leaking the toolchain (or the rest of the host PATH) into the fixture.
        fixture = DeploymentTests('test_valid_commit_success')
        self.addCleanup(fixture.doCleanups)
        with mock.patch.dict(os.environ, {'PATH': str(toolchain) + os.pathsep + os.environ['PATH']}):
            fixture.setUp()
            self.assertEqual((fixture.bin / 'node').readlink(), node)
            self.assertIn('export PATH=' + str(fixture.bin) + '\n', fixture.script.read_text())
            self.assertNotIn('/usr/bin/node', fixture.script.read_text())
            fixture.test_valid_commit_success()
        self.assertEqual(SCRIPT.read_bytes(), original)

    def test_missing_npm_dependency_is_rejected(self):
        (self.bin / 'npm').unlink()
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('ERROR: Missing dependency: npm', self.output)
        self.assertEqual(self.events(), [])

    def test_npm_double_fails_closed_if_executed(self):
        result = subprocess.run([str(self.bin / 'npm'), 'ci'],
                                env={'PATH': str(self.bin), 'FIXTURE_ROOT': str(self.root)},
                                capture_output=True, text=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Unexpected npm execution', result.stderr)
        self.assertEqual(self.events(), [])
        self.assertFalse((self.previous / 'node_modules').exists())

    def test_invalid_commit_identifiers(self):
        for sha in ('', 'a'*39, 'a'*41, 'A'*40, '../' + SHA, '$(id)', 'a'*39 + 'g'):
            with self.subTest(sha=sha):
                self.assert_failed_unactivated(self.run_deploy(sha=sha))

    def test_invalid_digests(self):
        for digest in ('x', 'a'*63, 'A'*64, '0'*64, '../digest'):
            with self.subTest(digest=digest):
                self.assert_failed_unactivated(self.run_deploy(digest=digest))

    def test_malicious_member_names(self):
        for name in ('../escape', '/etc/escape', 'src/../../escape', 'src//bad',
                     'src/./bad', 'src\\bad', 'unexpected', '.env', 'src/.', 'src/bad\nname'):
            with self.subTest(name=name):
                self.archive(REQUIRED + [(name, b'bad')])
                self.assert_failed_unactivated(self.run_deploy())

    def test_malicious_member_types(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.CONTTYPE):
            with self.subTest(kind=kind):
                member = tarfile.TarInfo('src/bad')
                member.type = kind
                member.linkname = '/etc/secret'
                self.archive(REQUIRED + [member])
                self.assert_failed_unactivated(self.run_deploy())

    def test_oversized_uncompressed_archive(self):
        self.archive(REQUIRED + [('src/large.mjs', b'0' * (64 * 1024 * 1024))])
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Archive is too large', self.output)

    def test_oversized_compressed_upload(self):
        with self.upload.open('wb') as archive:
            archive.truncate(16 * 1024 * 1024 + 1)
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Compressed archive is too large', self.output)

    def test_oversized_tar_metadata_stream(self):
        import gzip
        with gzip.open(self.upload, 'wb') as archive:
            for _ in range(67):
                archive.write(b'\0' * (1024 * 1024))
        self.digest = hashlib.sha256(self.upload.read_bytes()).hexdigest()
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Expanded tar stream is too large', self.output)

    def test_too_many_members(self):
        self.archive(REQUIRED + [('src/file' + str(i), b'') for i in range(510)])
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Too many files', self.output)

    def test_duplicate_members(self):
        self.archive(REQUIRED + [REQUIRED[0]])
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Duplicate archive member', self.output)

    def test_sparse_member_rejected(self):
        member = tarfile.TarInfo('src/sparse')
        member.pax_headers = {'GNU.sparse.size': '100000000', 'GNU.sparse.map': ''}
        self.archive(REQUIRED + [member])
        self.assert_failed_unactivated(self.run_deploy())

    def test_manifest_directory_rejected(self):
        member = tarfile.TarInfo('package.json')
        member.type = tarfile.DIRTYPE
        self.archive([member, *REQUIRED[1:]])
        self.assert_failed_unactivated(self.run_deploy())
        self.assertIn('Unexpected archive member shape', self.output)

    def test_missing_required_files(self):
        for index in range(3):
            with self.subTest(missing=REQUIRED[index][0]):
                self.archive([item for i, item in enumerate(REQUIRED) if i != index])
                self.assert_failed_unactivated(self.run_deploy())
                self.assertIn('Required backend files missing', self.output)

    def test_truncated_archive(self):
        self.upload.write_bytes(b'not gzip')
        self.digest = hashlib.sha256(self.upload.read_bytes()).hexdigest()
        self.assert_failed_unactivated(self.run_deploy())

    def test_upload_symlink_rejected(self):
        self.upload.unlink()
        self.upload.symlink_to(self.previous / 'known-good')
        self.assert_failed_unactivated(self.run_deploy())

    def test_existing_release_same_digest(self):
        self.assertEqual(self.run_deploy().returncode, 0, self.output)
        (self.app / 'current').unlink()
        (self.app / 'current').symlink_to('releases/' + LEGACY)
        result = self.run_deploy()
        self.assertEqual(result.returncode, 0, self.output)
        self.assertIn('Reusing', self.output)
        self.assertEqual(self.events().count('install'), 1)

    def test_existing_release_wrong_or_missing_digest(self):
        release = self.releases / SHA
        release.mkdir()
        self.assert_failed_unactivated(self.run_deploy())
        (release / '.archive-sha256').write_text('0'*64)
        self.assert_failed_unactivated(self.run_deploy())

    def test_existing_release_marker_symlink(self):
        release = self.releases / SHA
        release.mkdir()
        (release / '.archive-sha256').symlink_to(self.previous / 'known-good')
        self.assert_failed_unactivated(self.run_deploy())

    def test_permission_inspection_failure_is_closed(self):
        self.assert_failed_unactivated(self.run_deploy('find_fail'))

    def test_dependency_links_cannot_escape_immutable_release(self):
        self.assert_failed_unactivated(self.run_deploy('dependency_external_link'))
        self.assertIn('Dependency tree is not self-contained', self.output)

    def test_dependency_internal_links_are_supported(self):
        result = self.run_deploy('dependency_internal_link')
        self.assertEqual(result.returncode, 0, self.output)
        self.assertTrue((self.releases / SHA / 'node_modules/alias.js').is_symlink())

    def test_existing_release_symlink(self):
        (self.releases / SHA).symlink_to(self.previous)
        self.assert_failed_unactivated(self.run_deploy())

    def test_existing_release_writable(self):
        release = self.releases / SHA
        release.mkdir(mode=0o777)
        release.chmod(0o777)
        (release / '.archive-sha256').write_text(self.digest)
        self.assert_failed_unactivated(self.run_deploy())

    def test_already_deployed_requires_health(self):
        self.assertEqual(self.run_deploy().returncode, 0, self.output)
        result = self.run_deploy('health_fail')
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertNotIn('Already deployed', self.output)
        self.assertEqual(self.events().count('restart:' + SHA), 1)

    def test_interrupted_staging(self):
        self.assert_failed_unactivated(self.run_deploy('staging_TERM'))
        self.assertEqual(list(self.releases.glob('.npm-*')), [])

    def test_interrupted_before_switch(self):
        self.assert_rollback('before_TERM', 143)

    def test_interrupted_restart(self):
        self.assert_rollback('restart_TERM', 143)

    def test_repeated_signal_during_rollback_is_ignored(self):
        self.assert_rollback('second_TERM')

    def test_interrupted_after_switch_all_catchable_signals(self):
        for sig, status in (('TERM', 143), ('HUP', 129), ('INT', 130)):
            with self.subTest(signal=sig):
                self.assert_rollback('after_' + sig, status)

    def test_disconnected_ssh_output_does_not_prevent_rollback(self):
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            result = subprocess.run(['bash', str(self.script), SHA, self.digest],
                                    env={**os.environ, 'FIXTURE_ROOT': str(self.root),
                                         'SCENARIO': 'after_HUP'}, stdout=write_fd,
                                    stderr=write_fd, timeout=20)
        finally:
            os.close(write_fd)
        self.assertEqual(result.returncode, 129)
        self.assertEqual((self.app / 'current').resolve(), self.previous)
        self.assertIn('restart:' + LEGACY, self.events())
        self.assertIn('health:' + LEGACY, self.events())
        self.assertFalse((self.app / '.deployment-transaction').exists())
        self.assertIn('ROLLBACK SUCCEEDED', (self.root / 'diagnostics').read_text())

    def test_failed_switch(self):
        self.assert_rollback('switch_fail')

    def test_failed_restart_successful_rollback(self):
        self.assert_rollback('restart_fail')

    def test_failed_health_successful_rollback(self):
        self.assert_rollback('health_fail')

    def test_wrong_health_json(self):
        self.assert_rollback('bad_json')

    def test_inactive_service(self):
        self.assert_rollback('inactive')

    def test_failed_rollback_restart(self):
        result = self.run_deploy('rollback_restart_fail')
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertIn('CRITICAL: Rollback failed', self.output)
        self.assertTrue((self.app / '.deployment-transaction').exists())
        self.assertTrue((self.releases / SHA).is_dir())
        self.assertEqual((self.app / 'current').resolve(), self.previous)

    def test_failed_rollback_health(self):
        result = self.run_deploy('rollback_health_fail')
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertIn('CRITICAL: Rollback failed', self.output)
        self.assertTrue((self.app / '.deployment-transaction').exists())

    def test_retry_recovers_failed_rollback_and_stays_nonzero(self):
        self.assertNotEqual(self.run_deploy('rollback_health_fail').returncode, 0)
        self.assert_rollback('')
        self.assertEqual(self.events().count('install'), 1)

    def test_failed_rollback_switch(self):
        result = self.run_deploy('rollback_switch_fail')
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertIn('CRITICAL: Rollback failed', self.output)
        self.assertEqual((self.app / 'current').resolve(), self.releases / SHA)
        self.assertTrue((self.app / '.deployment-transaction').exists())
        self.assertEqual(list(self.app.glob('.current-rollback-*')), [])

    def test_unexpected_current_target_not_overwritten(self):
        unexpected = self.releases / 'legacy-20261014T130000Z'
        unexpected.mkdir()
        result = self.run_deploy('unexpected_current')
        self.assertNotEqual(result.returncode, 0, self.output)
        self.assertIn('CRITICAL: Rollback failed', self.output)
        self.assertEqual((self.app / 'current').resolve(), unexpected)
        self.assertTrue((self.app / '.deployment-transaction').exists())

    def test_malformed_transaction_rejected(self):
        (self.app / '.deployment-transaction').write_text('/etc\n/escape\n')
        self.assert_failed_unactivated(self.run_deploy())
        self.assertTrue((self.app / '.deployment-transaction').exists())

    def test_uncatchable_interruption_recovered_next_invocation(self):
        result = self.run_deploy('after_KILL')
        self.assertEqual(result.returncode, -signal.SIGKILL, self.output)
        self.assertEqual((self.app / 'current').resolve(), self.releases / SHA)
        self.assertTrue((self.app / '.deployment-transaction').exists())
        self.assert_rollback('')

    def test_lock_remains_held_through_rollback(self):
        # Use a nonblocking probe inside restart commands. A second real flock
        # on the same fixture path must fail, including during rollback.
        double = DOUBLE.replace("event('restart:' + active)",
            "event('restart:' + active)\n"
            "        probe = subprocess.run(['/usr/bin/flock', '-n', str(root / 'deploy.lock'), 'true'])\n"
            "        if probe.returncode == 0: sys.exit('Lock was released during restart')")
        (self.bin / 'systemctl').write_text(double)
        self.assert_rollback('health_fail')

    def test_conflicting_deployment_lock(self):
        import fcntl
        with (self.root / 'deploy.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assert_failed_unactivated(self.run_deploy())
            self.assertIn('Another deployment is running', self.output)


class PackagingTests(unittest.TestCase):
    def test_exact_committed_source_and_tar_compatibility(self):
        workflow = (ROOT / '.github/workflows/backend-production.yml').read_text()
        start = workflow.index('          git -C "$GITHUB_WORKSPACE" archive --format=tar ')
        end = workflow.index('\n          cd "$RUNNER_TEMP"', start)
        command = '\n'.join(line[10:] for line in workflow[start:end].splitlines())
        with tempfile.TemporaryDirectory(prefix='toolbox-archive-test-') as directory:
            root = Path(directory)
            # Use existing commit objects in a LOCAL disposable checkout. No new
            # commits, project index changes, remote fetches or network access.
            sha = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
            subprocess.run(['git', 'clone', '--quiet', '--shared', '--no-checkout',
                            str(ROOT), str(root)], check=True)
            subprocess.run(['git', '-C', str(root), 'checkout', '--quiet', '--detach', sha], check=True)
            backend = root / 'backend'
            original = (backend / 'src/server.mjs').read_bytes()
            members = subprocess.check_output(['git', '-C', str(root), 'ls-tree', '-r', '--name-only',
                                               sha + ':backend', 'package.json', 'package-lock.json', 'src'],
                                              text=True).splitlines()
            expected = set(members)
            for member in members:
                expected.update(str(parent) for parent in Path(member).parents if str(parent) != '.')
            (backend / 'src/server.mjs').write_text('// modified by tests; must not ship')
            (backend / 'src/untracked.mjs').write_text('// must not ship')
            (backend / '.env').write_text('DISPOSABLE_FIXTURE=1')
            subprocess.run(['bash', '-Eeuo', 'pipefail', '-c', command], cwd=backend,
                           env={**os.environ, 'GITHUB_SHA': sha, 'RUNNER_TEMP': str(root),
                                'GITHUB_WORKSPACE': str(root)}, check=True)
            archive = root / ('backend-' + sha + '.tar.gz')
            original_archive = archive.read_bytes()
            # A retry must identify the same immutable release, not a tarball
            # whose timestamps depend on when this job happens to run.
            subprocess.run(['bash', '-Eeuo', 'pipefail', '-c', command], cwd=backend,
                           env={**os.environ, 'GITHUB_SHA': sha, 'RUNNER_TEMP': str(root),
                                'GITHUB_WORKSPACE': str(root)}, check=True)
            self.assertEqual(archive.read_bytes(), original_archive)
            commit_time = int(subprocess.check_output(['git', '-C', str(root), 'show', '-s',
                              '--format=%ct', sha], text=True).strip())
            with tarfile.open(archive, 'r:gz') as tar:
                self.assertEqual(set(tar.getnames()), expected)
                self.assertTrue(all(member.mtime == commit_time for member in tar.getmembers()))
                self.assertEqual(tar.extractfile('src/server.mjs').read(), original)
            # Execute the exact embedded validator against git archive output.
            source = SCRIPT.read_text()
            validator = source.split('python3 -I - "$private_archive" "$staging" <<\'PY\'\n')[1].split('\nPY')[0]
            staging = root / 'validated'
            staging.mkdir()
            subprocess.run(['python3', '-c', validator, str(archive), str(staging)], check=True)
            self.assertEqual((staging / 'src/server.mjs').read_bytes(), original)

    def test_workflow_security_and_enablement_guards(self):
        workflow = (ROOT / '.github/workflows/backend-production.yml').read_text()
        self.assertIn('workflow_dispatch:', workflow)
        self.assertNotIn('  push:', workflow)
        self.assertNotIn('pull_request', workflow)
        self.assertIn("github.repository == 'ALEXRUZI/BAZMEG.TECH-IT-Toolbox'", workflow)
        self.assertEqual(workflow.count("vars.TOOLBOX_PRODUCTION_ENABLED == 'true'"), 4)
        self.assertEqual(workflow.count("github.ref == 'refs/heads/main'"), 4)
        self.assertNotIn('scp ', workflow)
        self.assertNotIn('ssh ', workflow)
        self.assertIn('cancel-in-progress: false', workflow)
        self.assertNotIn('self-hosted', workflow)
        self.assertIn('environment: production', workflow)
        self.assertIn('needs: checks', workflow)
        self.assertIn('uses: ./.github/workflows/deploy.yml', workflow)
        self.assertIn('PRODUCTION_RELEASE_SIGNING_KEY', workflow)
        self.assertNotIn('secrets.TOOLBOX_DEPLOY_', workflow)
        self.assertNotIn('BACKEND_SECRET', workflow)
        self.assertIn('verify-publication.py', workflow)
        self.assertIn('verify-production.py', workflow)
        self.assertIn('inputs.approved_sha == github.sha', workflow)
        self.assertIn('needs: [accept-backend, build-frontend]', workflow)

    def test_migration_guard_precedes_link(self):
        doc = (ROOT / 'deploy/PRODUCTION-BACKEND.md').read_text()
        self.assertLess(doc.index('if [[ -e "$APP/current" || -L "$APP/current" ]]'),
                        doc.index('ln -sT "releases/$LEGACY" "$APP/current"'))
        # The documented native predicate rejects every existing path type.
        with tempfile.TemporaryDirectory(prefix='toolbox-migration-test-') as directory:
            root = Path(directory)
            for kind in ('directory', 'file', 'symlink', 'dangling'):
                path = root / kind
                if kind == 'directory': path.mkdir()
                elif kind == 'file': path.touch()
                elif kind == 'symlink': path.symlink_to(root / 'file')
                else: path.symlink_to(root / 'absent')
                result = subprocess.run(['bash', '-c', '[[ -e "$1" || -L "$1" ]]', 'sh', str(path)])
                self.assertEqual(result.returncode, 0)


if __name__ == '__main__':
    unittest.main()
