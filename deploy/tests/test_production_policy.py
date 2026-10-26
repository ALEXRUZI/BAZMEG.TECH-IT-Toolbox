"""Offline owner approval, Pages artifact and Cloudflare contract regressions."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import hashlib
import io
import subprocess
import os
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f'deploy/{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


gate = module('verify-production')
artifact = module('pages-artifact')
cloudflare = module('verify-cloudflare')
health = module('verify-pages-health')
SHA = 'a' * 40
IDENTITY = dict(release=f'production-7-17-{SHA}', sequence='7', commit=SHA,
                archiveSha256='b' * 64, manifestSha256='c' * 64, keyId='test-key')


class ProductionPolicyTests(unittest.TestCase):
    def test_owner_dispatch_can_self_approve_and_all_drift_fails_closed(self):
        environment = {'can_admins_bypass': False, 'protection_rules': [{'type': 'required_reviewers',
            'prevent_self_review': False, 'reviewers': [
                {'type': 'User', 'reviewer': {'login': 'ALEXRUZI'}}]}],
            'deployment_branch_policy': {'protected_branches': False, 'custom_branch_policies': True}}
        branches = {'total_count': 1, 'branch_policies': [{'name': 'main', 'type': 'branch'}]}
        context = {'GITHUB_REPOSITORY': gate.REPOSITORY, 'GITHUB_REF': 'refs/heads/main',
            'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_ACTOR': 'ALEXRUZI',
            'GITHUB_TRIGGERING_ACTOR': 'ALEXRUZI', 'GITHUB_SHA': SHA, 'APPROVED_SHA': SHA,
            'GITHUB_RUN_ATTEMPT': '1'}
        main = {'object': {'sha': SHA}}
        gate.verify(environment, branches, main, context)
        mutations = [
            lambda e, b, m, c: e.clear(),
            lambda e, b, m, c: e.pop('can_admins_bypass'),
            lambda e, b, m, c: e['protection_rules'].append({'type': 'custom_deployment_protection_rule'}),
            lambda e, b, m, c: e['protection_rules'][0].update(prevent_self_review=True),
            lambda e, b, m, c: e['protection_rules'][0].pop('prevent_self_review'),
            lambda e, b, m, c: e['protection_rules'][0].update(reviewers=[]),
            lambda e, b, m, c: e['protection_rules'][0]['reviewers'].append({'type': 'User'}),
            lambda e, b, m, c: e['protection_rules'][0]['reviewers'][0].update(type='Team'),
            lambda e, b, m, c: e['protection_rules'][0]['reviewers'][0]['reviewer'].update(login='other'),
            lambda e, b, m, c: e.update(deployment_branch_policy=None),
            lambda e, b, m, c: b['branch_policies'][0].update(name='*'),
            lambda e, b, m, c: b['branch_policies'][0].update(type='tag'),
            lambda e, b, m, c: b.update(total_count=2),
            lambda e, b, m, c: b.update(branch_policies=[]),
            lambda e, b, m, c: m['object'].update(sha='b' * 40),
        ]
        for value in (True, None, 0, 1, 'false', '', [], {}):
            mutations.append(lambda e, b, m, c, v=value: e.update(can_admins_bypass=v))
        for key, value in (('GITHUB_REPOSITORY', gate.REPOSITORY + '-dev'),
                ('GITHUB_REF', 'refs/tags/main'), ('GITHUB_EVENT_NAME', 'push'),
                ('GITHUB_ACTOR', 'other'), ('GITHUB_TRIGGERING_ACTOR', 'other'),
                 ('APPROVED_SHA', 'b' * 40), ('GITHUB_SHA', 'main'), ('GITHUB_RUN_ATTEMPT', '2')):
            mutations.append(lambda e, b, m, c, k=key, v=value: c.update({k: v}))
        for number, mutation in enumerate(mutations):
            values = copy.deepcopy((environment, branches, main, context))
            mutation(*values)
            with self.subTest(number=number), self.assertRaises(ValueError):
                gate.verify(*values)

    def test_workflow_secret_boundaries_and_backend_first_order(self):
        text = (ROOT / '.github/workflows/backend-production.yml').read_text()
        build, deployment = text.split('\n  publish-backend:\n', 1)
        backend, frontend = deployment.split('\n  deploy-frontend:\n', 1)
        self.assertNotIn('secrets.', build)
        self.assertNotIn('CLOUDFLARE_API_TOKEN', backend)
        self.assertNotIn('PRODUCTION_BACKEND_SSH_KEY', frontend)
        self.assertNotIn('npm ', backend)
        self.assertIn('needs: [validate-package, build-frontend]', backend)
        self.assertIn('wait-backend.py', backend)
        self.assertIn('needs: [accept-backend, build-frontend]', frontend)
        self.assertEqual(text.count('environment: production'), 2)
        self.assertIn('environment: production-pages', frontend)
        self.assertIn('--environment production-pages', frontend)
        self.assertIn('--environment production\n', backend)
        self.assertEqual(text.count('deploy/verify-production.py'), 5)
        self.assertIn('github.run_attempt == 1', build)
        self.assertIn('npm ci --ignore-scripts --prefix deploy/pages', frontend)
        self.assertIn('needs: authorize', build)
        self.assertIn('before requesting environment review', build)
        self.assertIn('--outdir frontend/dist/_worker.js', build)
        self.assertIn('--branch main --commit-hash "$GITHUB_SHA"', frontend)
        self.assertIn('--no-bundle', frontend)
        upload = frontend.split('- name: Deploy only verified assets')[1]
        self.assertIn('PRODUCTION_PAGES_URL: ${{ vars.PRODUCTION_PAGES_URL }}', upload)
        self.assertIn('EXPECTED_BACKEND_DIGEST: ${{ needs.accept-backend.outputs.digest }}', upload)
        self.assertLess(upload.index('python3 -I deploy/verify-pages-health.py'),
                        upload.index('"$tool" pages deploy'))
        self.assertIn('cd "$RUNNER_TEMP/toolbox-pages"', frontend)
        self.assertIn('artifact-ids: ${{ needs.validate-package.outputs.artifact_id }}', backend)
        self.assertIn('artifact-ids: ${{ needs.build-frontend.outputs.artifact_id }}', frontend)
        self.assertEqual(build.count('${{ github.run_id }}-${{ github.run_attempt }}'), 2)
        self.assertNotIn('overwrite: true', text)
        self.assertNotIn('secrets: inherit', text)
        self.assertNotIn('self-hosted', text)
        self.assertNotIn('  push:', text)

    def test_artifact_exact_bytes_sha_paths_and_recovery(self):
        with tempfile.TemporaryDirectory(prefix='toolbox-pages-artifact-') as temporary:
            root = Path(temporary)
            (root / 'index.html').write_text('<html>disposable</html>')
            (root / '_worker.js').mkdir()
            (root / '_worker.js/index.js').write_text('export default {};')
            (root / '_routes.json').write_text(json.dumps({'version': 1, 'include': ['/api/*'], 'exclude': []}))
            artifact.process('seal', root, SHA)
            for scenario in ('sha', 'extra', 'edit', 'missing', 'config', 'symlink', 'routes'):
                marker = (root / artifact.MARKER).read_bytes()
                original = (root / '_worker.js/index.js').read_bytes()
                routes = (root / '_routes.json').read_bytes()
                candidate = root / 'extra.js'
                if scenario == 'extra': candidate.write_text('// extra')
                elif scenario == 'edit': (root / '_worker.js/index.js').write_text('// tamper')
                elif scenario == 'missing': (root / '_worker.js/index.js').unlink()
                elif scenario == 'config': candidate = root / '.env'; candidate.write_text('disposable')
                elif scenario == 'symlink': candidate.symlink_to('/etc/passwd')
                elif scenario == 'routes': (root / '_routes.json').write_text('{}')
                with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                    artifact.process('verify', root, 'b' * 40 if scenario == 'sha' else SHA)
                if candidate.exists() or candidate.is_symlink(): candidate.unlink()
                (root / '_worker.js/index.js').write_bytes(original)
                (root / '_routes.json').write_bytes(routes)
                self.assertEqual((root / artifact.MARKER).read_bytes(), marker)
            artifact.process('verify', root, SHA)
            self.assertFalse((root / artifact.MARKER).exists())

    def test_cloudflare_requires_disabled_git_builds_and_server_side_bindings(self):
        project = {'production_branch': 'main', 'source': {'type': 'github', 'config': {
            'owner': 'ALEXRUZI', 'repo_name': 'BAZMEG.TECH-IT-Toolbox',
            'production_deployments_enabled': False, 'preview_deployment_setting': 'none'}},
            'deployment_configs': {'production': {'env_vars': {
                'BACKEND_ORIGIN': {'type': 'plain_text', 'value': 'https://backend.example.test'},
                'BACKEND_SECRET': {'type': 'secret_text'}}}}}
        expected = cloudflare.verify_project(project)
        for scenario in ('main', 'repo', 'auto-production', 'auto-preview', 'origin', 'secret', 'missing'):
            candidate = copy.deepcopy(project)
            config = candidate['source']['config']
            bindings = candidate['deployment_configs']['production']['env_vars']
            if scenario == 'main': candidate['production_branch'] = 'dev'
            elif scenario == 'repo': config['repo_name'] += '-dev'
            elif scenario == 'auto-production': config['production_deployments_enabled'] = True
            elif scenario == 'auto-preview': config['preview_deployment_setting'] = 'all'
            elif scenario == 'origin': bindings['BACKEND_ORIGIN']['value'] = 'http://backend.example.test'
            elif scenario == 'secret': bindings['BACKEND_SECRET']['type'] = 'plain_text'
            else: candidate = {}
            with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                cloudflare.verify_project(candidate)
        project['deployment_configs']['production']['compatibility_date'] = '2026-10-17'
        self.assertNotEqual(cloudflare.verify_project(project), expected)

    def test_cloudflare_requires_exact_successful_canonical_deployment(self):
        deployment_id = 'a' * 36
        project = {'canonical_deployment': {'id': deployment_id}}
        deployment = {'id': deployment_id, 'environment': 'production',
            'deployment_trigger': {'metadata': {'commit_hash': SHA}},
            'latest_stage': {'name': 'deploy', 'status': 'success', 'ended_on': 'fixture'}}
        cloudflare.verify_deployment(deployment, project, SHA, deployment_id)
        for field, value in (('id', 'other'), ('environment', 'preview'),
                ('latest_stage', {'name': 'deploy', 'status': 'failure'}),
                ('latest_stage', {'name': 'deploy', 'status': 'active'}),
                ('deployment_trigger', {'metadata': {'commit_hash': 'b' * 40}})):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cloudflare.verify_deployment({**deployment, field: value}, project, SHA, deployment_id)
        with self.assertRaises(ValueError):
            cloudflare.verify_deployment(deployment, {}, SHA, deployment_id)

    def test_acceptance_rejects_unsafe_urls_without_network(self):
        with patch.object(health, 'build_opener') as opener:
            for origin in ('http://example.test', 'https://user:pass@example.test',
                           'https://example.test/path', 'https://example.test?x=1', '',
                           'https://example.test:bad', 'https://example.test:8443', ' https://example.test',
                           'https://127.0.0.1', 'https://10.0.0.1', 'https://[::1]',
                           'https://127.1', 'https://2130706433', 'https://localhost',
                           'https://backend.internal', 'https://backend.local'):
                with self.subTest(origin=origin), self.assertRaises(ValueError):
                    health.verify(origin, SHA, 'b' * 64)
            opener.assert_not_called()

    def test_explicit_current_environment_review_and_cancelled_run(self):
        environment = {'id': 7, 'name': 'production-pages'}
        review = {'environments': [environment], 'state': 'approved',
                  'user': {'type': 'User', 'login': 'ALEXRUZI'}}
        gate.verify_approval(environment, [review])
        for history in ([], [review, review], [{**review, 'state': 'rejected'}],
                        [{**review, 'user': {'type': 'User', 'login': 'other'}}],
                        [{**review, 'environments': [{'id': 8, 'name': 'production'}]}]):
            with self.subTest(history=history), self.assertRaises(ValueError):
                gate.verify_approval(environment, history)
        context = {'GITHUB_RUN_ID': '17', 'GITHUB_SHA': SHA}
        run = {'id': 17, 'run_attempt': 1, 'event': 'workflow_dispatch', 'head_sha': SHA,
               'head_branch': 'main', 'status': 'in_progress', 'conclusion': None,
               'actor': {'login': 'ALEXRUZI'}, 'triggering_actor': {'login': 'ALEXRUZI'}}
        gate.verify_run(run, context)
        for field, value in (('status', 'completed'), ('conclusion', 'cancelled'), ('run_attempt', 2),
                             ('head_sha', 'b' * 40), ('id', 18), ('event', 'pull_request')):
            with self.subTest(field=field), self.assertRaises(ValueError):
                gate.verify_run({**run, field: value}, context)

    def test_live_acceptance_probes_exact_revision_contract_and_frontend_bytes(self):
        digest = 'b' * 64
        index = b'<html>disposable fixture</html>'
        responses = [
            (200, {'ok': True, 'message': 'toolbox API reachable'}),
            (200, {'ok': True, 'revision': SHA, 'archiveSha256': digest, 'apiContract': 'toolbox-api-v1',
                   'authorization': IDENTITY}),
            *[(400, {'ok': False, 'error': {'code': code, 'message': message}, **extra})
              for code, message, extra in [
                ('INVALID_MODE', 'Choose single or burst DNS check mode.', {}),
                ('INVALID_TARGET', 'Enter a public website domain name.', {}),
                ('INVALID_HOST', 'Enter a valid public hostname.', {}),
                ('INVALID_INPUT', 'Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.',
                 {'attempts': [], 'rawResponses': []})]],
        ]
        class Response(io.BytesIO):
            def __init__(self, status, data):
                super().__init__(data)
                self.status = status
                self.headers = {'Content-Type': 'text/html'}
        with tempfile.TemporaryDirectory(prefix='toolbox-live-probes-') as temp:
            marker = Path(temp) / 'verified.json'
            marker.write_text(json.dumps({'sha': SHA, 'files': {'index.html': hashlib.sha256(index).hexdigest()}}))
            for scenario in ('valid', 'valid-without-artifact', 'revision', 'digest', 'contract', 'endpoint', 'health', 'frontend', 'oversized',
                             'old-authorization', 'different-run', 'sequence', 'manifest', 'key', 'missing', 'null'):
                values = copy.deepcopy(responses)
                if scenario == 'revision': values[1][1]['revision'] = 'c' * 40
                elif scenario == 'digest': values[1][1]['archiveSha256'] = 'c' * 64
                elif scenario == 'contract': values[1][1]['apiContract'] = 'incompatible'
                elif scenario == 'endpoint': values[4] = (404, {})
                elif scenario == 'health': values[0] = (503, {})
                elif scenario == 'oversized': values[0] = (200, {'data': 'x' * 5000})
                elif scenario == 'old-authorization':
                    values[1][1]['authorization'].update(release=f'production-6-16-{SHA}', sequence='6')
                elif scenario == 'different-run': values[1][1]['authorization']['release'] = f'production-7-18-{SHA}'
                elif scenario == 'sequence': values[1][1]['authorization']['sequence'] = '8'
                elif scenario == 'manifest': values[1][1]['authorization']['manifestSha256'] = 'd' * 64
                elif scenario == 'key': values[1][1]['authorization']['keyId'] = 'other-key'
                elif scenario == 'missing': del values[1][1]['authorization']
                elif scenario == 'null': values[1][1]['authorization'] = None
                outputs = [Response(status, json.dumps(body).encode()) for status, body in values]
                outputs.append(Response(200, b'wrong revision' if scenario == 'frontend' else index))
                with patch.object(health, 'build_opener') as opener:
                    opener.return_value.open.side_effect = outputs
                    if scenario in ('valid', 'valid-without-artifact'):
                        health.verify('https://pages.example.test', SHA, digest,
                                      marker if scenario == 'valid' else None, identity=IDENTITY)
                        self.assertEqual(opener.return_value.open.call_count, 7)
                        self.assertIsInstance(opener.call_args.args[0], health.NoRedirect)
                        paths = ['/api/ping', '/api/release', '/api/tools/dns-check',
                                 '/api/tools/http-header-check', '/api/tools/tls-check',
                                 '/api/tools/rdap-lookup', '/']
                        for call, path in zip(opener.return_value.open.call_args_list, paths):
                            with self.subTest(scenario=scenario, path=path):
                                request = call.args[0]
                                self.assertEqual(request.full_url, 'https://pages.example.test' + path)
                                self.assertEqual(request.get_header('User-agent'),
                                                 'Toolbox-Production-Acceptance/1.0')
                                self.assertEqual(call.kwargs, {'timeout': 20})
                                diagnostic = path.startswith('/api/tools/')
                                self.assertEqual(request.get_method(), 'POST' if diagnostic else 'GET')
                                self.assertEqual(request.data, b'{}' if diagnostic else None)
                                if path.startswith('/api/'):
                                    self.assertEqual(request.get_header('Cache-control'), 'no-cache')
                                    self.assertEqual(request.get_header('Content-type'), 'application/json')
                    else:
                        with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                            health.verify('https://pages.example.test', SHA, digest, marker, identity=IDENTITY)

    def test_workflow_outputs_validate_current_signed_authorization_before_network(self):
        context = dict(GITHUB_SHA=SHA, GITHUB_RUN_NUMBER='7', GITHUB_RUN_ID='17',
                       EXPECTED_AUTHORIZATION_SEQUENCE='7', EXPECTED_RELEASE_ID=IDENTITY['release'],
                       EXPECTED_BACKEND_DIGEST=IDENTITY['archiveSha256'],
                       EXPECTED_MANIFEST_SHA256=IDENTITY['manifestSha256'], EXPECTED_SIGNING_KEY_ID='test-key')
        def validate(values):
            identity = health.expected_authorization(values)
            health.validate_identity(identity, SHA, 'b' * 64, values['GITHUB_RUN_ID'])
        validate(context)
        for field, bad in [('EXPECTED_RELEASE_ID', f'production-7-18-{SHA}'),
                           ('EXPECTED_AUTHORIZATION_SEQUENCE', '6'), ('EXPECTED_AUTHORIZATION_SEQUENCE', '07'),
                           ('EXPECTED_AUTHORIZATION_SEQUENCE', str(2**63)),
                           ('EXPECTED_MANIFEST_SHA256', ''), ('EXPECTED_MANIFEST_SHA256', 'X' * 64),
                           ('EXPECTED_SIGNING_KEY_ID', 'bad\noutput'), ('EXPECTED_BACKEND_DIGEST', 'c' * 64)]:
            with self.subTest(field=field, bad=bad), self.assertRaises(ValueError):
                validate({**context, field: bad})
        for identity in (None, {}, {**IDENTITY, 'sequence': 7}, {**IDENTITY, 'manifestSha256': 'bad'}):
            with patch.object(health, 'build_opener') as opener, self.assertRaises(ValueError):
                health.verify('https://pages.example.test', SHA, 'b' * 64, identity=identity)
            opener.assert_not_called()

    def test_pages_cannot_bypass_exact_authorization_wait_or_preupload_recheck(self):
        text = (ROOT / '.github/workflows/backend-production.yml').read_text()
        publish, rest = text.split('\n  accept-backend:\n')
        acceptance, frontend = rest.split('\n  deploy-frontend:\n')
        self.assertIn('needs: [accept-backend, build-frontend]', frontend)
        self.assertNotIn('always()', frontend)
        self.assertNotIn('continue-on-error', text)
        self.assertIn('run: python3 -I deploy/wait-backend.py', acceptance)
        for output in ('release', 'sequence', 'manifest', 'key'):
            self.assertIn(f'{output}: ${{{{ needs.publish-backend.outputs.{output} }}}}', acceptance)
            self.assertIn(f'${{{{ steps.sign.outputs.', publish)
            self.assertEqual(frontend.count(f'${{{{ needs.accept-backend.outputs.{output} }}}}'), 2)
        self.assertLess(frontend.index('verify-cloudflare.py before'), frontend.index('deploy/verify-pages-health.py'))
        self.assertLess(frontend.index('deploy/verify-pages-health.py'), frontend.index('"$tool" pages deploy'))

    def test_pull_only_publication_secret_and_permissions_boundary(self):
        text = (ROOT / '.github/workflows/backend-production.yml').read_text()
        for forbidden in ('PRODUCTION_BACKEND_SSH', 'scp ', 'ssh ', 'sftp ', 'sudo ', 'DEPLOY_HOST'):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count('contents: write'), 1)
        self.assertEqual(text.count('secrets.PRODUCTION_RELEASE_SIGNING_KEY'), 1)
        signing = text.split('\n  publish-backend:\n')[1].split('\n  accept-backend:\n')[0]
        self.assertIn('environment: production', signing)
        self.assertIn('--environment production', signing)
        self.assertIn('gh release create', signing)
        self.assertIn('independent-backend.tar.gz', signing)
        self.assertIn('"$snapshot" == "$EXPECTED_SNAPSHOT"', signing)
        self.assertLess(signing.index('independent-backend.tar.gz'), signing.index('RELEASE_SIGNING_KEY:'))
        self.assertIn('--draft=false', signing)
        self.assertNotIn('--clobber', signing.replace('# A new run has a unique identity. Never edit/upload --clobber or reuse a tag.', ''))
        self.assertIn('needs: [publish-backend, validate-package]', text)
        self.assertNotIn('BACKEND_SECRET', text)

    def test_cloudflare_preflight_and_exact_receipt_without_network_or_secret_logs(self):
        project_name = 'toolbox-fixture'
        deployment_id = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        project = {'name': project_name, 'subdomain': project_name + '.pages.dev', 'domains': ['ui.example.test'],
            'production_branch': 'main', 'source': {'type': 'github', 'config': {
                'owner': 'ALEXRUZI', 'repo_name': 'BAZMEG.TECH-IT-Toolbox',
                'production_deployments_enabled': False, 'preview_deployment_setting': 'none'}},
            'deployment_configs': {'production': {'env_vars': {
                'BACKEND_ORIGIN': {'type': 'plain_text', 'value': 'https://backend.example.test'},
                'BACKEND_SECRET': {'type': 'secret_text'}}}},
            'canonical_deployment': {'id': deployment_id}}
        deployment = {'id': deployment_id, 'environment': 'production',
            'deployment_trigger': {'metadata': {'commit_hash': SHA}},
            'latest_stage': {'name': 'deploy', 'status': 'success'}}
        class Response(io.BytesIO):
            pass
        with tempfile.TemporaryDirectory(prefix='toolbox-cloudflare-') as temporary:
            output = Path(temporary) / 'deploy.jsonl'
            record = {'type': 'pages-deploy', 'pages_project': project_name, 'deployment_id': deployment_id}
            env = {'CLOUDFLARE_API_TOKEN': 'disposable-cloudflare-token', 'CLOUDFLARE_ACCOUNT_ID': 'a' * 32,
                   'PRODUCTION_PAGES_PROJECT': project_name, 'PRODUCTION_PAGES_URL': 'https://ui.example.test',
                   'RUNNER_TEMP': temporary, 'WRANGLER_OUTPUT_FILE_PATH': str(output), 'GITHUB_SHA': SHA}
            for scenario in ('valid', 'missing-token', 'wrong-origin', 'settings-drift', 'missing-receipt',
                             'duplicate-receipt', 'malformed-id', 'wrong-revision'):
                values = copy.deepcopy(env)
                if scenario == 'missing-token': values['CLOUDFLARE_API_TOKEN'] = ''
                elif scenario == 'wrong-origin': values['PRODUCTION_PAGES_URL'] = 'https://other.example.test'
                current_project, current_deployment = copy.deepcopy(project), copy.deepcopy(deployment)
                def api(request, timeout):
                    data = current_deployment if '/deployments/' in request.full_url else current_project
                    return Response(json.dumps({'success': True, 'result': data}).encode())
                with patch.dict(os.environ, values), patch.object(cloudflare, 'build_opener') as opener:
                    opener.return_value.open.side_effect = api
                    if scenario in ('missing-token', 'wrong-origin'):
                        with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                            cloudflare.main('before')
                        if scenario == 'missing-token': opener.assert_not_called()
                        continue
                    cloudflare.main('before')
                    if scenario == 'settings-drift':
                        current_project['deployment_configs']['production']['compatibility_date'] = '2026-10-17'
                    elif scenario == 'wrong-revision':
                        current_deployment['deployment_trigger']['metadata']['commit_hash'] = 'c' * 40
                    candidate = {**record, 'deployment_id': '-' * 36} if scenario == 'malformed-id' else record
                    output.write_text('' if scenario == 'missing-receipt' else json.dumps(candidate) + '\n')
                    if scenario == 'duplicate-receipt': output.write_text(output.read_text() * 2)
                    if scenario == 'valid':
                        with patch('builtins.print') as printed:
                            cloudflare.main('after')
                        self.assertNotIn(values['CLOUDFLARE_API_TOKEN'], str(printed.call_args_list))
                    else:
                        with self.subTest(scenario=scenario), self.assertRaises(ValueError):
                            cloudflare.main('after')
                    self.assertIsInstance(opener.call_args.args[0], cloudflare.NoRedirect)


if __name__ == '__main__':
    unittest.main()
