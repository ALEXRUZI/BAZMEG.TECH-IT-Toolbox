#!/usr/bin/env python3
"""Read-only Pages pre/postflight. Never print configuration or API responses."""
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def verify_project(project):
    source = project.get('source', {})
    config = source.get('config', {})
    if (project.get('production_branch') != 'main' or source.get('type') != 'github' or
            config.get('owner', '').casefold() != 'alexruzi' or
            config.get('repo_name') != 'BAZMEG.TECH-IT-Toolbox' or
            config.get('production_deployments_enabled') is not False or
            config.get('preview_deployment_setting') != 'none'):
        raise ValueError('Existing public Pages project must disable automatic Git deployments')
    production = project.get('deployment_configs', {}).get('production', {})
    bindings = production.get('env_vars', {})
    origin = urlsplit(bindings.get('BACKEND_ORIGIN', {}).get('value', ''))
    if (origin.scheme != 'https' or not origin.hostname or origin.username or origin.password or
            origin.path not in ('', '/') or origin.query or origin.fragment or
            bindings.get('BACKEND_SECRET', {}).get('type') != 'secret_text'):
        raise ValueError('Required server-side HTTPS origin and secret binding missing')
    # Includes compatibility settings and binding metadata; never stored in logs.
    return hashlib.sha256(json.dumps(production, sort_keys=True).encode()).hexdigest()


def verify_deployment(deployment, project, sha, deployment_id):
    if (deployment.get('id') != deployment_id or
            project.get('canonical_deployment', {}).get('id') != deployment_id or
            deployment.get('environment') != 'production' or
            deployment.get('deployment_trigger', {}).get('metadata', {}).get('commit_hash') != sha or
            deployment.get('latest_stage', {}).get('name') != 'deploy' or
            deployment.get('latest_stage', {}).get('status') != 'success'):
        raise ValueError('Exact production Pages deployment did not become healthy canonical release')


def main(mode):
    account = os.environ['CLOUDFLARE_ACCOUNT_ID']
    project_name = os.environ['PRODUCTION_PAGES_PROJECT']
    token = os.environ['CLOUDFLARE_API_TOKEN']
    if (not re.fullmatch('[0-9a-f]{32}', account) or
            not re.fullmatch('[a-z0-9][a-z0-9-]{0,62}', project_name) or
            not token or token != token.strip() or re.search(r'[\x00-\x20\x7f]', token)):
        raise ValueError('Explicit existing Cloudflare account/project required')
    base = f'https://api.cloudflare.com/client/v4/accounts/{account}/pages/projects/{project_name}'
    opener = build_opener(NoRedirect())

    def api(suffix=''):
        request = Request(base + suffix, headers={
            'Authorization': 'Bearer ' + token})
        with opener.open(request, timeout=30) as response:
            body = response.read(2 * 1024 * 1024 + 1)
        if len(body) > 2 * 1024 * 1024:
            raise ValueError('Oversized Cloudflare response')
        data = json.loads(body)
        if data.get('success') is not True:
            raise ValueError('Cloudflare read-only verification failed')
        return data['result']

    project = api()
    origin = urlsplit(os.environ['PRODUCTION_PAGES_URL'])
    if (project.get('name') != project_name or origin.scheme != 'https' or
            origin.username or origin.password or origin.port not in (None, 443) or
            origin.path not in ('', '/') or origin.query or origin.fragment or
            origin.hostname not in [project.get('subdomain'), *project.get('domains', [])]):
        raise ValueError('Acceptance origin must belong to the exact existing Pages project')
    fingerprint = verify_project(project)
    record = Path(os.environ['RUNNER_TEMP']) / 'pages-production-settings.sha256'
    if mode == 'before':
        record.write_text(fingerprint)
    elif mode == 'after':
        if record.read_text() != fingerprint:
            raise ValueError('Production bindings/settings changed during deployment')
        entries = [json.loads(line) for line in Path(os.environ['WRANGLER_OUTPUT_FILE_PATH']).read_text().splitlines()]
        outputs = [entry for entry in entries if entry.get('type') == 'pages-deploy' and
                   entry.get('pages_project') == project_name]
        if len(outputs) != 1 or not re.fullmatch(
                '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                outputs[0].get('deployment_id', '')):
            raise ValueError('One exact Wrangler deployment receipt required')
        deployment_id = outputs[0]['deployment_id']
        verify_deployment(api('/deployments/' + deployment_id), project,
                          os.environ['GITHUB_SHA'], deployment_id)
        print('Verified production Pages deployment ' + deployment_id)
    else:
        raise ValueError('Unknown verification mode')


if __name__ == '__main__':
    try:
        main(sys.argv[1])
    except Exception:
        raise SystemExit('Cloudflare production verification failed; inspect settings/rollback runbook') from None
