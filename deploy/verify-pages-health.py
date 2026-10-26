#!/usr/bin/env python3
"""Bounded HTTPS acceptance without application credentials or raw response logs."""
import json
import hashlib
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit
from urllib.request import build_opener, HTTPRedirectHandler


USER_AGENT = 'Toolbox-Production-Acceptance/1.0'


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def expected_authorization(context):
    sha = context['GITHUB_SHA']
    sequence = context['EXPECTED_AUTHORIZATION_SEQUENCE']
    run = context['GITHUB_RUN_ID']
    if (not re.fullmatch('[1-9][0-9]{0,18}', sequence) or int(sequence) >= 2**63 or
            sequence != context['GITHUB_RUN_NUMBER'] or
            not re.fullmatch('[1-9][0-9]{0,18}', run) or int(run) >= 2**63):
        raise ValueError('Exact current authorization sequence/run required')
    return dict(release=context['EXPECTED_RELEASE_ID'], sequence=sequence, commit=sha,
                archiveSha256=context['EXPECTED_BACKEND_DIGEST'],
                manifestSha256=context['EXPECTED_MANIFEST_SHA256'], keyId=context['EXPECTED_SIGNING_KEY_ID'])


def validate_identity(identity, sha, digest, run=None):
    if (not re.fullmatch('[0-9a-f]{40}', sha) or not re.fullmatch('[0-9a-f]{64}', digest) or
            run is not None and not re.fullmatch('[1-9][0-9]{0,18}', run) or
            not isinstance(identity, dict) or set(identity) != {
            'release', 'sequence', 'commit', 'archiveSha256', 'manifestSha256', 'keyId'} or
            not all(isinstance(v, str) for v in identity.values()) or
            not re.fullmatch('[1-9][0-9]{0,18}', identity['sequence']) or
            int(identity['sequence']) >= 2**63 or identity['commit'] != sha or
            identity['archiveSha256'] != digest or
            not re.fullmatch('[0-9a-f]{64}', identity['manifestSha256']) or
            not re.fullmatch('[a-z0-9-]{1,48}', identity['keyId']) or
            not re.fullmatch(rf'production-{identity["sequence"]}-{run or "[1-9][0-9]{0,18}"}-{sha}',
                             identity['release'])):
        raise ValueError('Exact signed authorization outputs required')


def verify(origin, sha, digest, artifact=None, identity=None):
    url = urlsplit(origin)
    # This must be the public Pages DNS origin, never a BE IP/private host literal.
    # Its Cloudflare project/domain membership is independently operator-verified
    # before enablement and rechecked by the existing credentialed Pages preflight.
    public_dns = (url.hostname is not None and re.fullmatch(
        r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}',
        url.hostname) and not url.hostname.endswith(('.local', '.localhost', '.internal', '.localdomain')))
    if (origin != origin.strip() or re.search(r'[\x00-\x20\x7f]', origin) or
            url.scheme != 'https' or not public_dns or url.username or url.password or
            url.port not in (None, 443) or
            url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('Verified production HTTPS origin required')
    if not re.fullmatch('[0-9a-f]{40}', sha) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Expected backend revision and archive digest required')
    validate_identity(identity, sha, digest)
    opener = build_opener(NoRedirect())
    from urllib.request import Request

    def request(path, expected, body=None):
        request = Request(origin.rstrip('/') + path, data=body,
                          headers={'Cache-Control': 'no-cache', 'Content-Type': 'application/json',
                                   'User-Agent': USER_AGENT})
        # Error envelopes are intentional compatibility probes, never outbound work.
        from urllib.error import HTTPError
        try:
            response = opener.open(request, timeout=20)
        except HTTPError as error:
            response = error
        with response:
            data = response.read(4097)
            if len(data) > 4096 or (response.status, json.loads(data)) != expected:
                raise ValueError('Authenticated backend identity/compatibility acceptance failed')

    request('/api/ping', (200, {'ok': True, 'message': 'toolbox API reachable'}))
    request('/api/release', (200, {'ok': True, 'revision': sha, 'archiveSha256': digest,
                                 'apiContract': 'toolbox-api-v1', 'authorization': identity}))
    probes = [('dns-check', 'INVALID_MODE', 'Choose single or burst DNS check mode.'),
              ('http-header-check', 'INVALID_TARGET', 'Enter a public website domain name.'),
              ('tls-check', 'INVALID_HOST', 'Enter a valid public hostname.'),
              ('rdap-lookup', 'INVALID_INPUT', 'Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.')]
    for tool, code, message in probes:
        body = {'ok': False, 'error': {'code': code, 'message': message}}
        if tool == 'rdap-lookup':
            body.update(attempts=[], rawResponses=[])
        request('/api/tools/' + tool, (400, body), b'{}')
    with opener.open(Request(origin.rstrip('/') + '/', headers={'User-Agent': USER_AGENT}), timeout=20) as response:
        if response.status != 200 or 'text/html' not in response.headers.get('Content-Type', ''):
            raise ValueError('Frontend acceptance failed')
        if artifact:
            metadata = json.loads(Path(artifact).read_text())
            data = response.read(4 * 1024 * 1024 + 1)
            if (metadata.get('sha') != sha or len(data) > 4 * 1024 * 1024 or
                    hashlib.sha256(data).hexdigest() != metadata.get('files', {}).get('index.html')):
                raise ValueError('Live frontend bytes differ from approved artifact')


if __name__ == '__main__':
    try:
        identity = expected_authorization(os.environ)
        validate_identity(identity, os.environ['GITHUB_SHA'], os.environ['EXPECTED_BACKEND_DIGEST'],
                          os.environ['GITHUB_RUN_ID'])
        verify(os.environ['PRODUCTION_PAGES_URL'], os.environ['GITHUB_SHA'],
               os.environ['EXPECTED_BACKEND_DIGEST'], sys.argv[1] if len(sys.argv) > 1 else None,
               identity=identity)
        print('Verified authenticated backend ' + os.environ['GITHUB_SHA'] +
              ' authorization ' + identity['release'] + ' manifest SHA-256 ' + identity['manifestSha256'] +
              (' and exact frontend HTML' if len(sys.argv) > 1 else ' before frontend upload'))
    except Exception:
        raise SystemExit('Production HTTPS/Function verification failed; inspect rollback runbook') from None
