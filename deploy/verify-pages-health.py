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


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def verify(origin, sha, digest, artifact=None):
    url = urlsplit(origin)
    if (origin != origin.strip() or re.search(r'[\x00-\x20\x7f]', origin) or
            url.scheme != 'https' or not url.hostname or url.username or url.password or
            url.port not in (None, 443) or
            url.path not in ('', '/') or url.query or url.fragment):
        raise ValueError('Verified production HTTPS origin required')
    if not re.fullmatch('[0-9a-f]{40}', sha) or not re.fullmatch('[0-9a-f]{64}', digest):
        raise ValueError('Expected backend revision and archive digest required')
    opener = build_opener(NoRedirect())
    from urllib.request import Request

    def request(path, expected, body=None):
        request = Request(origin.rstrip('/') + path, data=body,
                          headers={'Cache-Control': 'no-cache', 'Content-Type': 'application/json'})
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
                                 'apiContract': 'toolbox-api-v1'}))
    probes = [('dns-check', 'INVALID_MODE', 'Choose single or burst DNS check mode.'),
              ('http-header-check', 'INVALID_TARGET', 'Enter a public website domain name.'),
              ('tls-check', 'INVALID_HOST', 'Enter a valid public hostname.'),
              ('rdap-lookup', 'INVALID_INPUT', 'Enter one domain, IPv4/IPv6 address, or AS-prefixed ASN.')]
    for tool, code, message in probes:
        body = {'ok': False, 'error': {'code': code, 'message': message}}
        if tool == 'rdap-lookup':
            body.update(attempts=[], rawResponses=[])
        request('/api/tools/' + tool, (400, body), b'{}')
    with opener.open(origin.rstrip('/') + '/', timeout=20) as response:
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
        verify(os.environ['PRODUCTION_PAGES_URL'], os.environ['GITHUB_SHA'],
               os.environ['EXPECTED_BACKEND_DIGEST'], sys.argv[1] if len(sys.argv) > 1 else None)
        print('Verified authenticated backend ' + os.environ['GITHUB_SHA'] +
              ' archive SHA-256 ' + os.environ['EXPECTED_BACKEND_DIGEST'] +
              (' and exact frontend HTML' if len(sys.argv) > 1 else ' before frontend upload'))
    except Exception:
        raise SystemExit('Production HTTPS/Function verification failed; inspect rollback runbook') from None
