#!/usr/bin/env python3
"""Bounded acceptance through the existing public Pages Function, never BE SSH."""
import os
import importlib.util
from pathlib import Path
import subprocess
import time


def wait(run=subprocess.run, sleep=time.sleep):
    spec = importlib.util.spec_from_file_location('pages_health', Path(__file__).with_name('verify-pages-health.py'))
    health = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(health)
    identity = health.expected_authorization(os.environ)
    health.validate_identity(identity, os.environ['GITHUB_SHA'], os.environ['EXPECTED_BACKEND_DIGEST'],
                             os.environ['GITHUB_RUN_ID'])
    # Overall 25-minute budget, independently bounded by the Actions job timeout.
    deadline = time.monotonic() + 1500
    for _ in range(30):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            result = run(['/usr/bin/python3', '-I', str(Path(__file__).with_name('verify-pages-health.py'))],
                         env=os.environ.copy(), timeout=min(170, remaining), capture_output=True)
        except subprocess.TimeoutExpired:
            break
        if result.returncode == 0:
            print('Exact signed authorization, backend revision, digest and compatibility accepted')
            return
        if time.monotonic() + 50 >= deadline:
            break
        sleep(50)
    raise ValueError('Backend acceptance timed out; Pages remains blocked')


if __name__ == '__main__':
    try:
        wait()
    except Exception:
        raise SystemExit('Backend acceptance failed; inspect pull journal before fresh authorization') from None
