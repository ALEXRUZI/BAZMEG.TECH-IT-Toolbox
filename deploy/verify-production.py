#!/usr/bin/env python3
"""Fail closed on owner-only, self-approvable public production metadata.

Read-only GitHub requests; no production credential or application code required.
Branch protection must additionally be configured by the owner (see runbook).
"""
import json
import os
import re
import subprocess
import argparse

OWNER = 'ALEXRUZI'
REPOSITORY = OWNER + '/BAZMEG.TECH-IT-Toolbox'
ENVIRONMENTS = ('production', 'production-pages')


def verify(environment, branches, main, context):
    if (context.get('GITHUB_REPOSITORY') != REPOSITORY or
            context.get('GITHUB_REF') != 'refs/heads/main' or
            context.get('GITHUB_EVENT_NAME') != 'workflow_dispatch' or
            any(context.get(key, '').casefold() != OWNER.casefold()
                for key in ('GITHUB_ACTOR', 'GITHUB_TRIGGERING_ACTOR'))):
        raise ValueError('Only the owner may dispatch/rerun production on public main')
    # Review history is run-scoped, not attempt-scoped. Never reuse an old review
    # or successful backend job on a partial rerun. Retry by fresh dispatch instead.
    if context.get('GITHUB_RUN_ATTEMPT') != '1':
        raise ValueError('Production retries require a fresh dispatch and approvals')
    sha = context.get('GITHUB_SHA', '')
    if (not re.fullmatch('[0-9a-f]{40}', sha) or
            context.get('APPROVED_SHA') != sha or main.get('object', {}).get('sha') != sha):
        raise ValueError('Approved SHA must equal this run and the current public main tip')
    if environment.get('can_admins_bypass') is not False:
        raise ValueError('Administrator bypass must be explicitly disabled')
    rules = [rule for rule in environment.get('protection_rules', [])
             if rule.get('type') == 'required_reviewers']
    if len(rules) != 1 or rules[0].get('prevent_self_review') is not False:
        raise ValueError('Owner reviewer required with Prevent self-review disabled')
    if any(rule.get('type') not in ('required_reviewers', 'branch_policy')
           for rule in environment.get('protection_rules', [])):
        raise ValueError('Additional production approval/protection rules are not permitted')
    reviewers = rules[0].get('reviewers', [])
    if (len(reviewers) != 1 or reviewers[0].get('type') != 'User' or
            reviewers[0].get('reviewer', {}).get('login', '').casefold() != OWNER.casefold()):
        raise ValueError('Repository owner must be the sole required reviewer')
    if environment.get('deployment_branch_policy') != {
            'protected_branches': False, 'custom_branch_policies': True}:
        raise ValueError('Selected main-only branch policy required')
    policies = branches.get('branch_policies', [])
    if (branches.get('total_count') != 1 or len(policies) != 1 or
            policies[0].get('name') != 'main' or policies[0].get('type') != 'branch'):
        raise ValueError('Only the exact main branch may deploy')


def verify_approval(environment, history):
    environment_id = environment.get('id')
    if type(environment_id) is not int or environment_id <= 0:
        raise ValueError('Production environment identity missing')
    reviews = [review for review in history if any(
        item.get('id') == environment_id and item.get('name') == environment.get('name')
        for item in review.get('environments', []))]
    if (len(reviews) != 1 or reviews[0].get('state') != 'approved' or
            reviews[0].get('user', {}).get('type') != 'User' or
            reviews[0].get('user', {}).get('login', '').casefold() != OWNER.casefold()):
        raise ValueError('One explicit owner environment approval required for this run')


def verify_run(run, context):
    if (str(run.get('id')) != context.get('GITHUB_RUN_ID') or
            run.get('run_attempt') != 1 or run.get('event') != 'workflow_dispatch' or
            run.get('head_sha') != context.get('GITHUB_SHA') or run.get('head_branch') != 'main' or
            run.get('status') != 'in_progress' or run.get('conclusion') is not None or
            any(run.get(key, {}).get('login', '').casefold() != OWNER.casefold()
                for key in ('actor', 'triggering_actor'))):
        raise ValueError('Current live owner-dispatched first attempt required')


def api(path):
    return json.loads(subprocess.check_output(['gh', 'api', f'repos/{REPOSITORY}/{path}'], timeout=30))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--environment', choices=ENVIRONMENTS)
    args = parser.parse_args()
    try:
        run_id = os.environ['GITHUB_RUN_ID']
        if not re.fullmatch('[0-9]+', run_id):
            raise ValueError('Invalid workflow run identity')
        verify_run(api('actions/runs/' + run_id), os.environ)
        for name in (args.environment,) if args.environment else ENVIRONMENTS:
            environment = api('environments/' + name)
            if environment.get('name') != name:
                raise ValueError('Production environment identity mismatch')
            verify(environment, api('environments/' + name + '/deployment-branch-policies'),
                   api('git/ref/heads/main'), os.environ)
            if args.environment:
                verify_approval(environment, api('actions/runs/' + run_id + '/approvals'))
    except Exception:
        raise SystemExit('Production authorization failed; inspect approval/settings/retry runbook') from None
