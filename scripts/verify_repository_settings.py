#!/usr/bin/env python3
"""Administrator-only preflight before allowing public VulnImprint releases.

Run this locally with a GH account with repository administration *read*
access. The GitHub Actions GITHUB_TOKEN deliberately does not have that scope.
This process does not modify remote settings or create a release.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys

REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/vuln_imprint\Z", re.IGNORECASE)


class RepositoryNotReady(RuntimeError):
    """A required repository-side release control is absent."""


def get_resource(path: str):
    proc = subprocess.run(
        ['gh', 'api', '-H', 'X-GitHub-Api-Version: 2026-03-10', path],
        text=True,
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0:
        raise RepositoryNotReady(
            f'GitHub administrative API unavailable: {path}: {proc.stderr.strip()[:300]}'
        )
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RepositoryNotReady(
            f'GitHub administrative API returned invalid JSON: {path}') from exc
    if not isinstance(data, (dict, list)):
        raise RepositoryNotReady(
            f'GitHub administrative API returned invalid object: {path}')
    return data


def get_json(path: str) -> dict:
    data = get_resource(path)
    if not isinstance(data, dict):
        raise RepositoryNotReady(f'GitHub API expected object: {path}')
    return data


def get_list(path: str) -> list:
    data = get_resource(path)
    if not isinstance(data, list):
        raise RepositoryNotReady(f'GitHub API expected list: {path}')
    return data


def verifies_release_tag(pattern: str) -> bool:
    """Only accept policies that cover both first and later version tags."""
    return isinstance(pattern, str) and all(
        fnmatch.fnmatchcase(tag, pattern)
        for tag in ('refs/tags/v0.1.0', 'refs/tags/v99.99.99'))


def verify_release_tag_ruleset(repo: str) -> None:
    rulesets = get_list(f'repos/{repo}/rulesets?includes_parents=true')
    for ruleset in rulesets:
        if (not isinstance(ruleset, dict) or ruleset.get('target') != 'tag' or
                ruleset.get('enforcement') != 'active'):
            continue
        identifier = ruleset.get('id')
        if type(identifier) is not int:
            continue
        detail = get_json(f'repos/{repo}/rulesets/{identifier}')
        conditions = detail.get('conditions') or {}
        refs = conditions.get('ref_name') or {}
        include = refs.get('include') or []
        exclude = refs.get('exclude') or []
        covered = any(x == '~ALL' or verifies_release_tag(x) for x in include)
        # Exclusions would allow some version tags to bypass immutability.
        excluded = bool(exclude)
        rule_types = {
            r.get('type')
            for r in detail.get('rules', [])
            if isinstance(r, dict)
        }
        if (covered and not excluded and
            {'deletion', 'update'} <= rule_types and
                not detail.get('bypass_actors')):
            return
    raise RepositoryNotReady(
        'active v* tag ruleset must block tag updates/deletion without bypass')


def verify_production_environment(repo: str) -> None:
    env = get_json(f'repos/{repo}/environments/production')
    approval = [
        r for r in env.get('protection_rules', [])
        if isinstance(r, dict) and r.get('type') == 'required_reviewers' and
        r.get('reviewers') and r.get('prevent_self_review') is True
    ]
    if not approval:
        raise RepositoryNotReady(
            'production must require independent deployment approval')
    branch_policy = env.get('deployment_branch_policy') or {}
    if branch_policy.get('custom_branch_policies') is not True:
        raise RepositoryNotReady(
            'production must restrict deployments to release version tags')
    policies = get_json(
        f'repos/{repo}/environments/production/deployment-branch-policies')
    policies = policies.get('branch_policies')
    if not isinstance(policies, list) or not any(
            isinstance(policy, dict) and policy.get('type') == 'tag' and
            verifies_release_tag('refs/tags/' + policy.get('name', ''))
            for policy in policies):
        raise RepositoryNotReady(
            'production deployment must be restricted to v* tags')


def verify(repo: str) -> None:
    if not REPO.fullmatch(repo) or repo.lower().endswith('/.'):
        raise RepositoryNotReady('expected OWNER/vuln_imprint')
    settings = get_json(f'repos/{repo}')
    if settings.get('private') is not False or settings.get(
            'default_branch') != 'main':
        raise RepositoryNotReady('the repository must be public and use main')
    immutability = get_json(f'repos/{repo}/immutable-releases')
    if immutability.get('enabled') is not True:
        raise RepositoryNotReady('immutable GitHub Releases must be enabled')
    # A classic branch protection rule or equivalent ruleset must be configured.
    # github REST /branches/main/protection gives a definitive classic policy.
    # Rulesets-only installations need separate explicit administration review.
    branch = get_json(f'repos/{repo}/branches/main/protection')
    if not branch.get('required_pull_request_reviews'):
        raise RepositoryNotReady(
            'main requires an actual pull request review policy')
    checks = branch.get('required_status_checks') or {}
    required = set(checks.get('contexts') or ())
    required.update(
        item.get('context', '')
        for item in checks.get('checks') or ()
        if isinstance(item, dict))
    for job in ('google-style', 'offline', 'security', 'native'):
        if not any(name == job or name.endswith(' / ' +
                                                job) or name.endswith('/' + job)
                   for name in required):
            raise RepositoryNotReady(
                f'main protection must require source CI job {job}')
    if not branch.get('enforce_admins', {}).get('enabled'):
        raise RepositoryNotReady('main protection must include administrators')
    verify_release_tag_ruleset(repo)
    verify_production_environment(repo)
    print(
        f'PASS: {repo} has immutable releases, protected main/tags and independently approved production'
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', required=True, help='OWNER/vuln_imprint')
    args = parser.parse_args()
    try:
        verify(args.repo)
    except (RepositoryNotReady, FileNotFoundError,
            subprocess.TimeoutExpired) as exc:
        print(f'REPOSITORY NOT READY: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
