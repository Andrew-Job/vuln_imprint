#!/usr/bin/env python3
"""Enforce a protected, reviewed source revision for a release.

All admitted CVEs are compiled directly from the checked-out Git tree.
Native affected/fixed validation must have passed in required CI before merge.
"""
from __future__ import annotations
import json
import os
import re
import subprocess
import sys

HASH40 = re.compile(r'[0-9a-f]{40}\Z')
TAG = re.compile(r'v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z')

class InputRejected(ValueError):
    pass


def command(*args: str) -> str:
    completed = subprocess.run(args, capture_output=True, text=True, check=True, timeout=35)
    return completed.stdout.strip()


def gh_api(endpoint: str) -> dict:
    return json.loads(command('gh', 'api', endpoint))


def verify(*, ref: str, sha: str, repository: str) -> dict:
    if not ref.startswith('refs/tags/') or not TAG.fullmatch(ref[10:]):
        raise InputRejected('release can run only for a stable protected version tag')
    if not HASH40.fullmatch(sha) or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise InputRejected('invalid release source identity')
    version = ref[10:]
    if command('git','rev-parse','HEAD') != sha:
        raise InputRejected('checkout HEAD differs from release Git SHA')
    if command('git','rev-parse',f'refs/tags/{version}^{{commit}}') != sha:
        raise InputRejected('release tag does not resolve to checked-out commit')
    if command('git','status','--porcelain','--untracked-files=no'):
        raise InputRejected('release source checkout is modified')
    subprocess.run(['git','merge-base','--is-ancestor',sha,'refs/remotes/origin/main'],
                   check=True,timeout=20)
    # CI must have succeeded for the exact source revision, not just an
    # unrelated workflow execution on main or a previous revision.
    ci=gh_api(f'repos/{repository}/actions/workflows/ci.yml/runs?head_sha={sha}&status=success&per_page=100')
    if not any(run.get('head_sha')==sha and run.get('event')=='push' and
               run.get('conclusion')=='success' and run.get('head_branch')=='main'
               for run in ci.get('workflow_runs', [])):
        raise InputRejected('required source/native CI has not passed for the exact release SHA')
    return {'version': version, 'source_sha': sha}


def main() -> int:
    try:
        outcome=verify(
            ref=os.environ['GITHUB_REF'], sha=os.environ['GITHUB_SHA'],
            repository=os.environ['GITHUB_REPOSITORY'])
        print(json.dumps(outcome,sort_keys=True))
        if os.getenv('GITHUB_OUTPUT'):
            with open(os.environ['GITHUB_OUTPUT'],'a',encoding='utf-8') as f:
                for key,value in outcome.items():
                    f.write(f'{key}={value}\n')
        return 0
    except (InputRejected,OSError,KeyError,ValueError,subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print('RELEASE SOURCE REJECTED:',exc,file=sys.stderr)
        return 2

if __name__=='__main__':raise SystemExit(main())
