"""End-to-end batch execution with explicit provenance, source locking, and failures.

No CVE is marked verified when acquisition, compilation, validation, or the
native YARA-X oracle failed to run. Untrusted source builds require sandboxed CI.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path
from .database import merge_packs
from .pipeline import run
from .yara_engine import compile_database

# Whitelist the release-tag conventions of supported upstream C/C++ libraries.
# Exact tag commits are always resolved and pinned before any source build.
ALLOWED_REF = re.compile(r'(?:v\d+\.\d+(?:\.\d+)?(?:[.-][A-Za-z0-9]+)?'
                         r'|curl-\d+_\d+_\d+'
                         r'|openssl-\d+\.\d+\.\d+)\Z')


def resolve_git_ref(url: str, ref: str) -> str:
    if not url.startswith('https://') or not ALLOWED_REF.fullmatch(ref):
        raise ValueError(
            'only HTTPS upstream Git and version tags are supported')
    wanted = f'refs/tags/{ref}'
    proc = subprocess.run(
        ['git', 'ls-remote', '--tags', url, wanted, wanted + '^{}'],
        capture_output=True,
        text=True,
        check=True,
        timeout=40)
    entries = {
        name: digest
        for digest, name in (line.split() for line in proc.stdout.splitlines())
    }
    commit = entries.get(wanted + '^{}') or entries.get(wanted)
    if not commit or not re.fullmatch(r'[0-9a-fA-F]{40}|[0-9a-fA-F]{64}',
                                      commit):
        raise ValueError(f'unresolvable Git version tag {ref} at {url}')
    return commit.lower()


def freeze_manifest(source: Path,
                    output: Path,
                    cache: dict | None = None) -> dict:
    data = json.loads(source.read_text())
    if not isinstance(data, dict):
        raise ValueError('CVE catalog entry must be a JSON object')
    builds = data.get('builds', [])
    if not isinstance(builds, list):
        raise ValueError('builds must be a list')
    # Validate complete recipe shapes before resolving any network refs.
    for job in builds:
        if not isinstance(job, dict) or not isinstance(job.get('source'), dict):
            raise ValueError('each build requires an object source')
        src = job['source']
        if 'git' in src and ('ref'
                             in src) and (not isinstance(src['git'], str) or
                                          not isinstance(src['ref'], str)):
            raise ValueError('Git source/ref must be strings')
    cache = cache if cache is not None else {}
    for job in builds:
        src = job['source']
        if 'git' not in src or 'ref' not in src:
            continue
        key = src['git'], src['ref']
        if key not in cache:
            cache[key] = resolve_git_ref(*key)
        src['commit'] = cache[key]
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, sort_keys=True, indent=2) + '\n')
    return data


def batch_run(catalog: Path,
              output: Path,
              store: Path | None = None,
              compile_native=True,
              include_experimental=False) -> dict:
    catalog = Path(catalog).resolve()
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    if not catalog.is_dir():
        raise ValueError('catalog must be a directory')
    files = sorted(catalog.glob('CVE-*.json'))
    if not files:
        raise ValueError('no CVE JSON manifests in catalog')
    entries = []
    cache = {}
    completed = []
    os.environ.setdefault('VULNIMPRINT_GIT_MIRROR_CACHE',
                          str(output / 'git-mirrors'))
    for source in files:
        cve = source.stem
        result = {'cve': cve, 'manifest': str(source), 'status': 'NOT_STARTED'}
        locked = output / 'locked' / (source.name)
        try:
            freeze_manifest(source, locked, cache)
            result['locked_manifest'] = str(locked.relative_to(output))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError, ValueError, TypeError, KeyError) as exc:
            result.update(status='BLOCKED_SOURCE_ACQUISITION',
                          error=f'{type(exc).__name__}: {exc}')
            entries.append(result)
            continue
        try:
            target = output / 'cases' / cve
            report = run(locked, target, store=store)
            result.update(status=report['status'],
                          yara_x=report['yara_x_validation']['status'],
                          metrics=report['metrics'],
                          selected_rules=len(
                              json.loads(
                                  (target / 'pack.json').read_text())['rules']),
                          report=str(
                              (target / 'report.json').relative_to(output)))
            if result['status'] not in ('NO_SIGNATURE', 'QUALITY_REJECTED'):
                completed.append(target)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
                OSError, ValueError, RuntimeError, KeyError, TypeError,
                tarfile.TarError, zipfile.BadZipFile) as exc:
            result.update(status='BLOCKED_BUILD_OR_ANALYSIS',
                          error=f'{type(exc).__name__}: {exc}')
        entries.append(result)
        (output / 'batch-status.partial.json'
        ).write_text(json.dumps({'entries': entries}, indent=2) + '\n')
    dbdir = output / 'database'
    dbindex = merge_packs(completed,
                          dbdir,
                          allow_experimental=include_experimental)
    native = {'status': 'NOT_ATTEMPTED'}
    if compile_native and dbindex['included_cve_count']:
        try:
            native = {'status': 'PASS', **compile_database(dbdir)}
        except (ImportError, RuntimeError, ValueError, OSError) as exc:
            native = {
                'status': 'BLOCKED_YARA_X',
                'error': f'{type(exc).__name__}: {exc}'
            }
    elif compile_native:
        native = {'status': 'NO_ADMITTED_PACKS'}
    report = {
        'schema_version':
            1,
        'requested_cves':
            len(files),
        'completed_pipeline_cves':
            len([
                x for x in entries
                if x['status'] not in ('BLOCKED_SOURCE_ACQUISITION',
                                       'BLOCKED_BUILD_OR_ANALYSIS',
                                       'NOT_STARTED')
            ]),
        'strictly_validated_cves':
            len([
                x for x in entries if x['status'] == 'VALIDATED_ON_GIVEN_CORPUS'
            ]),
        'included_cves':
            dbindex['included_cve_count'],
        'native_database':
            native,
        'entries':
            entries,
        'interpretation':
            'Zero generated signatures is not a zero-vulnerability result. Only verified source builds and native YARA-X scans count as completed.'
    }
    (output / 'batch-report.json'
    ).write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    return report
