#!/usr/bin/env python3
"""Screen CVE byte masks against SHA-pinned ELF64-x86-64 control binaries.

A reference byte matcher is used for quick candidate screening, not as a
replacement for YARA-X or a claim of production acceptance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

from factory.patterns import Pattern
from tools.manual_rules import analyze_hex, normalized_hex

_CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')
_HASH = re.compile(r'[a-f0-9]{64}\Z')
_LABELS = {'affected', 'fixed', 'backport', 'unrelated'}


class SampleError(ValueError):
    pass


def _executable_regions(path: Path) -> list[tuple[int, bytes]]:
    data = path.read_bytes()
    if (len(data) < 64 or data[:4] != b'\x7fELF' or data[4] != 2 or
            data[5] != 1 or int.from_bytes(data[18:20], 'little') != 62):
        raise SampleError(f'{path}: expected little-endian x86-64 ELF64')
    try:
        output = subprocess.check_output(
            ['readelf', '-Wl', str(path)],
            text=True,
            stderr=subprocess.PIPE,
            timeout=30)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired,
            FileNotFoundError) as exc:
        raise SampleError(f'{path}: readelf failed: {exc}') from exc
    regions = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[0] != 'LOAD':
            continue
        # readelf -Wl: LOAD offset vaddr paddr filesz memsz flags align
        if not any('E' in flag for flag in fields[6:-1]):
            continue
        try:
            start, size = int(fields[1], 16), int(fields[4], 16)
        except ValueError as exc:
            raise SampleError(f'{path}: invalid readelf LOAD segment') from exc
        if start < 0 or size < 0 or start + size > len(data):
            raise SampleError(f'{path}: executable segment exceeds file bounds')
        if size:
            regions.append((start, data[start:start + size]))
    if not regions:
        raise SampleError(f'{path}: no executable PT_LOAD data')
    return regions


def _patterns(args) -> tuple[str, list[Pattern]]:
    if args.pack:
        from tools.production_db import validate_source_pack
        pack_path = args.pack
        pack = json.loads(pack_path.read_text(encoding='utf-8'))
        if pack.get('cve') != args.cve:
            raise SampleError('pack CVE differs from requested CVE')
        validate_source_pack(pack,
                             pack_path.parent / 'rules-exec.yar',
                             packfile=pack_path)
        strings = [
            rule['hex']
            for record in pack['records']
            for rule in record['rules']
        ]
        return 'existing-cve-pack', [Pattern.from_hex(x) for x in strings]
    strings = [normalized_hex(x) for x in args.hex]
    if not strings:
        raise SampleError('supply --hex (repeatable) or --pack')
    for string in strings:
        length, fixed = analyze_hex(string)
        if length < 28 or fixed < 24:
            raise SampleError(
                'each mask requires >=28 bytes and >=24 fixed bytes')
    return 'proposed-hex', [Pattern.from_hex(x) for x in strings]


def evaluate(cve: str, manifest: Path, patterns: list[Pattern],
             origin: str) -> dict:
    if not _CVE.fullmatch(cve):
        raise SampleError('invalid CVE ID')
    specification = json.loads(manifest.read_text(encoding='utf-8'))
    if specification.get('schema_version') != 1 or specification.get(
            'cve') != cve:
        raise SampleError('invalid sample manifest schema or CVE')
    entries = specification.get('samples')
    if not isinstance(entries, list) or not entries:
        raise SampleError('sample manifest is empty')
    counts = {key: 0 for key in _LABELS}
    seen_ids = set()
    seen_digests = set()
    results = []
    for item in entries:
        if not isinstance(item, dict):
            raise SampleError('sample entry must be an object')
        sid, label, digest = (item.get(x) for x in ('id', 'label', 'sha256'))
        if not isinstance(sid, str) or not sid or sid in seen_ids:
            raise SampleError(f'invalid/duplicate sample id: {sid}')
        if label not in _LABELS:
            raise SampleError(f'{sid}: unsupported ground-truth label')
        if not isinstance(digest, str) or not _HASH.fullmatch(digest):
            raise SampleError(f'{sid}: invalid pinned sha256')
        if digest in seen_digests:
            raise SampleError(
                f'{sid}: repeated binary digest is not a new sample')
        if not item.get('label_basis') or not item.get('origin'):
            raise SampleError(f'{sid}: origin and ground-truth basis required')
        name = item.get('path')
        if not isinstance(name, str) or not name:
            raise SampleError(f'{sid}: missing binary path')
        path = Path(name).expanduser()
        if not path.is_absolute():
            path = (manifest.resolve().parent / path).resolve()
        if not path.is_file() or path.is_symlink():
            raise SampleError(f'{sid}: binary missing or symlink: {path}')
        with path.open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != digest:
            raise SampleError(f'{sid}: SHA-256 mismatch')
        regions = _executable_regions(path)
        hit_details = []
        for index, pattern in enumerate(patterns):
            hit_details.extend({
                'pattern_index': index,
                'file_offset': offset
            } for offset in pattern.search(regions))
        hit_details.sort(key=lambda h: (h['file_offset'], h['pattern_index']))
        expected = label == 'affected'
        observed = bool(hit_details)
        counts[label] += 1
        seen_ids.add(sid)
        seen_digests.add(digest)
        results.append({
            'id': sid,
            'label': label,
            'sha256': digest,
            'matched': observed,
            'expected_match': expected,
            'passed': observed == expected,
            'matches': hit_details,
        })
    if not counts['affected'] or not counts['fixed'] or not counts['unrelated']:
        raise SampleError('affected, fixed and unrelated controls are required')
    # A preliminary screen need not have a large corpus, but never silently
    # presents a positive-only set as a successful discriminating signature.
    passed = all(item['passed'] for item in results)
    return {
        'schema_version':
            1,
        'cve':
            cve,
        'method':
            'reference-match/executable-PT_LOAD',
        'source':
            origin,
        'status':
            'PASS_PRELIMINARY' if passed else 'FAIL_PRELIMINARY',
        'native_yara_x_executed':
            False,
        'production_admission':
            False,
        'counts':
            dict(sorted(counts.items())),
        'pattern_count':
            len(patterns),
        'patterns_sha256':
            hashlib.sha256('\n'.join(
                p.to_hex() for p in patterns).encode('ascii')).hexdigest(),
        'results':
            results,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cve', required=True)
    parser.add_argument('--samples', required=True, type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--hex',
                       action='append',
                       help='candidate byte mask; repeat for variants')
    group.add_argument('--pack',
                       type=Path,
                       help='CVE pack.json and adjacent canonical YARA rules')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        source, patterns = _patterns(args)
        result = evaluate(args.cve, args.samples, patterns, source)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) +
                               '\n',
                               encoding='utf-8')
        print(
            json.dumps(
                {
                    'cve': args.cve,
                    'status': result['status'],
                    'results': len(result['results']),
                    'report': str(args.output)
                },
                sort_keys=True))
        return 0 if result['status'] == 'PASS_PRELIMINARY' else 2
    except (OSError, ValueError, TypeError, KeyError,
            subprocess.CalledProcessError) as exc:
        print(f'BINARY SAMPLE CHECK REJECTED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
