#!/usr/bin/env python3
"""Manual CVE hex signatures: author standard YARA-X sources without bypassing QA.

No source generated here enters the production DB automatically. The release
validator consumes an independently reviewed case + real affected/fixed controls.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.production_db import ReleaseRejected, CVE

HEX_BYTE = re.compile(r'(?:[A-Fa-f0-9]{2}|\?\?)\Z')
RULE_ID = re.compile(r'[A-Za-z_][A-Za-z_0-9]*\Z')


def canonical_rule_id(cve: str) -> str:
    if not CVE.fullmatch(cve):
        raise ReleaseRejected('invalid CVE ID')
    return cve.replace('-', '_') + '_ELF64_x86_64'


def normalized_hex(pattern: str) -> str:
    tokens = pattern.strip().split()
    if not tokens or not all(HEX_BYTE.fullmatch(t) for t in tokens):
        raise ReleaseRejected(
            'this pilot supports YARA hexadecimal byte tokens (including ??), not jumps or regexes'
        )
    return ' '.join(t.upper() for t in tokens)


def analyze_hex(pattern: str) -> tuple[int, int]:
    tokens = normalized_hex(pattern).split()
    return len(tokens), sum('?' not in t for t in tokens)


def check_manual_source(pack: dict, source: str) -> None:
    """Restricted manual YARA subset: one globally unique rule, hex only.

    The native YARA-X compiler validates the actual language. These checks bind
    its source strings and metadata to the manifest and reject external includes.
    """
    cve = pack['cve']
    rid = canonical_rule_id(cve)
    if pack.get('source_type') != 'manual':
        raise ReleaseRejected(f'{cve}: manual source type is required')
    if len(source.encode()) > 1 << 20:
        raise ReleaseRejected(f'{cve}: manual rule exceeds size limit')
    # Fail closed on ambiguous constructs; neither include files nor module imports
    # are necessary for ELF executable byte-range fingerprinting.
    if re.search(r'\b(include|import|private|global)\b', source):
        raise ReleaseRejected(
            f'{cve}: include/import/global/private not allowed in manual source'
        )
    headers = re.findall(r'\brule\s+([A-Za-z_][A-Za-z_0-9]*)\s*(?::[^{}]*)?\{',
                         source)
    if headers != [rid]:
        raise ReleaseRejected(
            f'{cve}: exactly one rule named {rid} is required')
    if re.findall(r'\bcve\s*=\s*"([^"]+)"', source) != [cve]:
        raise ReleaseRejected(f'{cve}: CVE metadata must be exact and unique')
    if re.findall(r'\bevidence\s*=\s*"([^"]+)"',
                  source) != [pack.get('status')]:
        raise ReleaseRejected(
            f'{cve}: evidence metadata must equal pack status')
    # The first public profile intentionally accepts only a single, explicit
    # any-of-hex-patterns condition. More expressive YARA semantics must receive
    # a separate reviewed parser/validator rather than regex-based admission.
    if not re.search(r'\bcondition\s*:\s*any\s+of\s+them\s*\}\s*\Z', source):
        raise ReleaseRejected(
            f'{cve}: manual condition must be exactly any of them')
    matches = re.findall(r'\$([A-Za-z_][A-Za-z_0-9]*)\s*=\s*\{([^{}]+)\}',
                         source)
    if len(matches) != len(pack['rules']) or not matches:
        raise ReleaseRejected(
            f'{cve}: each declared hex pattern must be present exactly once')
    if len({name for name, _ in matches}) != len(matches):
        raise ReleaseRejected(f'{cve}: duplicate YARA string identifier')
    expected = [normalized_hex(rule['hex']) for rule in pack['rules']]
    actual = [normalized_hex(body) for _, body in matches]
    if actual != expected:
        raise ReleaseRejected(f'{cve}: YARA bytes differ from reviewed pack')
    # Reject extra literal or regex string definitions, even if not used by the condition.
    all_definitions = re.findall(r'\$[A-Za-z_][A-Za-z_0-9]*\s*=', source)
    if len(all_definitions) != len(matches):
        raise ReleaseRejected(
            f'{cve}: manual signatures must use approved hex strings only')


def initialize(cve: str, patterns: list[str], out: Path) -> dict:
    if out.exists() and any(out.iterdir()):
        raise ReleaseRejected('manual submission directory must be empty')
    if not patterns:
        raise ReleaseRejected('at least one hex pattern required')
    rid = canonical_rule_id(cve)
    entries = []
    for i, pattern in enumerate(patterns):
        norm = normalized_hex(pattern)
        length, fixed = analyze_hex(norm)
        if length < 28 or fixed < 24:
            raise ReleaseRejected(
                'too-short manual rule; minimum 28 bytes / 24 completely fixed bytes'
            )
        entries.append({
            'id': f'{cve}-manual-{i:02d}',
            'hex': norm,
            'length': length,
            'fixed_bytes': fixed
        })
    pack = {
        'schema_version':
            1,
        'cve':
            cve,
        'source_type':
            'manual',
        'status':
            'CANDIDATE_ONLY',
        'platform': {
            'os': 'linux',
            'format': 'ELF',
            'arch': 'x86-64',
            'bits': 64,
            'abi': 'sysv'
        },
        'rules':
            entries,
        'notes':
            'Manual hypothesis only; no production admission until independent reviewed evidence passes.'
    }
    lines = [
        f'rule {rid} : vuln_imprint manual {{', '  meta:', f'    cve = "{cve}"',
        '    evidence = "CANDIDATE_ONLY"', '  strings:'
    ]
    for i, item in enumerate(entries):
        lines.append(f'    $v{i} = {{ {item["hex"]} }}')
    lines.extend(['  condition:', '    any of them', '}', ''])
    source = '\n'.join(lines)
    check_manual_source(pack, source)
    out.mkdir(parents=True, exist_ok=True)
    (out /
     'pack.json').write_text(json.dumps(pack, indent=2, sort_keys=True) + '\n')
    (out / 'rules-exec.yar').write_text(source)
    return pack


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description=
        'Initialize or statically check a human-authored CVE YARA-X rule')
    sub = p.add_subparsers(dest='cmd', required=True)
    a = sub.add_parser('init')
    a.add_argument('--cve', required=True)
    a.add_argument('--hex',
                   action='append',
                   required=True,
                   help='YARA hex byte tokens, repeat for alternatives')
    a.add_argument('--output', type=Path, required=True)
    v = sub.add_parser('lint')
    v.add_argument('--directory', type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.cmd == 'init':
            pack = initialize(args.cve, args.hex, args.output)
        else:
            pack = json.loads((args.directory / 'pack.json').read_text())
            check_manual_source(pack,
                                (args.directory / 'rules-exec.yar').read_text())
        print(
            json.dumps({
                'status': 'MANUAL_SOURCE_CHECKED_NOT_VALIDATED',
                'cve': pack['cve']
            }))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f'MANUAL RULE REJECTED: {e}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
