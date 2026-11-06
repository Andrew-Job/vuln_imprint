#!/usr/bin/env python3
"""Create and lint CVE-owned manual YARA-X database records."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from tools.production_db import ReleaseRejected, CVE

HEX_BYTE = re.compile(r'(?:[A-Fa-f0-9]{2}|\?\?)\Z')


def normalized_hex(pattern: str) -> str:
    tokens = pattern.strip().split()
    if not tokens or not all(HEX_BYTE.fullmatch(token) for token in tokens):
        raise ReleaseRejected(
            'manual signatures require hexadecimal byte tokens or ?? wildcards')
    return ' '.join(token.upper() for token in tokens)


def analyze_hex(pattern: str) -> tuple[int, int]:
    tokens = normalized_hex(pattern).split()
    return len(tokens), sum('?' not in token for token in tokens)


def render_manual_source(pack: dict) -> str:
    """Render the canonical source for all records in one CVE pack."""
    if not isinstance(pack, dict) or pack.get('cve') is None:
        raise ReleaseRejected('manual CVE pack is required')
    records = pack.get('records')
    if not isinstance(records, list) or not records:
        raise ReleaseRejected('manual pack must contain records')
    for record in records:
        if record.get('source_type') != 'manual':
            raise ReleaseRejected('all records must use manual source type')
    from factory.yara_engine import source_from_packs
    try:
        return source_from_packs([pack])
    except (TypeError, ValueError, KeyError) as exc:
        raise ReleaseRejected(str(exc)) from exc


def check_manual_source(pack: dict, source: str) -> None:
    if len(source.encode('utf-8')) > 1 << 20:
        raise ReleaseRejected('manual YARA source exceeds size limit')
    if source != render_manual_source(pack):
        raise ReleaseRejected(
            'manual YARA source differs from canonical CVE pack')


def initialize(cve: str,
               patterns: list[str],
               out: Path,
               *,
               record_key: str = 'default',
               channel: str = 'test') -> dict:
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        raise ReleaseRejected('invalid CVE identifier')
    if channel not in ('test', 'production'):
        raise ReleaseRejected('channel must be test or production')
    if out.exists() and any(out.iterdir()):
        raise ReleaseRejected('manual submission directory must be empty')
    if not patterns:
        raise ReleaseRejected('at least one hex pattern required')
    from factory.signature_identity import new_record_id

    platform = {
        'os': 'linux',
        'format': 'ELF',
        'arch': 'x86-64',
        'bits': 64,
        'abi': 'sysv'
    }
    entries = []
    for index, pattern in enumerate(patterns):
        normalized = normalized_hex(pattern)
        length, fixed = analyze_hex(normalized)
        if length < 28 or fixed < 24:
            raise ReleaseRejected(
                'too-short manual rule; minimum 28 bytes / 24 completely fixed bytes'
            )
        entries.append({
            'id': f'{cve}-manual-{index:02d}',
            'hex': normalized,
            'length': length,
            'fixed_bytes': fixed,
        })
    pack = {
        'schema_version':
            3,
        'cve':
            cve,
        'records': [{
            'record_id':
                new_record_id(cve, record_key),
            'channel':
                channel,
            'source_type':
                'manual',
            'platform':
                platform,
            'supported_profiles': [],
            'rules':
                entries,
            'notes':
                'Manual machine-code record; correctness is evaluated separately.',
        }],
    }
    source = render_manual_source(pack)
    check_manual_source(pack, source)
    out.mkdir(parents=True, exist_ok=True)
    (out / 'pack.json').write_text(json.dumps(pack, indent=2, sort_keys=True) +
                                   '\n',
                                   encoding='utf-8')
    (out / 'rules-exec.yar').write_text(source, encoding='utf-8')
    return pack


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Initialize or lint a CVE-owned manual YARA-X record')
    sub = parser.add_subparsers(dest='cmd', required=True)
    init = sub.add_parser('init')
    init.add_argument('--cve', required=True)
    init.add_argument('--hex',
                      action='append',
                      required=True,
                      help='YARA hex byte tokens; repeat for alternatives')
    init.add_argument('--record-key',
                      default='default',
                      help='stable key when a CVE owns multiple records')
    init.add_argument('--channel',
                      choices=('test', 'production'),
                      default='test')
    init.add_argument('--output', type=Path, required=True)
    lint = sub.add_parser('lint')
    lint.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == 'init':
            pack = initialize(args.cve,
                              args.hex,
                              args.output,
                              record_key=args.record_key,
                              channel=args.channel)
        else:
            pack = json.loads((args.directory / 'pack.json').read_text())
            check_manual_source(pack,
                                (args.directory / 'rules-exec.yar').read_text())
        print(
            json.dumps(
                {
                    'status': 'PASS',
                    'cve': pack['cve'],
                    'record_count': len(pack['records']),
                    'channel': pack['records'][0]['channel'],
                },
                sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'MANUAL RULE REJECTED: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
