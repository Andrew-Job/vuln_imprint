#!/usr/bin/env python3
"""Check CVE-owned YARA source and SHA-tied machine-code anchors.

This verifies source consistency only. It does not invoke YARA-X or certify
detector correctness.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def check(db_root: Path, project_root: Path) -> dict:
    sys.path.insert(0, str(project_root))
    from factory.patterns import Pattern
    from factory.yara_engine import source_from_packs
    from tools.manual_rules import check_manual_source

    packs = []
    baseline = ('CVE-2026-22695', 'CVE-2026-22801', 'CVE-2026-25646',
                'CVE-2026-33416', 'CVE-2026-34757')
    for cve in baseline:
        path = project_root / 'signatures' / cve / 'pack.json'
        pack = json.loads(path.read_text(encoding='utf-8'))
        if pack.get('schema_version') != 3 or not pack.get('records'):
            raise ValueError(f'{path}: invalid CVE pack schema')
        for record in pack['records']:
            if record.get('channel') != 'production':
                raise ValueError(f'{path}: record is not in production channel')
        check_manual_source(pack, (path.parent / 'rules-exec.yar').read_text(encoding='utf-8'))
        packs.append(pack)
    pattern_count = sum(len(record['rules']) for pack in packs
                        for record in pack['records'])
    if len(packs) != 5 or pattern_count != 25:
        raise ValueError('unexpected CVE or machine-pattern count')
    if (db_root / 'database-exec.yar').read_text(encoding='utf-8') != source_from_packs(packs):
        raise ValueError('combined YARA source differs from CVE packs')
    anchors = json.loads((db_root / 'machine-anchors.json').read_text(encoding='utf-8'))
    if set(anchors) != {'CVE-2026-33416', 'CVE-2026-34757'}:
        raise ValueError('expected machine anchor evidence is missing')
    verified = 0
    for cve, entries in anchors.items():
        rules = {rule['hex'] for pack in packs if pack['cve'] == cve
                 for record in pack['records'] for rule in record['rules']}
        if len(entries) != len(rules):
            raise ValueError(f'{cve}: machine anchor count does not match the rules')
        for anchor in entries:
            if anchor['hex'] not in rules:
                raise ValueError(f'{cve}: source mask has no matching machine anchor')
            pattern = Pattern.from_hex(anchor['hex'])
            raw = bytes.fromhex(anchor['raw_bytes'])
            if len(raw) != anchor['bytes'] or len(raw) != len(pattern.data):
                raise ValueError(f'{cve}: incorrect machine anchor length')
            if pattern.fixed != anchor['fixed_bytes'] or pattern.fixed < 24:
                raise ValueError(f'{cve}: machine mask contains too few fixed bytes')
            if not pattern.matches_at(raw, 0):
                raise ValueError(f'{cve}: mask does not match its original bytecode')
            first_fixed = pattern.mask.index(255)
            mutant = bytearray(raw)
            mutant[first_fixed] ^= 0xFF
            if pattern.matches_at(mutant, 0):
                raise ValueError(f'{cve}: mutation of a fixed byte is still accepted')
            verified += 1
    if verified != 15:
        raise ValueError('missing new real-machine anchors')
    return {
        'status': 'PASS',
        'channel': 'production',
        'cve_count': len(packs),
        'record_count': sum(len(pack['records']) for pack in packs),
        'patterns': pattern_count,
        'new_real_ELF_instruction_anchors': verified,
        'native_YARA_X_compilation': False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', required=True, type=Path)
    parser.add_argument('--db-root', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result = check(args.db_root, args.project_root)
    except (OSError, ValueError, ImportError, KeyError, TypeError) as exc:
        print(f'SOURCE CHECK FAILED: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
