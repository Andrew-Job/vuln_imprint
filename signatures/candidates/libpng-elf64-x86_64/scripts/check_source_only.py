#!/usr/bin/env python3
"""Check restricted YARA-X candidate source and SHA-tied machine-code anchors.

This checks syntax using VulnImprint's conservative, restricted source checker;
it does NOT invoke the official YARA-X parser/compiler and does NOT certify CVEs.
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
    for path in sorted(db_root.glob('CVE-*/pack.json')):
        pack = json.loads(path.read_text(encoding='utf-8'))
        if pack.get('status') != 'CANDIDATE_ONLY':
            raise ValueError(f'{path}: candidate unexpectedly promoted to production')
        check_manual_source(pack, (path.parent / 'rules-exec.yar').read_text(encoding='utf-8'))
        packs.append(pack)
    if len(packs) != 5 or sum(len(pack['rules']) for pack in packs) != 25:
        raise ValueError('unexpected CVE or machine-pattern count')
    if (db_root / 'database-exec.yar').read_text(encoding='utf-8') != source_from_packs(packs):
        raise ValueError('combined YARA source differs from reviewed CVE packs')
    anchors = json.loads((db_root / 'machine-anchors.json').read_text(encoding='utf-8'))
    if set(anchors) != {'CVE-2026-33416', 'CVE-2026-34757'}:
        raise ValueError('expected machine anchor evidence is missing')
    verified = 0
    for cve, entries in anchors.items():
        rules = {rule['hex'] for pack in packs if pack['cve'] == cve for rule in pack['rules']}
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
        'status': 'OFFLINE_SOURCE_ANCHORS_CHECKED',
        'candidate_cves': len(packs),
        'patterns': sum(len(pack['rules']) for pack in packs),
        'new_real_ELF_instruction_anchors': verified,
        'native_YARA_X_compilation': False,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--project-root', required=True, type=Path)
    ap.add_argument('--db-root', type=Path, default=Path(__file__).resolve().parents[1])
    args = ap.parse_args()
    try:
        result = check(args.db_root, args.project_root)
    except (OSError, ValueError, ImportError, KeyError, TypeError) as exc:
        print(f'SOURCE CHECK FAILED: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
