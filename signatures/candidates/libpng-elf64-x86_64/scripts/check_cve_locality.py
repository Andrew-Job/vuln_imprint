#!/usr/bin/env python3
"""Check that new CVE prototype hits lie in expected libpng exported functions.

This check executes the project reference matcher (not YARA-X). It requires the
exact binary samples from specimen-inventory.json; all SHA-256s are checked.
The local binary paths in that evidence file are environment-specific.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

EXPECTED = {
    'CVE-2026-33416': frozenset({'png_set_PLTE', 'png_set_tRNS'}),
    'CVE-2026-34757': frozenset({'png_set_hIST'}),
}
POSITIVES = frozenset({'rdkit', 'fiona', 'cadquery', 'opencv', 'rasterio', 'torchvision', 'pedalboard'})
NEGATIVES = frozenset({'debian', 'pillow'})


def readelf_symbols(path: Path, names: frozenset[str]):
    output = subprocess.check_output(['readelf', '-W', '--dyn-syms', str(path)], text=True)
    symbols = []
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) < 8 or tokens[3] != 'FUNC':
            continue
        name = tokens[7].split('@')[0]
        if name in names:
            symbols.append((int(tokens[1], 16), int(tokens[2]), name))
    if not symbols:
        raise ValueError(f'no exported expected functions found in {path}')
    return symbols


def readelf_exec_segments(path: Path, raw: bytes):
    output = subprocess.check_output(['readelf', '-Wl', str(path)], text=True)
    segments = []
    for line in output.splitlines():
        tokens = line.split()
        if len(tokens) > 7 and tokens[0] == 'LOAD' and 'E' in tokens[6:-1]:
            offset, vaddr, size = int(tokens[1], 16), int(tokens[2], 16), int(tokens[4], 16)
            if offset < 0 or size <= 0 or offset + size > len(raw):
                raise ValueError(f'invalid executable segment bounds in {path}')
            segments.append((offset, vaddr, size))
    if not segments:
        raise ValueError(f'no executable PT_LOAD for {path}')
    return segments


def run(db_root: Path, project_root: Path):
    sys.path.insert(0, str(project_root))
    from factory.patterns import Pattern

    samples = json.loads((db_root / 'evidence/specimen-inventory.json').read_text())
    if len(samples) != 9:
        raise ValueError('expected exactly nine reference libpng specimens')
    by_cve = {}
    for cve, functions in EXPECTED.items():
        pack = json.loads((db_root / cve / 'pack.json').read_text())
        patterns = [Pattern.from_hex(rule['hex']) for rule in pack['rules']]
        by_cve[cve] = []
        for record in samples:
            sample_id = record['id']
            if sample_id not in POSITIVES | NEGATIVES:
                raise ValueError(f'unknown specimen {sample_id}')
            path = Path(record['local_path'])
            raw = path.read_bytes()
            if hashlib.sha256(raw).hexdigest() != record['sha256']:
                raise ValueError(f'specimen SHA-256 mismatch: {sample_id}')
            symbols = readelf_symbols(path, functions)
            segments = readelf_exec_segments(path, raw)
            hit_count = 0
            names = set()
            # Search entire ELF, not only executable ranges, to catch accidental hits
            # outside of the expected function as well.
            for pattern in patterns:
                for offset in pattern.search([(0, raw)]):
                    end = offset + len(pattern.data)
                    location = None
                    for file_off, vaddr, length in segments:
                        if file_off <= offset and end <= file_off + length:
                            hit_va = vaddr + offset - file_off
                            for base, size, name in symbols:
                                if base <= hit_va and hit_va + len(pattern.data) <= base + size:
                                    location = name
                                    break
                    if location is None:
                        raise ValueError(f'{cve}/{sample_id}: unexpected or out-of-function hit at {offset:#x}')
                    hit_count += 1
                    names.add(location)
            if sample_id in POSITIVES and not hit_count:
                raise ValueError(f'{cve}/{sample_id}: missing affected-implementation hit')
            if sample_id in NEGATIVES and hit_count:
                raise ValueError(f'{cve}/{sample_id}: hit on fixed-implementation control')
            by_cve[cve].append({'specimen': sample_id, 'hits': hit_count, 'functions': sorted(names)})
    return {
        'state': 'OFFLINE_MATCH_LOCALITY_CHECKED_NOT_YARA_X_RUNTIME',
        'total_sample_checks': sum(map(len, by_cve.values())),
        'new_cves': by_cve,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', required=True, type=Path)
    parser.add_argument('--db-root', default=Path(__file__).resolve().parents[1], type=Path)
    args = parser.parse_args()
    try:
        result = run(args.db_root, args.project_root)
    except (OSError, ValueError, KeyError, IndexError, subprocess.CalledProcessError) as exc:
        print(f'LOCALITY CHECK FAILED: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
