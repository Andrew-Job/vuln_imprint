#!/usr/bin/env python3
"""Smoke-build compiler lanes and report exact toolchain provenance.

CVE tests still require independent patch-state holds; this command only
verifies that the requested compiler versions are genuinely installed and can
produce an x86_64 ELF executable with both release optimization profiles.
"""
from __future__ import annotations
import argparse
import json
import hashlib
import subprocess
import tempfile
from pathlib import Path
from factory.toolchains import probe_compiler, ToolchainMismatch

DEFAULT_LANES = ('gcc-11', 'gcc-12', 'clang-14', 'clang-15')


def check_lanes(lanes=DEFAULT_LANES) -> list[dict]:
    seen = set()
    report = []
    with tempfile.TemporaryDirectory(
            prefix='vulnimprint-toolchain-') as directory:
        root = Path(directory)
        source = root / 'marker.c'
        source.write_text(
            'volatile int marker=0x519a7; int main(void){return marker==0;}\n')
        for name in lanes:
            for opt in ('-O2', '-O3'):
                record = probe_compiler(name, optimization=opt)
                if (record['family'], record['major'], opt) in seen:
                    raise ToolchainMismatch(
                        f'duplicate toolchain lane: {name}/{opt}')
                seen.add((record['family'], record['major'], opt))
                target = root / (name + '-' + opt[1:])
                subprocess.run(
                    [record['executable'], opt,
                     str(source), '-o',
                     str(target)],
                    check=True,
                    timeout=60,
                    capture_output=True)
                header = target.open('rb').read(5)
                if header != b'\x7fELF\x02':
                    raise ToolchainMismatch(f'{name}: not an ELF64 executable')
                with target.open('rb') as stream:
                    record['test_artifact_sha256'] = hashlib.file_digest(
                        stream, 'sha256').hexdigest()
                report.append(record)
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path)
    parser.add_argument('--lanes', nargs='+', default=list(DEFAULT_LANES))
    args = parser.parse_args()
    try:
        result = {
            'schema_version': 1,
            'status': 'PASS',
            'builds': check_lanes(args.lanes)
        }
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(
                json.dumps(result, sort_keys=True, indent=2) + '\n')
        print(
            json.dumps({
                'status':
                    'PASS',
                'build_count':
                    len(result['builds']),
                'compilers':
                    sorted({
                        (r['family'], r['version']) for r in result['builds']
                    })
            }))
    except (ToolchainMismatch, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        print('TOOLCHAIN MATRIX FAILED:', error)
        raise SystemExit(2)


if __name__ == '__main__':
    main()
