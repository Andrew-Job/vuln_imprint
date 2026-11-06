#!/usr/bin/env python3
"""Use `python cli.py run --manifest ... --output ...` or `scan ...`."""
from __future__ import annotations
import argparse, json, subprocess, sys, time
from pathlib import Path
from factory.pipeline import run, reference_scan, yara_scan
from factory.database import merge_packs
from factory.batch import batch_run, freeze_manifest
from factory.yara_engine import YaraXScanner, compile_database


def main(argv=None):
    p = argparse.ArgumentParser(
        description=
        'VulnImprint Factory: manifest-driven CVE acquisition and mining')
    sub = p.add_subparsers(dest='cmd', required=True)
    gen = sub.add_parser('run', help='Mine, validate, export YARA-X pack')
    gen.add_argument('--manifest', type=Path, required=True)
    gen.add_argument('--output', type=Path, required=True)
    gen.add_argument('--store',
                     type=Path,
                     help='local content-addressed specimen store')
    multi = sub.add_parser(
        'batch',
        help=
        'Pinned source acquisition, builds, mining, and YARA-X database for many CVEs'
    )
    multi.add_argument('--catalog',
                       type=Path,
                       default=Path('run/research-catalog'))
    multi.add_argument('--output', type=Path, required=True)
    multi.add_argument('--store', type=Path)
    multi.add_argument('--include-experimental', action='store_true')
    multi.add_argument('--no-compile', action='store_true')
    freeze = sub.add_parser(
        'freeze', help='Lock upstream Git tags to full immutable commits')
    freeze.add_argument('--manifest', type=Path, required=True)
    freeze.add_argument('--output', type=Path, required=True)
    scan = sub.add_parser(
        'scan', help='Scan with YARA-X or explicit reference verifier')
    scan.add_argument('--pack', type=Path, required=True)
    scan.add_argument('--target', type=Path, required=True)
    scan.add_argument('--engine',
                      choices=['yara-x', 'reference'],
                      default='yara-x')
    db = sub.add_parser(
        'database',
        help='Compile quality-gated CVE packs into a YARA-X source database')
    db.add_argument('--packs', type=Path, required=True)
    db.add_argument('--output', type=Path, required=True)
    db.add_argument('--allow-experimental', action='store_true')
    db_compile = sub.add_parser(
        'compile-db',
        help=
        'Compile an experimental merged database using YARA-X Python bindings')
    db_compile.add_argument('--database', type=Path, required=True)
    scan_db = sub.add_parser(
        'scan-db', help='Scan ELF with persistent compiled YARA-X database')
    scan_db.add_argument('--database', type=Path, required=True)
    scan_db.add_argument('--target', type=Path, required=True)
    batch = sub.add_parser(
        'scan-batch',
        help='Scan many ELF files with one loaded YARA-X database')
    batch.add_argument('--database', type=Path, required=True)
    batch.add_argument('--directory', type=Path, required=True)
    batch.add_argument('--recursive', action='store_true')
    batch.add_argument('--output',
                       type=Path,
                       help='JSON report including findings and throughput')
    args = p.parse_args(argv)
    try:
        if args.cmd == 'freeze':
            data = freeze_manifest(args.manifest, args.output)
            print(
                json.dumps({
                    'locked': str(args.output),
                    'cve': data['cve']
                },
                           indent=2))
            return 0
        if args.cmd == 'batch':
            data = batch_run(args.catalog,
                             args.output,
                             store=args.store or args.output / 'specimen-store',
                             compile_native=not args.no_compile,
                             include_experimental=args.include_experimental)
            print(
                json.dumps(
                    {
                        'requested_cves':
                            data['requested_cves'],
                        'completed_pipeline_cves':
                            data['completed_pipeline_cves'],
                        'strictly_validated_cves':
                            data['strictly_validated_cves'],
                        'native_database':
                            data['native_database']['status']
                    },
                    indent=2))
            return 0 if data['strictly_validated_cves'] == data[
                'requested_cves'] and data['native_database'][
                    'status'] == 'PASS' else 2
        if args.cmd == 'run':
            report = run(args.manifest, args.output, store=args.store)
            print(
                json.dumps(
                    {
                        'cve': report['cve'],
                        'status': report['status'],
                        'metrics': report['metrics'],
                        'mining': report['mining']
                    },
                    indent=2))
            return 0 if report['status'] not in ('NO_SIGNATURE',
                                                 'QUALITY_REJECTED') else 2
        if args.cmd == 'database':
            obj = merge_packs([x for x in args.packs.iterdir() if x.is_dir()],
                              args.output, args.allow_experimental)
            print(json.dumps(obj, indent=2))
            return 0
        if args.cmd == 'compile-db':
            obj = compile_database(args.database)
            print(json.dumps(obj, indent=2))
            return 0
        if args.cmd == 'scan-db':
            obj = YaraXScanner.load(args.database / 'database.compiled').scan(
                args.target)
            print(json.dumps(obj, indent=2))
            return 0
        if args.cmd == 'scan-batch':
            from factory.elf import UnsupportedBinary
            start = time.perf_counter()
            scanner = YaraXScanner.load(args.database / 'database.compiled')
            loaded_seconds = time.perf_counter() - start
            files = (args.directory.rglob('*')
                     if args.recursive else args.directory.iterdir())
            findings = []
            scanned = 0
            unsupported = 0
            failed = []
            size = 0
            for path in sorted(files):
                if not path.is_file():
                    continue
                try:
                    obj = scanner.scan(path)
                except UnsupportedBinary:
                    unsupported += 1
                    continue
                except (OSError, RuntimeError) as e:
                    failed.append({'path': str(path), 'error': str(e)})
                    continue
                scanned += 1
                size += path.stat().st_size
                if obj['detected']:
                    findings.append(obj)
            seconds = time.perf_counter() - start - loaded_seconds
            result = {
                'engine':
                    'YARA-X',
                'scanned':
                    scanned,
                'unsupported':
                    unsupported,
                'errors':
                    failed,
                'hits':
                    len(findings),
                'bytes':
                    size,
                'load_seconds':
                    loaded_seconds,
                'scan_seconds':
                    seconds,
                'throughput_mib_s':
                    round(size / (1 << 20) / max(seconds, 1e-6), 3),
                'findings':
                    findings
            }
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps(result, indent=2))
            return 0 if not failed else 2
        obj = yara_scan(
            args.pack,
            args.target) if args.engine == 'yara-x' else reference_scan(
                args.pack, args.target)
        print(json.dumps(obj, indent=2))
        return 0
    except (ValueError, RuntimeError, OSError, KeyError,
            subprocess.CalledProcessError) as err:
        print(f'ERROR: {err}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
