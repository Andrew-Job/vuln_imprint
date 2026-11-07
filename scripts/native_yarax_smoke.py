#!/usr/bin/env python3
"""Mandatory native YARA-X C API integration test (never mocks or skips).

Builds genuinely stripped ELF positives/negatives with the system C compiler,
compiles/saves/loads a YARA-X DB through the C++ binary, and verifies that
only executable code is scanned by default. Run in CI *after* cargo cinstall.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

# Unusual marker chosen to avoid coincidental matches in compiler runtime code.
MARKER = 'DE AD 51 61 C3 40 28 7F 92 12 83 4A 18 6F A5 3B'
HEX_C = ', '.join('0x' + b.lower() for b in MARKER.split())
RULE = '''rule VI_111111111111111111111111 {
  meta:
    cve = "CVE-2099-90001"
  strings:
    $marker = { %s }
  condition:
    any of them
}
rule VI_333333333333333333333333 {
  meta:
    cve = "CVE-2099-90001"
  strings:
    $marker = { %s }
  condition:
    any of them
}
rule VI_222222222222222222222222 {
  meta:
    cve = "CVE-2099-90002"
  strings:
    $marker = { %s }
  condition:
    any of them
}
''' % (MARKER, MARKER, MARKER)


def run(*cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    if check and result.returncode != 0:
        raise RuntimeError(
            f'Command failed ({result.returncode}): {cmd!r}\n'
            f'stdout={result.stdout[-2000:]}\nstderr={result.stderr[-2000:]}')
    return result


def scan(scanner: Path, *args: str) -> dict:
    result = run(str(scanner), 'scan', *args)
    data = json.loads(result.stdout)
    assert data['engine'] == 'yara-x', data
    assert isinstance(data.get('results'), list), data
    return data


def matches(report: dict, expected: int) -> list:
    results = report['results']
    assert len(results) == 1, report
    assert results[0]['error'] is None, report
    assert results[0]['truncated'] is False, report
    actual = results[0]['matches']
    assert len(actual) == expected, (expected, report)
    return actual


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--scanner', type=Path, required=True)
    parser.add_argument('--cc', default='cc')
    parser.add_argument('--strip', default='strip')
    args = parser.parse_args()
    scanner = args.scanner.resolve()
    if not scanner.is_file():
        raise RuntimeError(f'No native C++ scanner binary: {scanner}')
    for tool in (args.cc, args.strip):
        if shutil.which(tool) is None:
            raise RuntimeError(f'Missing native compilation tool: {tool}')

    with tempfile.TemporaryDirectory(prefix='vulnimprint-native-') as td:
        tmp = Path(td)
        # Compiler must not transform/remove the signature itself. The bytes
        # are emitted in an opaque assembler block of an externally used function.
        positive_src = tmp / 'affected.c'
        positive_src.write_text('''
__attribute__((noinline,used)) void vi_marker(void) {
  __asm__ volatile (".byte %s" ::: "memory");
}
int main(void) { vi_marker(); return 0; }
''' % HEX_C)
        negative_src = tmp / 'fixed.c'
        negative_src.write_text('''
int main(void) { return 0; }
''')
        data_src = tmp / 'data_only.c'
        data_src.write_text('''
__attribute__((used)) const unsigned char vulnerable_looking_data[] = {%s};
int main(void) { return vulnerable_looking_data[0] == 0; }
''' % HEX_C)
        elf = {}
        for name, src in [('affected', positive_src), ('fixed', negative_src),
                          ('data_only', data_src)]:
            output = tmp / name
            run(args.cc, '-O2', str(src), '-o', str(output))
            run(args.strip, '--strip-all', str(output))
            elf[name] = output
        rules = tmp / 'rules.yar'
        rules.write_text(RULE)
        compiled = tmp / 'compiled.yarc'
        run(str(scanner), 'compile', '--rules', str(rules), '--output',
            str(compiled))
        verified = json.loads(
            run(str(scanner), 'verify', '--compiled', str(compiled)).stdout)
        assert verified['engine'] == 'yara-x' and verified[
            'rules'] == 3, verified
        assert verified['db_sha256'] == hashlib.sha256(
            compiled.read_bytes()).hexdigest(), verified

        affected = scan(scanner, '--compiled', str(compiled), '--json',
                        str(elf['affected']))
        affected_hits = matches(affected, 3)
        assert {hit['cve'] for hit in affected_hits
               } == {'CVE-2099-90001', 'CVE-2099-90002'}, affected_hits
        assert {hit['record_id'] for hit in affected_hits} == {
            'VI_111111111111111111111111', 'VI_222222222222222222222222',
            'VI_333333333333333333333333'
        }, affected_hits
        assert affected['cve_count'] == 2 and affected[
            'pattern_hits'] == 3, affected
        assert affected['unique_cves'] == ['CVE-2099-90001',
                                           'CVE-2099-90002'], affected
        for hit in affected_hits:
            assert hit['pattern'].lstrip('$') == 'marker', hit
            assert hit['rule'] == hit['record_id'], hit
            assert hit['length'] == len(
                MARKER.split()) and hit['executable'] is True, hit
            file_offset = int(hit['file_offset'], 16)
            assert elf['affected'].read_bytes()[file_offset:file_offset +
                                                hit['length']] == bytes.fromhex(
                                                    MARKER), hit
            assert hit['virtual_address'] is not None, hit

        # The YARA-X engine suppresses offsets at its own per-pattern limit.
        # We must signal potentially incomplete reports, even when the
        # VulnImprint-wide hit cap has not been reached.
        capped = run(str(scanner),
                     'scan',
                     '--compiled',
                     str(compiled),
                     '--max-per-pattern',
                     '1',
                     '--json',
                     str(elf['affected']),
                     check=False)
        assert capped.returncode == 2, capped
        capped_report = json.loads(capped.stdout)
        assert len(capped_report['results']) == 1, capped_report
        assert capped_report['results'][0]['truncated'] is True, capped_report
        assert len(capped_report['results'][0]['matches']) == 3, capped_report

        source_hits = matches(
            scan(scanner, '--rules', str(rules), '--json',
                 str(elf['affected'])), 3)
        assert {item['file_offset'] for item in source_hits
               } == {item['file_offset'] for item in affected_hits
                    }, (source_hits, affected_hits)

        # User-supplied rules without CVE metadata must not fabricate CVE or
        # VulnImprint record identities.
        custom_rules = tmp / 'custom.yar'
        custom_rules.write_text('rule CUSTOM_RULE {\n'
                                '  strings:\n'
                                f'    $marker = {{ {MARKER} }}\n'
                                '  condition:\n'
                                '    any of them\n'
                                '}\n')
        custom_report = scan(scanner, '--rules', str(custom_rules), '--json',
                             str(elf['affected']))
        custom_hits = matches(custom_report, 1)
        assert custom_hits[0]['cve'] is None, custom_hits
        assert custom_hits[0]['record_id'] is None, custom_hits
        assert custom_hits[0]['rule'] == 'CUSTOM_RULE', custom_hits
        assert custom_report['cve_count'] == 0, custom_report
        assert custom_report['unique_cves'] == [], custom_report

        # Invalid CVE metadata and an unrelated user-defined "issue" field
        # must not create CVE identities or fail an otherwise valid scan.
        invalid_meta = tmp / 'invalid-meta.yar'
        invalid_meta.write_text('rule CUSTOM_METADATA {\n'
                                '  meta:\n'
                                '    cve = "not-a-cve"\n'
                                '    issue = "CVE-2099-90001"\n'
                                '  strings:\n'
                                f'    $marker = {{ {MARKER} }}\n'
                                '  condition:\n'
                                '    any of them\n'
                                '}\n')
        untrusted = scan(scanner, '--rules', str(invalid_meta), '--json',
                         str(elf['affected']))
        untrusted_hits = matches(untrusted, 1)
        assert untrusted_hits[0]['cve'] is None, untrusted_hits
        assert untrusted_hits[0]['record_id'] is None, untrusted_hits
        assert untrusted['cve_count'] == 0, untrusted

        matches(
            scan(scanner, '--compiled', str(compiled), '--json',
                 str(elf['fixed'])), 0)

        # --all-sections is not an escape hatch to a raw-byte scanner.
        # An unsupported file or architecture must yield an explicit error
        # and a nonzero process status even if it happens to contain a hit.
        invalid_target = tmp / 'not-elf.bin'
        invalid_target.write_bytes(bytes.fromhex(MARKER))
        wrong_arch = tmp / 'wrong-arch.elf'
        wrong_arch.write_bytes(elf['affected'].read_bytes())
        with wrong_arch.open('r+b') as image:
            image.seek(18)
            image.write(b'\x03\x00')  # EM_386, not x86-64
        for target in (invalid_target, wrong_arch):
            for switch in ((), ('--all-sections',)):
                invalid_scan = run(str(scanner),
                                   'scan',
                                   '--compiled',
                                   str(compiled),
                                   *switch,
                                   '--json',
                                   str(target),
                                   check=False)
                assert invalid_scan.returncode == 2, invalid_scan
                error_report = json.loads(invalid_scan.stdout)
                assert error_report['errors'] == 1, error_report
                assert len(error_report['results']) == 1, error_report
                assert error_report['results'][0]['error'], error_report
                assert error_report['results'][0]['matches'] == [], error_report

        # Linux filenames can contain arbitrary bytes except NUL and slash.
        # JSON must remain valid UTF-8 and retain an unambiguous raw path.
        invalid_name = tmp / os.fsdecode(b'invalid_\xff.elf')
        shutil.copy2(elf['fixed'], invalid_name)
        unicode_report = scan(scanner, '--compiled', str(compiled), '--json',
                              str(invalid_name))
        assert unicode_report['results'][0]['file_bytes_hex'] == (os.fsencode(
            str(invalid_name)).hex()), unicode_report
        assert '\ufffd' in unicode_report['results'][0]['file'], unicode_report
        assert unicode_report['results'][0]['error'] is None, unicode_report

        # The parser must reject overflow before converting to unsigned int.
        bad_threads = run(str(scanner),
                          'scan',
                          '--compiled',
                          str(compiled),
                          '--threads',
                          '4294967297',
                          '--json',
                          str(elf['fixed']),
                          check=False)
        assert bad_threads.returncode == 2, bad_threads
        matches(
            scan(scanner, '--compiled', str(compiled), '--json',
                 str(elf['data_only'])), 0)
        rodata_hits = matches(
            scan(scanner, '--compiled', str(compiled), '--all-sections',
                 '--json', str(elf['data_only'])), 3)
        for item in rodata_hits:
            assert item['executable'] is False, item
            assert item['virtual_address'] is None, item

        # Full-file scanning must preserve executable classification and the
        # linked ELF virtual address for the same bytes in .text.
        whole_file_hits = matches(
            scan(scanner, '--compiled', str(compiled), '--all-sections',
                 '--json', str(elf['affected'])), 3)
        for item in whole_file_hits:
            assert item['executable'] is True, item
        assert {item['record_id'] for item in whole_file_hits
               } == {item['record_id'] for item in affected_hits
                    }, whole_file_hits
        assert {item['file_offset'] for item in whole_file_hits
               } == {item['file_offset'] for item in affected_hits
                    }, whole_file_hits
        assert {item['virtual_address'] for item in whole_file_hits
               } == {item['virtual_address'] for item in affected_hits
                    }, whole_file_hits

        # Relocatable ET_REL objects contain executable code but have not been
        # assigned a linked virtual address. Do not substitute sh_addr=0.
        relocatable = tmp / 'affected.o'
        run(args.cc, '-O2', '-c', str(positive_src), '-o', str(relocatable))
        for switch in ((), ('--all-sections',)):
            object_hits = matches(
                scan(scanner, '--compiled', str(compiled), *switch, '--json',
                     str(relocatable)), 3)
            for item in object_hits:
                assert item['executable'] is True, item
                assert item['virtual_address'] is None, item
            assert {item['record_id'] for item in object_hits
                   } == {item['record_id'] for item in affected_hits
                        }, object_hits
            for item in object_hits:
                obj_offset = int(item['file_offset'], 16)
                assert relocatable.read_bytes(
                )[obj_offset:obj_offset +
                  len(MARKER.split())] == bytes.fromhex(MARKER), item

        collection_dir = tmp / 'collection'
        collection_dir.mkdir()
        for path in elf.values():
            shutil.copy2(path, collection_dir / path.name)
        collection = scan(scanner, '--compiled', str(compiled), '--threads',
                          '2', '--recursive', '--json', str(collection_dir))
        assert len(collection['results']) == 3, collection
        assert all(
            row['error'] is None for row in collection['results']), collection
        scanned = [
            r for r in collection['results'] if r['file'].endswith('/affected')
        ]
        assert len(scanned) == 1 and len(scanned[0]['matches']) == 3, scanned
        broken = tmp / 'invalid.yarc'
        broken.write_bytes(b'Not a serialized YARA-X DB!')
        invalid = run(str(scanner),
                      'verify',
                      '--compiled',
                      str(broken),
                      check=False)
        assert invalid.returncode != 0, 'YARA-X must reject corrupted serialized DB'

        print(
            json.dumps(
                {
                    'status': 'PASS',
                    'engine': 'native-yara-x-capi',
                    'database_rules': 3,
                    'affected_hits': len(affected_hits),
                    'fixed_hits': 0,
                    'data_only_exec_hits': 0,
                    'data_only_full_file_hits': 3,
                    'correct_file_offset': True,
                    'compiled_roundtrip': True,
                    'bad_compiled_database_rejected': True,
                    'per_pattern_cap_detected': True,
                },
                sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, AssertionError, subprocess.TimeoutExpired,
            json.JSONDecodeError) as exc:
        print(f'NATIVE YARA-X INTEGRATION FAILED: {exc}', file=sys.stderr)
        raise SystemExit(2)
