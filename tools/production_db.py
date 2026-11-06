#!/usr/bin/env python3
"""Fail-closed native validation + release database for VulnImprint.

This is a release tool, not a substitute for any CVE-specific source review.
Only an explicitly reviewed case corpus with pinned SHA and patch-state controls
may be admitted. It always executes the real compiled C++ YARA-X scanner.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path
from factory.toolchains import probe_compiler, ToolchainMismatch
from tempfile import TemporaryDirectory

CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
ALLOWED_QUALITY = {'CVE_SPECIFIC_VALIDATED'}
VALID_LABELS = {'affected', 'fixed', 'backport', 'unrelated'}
SUPPORTED = ('linux', 'ELF', 'x86-64', 64, 'sysv')
ENGINE_VERSION = '1.23.0'
PROFILE_ID = 'linux-elf64-x86_64-sysv'
VERSION = re.compile(r'\d+\.\d+(?:\.\d+){1,2}\Z')
COMPILER_FAMILIES = {'gcc', 'clang'}
# Supported first-release toolchain matrix. Every compiler/optimization lane
# is tested separately on both affected and fixed independent specimens.
REQUIRED_LANES = {(family, major, opt)
                  for family, majors in (('gcc', (11, 12)), ('clang', (14, 15)))
                  for major in majors
                  for opt in ('-O2', '-O3')}


class ReleaseRejected(ValueError):
    pass


def sha256(path: Path) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def write_json(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + '\n')


def read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ReleaseRejected(f'{path}: {e}') from e


def validate_source_pack(pack: dict, rulefile: Path, *, packfile: Path) -> None:
    cve = pack.get('cve')
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        raise ReleaseRejected('invalid CVE id')
    if pack.get('schema_version') != 1:
        raise ReleaseRejected(f'{cve}: unsupported pack schema')
    if pack.get('status') in ('NO_SIGNATURE', 'QUALITY_REJECTED',
                              'INCONCLUSIVE'):
        raise ReleaseRejected(f'{cve}: rejected source pack')
    if not isinstance(pack.get('rules'), list) or not pack['rules']:
        raise ReleaseRejected(f'{cve}: empty patterns')
    p = pack.get('platform', {})
    if (not isinstance(p, dict) or
            set(p) != {'os', 'format', 'arch', 'bits', 'abi'} or
        (p.get('os'), p.get('format'), p.get('arch'), p.get('bits'),
         p.get('abi')) != SUPPORTED or type(p.get('bits')) is not int):
        raise ReleaseRejected(f'{cve}: unsupported or noncanonical platform')
    if not rulefile.is_file() or not rulefile.read_text().strip():
        raise ReleaseRejected(f'{cve}: missing YARA source')
    ids = set()
    for rule in pack['rules']:
        pat = rule.get('hex', '')
        if rule.get('id') in ids:
            raise ReleaseRejected(f'{cve}: duplicate pattern id')
        ids.add(rule.get('id'))
        if len(pat) > 16384 or not re.fullmatch(
                r'(?:(?:[a-fA-F0-9]{2}|\?\?)\s+)*(?:[a-fA-F0-9]{2}|\?\?)', pat):
            raise ReleaseRejected(f'{cve}: invalid hex pattern')
        # Never trust attacker- or generator-supplied strength metadata. A
        # claimed 100 fixed bytes must not make an all-wildcard rule publishable.
        tokens = pat.split()
        fixed_bytes = sum('?' not in byte for byte in tokens)
        if (type(rule.get('length')) is not int or
                type(rule.get('fixed_bytes')) is not int or
                rule['length'] != len(tokens) or
                rule['fixed_bytes'] != fixed_bytes):
            raise ReleaseRejected(
                f'{cve}: pattern length/fixed_bytes do not match hex bytes')
        if fixed_bytes < 24 or len(tokens) < 28:
            raise ReleaseRejected(
                f'{cve}: weak pattern, fixed bytes / length too short')
    if pack.get('source_type') == 'manual':
        from tools.manual_rules import check_manual_source
        if pack.get('status') != 'CVE_SPECIFIC_VALIDATED':
            raise ReleaseRejected(
                f'{cve}: manual rule must be approved before production')
        check_manual_source(pack, rulefile.read_text())
    elif pack.get('source_type', 'factory') == 'factory':
        from factory.yara_engine import source_from_packs
        expected_source = source_from_packs([pack])
        if rulefile.read_text().strip() != expected_source.strip():
            raise ReleaseRejected(
                f'{cve}: Factory source does not match recorded hex patterns and status'
            )
    else:
        raise ReleaseRejected(f'{cve}: unknown signature source type')
    if packfile.stat().st_size > 1 << 20 or rulefile.stat().st_size > 1 << 20:
        raise ReleaseRejected(f'{cve}: oversized metadata/rules')


def native_scan(scanner: Path,
                rules: Path,
                target: Path,
                *,
                compiled: bool = False) -> dict:
    options = ['--compiled' if compiled else '--rules', str(rules)]
    cmd = [str(scanner), 'scan', *options, '--json', str(target)]
    p = subprocess.run(cmd,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,
                       text=True,
                       timeout=120)
    if p.returncode != 0:
        raise ReleaseRejected(
            f'native scan failed for {target}: {p.stderr[:600]}')
    try:
        parsed = json.loads(p.stdout)
        res = parsed['results']
        if parsed['engine'] != 'yara-x' or len(res) != 1:
            raise ValueError('bad scanner schema')
        item = res[0]
        if item['error'] is not None or item.get('truncated'):
            raise ValueError('scanner returned error or truncated results')
        return item
    except (KeyError, TypeError, ValueError, IndexError) as err:
        raise ReleaseRejected(
            f'bad native scan report for {target}: {err}') from err


def verify_static_product(specimen: Path) -> None:
    """Inspect a *real* stripped static ELF executable, not its JSON labels.

    A shared object, ET_REL, dynamically linked executable, unstripped host or
    zero-entry ET_DYN is never given independent static-product credit.
    Signature matches and independently verified release origin are additional
    requirements; ELF structure alone cannot prove who produced the file.
    """
    from factory.elf import ELF, UnsupportedBinary
    try:
        elf = ELF(specimen)
        image = elf._file
        if image['e_type'] not in ('ET_EXEC', 'ET_DYN'):
            raise ReleaseRejected(
                'independent static product must be an executable ELF')
        entry = int(image['e_entry'])
        if not entry or not any(va <= entry < va + length
                                for va, _, length in elf.segments):
            raise ReleaseRejected(
                'independent static product has no executable entry point')
        if any(segment['p_type'] == 'PT_INTERP'
               for segment in image.iter_segments()):
            raise ReleaseRejected(
                'independent static product uses a dynamic interpreter')
        if any(section['sh_type'] == 'SHT_SYMTAB'
               for section in image.iter_sections()):
            raise ReleaseRejected('independent static product is not stripped')
        for segment in image.iter_segments():
            if segment['p_type'] == 'PT_DYNAMIC':
                for tag in segment.iter_tags():
                    if tag.entry.d_tag == 'DT_NEEDED':
                        raise ReleaseRejected(
                            'independent static product depends on shared libraries'
                        )
    except (UnsupportedBinary, OSError, ValueError) as exc:
        if isinstance(exc, ReleaseRejected):
            raise
        raise ReleaseRejected(f'invalid independent static ELF: {exc}') from exc


def verify_third_party_attestation(specimen: Path, row: dict) -> None:
    """Check binary bytes against a *verified* upstream GitHub attestation.

    The signer identity is not inferred from untrusted rule metadata. Its exact
    full workflow path is required. Use gh >=2.102.0 so the workflow matcher
    verifies the exact signer workflow identity.
    """
    repo = row.get('attestation_repository', '')
    workflow = row.get('attestation_signer_workflow', '')
    if (not isinstance(repo, str) or
            not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo) or
            not isinstance(workflow, str) or
            not workflow.startswith(repo + '/.github/workflows/') or
            not re.fullmatch(
                re.escape(repo) + r'/\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml',
                workflow) or
            not row.get('origin',
                        '').startswith('https://github.com/' + repo + '/')):
        raise ReleaseRejected(
            'third-party static sample requires pinned upstream signing identity'
        )
    try:
        version = subprocess.run(['gh', '--version'],
                                 check=True,
                                 capture_output=True,
                                 text=True,
                                 timeout=15).stdout
        match = re.search(r'gh version (\d+)\.(\d+)\.(\d+)', version)
        if not match or tuple(map(int, match.groups())) < (2, 102, 0):
            raise ReleaseRejected(
                'GitHub CLI >= 2.102.0 is required for signer identity checking'
            )
        response = subprocess.run([
            'gh', 'attestation', 'verify',
            str(specimen), '--repo', repo, '--signer-workflow', workflow,
            '--format', 'json'
        ],
                                  check=True,
                                  capture_output=True,
                                  text=True,
                                  timeout=120)
        verified = json.loads(response.stdout)
        if not isinstance(verified, list) or not verified:
            raise ReleaseRejected(
                'no valid verified GitHub attestation for static specimen')
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            ValueError) as exc:
        if isinstance(exc, ReleaseRejected):
            raise
        raise ReleaseRejected(
            'third-party static product origin attestation failed') from exc


def validate_reviewed_toolchain(row: dict, cve: str) -> dict | None:
    """A real source-built holdout must be tied to an exact compiler executable.

    Third-party stripped products may have an unidentified compiler and cannot
    count toward compiler-version coverage. This is preferable to guessing it.
    """
    kind = row.get('binary_kind')
    if kind == 'stripped_third_party_executable' and not row.get(
            'build_profile'):
        return None  # no guessed compiler lane for independent third-party product
    if kind != 'source_built_elf':
        raise ReleaseRejected(f'{cve}: unsupported source-built binary kind')
    role = row.get('artifact_role')
    if role not in ('host_0', 'host_1'):
        raise ReleaseRejected(
            f'{cve}: compiler lane must use a linked host_0/host_1')
    profile = row.get('build_profile')
    if not isinstance(profile, dict):
        raise ReleaseRejected(
            f'{cve}: missing measured toolchain build_profile')
    family = profile.get('compiler_family')
    version = str(profile.get('compiler_version', ''))
    sha = str(profile.get('compiler_binary_sha256', ''))
    target = profile.get('compiler_target')
    opt = profile.get('optimization')
    if (family not in COMPILER_FAMILIES or not VERSION.fullmatch(version) or
            not HASH.fullmatch(sha) or not isinstance(target, str) or
            not target or
            opt not in ('-O0', '-O1', '-O2', '-O3', '-Os', '-Oz')):
        raise ReleaseRejected(
            f'{cve}: invalid measured compiler/version/digest/target/flags')
    expected_major = profile.get('compiler_major')
    if expected_major is not None and (isinstance(expected_major, bool) or
                                       str(expected_major)
                                       != version.split('.')[0]):
        raise ReleaseRejected(
            f'{cve}: compiler major != recorded exact version')
    # A version string and SHA supplied in JSON are not measured provenance.
    # Bind every claimed compiler lane to the source-build worker's record and
    # to the exact reviewed sample bytes. No record -> no lane credit.
    evidence = row.get('build_provenance')
    if not isinstance(evidence, dict) or evidence.get('schema_version') != 1:
        raise ReleaseRejected(f'{cve}: measured build provenance missing')
    source = evidence.get('source')
    tc = evidence.get('toolchain')
    artifacts = evidence.get('artifacts')
    commands = evidence.get('commands')
    if (not isinstance(source, dict) or source.get('type') != 'git' or
            source.get('commit') != row.get('source_commit') or
            not isinstance(tc, dict) or not isinstance(artifacts, dict) or
            not isinstance(evidence.get('source_provenance_sha256'), str) or
            not HASH.fullmatch(evidence['source_provenance_sha256']) or
            set(artifacts)
            != {'module.o', 'libcomponent.a', 'host_0', 'host_1'} or
            any(not HASH.fullmatch(str(x)) for x in artifacts.values()) or
            not HASH.fullmatch(str(row.get('sha256', ''))) or
            row['sha256'] != artifacts[role] or
            not isinstance(commands, list) or not commands or not all(
                isinstance(command, list) and command and all(
                    isinstance(arg, str)
                    for arg in command)
                for command in commands)):
        raise ReleaseRejected(
            f'{cve}: build provenance does not bind the sample to source and commands'
        )
    for actual, claimed in ((tc.get('family'),
                             family), (tc.get('version'),
                                       version), (tc.get('binary_sha256'), sha),
                            (tc.get('target'), target), (tc.get('optimization'),
                                                         opt)):
        if actual != claimed:
            raise ReleaseRejected(
                f'{cve}: build provenance compiler profile mismatch')

    def command_uses_optimization(argv: list[str]) -> bool:
        # Exact compiler flag, or explicit CMake C_FLAGS setting; matching a
        # substring in an artifact filename is not provenance.
        return (opt in argv or any(
            arg.startswith('-DCMAKE_C_FLAGS=') and
            opt in arg.split('=', 1)[1].split() for arg in argv))

    if not any(command_uses_optimization(argv) for argv in commands):
        raise ReleaseRejected(
            f'{cve}: no measured compiler optimization in build commands')
    # Only a compiler invocation that *linked the specific reviewed host* may
    # support a release lane. "echo -O2" and an unrelated module.o are invalid.
    compiler_path = tc.get('executable')
    if not isinstance(compiler_path, str) or not compiler_path:
        raise ReleaseRejected(f'{cve}: missing executable compiler path')

    def links_role(argv: list[str]) -> bool:
        if not argv or Path(argv[0]).name != Path(compiler_path).name:
            return False
        return any(
            argv[i] == '-o' and Path(argv[i + 1]).name == role
            for i in range(len(argv) - 1)) and opt in argv and '-c' not in argv

    if not any(links_role(argv) for argv in commands):
        raise ReleaseRejected(
            f'{cve}: no observed compiler link command for {role}')
    # Independently remeasure compiler version, executable digest and target on
    # the trusted release runner; never grant a lane from supplied JSON alone.
    try:
        measured = probe_compiler(tc.get('requested_executable', compiler_path),
                                  expected_major=int(version.split('.')[0]),
                                  expected_version=version,
                                  optimization=opt)
    except (ToolchainMismatch, OSError, ValueError) as exc:
        raise ReleaseRejected(
            f'{cve}: compiler cannot be independently remeasured') from exc
    if (measured['binary_sha256'] != sha or measured['target'] != target):
        raise ReleaseRejected(
            f'{cve}: compiler identity contradicts release runner measurement')
    return {
        'family': family,
        'version': version,
        'major': int(version.split('.')[0]),
        'binary_sha256': sha,
        'target': target,
        'optimization': opt
    }


def validate_case(case: Path,
                  scanner: Path,
                  *,
                  minimum_unrelated: int = 20) -> dict:
    packpath = case / 'pack.json'
    rulefile = case / 'rules-exec.yar'
    pack = read_json(packpath)
    validate_source_pack(pack, rulefile, packfile=packpath)
    cve = pack['cve']
    spec = read_json(case / 'reviewed-evidence.json')
    if spec.get('schema_version') != 2 or spec.get('cve') != cve:
        raise ReleaseRejected(f'{cve}: mismatched evidence schema or CVE')
    if spec.get('quality') not in ALLOWED_QUALITY:
        raise ReleaseRejected(f'{cve}: evidence not CVE-specific validated')
    if spec.get('rules_sha256') != sha256(rulefile) or spec.get(
            'pack_sha256') != sha256(packpath):
        raise ReleaseRejected(
            f'{cve}: evidence is not bound to exact pack and rules')
    rows = spec.get('samples')
    if not isinstance(rows, list):
        raise ReleaseRejected(f'{cve}: missing samples')
    training_lineages = spec.get('training_lineages')
    if not isinstance(training_lineages, list) or not training_lineages:
        raise ReleaseRejected(f'{cve}: training lineages not declared')
    counts = Counter()
    lineages = {k: set() for k in VALID_LABELS}
    measured = {'affected': set(), 'fixed': set(), 'backport': set()}
    seen = set()
    digests_seen = set()
    lineage_digests = {}
    results = []
    affected_versions = set()
    backport_versions = set()
    for row in rows:
        label = row.get('label')
        lineage = row.get('lineage')
        sampleid = row.get('id')
        if label not in VALID_LABELS or not lineage or not sampleid or sampleid in seen:
            raise ReleaseRejected(f'{cve}: malformed label/lineage/id')
        seen.add(sampleid)
        if row.get('split') != 'independent_holdout':
            raise ReleaseRejected(
                f'{cve}: all release samples must be independent holdouts')
        required_basis = 'independent_unrelated' if label == 'unrelated' else 'patch_state'
        if row.get('label_basis') != required_basis:
            raise ReleaseRejected(f'{cve}: invalid control label provenance')
        if label != 'unrelated' and not COMMIT.fullmatch(
                str(row.get('source_commit', ''))):
            raise ReleaseRejected(f'{cve}: immutable source commit missing')
        if not str(row.get('origin', '')).startswith('https://'):
            raise ReleaseRejected(f'{cve}: verified source origin required')
        supplied = Path(row.get('path', ''))
        # Only paths within the reviewed case directory can be trusted as release evidence.
        specimen = (case / supplied).resolve()
        if not specimen.is_relative_to(
                case.resolve()) or not specimen.is_file():
            raise ReleaseRejected(
                f'{cve}: specimen outside case dir or missing')
        digest = row.get('sha256')
        if not HASH.fullmatch(str(digest)) or digest != sha256(specimen):
            raise ReleaseRejected(
                f'{cve}: specimen SHA-256 mismatch: {sampleid}')
        if digest in digests_seen:
            raise ReleaseRejected(
                f'{cve}: duplicate binary digest cannot count as independent evidence'
            )
        digests_seen.add(digest)
        if lineage in lineage_digests and lineage_digests[lineage] != label:
            raise ReleaseRejected(
                f'{cve}: contradictory labels within one sample lineage')
        lineage_digests[lineage] = label
        hit = native_scan(scanner, rulefile, specimen)
        findings = [x for x in hit['matches'] if x.get('cve') == cve]
        if bool(findings) != (label == 'affected'):
            raise ReleaseRejected(
                f'{cve}: {label} sample misclassified: {sampleid}')
        if any(not x.get('executable') for x in findings):
            raise ReleaseRejected(f'{cve}: non-executable hit: {sampleid}')
        if lineage in training_lineages:
            raise ReleaseRejected(
                f'{cve}: independent holdout duplicates training lineage')
        tc = validate_reviewed_toolchain(row,
                                         cve) if label != 'unrelated' else None
        independent_static = False
        if label != 'unrelated' and row.get(
                'binary_kind') == 'stripped_third_party_executable':
            if row.get('linkage') not in ('static', 'dynamic'):
                raise ReleaseRejected(
                    f'{cve}: third-party linkage is not declared')
            if row['linkage'] == 'static':
                verify_static_product(specimen)
            # A declared third-party lineage is never by itself independent
            # source evidence, even for fixed/backport negative controls.
            verify_third_party_attestation(specimen, row)
            independent_static = label == 'affected' and row[
                'linkage'] == 'static'
        if tc and label in measured:
            measured[label].add(
                (tc['family'], tc['version'], tc['binary_sha256'],
                 tc['optimization'], tc['target']))
        if label == 'affected':
            affected_versions.add(row.get('version'))
        if label == 'backport':
            backport_versions.add(row.get('version'))
            if not COMMIT.fullmatch(str(row.get('patch_commit', ''))):
                raise ReleaseRejected(
                    f'{cve}: backport fix patch commit required')
        counts[label] += 1
        lineages[label].add(lineage)
        results.append({
            'id': sampleid,
            'label': label,
            'lineage': lineage,
            'sha256': digest,
            'matches': len(findings),
            'independent_static_product': independent_static
        })
    if counts['affected'] < 2 or counts['fixed'] < 2 or counts[
            'backport'] < 1 or counts['unrelated'] < minimum_unrelated:
        raise ReleaseRejected(
            f'{cve}: insufficient independent controls: {dict(counts)}')
    # A backport is a distinct negative control, not a second independent
    # upstream fixed lineage.  Do not let one fixed lineage + one backport
    # falsely satisfy the two-fixed-lineage policy.
    if len(lineages['affected']) < 2 or len(lineages['fixed']) < 2:
        raise ReleaseRejected(f'{cve}: insufficient affected/fixed lineages')
    if not affected_versions or not affected_versions.intersection(
            backport_versions):
        raise ReleaseRejected(
            f'{cve}: backport must fix an affected source-version family')
    # First supported profile has to have measured GCC and Clang evidence for
    # both vulnerable and fixed states. Exact versions remain in the DB index;
    # each release reports which versions were *actually* tested.
    for state in ('affected', 'fixed'):
        lanes = {(family, int(version.split('.')[0]), opt)
                 for family, version, digest, opt, target in measured[state]}
        missing = REQUIRED_LANES - lanes
        if missing:
            raise ReleaseRejected(
                f'{cve}: missing versioned {state} lanes: {sorted(missing)}')
    if lineages['affected'] & (lineages['fixed'] | lineages['backport']):
        raise ReleaseRejected(
            f'{cve}: affected vs fixed lineages must be independent')
    tested = {
        label: [{
            'compiler_family': family,
            'compiler_version': version,
            'compiler_binary_sha256': digest,
            'optimization': opt,
            'target': target
        } for family, version, digest, opt, target in sorted(rows)
               ] for label, rows in measured.items()
    }
    return {
        'schema_version': 2,
        'cve': cve,
        'quality': 'CVE_SPECIFIC_VALIDATED',
        'tested_build_profiles': tested,
        'native_scanner_sha256': sha256(scanner),
        'rules_sha256': sha256(rulefile),
        'pack_sha256': sha256(packpath),
        'counts': dict(counts),
        'samples': results,
        'evidence_sha256': sha256(case / 'reviewed-evidence.json')
    }


def build_release(cases: Path,
                  out: Path,
                  scanner: Path,
                  *,
                  min_cves: int = 1,
                  signatures: Path | None = None) -> dict:
    if not isinstance(min_cves, int) or min_cves < 1:
        raise ReleaseRejected('minimum CVE count must be a positive integer')
    scanner = scanner.resolve()
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected(
            'release requires real executable C++ YARA-X scanner')
    dirs = sorted(
        p for p in cases.iterdir() if p.is_dir() and (p / 'pack.json').exists())
    if len(dirs) < min_cves:
        raise ReleaseRejected(
            f'release requires >={min_cves} reviewed CVE packs; got {len(dirs)}'
        )
    if signatures is None:
        raise ReleaseRejected(
            'the complete Git validated signature tree is mandatory')
    out = out.resolve()
    if out.exists() and any(out.iterdir()):
        raise ReleaseRejected('refusing nonempty release output')
    results = []
    packs = []
    if signatures is not None:
        if not signatures.is_dir():
            raise ReleaseRejected(
                'reviewed Git signature directory does not exist')
        expected = {d.name for d in dirs}
        tracked = {d.name for d in signatures.iterdir() if d.is_dir()}
        if any(not CVE.fullmatch(name) for name in tracked):
            raise ReleaseRejected(
                'invalid directory in Git validated signatures')
        if expected != tracked:
            raise ReleaseRejected(
                f'Git signature / reviewed corpus CVE mismatch: {sorted(expected ^ tracked)}'
            )
        for d in dirs:
            if d.name != read_json(d / 'pack.json').get('cve'):
                raise ReleaseRejected('case directory does not match CVE ID')
            for name in ('pack.json', 'rules-exec.yar',
                         'reviewed-evidence.json'):
                canonical = signatures / d.name / name
                if not canonical.is_file() or sha256(canonical) != sha256(
                        d / name):
                    raise ReleaseRejected(
                        f'{d.name}: {name} differs from version-controlled source'
                    )
    for d in dirs:
        evidence = validate_case(d, scanner)
        pack = read_json(d / 'pack.json')
        if any(x['cve'] == pack['cve'] for x in results):
            raise ReleaseRejected('duplicate CVE in release')
        results.append(evidence)
        packs.append(pack)
    unique_unrelated = {
        x['sha256']
        for e in results
        for x in e['samples']
        if x['label'] == 'unrelated'
    }
    if len(unique_unrelated) < min(min_cves, 1000):
        raise ReleaseRejected(
            'insufficient unique unrelated negative controls across DB')
    if not any(x['independent_static_product']
               for e in results
               for x in e['samples']):
        raise ReleaseRejected(
            'no independent stripped third-party static-linking positive')
    # Compile in actual C++ YARA-X, not mock, Python YARA-X or reference code.
    # Publish exactly the YARA source that passed the CVE-specific native
    # holdout tests, not a regenerated source that could differ from it.
    rule_source = '\n'.join(
        (d / 'rules-exec.yar').read_text().strip() for d in dirs) + '\n'
    with TemporaryDirectory(prefix='vulnimprint-rel-') as scratch:
        tmp = Path(scratch)
        (tmp / 'database.yar').write_text(rule_source)
        compiled = tmp / 'database.yarc'
        process = subprocess.run([
            str(scanner), 'compile', '--rules',
            str(tmp / 'database.yar'), '--output',
            str(compiled)
        ],
                                 capture_output=True,
                                 text=True,
                                 timeout=120)
        if process.returncode != 0 or not compiled.is_file() or compiled.stat(
        ).st_size == 0:
            raise ReleaseRejected(
                f'native YARA-X compilation failed: {process.stderr[:600]}')
        # Full DB must return each expected positive and no known negatives.
        for d, e in zip(dirs, results):
            reviewed = read_json(d / 'reviewed-evidence.json')
            for sample in reviewed['samples']:
                result = native_scan(scanner,
                                     compiled,
                                     d / sample['path'],
                                     compiled=True)
                matched_cves = {x.get('cve') for x in result['matches']}
                if (e['cve']
                        in matched_cves) != (sample['label'] == 'affected'):
                    raise ReleaseRejected(
                        f'combined DB regression: {e["cve"]}/{sample["id"]}')
                # A file fixed for CVE-A can still legitimately contain CVE-B.
                # Only global unrelated controls are required to be clean of ALL
                # published CVEs; never mislabel a CVE-B hit as FP for CVE-A.
                if sample['label'] == 'unrelated' and matched_cves:
                    raise ReleaseRejected(
                        f'combined DB unrelated FP: {sample["id"]}')
        tmpout = tmp / 'release'
        tmpout.mkdir()
        shutil.copy2(compiled, tmpout / 'database.yarc')
        shutil.copy2(tmp / 'database.yar', tmpout / 'database.yar')
        write_json(
            tmpout / 'quality-report.json', {
                'schema_version': 1,
                'engine': 'YARA-X C API',
                'quality': 'CVE_SPECIFIC_VALIDATED',
                'packs': results
            })
        index = {
            'schema_version':
                1,
            'name':
                'VulnImprint DB',
            'profile': {
                'os': 'linux',
                'format': 'ELF',
                'arch': 'x86-64',
                'bits': 64,
                'abi': 'sysv'
            },
            'rule_quality':
                'CVE_SPECIFIC_VALIDATED',
            'pattern_count':
                sum(len(p['rules']) for p in packs),
            'yara_rule_count':
                len(packs),
            'cve_count':
                len(packs),
            'entries': [{
                'cve': x['cve'],
                'quality': 'CVE_SPECIFIC_VALIDATED',
                'pattern_count': len(p['rules']),
                'rule_id': x['cve'].replace('-', '_') + '_ELF64_x86_64',
                'pack_sha256': x['pack_sha256'],
                'rules_sha256': x['rules_sha256'],
                'validation_counts': x['counts'],
                'tested_build_profiles': x['tested_build_profiles']
            } for x, p in zip(results, packs)]
        }
        write_json(tmpout / 'index.json', index)
        sums = {
            p.name: sha256(p) for p in sorted(tmpout.iterdir()) if p.is_file()
        }
        write_json(
            tmpout / 'manifest.json', {
                'schema_version': 2,
                'artifacts': sums,
                'profile': PROFILE_ID,
                'cve_count': len(packs),
                'engine': {
                    'name': 'yara-x-capi',
                    'version': ENGINE_VERSION,
                    'serialized_rules_format': 'yara-x',
                    'scanner_min_version': '0.1.0',
                    'scanner_max_exclusive': '0.2.0'
                }
            })
        (tmpout / 'SHA256SUMS').write_text(''.join(
            f'{digest}  {name}\n' for name, digest in sorted(sums.items())))
        out.mkdir(parents=True, exist_ok=True)
        verify_release(tmpout, scanner=scanner)
        for p in tmpout.iterdir():
            shutil.copy2(p, out / p.name)
    return {'status': 'PASS', 'cve_count': len(packs), 'output': str(out)}


def assemble_validated(signatures: Path, out: Path, scanner: Path) -> dict:
    """Build the release database from the complete reviewed Git source tree.

    Corpus-driven native validation is performed before approval/merge. This
    command does not approve a candidate or silently drop an admitted CVE.
    """
    from scripts.check_validated_signatures import check

    if signatures.is_symlink(
    ) or signatures.name != "validated" or signatures.parent.name != "signatures":
        raise ReleaseRejected(
            "release source must be the canonical validated Git directory")
    project_root = signatures.resolve().parent.parent
    if signatures.resolve() != (project_root / "signatures" /
                                "validated").resolve():
        raise ReleaseRejected(
            "release source differs from validated Git directory")
    cves = check(project_root)
    if not cves:
        raise ReleaseRejected(
            "no Git-validated CVEs; cannot release an empty DB")
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected("native YARA-X scanner executable is required")
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ReleaseRejected("refusing nonempty database output")

    packs = []
    sources = []
    results = []
    for cve in cves:
        directory = signatures / cve
        pack = read_json(directory / "pack.json")
        evidence = read_json(directory / "reviewed-evidence.json")
        source = directory / "rules-exec.yar"
        # check() verifies approval, format and exact evidence/source hashes.
        # Do not generate new YARA source or silently normalize approved bytes.
        packs.append(pack)
        sources.append(source.read_text(encoding="utf-8").rstrip())
        counts = Counter(row.get("label") for row in evidence["samples"])
        results.append({
            "cve":
                cve,
            "quality":
                "CVE_SPECIFIC_VALIDATED",
            "pack_sha256":
                sha256(directory / "pack.json"),
            "rules_sha256":
                sha256(source),
            "evidence_sha256":
                sha256(directory / "reviewed-evidence.json"),
            "counts":
                dict(counts),
            "tested_build_profiles":
                sorted({(sample["build_profile"]["compiler_family"],
                         sample["build_profile"]["compiler_version"],
                         sample["build_profile"]["optimization"])
                        for sample in evidence["samples"]
                        if isinstance(sample, dict) and
                        isinstance(sample.get("build_profile"), dict) and all(
                            isinstance(sample["build_profile"].get(key), str)
                            for key in ("compiler_family", "compiler_version",
                                        "optimization"))}),
        })

    with TemporaryDirectory(prefix="vulnimprint-assemble-") as directory:
        work = Path(directory)
        (work / "database.yar").write_text("\n".join(sources) + "\n",
                                           encoding="utf-8")
        compiled = work / "database.yarc"
        try:
            proc = subprocess.run([
                str(scanner), "compile", "--rules",
                str(work / "database.yar"), "--output",
                str(compiled)
            ],
                                  capture_output=True,
                                  text=True,
                                  timeout=120,
                                  check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ReleaseRejected(
                "native YARA-X compilation could not complete") from error
        if proc.returncode or not compiled.is_file() or not compiled.stat(
        ).st_size:
            raise ReleaseRejected("native compilation failed: " +
                                  proc.stderr[:600])
        index = {
            "schema_version":
                1,
            "name":
                "VulnImprint DB",
            "profile": {
                "os": "linux",
                "format": "ELF",
                "arch": "x86-64",
                "bits": 64,
                "abi": "sysv"
            },
            "rule_quality":
                "CVE_SPECIFIC_VALIDATED",
            "pattern_count":
                sum(len(pack["rules"]) for pack in packs),
            "yara_rule_count":
                len(cves),
            "cve_count":
                len(cves),
            "entries": [{
                "cve": row["cve"],
                "quality": "CVE_SPECIFIC_VALIDATED",
                "pattern_count": len(pack["rules"]),
                "rule_id": row["cve"].replace("-", "_") + "_ELF64_x86_64",
                "pack_sha256": row["pack_sha256"],
                "rules_sha256": row["rules_sha256"],
                "validation_counts": row["counts"],
                "tested_build_profiles": row["tested_build_profiles"],
            } for row, pack in zip(results, packs)],
        }
        write_json(work / "index.json", index)
        write_json(
            work / "quality-report.json", {
                "schema_version": 1,
                "quality": "CVE_SPECIFIC_VALIDATED",
                "validation_stage": "reviewed_before_merge",
                "packs": results,
            })
        digests = {
            name: sha256(work / name)
            for name in ("database.yarc", "database.yar", "index.json",
                         "quality-report.json")
        }
        write_json(
            work / "manifest.json", {
                "schema_version": 2,
                "artifacts": digests,
                "profile": PROFILE_ID,
                "cve_count": len(cves),
                "engine": {
                    "name": "yara-x-capi",
                    "version": ENGINE_VERSION,
                    "serialized_rules_format": "yara-x",
                    "scanner_min_version": "0.1.0",
                    "scanner_max_exclusive": "0.2.0",
                },
            })
        (work / "SHA256SUMS").write_text("".join(
            f"{digest}  {name}\n" for name, digest in sorted(digests.items())),
                                         encoding="utf-8")
        verify_release(work, scanner=scanner)
        out.mkdir(parents=True, exist_ok=True)
        for name in (*digests, "manifest.json", "SHA256SUMS"):
            shutil.copy2(work / name, out / name)
    return {"status": "PASS", "cve_count": len(cves), "output": str(out)}


def verify_release(directory: Path, *, scanner: Path | None = None) -> dict:
    m = read_json(directory / 'manifest.json')
    if m.get('schema_version') != 2 or not isinstance(m.get('artifacts'), dict):
        raise ReleaseRejected('invalid DB manifest schema')
    if m.get('profile') != PROFILE_ID or m.get('engine') != {
            'name': 'yara-x-capi',
            'version': ENGINE_VERSION,
            'serialized_rules_format': 'yara-x',
            'scanner_min_version': '0.1.0',
            'scanner_max_exclusive': '0.2.0'
    }:
        raise ReleaseRejected(
            'DB profile or native scanner/engine compatibility mismatch')
    if set(m['artifacts']) != {
            'database.yarc', 'database.yar', 'index.json', 'quality-report.json'
    }:
        raise ReleaseRejected('incomplete release manifest')
    for name, digest in m['artifacts'].items():
        if not HASH.fullmatch(str(digest)) or sha256(
                directory / name) != digest:
            raise ReleaseRejected('release digest mismatch: ' + name)
    checksum_file = directory / 'SHA256SUMS'
    try:
        observed = {}
        for line in checksum_file.read_text().splitlines():
            digest, separator, name = line.partition('  ')
            if not separator or name in observed or not HASH.fullmatch(digest):
                raise ReleaseRejected('invalid or repeated SHA256SUMS entry')
            observed[name] = digest
        if observed != m['artifacts']:
            raise ReleaseRejected('SHA256SUMS does not match DB manifest')
    except OSError as exc:
        raise ReleaseRejected('missing SHA256SUMS') from exc
    index = read_json(directory / 'index.json')
    if index['cve_count'] < 1 or index['cve_count'] != m['cve_count']:
        raise ReleaseRejected('empty or inconsistent database')
    if index.get('schema_version') != 1 or index.get('profile') != {
            'os': 'linux',
            'format': 'ELF',
            'arch': 'x86-64',
            'bits': 64,
            'abi': 'sysv'
    }:
        raise ReleaseRejected('unsupported DB index version or binary profile')
    if index.get('yara_rule_count') != index['cve_count'] or index.get(
            'pattern_count', 0) < index['cve_count']:
        raise ReleaseRejected('inconsistent rule/pattern counts')
    if index['rule_quality'] != 'CVE_SPECIFIC_VALIDATED':
        raise ReleaseRejected('non-production rules in main index')
    if scanner is not None:
        try:
            completed = subprocess.run([
                str(scanner), 'verify', '--compiled',
                str(directory / 'database.yarc')
            ],
                                       capture_output=True,
                                       text=True,
                                       timeout=30)
            if completed.returncode != 0:
                raise ReleaseRejected(
                    'native YARA-X could not load compiled database')
            native = json.loads(completed.stdout)
            if native.get('engine') != 'yara-x' or native.get(
                    'rules') != index.get('yara_rule_count'):
                raise ReleaseRejected(
                    'native rule count and DB manifest differ')
        except (OSError, subprocess.TimeoutExpired, ValueError) as err:
            raise ReleaseRejected(
                'native YARA-X DB verification failed') from err
    return {'status': 'PASS', 'cve_count': index['cve_count']}


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build')
    b.add_argument('--cases', type=Path, required=True)
    b.add_argument('--output', type=Path, required=True)
    b.add_argument('--scanner', type=Path, required=True)
    b.add_argument('--min-cves', type=int, default=1)
    b.add_argument('--signatures',
                   type=Path,
                   required=True,
                   help='complete version-controlled validated CVE directory')
    assemble = sub.add_parser('assemble')
    assemble.add_argument('--signatures', type=Path, required=True)
    assemble.add_argument('--output', type=Path, required=True)
    assemble.add_argument('--scanner', type=Path, required=True)
    v = sub.add_parser('verify')
    v.add_argument('--database', type=Path, required=True)
    v.add_argument('--scanner', type=Path)
    a = p.parse_args(argv)
    try:
        if a.cmd == 'build':
            out = build_release(a.cases,
                                a.output,
                                a.scanner,
                                min_cves=a.min_cves,
                                signatures=a.signatures)
        elif a.cmd == 'assemble':
            out = assemble_validated(a.signatures, a.output, a.scanner)
        else:
            out = verify_release(a.database, scanner=a.scanner)
    except (ReleaseRejected, OSError, subprocess.TimeoutExpired) as err:
        print('RELEASE BLOCKED:', err, file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
