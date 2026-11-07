#!/usr/bin/env python3
"""CVE-owned database record validation and deterministic release assembly.

CVE is the source unit. Each database record belongs to exactly one CVE and
is independently identified; test records never enter the production DB.
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
from tempfile import TemporaryDirectory

from factory.signature_identity import record_sha256

CVE = re.compile(r'CVE-\d{4}-\d{4,}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMIT = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})\Z')
CHANNELS = frozenset({'test', 'production'})
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
    """Validate a CVE envelope and every independently owned DB record."""
    from factory.signature_identity import cve_pack_records
    from factory.yara_engine import source_from_packs

    try:
        records = cve_pack_records(pack)
    except (TypeError, ValueError) as exc:
        raise ReleaseRejected(str(exc)) from exc
    cve = pack['cve']
    record_ids = set()
    for record in records:
        record_id = record['record_id']
        if record_id in record_ids:
            raise ReleaseRejected(f'{cve}: duplicate record ID')
        record_ids.add(record_id)
        if record.get('channel') not in CHANNELS:
            raise ReleaseRejected(f'{cve}/{record_id}: invalid channel')
        if record.get('source_type') not in ('manual', 'factory'):
            raise ReleaseRejected(f'{cve}/{record_id}: unknown source type')
        platform = record.get('platform')
        if (not isinstance(platform, dict) or
                set(platform) != {'os', 'format', 'arch', 'bits', 'abi'} or
            (platform.get('os'), platform.get('format'), platform.get('arch'),
             platform.get('bits'), platform.get('abi')) != SUPPORTED or
                type(platform.get('bits')) is not int):
            raise ReleaseRejected(f'{cve}/{record_id}: unsupported platform')
        patterns = record.get('rules')
        if not isinstance(patterns, list) or not patterns:
            raise ReleaseRejected(f'{cve}/{record_id}: empty patterns')
        ids = set()
        for pattern in patterns:
            if not isinstance(pattern, dict):
                raise ReleaseRejected(f'{cve}/{record_id}: malformed pattern')
            pattern_id = pattern.get('id')
            pat = pattern.get('hex', '')
            if not isinstance(pattern_id,
                              str) or not pattern_id or pattern_id in ids:
                raise ReleaseRejected(
                    f'{cve}/{record_id}: duplicate/invalid pattern ID')
            ids.add(pattern_id)
            if len(pat) > 16384 or not re.fullmatch(
                    r'(?:(?:[a-fA-F0-9]{2}|\?\?)\s+)*(?:[a-fA-F0-9]{2}|\?\?)',
                    pat):
                raise ReleaseRejected(f'{cve}/{record_id}: invalid hex pattern')
            tokens = pat.split()
            fixed_bytes = sum('?' not in byte for byte in tokens)
            if (type(pattern.get('length')) is not int or
                    type(pattern.get('fixed_bytes')) is not int or
                    pattern['length'] != len(tokens) or
                    pattern['fixed_bytes'] != fixed_bytes):
                raise ReleaseRejected(
                    f'{cve}/{record_id}: pattern length/fixed_bytes mismatch')
            if fixed_bytes < 24 or len(tokens) < 28:
                raise ReleaseRejected(
                    f'{cve}/{record_id}: weak pattern, fixed bytes / length too short'
                )
    if not rulefile.is_file() or not rulefile.read_text(
            encoding='utf-8').strip():
        raise ReleaseRejected(f'{cve}: missing YARA source')
    try:
        expected_source = source_from_packs([pack])
    except (TypeError, ValueError, KeyError) as exc:
        raise ReleaseRejected(
            f'{cve}: invalid YARA source metadata: {exc}') from exc
    if rulefile.read_text(encoding='utf-8').strip() != expected_source.strip():
        raise ReleaseRejected(
            f'{cve}: YARA source differs from canonical CVE records')
    if packfile.is_symlink() or rulefile.is_symlink():
        raise ReleaseRejected(
            f'{cve}: symlinked source files are not permitted')
    if packfile.stat().st_size > 1 << 20 or rulefile.stat().st_size > 1 << 20:
        raise ReleaseRejected(f'{cve}: oversized metadata/rules')


def match_cves(hit: dict) -> set[str]:
    """Return the single owning CVE for one native database-record match."""
    cve = hit.get('cve') if isinstance(hit, dict) else None
    if cve is None:
        return set()
    if not isinstance(cve, str) or not CVE.fullmatch(cve):
        raise ReleaseRejected('native match has invalid CVE identifier')
    return {cve}


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
    # These identities describe the compiler that actually built the reviewed
    # specimen. A runner image upgrade is unrelated to historical provenance.
    # Authenticity must be verified from the source-build record and the
    # independently pinned, immutable binary specimen, not by comparing a
    # historical SHA against whichever compiler CI happens to install today.
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
    """Validate independent evidence for every record in one CVE pack."""
    packpath = case / 'pack.json'
    rulefile = case / 'rules-exec.yar'
    pack = read_json(packpath)
    validate_source_pack(pack, rulefile, packfile=packpath)
    cve = pack['cve']
    spec = read_json(case / 'reviewed-evidence.json')
    if spec.get('schema_version') != 3 or spec.get('cve') != cve:
        raise ReleaseRejected(f'{cve}: mismatched evidence schema or CVE')
    if spec.get('rules_sha256') != sha256(rulefile) or spec.get(
            'pack_sha256') != sha256(packpath):
        raise ReleaseRejected(
            f'{cve}: evidence is not bound to exact pack and rules')
    rows = spec.get('samples')
    if not isinstance(rows, list):
        raise ReleaseRejected(f'{cve}: missing samples')
    common_training = spec.get('training_lineages')
    if (not isinstance(common_training, list) or not common_training or
            any(not isinstance(x, str) or not x for x in common_training)):
        raise ReleaseRejected(f'{cve}: training lineages not declared')

    records = {r['record_id']: r for r in pack['records']}
    evidence_rows = spec.get('records')
    if not isinstance(evidence_rows, list):
        raise ReleaseRejected(f'{cve}: record-level evidence is required')
    evidence_by_id = {}
    for entry in evidence_rows:
        if not isinstance(entry, dict) or set(entry) != {
                'record_id', 'record_sha256', 'training_lineages', 'sample_ids'
        }:
            raise ReleaseRejected(f'{cve}: malformed record evidence')
        record_id = entry['record_id']
        if not isinstance(record_id, str) or record_id in evidence_by_id:
            raise ReleaseRejected(
                f'{cve}: duplicated/invalid evidence record ID')
        evidence_by_id[record_id] = entry
    if set(evidence_by_id) != set(records):
        raise ReleaseRejected(
            f'{cve}: evidence must cover every DB record exactly once')
    for record_id, record in records.items():
        entry = evidence_by_id[record_id]
        if entry['record_sha256'] != record_sha256(record):
            raise ReleaseRejected(f'{cve}/{record_id}: record SHA-256 mismatch')
        training = entry['training_lineages']
        sample_ids = entry['sample_ids']
        if (not isinstance(training, list) or not training or
                any(not isinstance(x, str) or not x for x in training) or
                not isinstance(sample_ids, list) or not sample_ids or
                any(not isinstance(x, str) or not x for x in sample_ids) or
                len(sample_ids) != len(set(sample_ids))):
            raise ReleaseRejected(
                f'{cve}/{record_id}: invalid training/sample IDs')

    sample_data = {}
    lineage_labels = {}
    digests_seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ReleaseRejected(f'{cve}: malformed specimen')
        label, lineage, sampleid = (row.get('label'), row.get('lineage'),
                                    row.get('id'))
        if (label not in VALID_LABELS or not isinstance(lineage, str) or
                not lineage or not isinstance(sampleid, str) or not sampleid or
                sampleid in sample_data):
            raise ReleaseRejected(f'{cve}: malformed label/lineage/id')
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
        if lineage in lineage_labels and lineage_labels[lineage] != label:
            raise ReleaseRejected(
                f'{cve}: contradictory labels within one sample lineage')
        lineage_labels[lineage] = label
        if lineage in common_training:
            raise ReleaseRejected(
                f'{cve}: independent holdout duplicates training lineage')
        hit = native_scan(scanner, rulefile, specimen)
        findings = [x for x in hit['matches'] if cve in match_cves(x)]
        if any(not x.get('executable') for x in findings):
            raise ReleaseRejected(f'{cve}: non-executable hit: {sampleid}')
        if any(x.get('record_id') not in records for x in findings):
            raise ReleaseRejected(
                f'{cve}: native match has unknown record ID: {sampleid}')
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
            verify_third_party_attestation(specimen, row)
            independent_static = label == 'affected' and row[
                'linkage'] == 'static'
        if label == 'backport' and not COMMIT.fullmatch(
                str(row.get('patch_commit', ''))):
            raise ReleaseRejected(f'{cve}: backport fix patch commit required')
        sample_data[sampleid] = {
            'row': row,
            'label': label,
            'lineage': lineage,
            'tc': tc,
            'findings': findings,
            'independent_static': independent_static,
            'summary': {
                'id': sampleid,
                'label': label,
                'lineage': lineage,
                'sha256': digest,
                'matches': len(findings),
                'independent_static_product': independent_static
            },
        }

    reports = []
    for record_id, record in records.items():
        entry = evidence_by_id[record_id]
        sample_ids = entry['sample_ids']
        if any(sampleid not in sample_data for sampleid in sample_ids):
            raise ReleaseRejected(
                f'{cve}/{record_id}: unknown evidence sample ID')
        counts = Counter()
        lineages = {k: set() for k in VALID_LABELS}
        measured = {'affected': set(), 'fixed': set(), 'backport': set()}
        affected_versions, backport_versions = set(), set()
        samples_for_record = []
        for sampleid in sample_ids:
            data = sample_data[sampleid]
            row, label, lineage = data['row'], data['label'], data['lineage']
            record_findings = [
                x for x in data['findings'] if x.get('record_id') == record_id
            ]
            if bool(record_findings) != (label == 'affected'):
                raise ReleaseRejected(
                    f'{cve}/{record_id}: {label} sample misclassified: {sampleid}'
                )
            if lineage in entry['training_lineages']:
                raise ReleaseRejected(
                    f'{cve}/{record_id}: independent holdout duplicates training lineage'
                )
            tc = data['tc']
            if tc and label in measured:
                measured[label].add(
                    (tc['family'], tc['version'], tc['binary_sha256'],
                     tc['optimization'], tc['target']))
            if label == 'affected':
                affected_versions.add(row.get('version'))
            if label == 'backport':
                backport_versions.add(row.get('version'))
            counts[label] += 1
            lineages[label].add(lineage)
            samples_for_record.append({
                **data['summary'], 'matches': len(record_findings)
            })
        if (counts['affected'] < 2 or counts['fixed'] < 2 or
                counts['backport'] < 1 or
                counts['unrelated'] < minimum_unrelated):
            raise ReleaseRejected(
                f'{cve}/{record_id}: insufficient independent controls: {dict(counts)}'
            )
        if len(lineages['affected']) < 2 or len(lineages['fixed']) < 2:
            raise ReleaseRejected(
                f'{cve}/{record_id}: insufficient affected/fixed lineages')
        if not affected_versions or not affected_versions.intersection(
                backport_versions):
            raise ReleaseRejected(
                f'{cve}/{record_id}: backport must fix an affected source-version family'
            )
        if lineages['affected'] & (lineages['fixed'] | lineages['backport']):
            raise ReleaseRejected(
                f'{cve}/{record_id}: affected vs fixed lineages must be independent'
            )
        supported = record.get('supported_profiles')
        if not isinstance(supported, list) or not supported:
            raise ReleaseRejected(
                f'{cve}/{record_id}: supported compiler profiles not declared')
        promised = set()
        for lane in supported:
            if (not isinstance(lane, dict) or set(lane)
                    != {'compiler_family', 'compiler_major', 'optimization'} or
                    lane['compiler_family'] not in COMPILER_FAMILIES or
                    type(lane['compiler_major']) is not int or
                    lane['compiler_major'] <= 0 or
                    lane['optimization'] not in ('-O2', '-O3')):
                raise ReleaseRejected(
                    f'{cve}/{record_id}: invalid supported compiler profile')
            key = (lane['compiler_family'], lane['compiler_major'],
                   lane['optimization'])
            if key in promised:
                raise ReleaseRejected(
                    f'{cve}/{record_id}: duplicate supported compiler profile')
            promised.add(key)
        for state in ('affected', 'fixed'):
            measured_lanes = {
                (family, int(version.split('.')[0]), opt)
                for family, version, digest, opt, target in measured[state]
            }
            if promised - measured_lanes:
                raise ReleaseRejected(
                    f'{cve}/{record_id}: missing supported {state} lanes: '
                    f'{sorted(promised - measured_lanes)}')
        tested = {
            label: [{
                'compiler_family': family,
                'compiler_version': version,
                'compiler_binary_sha256': digest,
                'optimization': opt,
                'target': target
            } for family, version, digest, opt, target in sorted(lanes)
                   ] for label, lanes in measured.items()
        }
        reports.append({
            'record_id':
                record_id,
            'record_sha256':
                record_sha256(record),
            'counts':
                dict(counts),
            'supported_profiles':
                sorted(supported,
                       key=lambda lane: (lane['compiler_family'], lane[
                           'compiler_major'], lane['optimization'])),
            'tested_build_profiles':
                tested,
            'samples':
                samples_for_record,
        })
    return {
        'schema_version': 3,
        'cve': cve,
        'record_count': len(reports),
        'records': reports,
        'counts': dict(Counter(item['label'] for item in sample_data.values())),
        'samples': [sample_data[row['id']]['summary'] for row in rows],
        'native_scanner_sha256': sha256(scanner),
        'rules_sha256': sha256(rulefile),
        'pack_sha256': sha256(packpath),
        'evidence_sha256': sha256(case / 'reviewed-evidence.json'),
    }


def review_cases(cases: Path,
                 scanner: Path,
                 *,
                 min_cves: int = 1,
                 signatures: Path | None = None) -> dict:
    """Review independently sourced CVE evidence; never assemble a database."""
    if not isinstance(min_cves, int) or min_cves < 1:
        raise ReleaseRejected('minimum CVE count must be a positive integer')
    scanner = scanner.resolve()
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected(
            'review requires real executable C++ YARA-X scanner')
    dirs = sorted(
        p for p in cases.iterdir() if p.is_dir() and (p / 'pack.json').exists())
    if len(dirs) < min_cves:
        raise ReleaseRejected(
            f'review requires >={min_cves} reviewed CVE packs; got {len(dirs)}')
    if signatures is None or not signatures.is_dir():
        raise ReleaseRejected('the complete Git CVE source tree is mandatory')
    expected = {directory.name for directory in dirs}
    tracked = {
        directory.name
        for directory in signatures.iterdir()
        if directory.is_dir() and (directory /
                                   'reviewed-evidence.json').is_file()
    }
    if expected != tracked:
        raise ReleaseRejected(
            f'Git signature / reviewed corpus CVE mismatch: {sorted(expected ^ tracked)}'
        )
    results = []
    for directory in dirs:
        if directory.name != read_json(directory / 'pack.json').get('cve'):
            raise ReleaseRejected('case directory does not match CVE ID')
        for name in ('pack.json', 'rules-exec.yar', 'reviewed-evidence.json'):
            canonical = signatures / directory.name / name
            if not canonical.is_file() or sha256(canonical) != sha256(
                    directory / name):
                raise ReleaseRejected(
                    f'{directory.name}: {name} differs from version-controlled source'
                )
        results.append(validate_case(directory, scanner))
    unrelated = {
        sample['sha256']
        for result in results
        for sample in result['samples']
        if sample['label'] == 'unrelated'
    }
    if len(unrelated) < min(min_cves, 1000):
        raise ReleaseRejected(
            'insufficient unique unrelated negative controls across DB')
    if not any(sample['independent_static_product']
               for result in results
               for sample in result['samples']):
        raise ReleaseRejected(
            'no independent stripped third-party static-linking positive')
    return {
        'status': 'PASS',
        'cve_count': len(results),
        'record_count': sum(result['record_count'] for result in results),
        'independent_validation': results,
    }


def assemble_git_tree(signatures: Path,
                      out: Path,
                      scanner: Path,
                      *,
                      channel: str = 'production') -> dict:
    """Compile CVE-owned records from Git for the requested DB channel."""
    from factory.signature_identity import cve_pack_records, record_identity
    from factory.yara_engine import source_from_packs
    from scripts.check_cve_source_tree import check

    if channel not in CHANNELS:
        raise ReleaseRejected('database channel must be test or production')
    if signatures.is_symlink() or signatures.name != 'signatures':
        raise ReleaseRejected(
            'release source must be the Git signatures directory')
    root = signatures.resolve().parent
    if signatures.resolve() != root / 'signatures':
        raise ReleaseRejected('noncanonical Git signatures directory')
    check(root)
    if not scanner.is_file() or not scanner.stat().st_mode & 0o111:
        raise ReleaseRejected('native YARA-X scanner executable is required')
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ReleaseRejected('refusing nonempty database output')

    catalog_cves = sorted(
        directory.name
        for directory in signatures.iterdir()
        if directory.is_dir() and CVE.fullmatch(directory.name))
    packs, selected_records, sources, entries = [], [], [], []
    seen_ids = set()
    for cve in catalog_cves:
        directory = signatures / cve
        pack_path = directory / 'pack.json'
        if not pack_path.is_file():
            if (directory / 'research.json').is_file():
                continue
            raise ReleaseRejected(f'{cve}: missing pack.json or research.json')
        rule_path = directory / 'rules-exec.yar'
        pack = read_json(pack_path)
        validate_source_pack(pack, rule_path, packfile=pack_path)
        records = cve_pack_records(pack)
        packs.append(pack)
        for record in records:
            record_id, owner = record_identity(cve, record)
            if record_id in seen_ids:
                raise ReleaseRejected(
                    f'duplicate database record ID: {record_id}')
            seen_ids.add(record_id)
            if channel == 'production' and record['channel'] != 'production':
                continue
            filtered = {**pack, 'records': [record]}
            selected_records.append((filtered, record))
            sources.append(source_from_packs([filtered]).rstrip())
            entries.append({
                'cve': owner,
                'record_id': record_id,
                'record_sha256': record_sha256(record),
                'channel': record['channel'],
                'platform': record['platform'],
                'pattern_count': len(record['rules']),
                'pack_sha256': sha256(pack_path),
                'rules_sha256': sha256(rule_path),
            })
    if not selected_records:
        raise ReleaseRejected(
            f'no {channel} database records in Git source tree')
    entries.sort(key=lambda row: (row['cve'], row['record_id']))
    sources_by_id = {
        record['record_id']: source
        for (_, record), source in zip(selected_records, sources)
    }
    rule_source = '\n'.join(
        sources_by_id[row['record_id']] for row in entries) + '\n'
    cves = sorted({row['cve'] for row in entries})
    excluded_from_channel = sorted(set(catalog_cves) - set(cves))
    record_count = len(entries)
    pattern_count = sum(row['pattern_count'] for row in entries)

    with TemporaryDirectory(prefix='vulnimprint-assemble-') as temporary:
        work = Path(temporary)
        (work / 'database.yar').write_text(rule_source, encoding='utf-8')
        compiled = work / 'database.yarc'
        try:
            process = subprocess.run([
                str(scanner), 'compile', '--rules',
                str(work / 'database.yar'), '--output',
                str(compiled)
            ],
                                     capture_output=True,
                                     text=True,
                                     timeout=120,
                                     check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ReleaseRejected('native YARA-X compilation failed') from exc
        if process.returncode or not compiled.is_file() or not compiled.stat(
        ).st_size:
            raise ReleaseRejected('native YARA-X compilation failed: ' +
                                  process.stderr[:600])
        write_json(
            work / 'index.json', {
                'schema_version': 2,
                'name': 'VulnImprint DB',
                'channel': channel,
                'profile': {
                    'os': 'linux',
                    'format': 'ELF',
                    'arch': 'x86-64',
                    'bits': 64,
                    'abi': 'sysv'
                },
                'record_count': record_count,
                'pattern_count': pattern_count,
                'cve_count': len(cves),
                'source_cves': catalog_cves,
                'excluded_from_channel_cves': excluded_from_channel,
                'entries': entries,
            })
        write_json(
            work / 'database-report.json', {
                'schema_version': 1,
                'channel': channel,
                'cve_count': len(cves),
                'record_count': record_count,
                'pattern_count': pattern_count,
                'records': entries,
            })
        digests = {
            name: sha256(work / name)
            for name in ('database.yarc', 'database.yar', 'index.json',
                         'database-report.json')
        }
        write_json(
            work / 'manifest.json', {
                'schema_version': 3,
                'artifacts': digests,
                'profile': PROFILE_ID,
                'channel': channel,
                'cve_count': len(cves),
                'record_count': record_count,
                'engine': {
                    'name': 'yara-x-capi',
                    'version': ENGINE_VERSION,
                    'serialized_rules_format': 'yara-x',
                    'scanner_min_version': '0.1.0',
                    'scanner_max_exclusive': '0.2.0',
                },
            })
        (work / 'SHA256SUMS').write_text(''.join(
            f'{digest}  {name}\n' for name, digest in sorted(digests.items())),
                                         encoding='utf-8')
        verify_release(work, scanner=scanner)
        out.mkdir(parents=True, exist_ok=True)
        for name in (*digests, 'manifest.json', 'SHA256SUMS'):
            shutil.copy2(work / name, out / name)
    return {
        'status': 'PASS',
        'channel': channel,
        'cve_count': len(cves),
        'record_count': record_count,
        'source_cve_count': len(catalog_cves),
        'output': str(out)
    }


def verify_release(directory: Path, *, scanner: Path | None = None) -> dict:
    """Verify database source, index, manifest and native compiled rule counts."""
    manifest = read_json(directory / 'manifest.json')
    if (manifest.get('schema_version') != 3 or
            not isinstance(manifest.get('artifacts'), dict) or
            manifest.get('channel') not in CHANNELS):
        raise ReleaseRejected('invalid DB manifest schema or channel')
    if manifest.get('profile') != PROFILE_ID or manifest.get('engine') != {
            'name': 'yara-x-capi',
            'version': ENGINE_VERSION,
            'serialized_rules_format': 'yara-x',
            'scanner_min_version': '0.1.0',
            'scanner_max_exclusive': '0.2.0'
    }:
        raise ReleaseRejected(
            'DB profile or native scanner/engine compatibility mismatch')
    expected_artifacts = {
        'database.yarc', 'database.yar', 'index.json', 'database-report.json'
    }
    if set(manifest['artifacts']) != expected_artifacts:
        raise ReleaseRejected('incomplete release manifest')
    for name, digest in manifest['artifacts'].items():
        if not HASH.fullmatch(str(digest)) or sha256(
                directory / name) != digest:
            raise ReleaseRejected('release digest mismatch: ' + name)
    checksum_file = directory / 'SHA256SUMS'
    observed = {}
    try:
        for line in checksum_file.read_text(encoding='utf-8').splitlines():
            digest, separator, name = line.partition('  ')
            if not separator or name in observed or not HASH.fullmatch(digest):
                raise ReleaseRejected('invalid or repeated SHA256SUMS entry')
            observed[name] = digest
    except OSError as exc:
        raise ReleaseRejected('missing SHA256SUMS') from exc
    if observed != manifest['artifacts']:
        raise ReleaseRejected('SHA256SUMS does not match DB manifest')

    index = read_json(directory / 'index.json')
    if (index.get('schema_version') != 2 or
            index.get('channel') != manifest['channel'] or
            index.get('profile') != {
                'os': 'linux',
                'format': 'ELF',
                'arch': 'x86-64',
                'bits': 64,
                'abi': 'sysv'
            }):
        raise ReleaseRejected(
            'unsupported DB index version, channel or binary profile')
    entries = index.get('entries')
    if not isinstance(entries, list) or not entries:
        raise ReleaseRejected('database has no records')
    record_ids, cves = set(), set()
    pattern_total = 0
    for entry in entries:
        if not isinstance(entry, dict):
            raise ReleaseRejected('malformed database record index entry')
        cve, record_id, channel = (entry.get('cve'), entry.get('record_id'),
                                   entry.get('channel'))
        if (not isinstance(cve, str) or not CVE.fullmatch(cve) or
                not isinstance(record_id, str) or
                not re.fullmatch(r'VI_[A-F0-9]{24}', record_id) or
                channel not in CHANNELS or
            (manifest['channel'] == 'production' and channel != 'production')):
            raise ReleaseRejected('invalid CVE/record identity or channel')
        if record_id in record_ids:
            raise ReleaseRejected('duplicate database record ID')
        record_ids.add(record_id)
        cves.add(cve)
        for digest_field in ('record_sha256', 'pack_sha256', 'rules_sha256'):
            digest = entry.get(digest_field)
            if not isinstance(digest, str) or not HASH.fullmatch(digest):
                raise ReleaseRejected('invalid source provenance digest')
        count = entry.get('pattern_count')
        if type(count) is not int or count < 1:
            raise ReleaseRejected('invalid per-record pattern count')
        platform = entry.get('platform')
        if platform != {
                'os': 'linux',
                'format': 'ELF',
                'arch': 'x86-64',
                'bits': 64,
                'abi': 'sysv'
        }:
            raise ReleaseRejected('unsupported record platform')
        pattern_total += count
    if (len(entries) != index.get('record_count') or
            len(cves) != index.get('cve_count') or
            pattern_total != index.get('pattern_count') or
            len(cves) != manifest.get('cve_count') or
            len(entries) != manifest.get('record_count')):
        raise ReleaseRejected('database record/CVE/pattern accounting mismatch')
    if entries != sorted(entries,
                         key=lambda row: (row['cve'], row['record_id'])):
        raise ReleaseRejected(
            'database records must be sorted by CVE and record ID')

    report = read_json(directory / 'database-report.json')
    if (report.get('schema_version') != 1 or
            report.get('channel') != index['channel'] or
            report.get('cve_count') != index['cve_count'] or
            report.get('record_count') != index['record_count'] or
            report.get('pattern_count') != index['pattern_count'] or
            report.get('records') != entries):
        raise ReleaseRejected('database report and index disagree')
    catalog = index.get('source_cves')
    excluded = index.get('excluded_from_channel_cves')
    if catalog is not None or excluded is not None:
        if (not isinstance(catalog, list) or catalog != sorted(set(catalog)) or
                not isinstance(excluded, list) or
                excluded != sorted(set(excluded)) or
                any(not isinstance(cve, str) or not CVE.fullmatch(cve)
                    for cve in catalog) or
                excluded != sorted(set(catalog) - cves) or
                not cves.issubset(set(catalog))):
            raise ReleaseRejected(
                'source CVE catalog disagrees with released records')
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
                    'rules') != index['record_count']:
                raise ReleaseRejected('native rule count and DB index differ')
        except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
            raise ReleaseRejected(
                'native YARA-X DB verification failed') from exc
    return {
        'status': 'PASS',
        'channel': index['channel'],
        'cve_count': index['cve_count'],
        'record_count': index['record_count']
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    review = sub.add_parser('review')
    review.add_argument('--cases', type=Path, required=True)
    review.add_argument('--scanner', type=Path, required=True)
    review.add_argument('--min-cves', type=int, default=1)
    review.add_argument('--signatures',
                        type=Path,
                        required=True,
                        help='complete version-controlled CVE directory')
    assemble = sub.add_parser('assemble')
    assemble.add_argument('--signatures', type=Path, required=True)
    assemble.add_argument('--output', type=Path, required=True)
    assemble.add_argument('--scanner', type=Path, required=True)
    assemble.add_argument('--channel',
                          choices=('test', 'production'),
                          default='production')
    v = sub.add_parser('verify')
    v.add_argument('--database', type=Path, required=True)
    v.add_argument('--scanner', type=Path)
    a = p.parse_args(argv)
    try:
        if a.cmd == 'review':
            out = review_cases(a.cases,
                               a.scanner,
                               min_cves=a.min_cves,
                               signatures=a.signatures)
        elif a.cmd == 'assemble':
            out = assemble_git_tree(a.signatures,
                                    a.output,
                                    a.scanner,
                                    channel=a.channel)
        else:
            out = verify_release(a.database, scanner=a.scanner)
    except (ReleaseRejected, OSError, subprocess.TimeoutExpired) as err:
        print('RELEASE BLOCKED:', err, file=sys.stderr)
        return 2
    print(json.dumps(out, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
