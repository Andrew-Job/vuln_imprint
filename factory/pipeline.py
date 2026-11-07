"""Manifest-driven binary signature production pipeline.

No CVE-specific code exists here. A CVE entry names samples, their labels,
optional known symbol names, and acquisition/build instructions. Failures in
source acquisition, architecture support or quality validation are explicit.
"""
from __future__ import annotations
import hashlib, json, os, re, subprocess, tempfile, urllib.request, tarfile, zipfile, shutil, fnmatch, sys
from pathlib import Path
from dataclasses import dataclass
from collections import Counter
from .patterns import Pattern
from .toolchains import check_profile
from .build_provenance import verify_record
from .git_source import get_git_source
from .evidence_isolation import is_independent_holdout
from .archive_safety import extract_zip
from .artifact_store import ArtifactStore
from .yara_engine import YaraXScanner, source_from_packs


@dataclass
class Sample:
    id: str
    path: Path
    label: str
    split: str
    version: str
    toolchain: str
    origin: str
    provenance: dict
    elf: ELF

    @property
    def regions(self):
        return self.elf.executable_ranges()


@dataclass(frozen=True)
class Candidate:
    pattern: Pattern
    source: str
    file_offset: int
    instructions: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('source download redirects are not permitted')


def environment_versions():
    result = {'python': sys.version.split()[0]}
    for tool in ('objdump', 'gcc', 'clang'):
        try:
            proc = subprocess.run([tool, '--version'],
                                  text=True,
                                  capture_output=True,
                                  timeout=5,
                                  check=True)
            result[tool] = proc.stdout.splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            result[tool] = 'unavailable'
    return result


def sha256(path: Path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _safe_extract_tar(archive: Path, dest: Path):
    """Reject links, duplicates, special files and decompression bombs."""
    with tarfile.open(archive) as tf:
        members = tf.getmembers()
        if len(members) > 100000:
            raise ValueError('source archive has too many members')
        if sum(m.size for m in members) > 512 * 1024 * 1024:
            raise ValueError('source archive expanded size exceeds 512 MiB')
        seen = set()
        for member in members:
            name = member.name
            if (not name or name.startswith('/') or '..' in Path(name).parts or
                    '\\' in name or name in seen or
                    member.size > 128 * 1024 * 1024 or
                    not (member.isfile() or member.isdir())):
                raise ValueError('unsafe source tar member')
            seen.add(name)
        tf.extractall(dest, filter='data')


def acquire(entry: dict, root: Path, work: Path) -> Path:
    """Resolve local paths/globs, or fetch sha256-pinned source artifacts.

    `commands` are optional trusted, argument-vector build commands and are
    intentionally separate from the CVE matching logic.
    """
    if 'path' in entry:
        path = Path(entry['path'].format(work=str(work.resolve()),
                                         root=str(
                                             root.resolve()))).expanduser()
        if not path.is_absolute():
            path = root / path
    elif 'wheel_glob' in entry:
        import site, glob
        matches = []
        for base in site.getsitepackages() + [site.getusersitepackages()]:
            matches.extend(glob.glob(str(Path(base) / entry['wheel_glob'])))
        matches = sorted(set(matches))
        if len(matches) != 1:
            raise FileNotFoundError(
                f'expected exactly one wheel source for {entry["wheel_glob"]}, found {len(matches)}'
            )
        path = Path(matches[0])
    elif 'glob' in entry:
        import glob
        matches = sorted(glob.glob(entry['glob']))
        if not matches:
            raise FileNotFoundError('no file matches ' + entry['glob'])
        if len(matches) > 1:
            raise ValueError('ambiguous glob: ' + entry['glob'])
        path = Path(matches[0])
    elif 'url' in entry:
        expected = entry.get('sha256')
        url = entry.get('url')
        if not isinstance(expected, str) or not re.fullmatch(
                r'[0-9a-f]{64}', expected):
            raise ValueError('valid SHA-256 is mandatory for URL acquisition')
        if not isinstance(url, str) or not url.startswith('https://'):
            raise ValueError('HTTPS URL is mandatory')
        path = work / ('download-' +
                       hashlib.sha256(entry['url'].encode()).hexdigest()[:16])
        if path.exists() and sha256(path) != entry['sha256']:
            # Never reuse a partial or corrupted download from a previous run.
            path.unlink()
        if not path.exists():
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(dir=work,
                                                 prefix='.download-',
                                                 delete=False) as output:
                    temporary = Path(output.name)
                    copied = 0
                    digest = hashlib.sha256()
                    with urllib.request.build_opener(_NoRedirect).open(
                            url, timeout=30) as response:
                        if response.geturl() != entry['url']:
                            raise ValueError(
                                'source download redirects are not permitted')
                        while block := response.read(1 << 20):
                            copied += len(block)
                            if copied > 1024 * 1024 * 1024:
                                raise ValueError(
                                    'source download exceeds 1 GiB limit')
                            digest.update(block)
                            output.write(block)
                    if digest.hexdigest() != entry['sha256']:
                        raise ValueError('SHA256 mismatch for source download')
                    output.flush()
                    os.fsync(output.fileno())
                os.replace(temporary, path)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
    else:
        raise ValueError('sample requires path, glob or url')
    if not path.exists():
        raise FileNotFoundError(path)
    if entry.get('sha256') and sha256(path) != entry['sha256']:
        raise ValueError('SHA256 mismatch for ' + str(path))
    if entry.get('member_glob') or entry.get('member'):
        pattern = entry.get('member_glob') or entry['member']
        if not isinstance(pattern, str) or not pattern:
            raise ValueError(
                'archive member selector must be a nonempty string')
        archive_digest = sha256(path)
        if path.suffix.lower() in ('.zip', '.whl'):
            with zipfile.ZipFile(path) as zf:
                matching = [
                    info for info in zf.infolist()
                    if fnmatch.fnmatch(info.filename, pattern)
                ]
                if len(matching) != 1:
                    raise ValueError(
                        f'{path}: archive member ambiguity: '
                        f'{[info.filename for info in matching[:5]]}')
                info = matching[0]
                name = info.filename
                mode = (info.external_attr >> 16) & 0o170000
                if (info.is_dir() or name.startswith('/') or '\\' in name or
                        ':' in name or
                        any(part in ('', '.', '..') for part in name.split('/'))
                        or mode not in (0, 0o100000) or
                        info.file_size > 128 * 1024 * 1024):
                    raise ValueError('unsafe or oversized ZIP member')
                out = _member_path(work, archive_digest, name)
                # Extract afresh rather than trusting old bytes at a cache path.
                with zf.open(info) as source:
                    _write_member(source, out, expected_size=info.file_size)
                path = out
        elif path.suffix.lower() == '.a':
            names = run_archive('ar', 't', str(path)).splitlines()
            matching = [
                name for name in names if fnmatch.fnmatch(name, pattern)
            ]
            if len(matching) != 1:
                raise ValueError(f'archive object ambiguity: {matching[:5]}')
            name = matching[0]
            if (not name or name != Path(name).name or name in ('.', '..') or
                    '\\' in name):
                raise ValueError('unsafe archive member')
            out = _member_path(work, archive_digest, name)
            _extract_ar_member(path, name, out)
            path = out
        else:
            raise ValueError(
                'member_glob supported for ZIP/wheel and ar archives')
    return path.resolve()


def _member_path(work: Path, archive_digest: str, member_name: str) -> Path:
    # The full member path, not its basename, participates in cache identity.
    identity = hashlib.sha256(
        (archive_digest + '\0' + member_name).encode()).hexdigest()
    return work / ('member-' + identity + Path(member_name).suffix[:16])


def _write_member(source, destination: Path, *, expected_size: int) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,
                                         prefix='.member-',
                                         delete=False) as output:
            temporary = Path(output.name)
            copied = 0
            while block := source.read(1 << 20):
                copied += len(block)
                if copied > 128 * 1024 * 1024 or copied > expected_size:
                    raise ValueError(
                        'archive member exceeds declared size or limit')
                output.write(block)
            if copied != expected_size:
                raise ValueError('truncated archive member')
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _extract_ar_member(archive: Path, name: str, destination: Path) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent,
                                         prefix='.member-',
                                         delete=False) as output:
            temporary = Path(output.name)
            subprocess.run(['ar', 'p', str(archive), name],
                           stdout=output,
                           stderr=subprocess.PIPE,
                           check=True,
                           timeout=60)
            output.flush()
            os.fsync(output.fileno())
            if output.tell() > 128 * 1024 * 1024:
                raise ValueError('archive object exceeds 128 MiB limit')
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_archive(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True,
                          text=True).stdout


def _prepare(manifest: dict,
             root: Path,
             work: Path,
             mirror_cache: Path | None = None):
    """Optional source-build recipes; suitable for gcc/clang cross/target profiles.

    Each command receives {workspace} and {source_dir} placeholders, no shell.
    Existing prebuilt binaries need no recipe.
    """
    builds = manifest.get('builds', [])
    if not isinstance(builds, list):
        raise ValueError('builds must be a list')
    names = set()
    # Validate every command and source shape before executing the first recipe.
    for i, job in enumerate(builds):
        if not isinstance(job, dict):
            raise ValueError(f'build {i}: expected an object')
        jobname = job.get('name', i)
        if not isinstance(jobname, (str, int)) or isinstance(jobname, bool):
            raise ValueError(f'build {i}: invalid name')
        jobname = str(jobname)
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', jobname) or jobname in names:
            raise ValueError('unsafe or duplicate build job name: ' + jobname)
        names.add(jobname)
        if not isinstance(job.get('source'), dict):
            raise ValueError(f'{jobname}: source must be an object')
        commands = job.get('commands', [])
        if not isinstance(commands, list) or any(
                not isinstance(cmd, list) or not cmd or any(
                    not isinstance(arg, str) or not arg
                    for arg in cmd)
                for cmd in commands):
            raise ValueError(
                f'{jobname}: commands must be nonempty argv string lists')
        if not isinstance(job.get('profile', {}), dict):
            raise ValueError(f'{jobname}: build profile must be an object')
        allowed = {'workspace', 'source_dir', 'root', 'repo'}
        for cmd in commands:
            for arg in cmd:
                try:
                    arg.format_map({key: 'PATH' for key in allowed})
                except (ValueError, KeyError, IndexError,
                        AttributeError) as exc:
                    raise ValueError(
                        f'{jobname}: invalid build command placeholder'
                    ) from exc
    for i, job in enumerate(builds):
        jobname = str(job.get('name', i))
        folder = work / ('build-' + jobname)
        # A build's previous binaries and extracted sources must never be reused
        # with a different source archive or an interrupted prior run.
        if folder.is_symlink():
            raise ValueError(
                f'{jobname}: build workspace must not be a symlink')
        if folder.exists():
            if not folder.is_dir():
                raise ValueError(
                    f'{jobname}: build workspace is not a directory')
            shutil.rmtree(folder)
        folder.mkdir(parents=True)
        if 'git' in job['source']:
            source_dir, source_info = get_git_source(job['source'],
                                                     work,
                                                     mirror_cache=mirror_cache)
        else:
            archive = acquire(job['source'], root, work)
            source_dir = folder / 'source'
            # Publish the source directory only after extraction completes.
            # An interrupted extraction cannot be mistaken for a valid cache.
            with tempfile.TemporaryDirectory(dir=folder,
                                             prefix='.source-') as staging:
                staging_dir = Path(staging)
                if tarfile.is_tarfile(archive):
                    _safe_extract_tar(archive, staging_dir)
                elif zipfile.is_zipfile(archive):
                    extract_zip(archive, staging_dir)
                else:
                    raise ValueError('unsupported source archive')
                os.replace(staging_dir, source_dir)
            source_info = {
                'type': 'archive',
                'sha256': sha256(archive),
                'origin': str(archive)
            }
        (folder / 'source-provenance.json'
        ).write_text(json.dumps(source_info, indent=2, sort_keys=True) + '\n')
        subst = {
            'workspace': str(folder.resolve()),
            'source_dir': str(source_dir.resolve()),
            'root': str(root.resolve()),
            'repo': str(Path(__file__).resolve().parent.parent)
        }
        commands = job.get('commands', [])
        if not isinstance(commands, list):
            raise ValueError('commands must be a list of argv lists')
        for cmd in commands:
            if (not isinstance(cmd, list) or not cmd or
                    not all(isinstance(arg, str) and arg for arg in cmd)):
                raise ValueError('commands must be nonempty argv string lists')
            try:
                args = [argument.format(**subst) for argument in cmd]
            except (ValueError, KeyError, IndexError) as exc:
                raise ValueError('invalid build command placeholder') from exc
            subprocess.run(args, cwd=folder, check=True, timeout=1800)
        if source_info['type'] == 'git':
            # The compiler must not modify the pinned upstream checkout while
            # manufacturing an apparently valid source provenance record.
            verified_path, verified_source = get_git_source(
                job['source'], work, mirror_cache=mirror_cache)
            if verified_path != source_dir or verified_source != source_info:
                raise ValueError(
                    f'{jobname}: source checkout changed during build')
        # Reproducible CVE recipes have a declared versioned compiler lane.
        # Reject silent fallback (e.g. clang-15 unexpectedly resolving to clang-17).
        profile = job.get('profile', {})
        if 'compiler_major' in profile or 'compiler_version_exact' in profile:
            proof = folder / 'toolchain-provenance.json'
            if not proof.is_file():
                raise ValueError(
                    f'{jobname}: required toolchain-provenance.json missing')
            toolchain = json.loads(proof.read_text())
            check_profile(profile, toolchain)
            verify_record(folder, source_info, toolchain)


def load_manifest(path: Path, output: Path, mirror_cache: Path | None = None):
    from .elf import ELF

    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise ValueError('CVE manifest must be a JSON object')
    ident = data.get('cve', '')
    if not isinstance(ident, str) or not re.fullmatch(r'CVE-\d{4}-\d{4,}',
                                                      ident):
        raise ValueError('invalid CVE ID')
    if data.get('schema_version') != 1:
        raise ValueError('expected schema_version=1')
    rows = data.get('samples')
    if not isinstance(rows, list) or not rows:
        raise ValueError('samples must be a nonempty list')
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('id'),
                                                       str) or not row['id']:
            raise ValueError('each sample requires a nonempty string id')
    roots = path.parent
    work = output / 'work'
    work.mkdir(parents=True, exist_ok=True)
    _prepare(data, roots, work, mirror_cache=mirror_cache)
    samples = []
    ids = set()
    for row in data['samples']:
        name = row['id']
        if name in ids:
            raise ValueError('duplicate sample id: ' + name)
        ids.add(name)
        if row['label'] not in ('affected', 'fixed', 'unrelated'):
            raise ValueError('unknown label for ' + name)
        if row['split'] not in ('train', 'holdout', 'regression', 'dev'):
            raise ValueError('unknown split for ' + name)
        p = acquire(row, roots, work)
        obj = ELF(p)
        samples.append(
            Sample(name, p, row['label'], row['split'],
                   row.get('version',
                           'unknown'), row.get('toolchain', 'unknown'),
                   row.get('origin', 'unknown'), {
                       k: v for k, v in row.items() if k not in ('path', 'glob')
                   }, obj))
    if not any(s.label == 'affected' and s.split == 'train' for s in samples):
        raise ValueError('at least one train affected sample required')
    if not any(s.label == 'fixed' and s.split == 'train' for s in samples):
        raise ValueError('at least one train fixed sample required')
    return data, samples


def normalized_windows(instructions,
                       min_instructions=6,
                       max_instructions=15,
                       min_bytes=28,
                       max_bytes=96,
                       min_fixed=24):
    """Extract contiguous instruction-aligned masked windows.

    No candidate is fabricated by replacing unknown instruction bytes with
    wildcards. Only decoded relative fields and supported relocations vary.
    """
    seen = set()
    for start, first in enumerate(instructions):
        buf, mask = bytearray(), bytearray()
        last_end = first.file_offset
        for j in range(start, min(len(instructions), start + max_instructions)):
            ins = instructions[j]
            if ins.section != first.section or ins.file_offset != last_end:
                break
            if len(buf) + len(ins.raw) > max_bytes:
                break
            buf.extend(ins.raw)
            mask.extend(ins.normalized.mask)
            last_end += len(ins.raw)
            n = j - start + 1
            if n < min_instructions or len(buf) < min_bytes:
                continue
            if mask.count(255) < min_fixed or mask.count(255) < .70 * len(mask):
                continue
            pat = Pattern(bytes(buf), bytes(mask))
            atom = pat.atom()[1]
            if len(atom) < 6:
                continue
            if pat.to_hex() in seen:
                continue
            seen.add(pat.to_hex())
            yield pat, first.file_offset, n


def _match(candidate: Pattern, sample: Sample, cache: dict):
    key = (sample.id, candidate.to_hex())
    if key not in cache:
        cache[key] = bool(candidate.search(sample.regions, first_only=True))
    return cache[key]


def select(samples, cfg, symbols):
    from .disasm import disassemble

    train = [s for s in samples if s.split == 'train']
    positives = [s for s in train if s.label == 'affected']
    negatives = [s for s in train if s.label != 'affected']
    cache = {}
    candidates = {}
    stats = {
        'train_affected': len(positives),
        'train_negative': len(negatives),
        'extracted': {},
        'rejected_negative': 0,
        'distinct': 0,
        'accepted': 0
    }
    for sample in positives:
        decoded = disassemble(sample.path, symbols,
                              int(cfg.get('max_instructions', 25000)))
        windows = list(
            normalized_windows(decoded, cfg.get('min_instructions', 6),
                               cfg.get('max_instructions_per_window', 15),
                               cfg.get('min_bytes',
                                       28), cfg.get('max_bytes', 96),
                               cfg.get('min_fixed', 24)))
        stats['extracted'][sample.id] = {
            'instructions': len(decoded),
            'candidate_windows': len(windows)
        }
        if len(windows) > int(cfg.get('max_candidates_per_sample', 50000)):
            windows = windows[:int(cfg.get('max_candidates_per_sample', 50000))]
            stats['candidate_truncated'] = True
        for pat, offset, n in windows:
            key = pat.to_hex()
            # one candidate per unique normalized pattern, not per seed.
            if key not in candidates:
                candidates[key] = Candidate(pat, sample.id, offset, n)
    stats['distinct'] = len(candidates)
    usable = []
    for candidate in candidates.values():
        if any(_match(candidate.pattern, neg, cache) for neg in negatives):
            stats['rejected_negative'] += 1
            continue
        coverage = frozenset(
            p.id for p in positives if _match(candidate.pattern, p, cache))
        if not coverage:
            continue
        usable.append((candidate, coverage))
    stats['accepted'] = len(usable)
    selected = []
    uncovered = set(s.id for s in positives)
    max_rules = int(cfg.get('max_rules', 12))
    # Greedy coverage, with explicit alternatives for dissimilar affected builds.
    while uncovered and len(selected) < max_rules:
        choices = [
            (c, cover) for c, cover in usable if len(cover & uncovered) > 0
        ]
        if not choices:
            break

        def score(pair):
            c, cover = pair
            return (len(cover & uncovered), len(cover), c.pattern.fixed,
                    c.pattern.atom()[1].__len__(), -len(c.pattern.data),
                    c.source, c.file_offset)

        best, cover = max(choices, key=score)
        selected.append((best, cover))
        uncovered -= cover
        usable = [(c, cover)
                  for c, cover in usable
                  if c.pattern.to_hex() != best.pattern.to_hex()]
    stats['uncovered_train'] = sorted(uncovered)
    return selected, stats


def scan_patterns(patterns, sample: Sample):
    findings = []
    for i, pat in enumerate(patterns):
        for offset in pat.search(sample.regions):
            findings.append({'rule': i, 'file_offset': offset})
    return findings


def yara_text(cve: str, rules: list[Pattern]):
    name = cve.replace('-', '_')
    result = [
        f'rule {name}_ELF64_x86_64 {{', '  meta:', f'    cve = "{cve}"',
        '    format = "ELF64"', '    arch = "x86_64"',
        '    status = "experimental"', '  strings:'
    ]
    for i, pat in enumerate(rules):
        result.append(f'    $v{i} = {{ {pat.to_hex()} }}')
    result.extend([
        '  condition:',
        '    uint32(0) == 0x464c457f and uint8(4) == 2 and uint16(18) == 0x3e and any of them',
        '}'
    ])
    return '\n'.join(result) + '\n'


def _validate(samples, selected):
    patterns = [c.pattern for c, _ in selected]
    results = []
    for s in samples:
        matches = scan_patterns(patterns, s)
        expected = s.label == 'affected'
        classification = ('TP' if expected else 'FP') if matches else (
            'FN' if expected else 'TN')
        results.append({
            'id': s.id,
            'origin': s.origin,
            'version': s.version,
            'toolchain': s.toolchain,
            'profile': s.provenance.get('profile'),
            'label': s.label,
            'split': s.split,
            'actual': bool(matches),
            'classification': classification,
            'match_count': len(matches),
            'matches': matches[:30],
            'sha256': sha256(s.path),
            'bytes': s.path.stat().st_size,
            'label_basis': s.provenance.get('label_basis', 'unknown')
        })
    return results


def validate_yara_x(cve: str, patterns: list[Pattern], samples: list[Sample]):
    """Compare native YARA-X with independent reference matcher on ELF code ranges."""
    if not patterns:
        return {
            'status': 'NO_PATTERNS',
            'message': 'No machine patterns to compile',
            'mismatches': []
        }
    try:
        from .signature_identity import new_record_id
        source = source_from_packs([{
            'schema_version':
                3,
            'cve':
                cve,
            'records': [{
                'record_id':
                    new_record_id(cve, 'factory-validation'),
                'channel':
                    'test',
                'source_type':
                    'factory',
                'platform': {
                    'os': 'linux',
                    'format': 'ELF',
                    'arch': 'x86-64',
                    'bits': 64,
                    'abi': 'sysv'
                },
                'rules': [{
                    'id': f'{cve}-pattern-{index}',
                    'hex': pattern.to_hex(),
                    'length': len(pattern.data),
                    'fixed_bytes': pattern.fixed
                } for index, pattern in enumerate(patterns)],
            }],
        }])
        scanner = YaraXScanner.compile(source)
    except RuntimeError as e:
        if 'not installed' in str(e).lower() or 'required' in str(e).lower():
            return {
                'status': 'NOT_INSTALLED',
                'message': str(e),
                'mismatches': []
            }
        return {
            'status': 'COMPILATION_FAILED',
            'message': repr(e),
            'mismatches': []
        }
    except Exception as e:
        return {
            'status': 'COMPILATION_FAILED',
            'message': repr(e),
            'mismatches': []
        }
    mismatches = []
    for sample in samples:
        try:
            outcome = scanner.scan(sample.path)
            actual = {(int(x['pattern'].removeprefix('$v')), x['file_offset'])
                      for x in outcome['matches']}
            expected = {(x['rule'], x['file_offset'])
                        for x in scan_patterns(patterns, sample)}
            if actual != expected:
                mismatches.append({
                    'id': sample.id,
                    'reference_count': len(expected),
                    'yara_count': len(actual),
                    'extra': sorted(actual - expected)[:8],
                    'missing': sorted(expected - actual)[:8]
                })
        except Exception as e:
            mismatches.append({'id': sample.id, 'error': repr(e)})
    return {
        'status': 'PASS' if not mismatches else 'MISMATCH',
        'mismatches': mismatches
    }


def run(manifest: Path,
        output: Path,
        store: Path | None = None,
        mirror_cache: Path | None = None):
    output.mkdir(parents=True, exist_ok=True)
    spec, samples = load_manifest(manifest, output, mirror_cache=mirror_cache)
    stored = []
    if store:
        cas = ArtifactStore(store)
        for sample in samples:
            metadata = {
                'label': sample.label,
                'split': sample.split,
                'version': sample.version,
                'toolchain': sample.toolchain,
                'origin': sample.origin,
                'provenance': sample.provenance
            }
            for job in spec.get('builds', []):
                folder = output / 'work' / ('build-' + job['name'])
                if sample.path.is_relative_to(folder.resolve()):
                    provenance_file = folder / 'source-provenance.json'
                    metadata['build'] = {
                        'job':
                            job['name'],
                        'profile':
                            job.get('profile', {}),
                        'source':
                            json.loads(provenance_file.read_text()),
                        'toolchain':
                            json.loads(
                                (folder /
                                 'toolchain-provenance.json').read_text()) if
                            (folder /
                             'toolchain-provenance.json').is_file() else None,
                        'build_provenance':
                            json.loads((folder /
                                        'build-provenance.json').read_text()) if
                            (folder /
                             'build-provenance.json').is_file() else None
                    }
                    break
            stored.append(
                cas.add(sample.path,
                        cve=spec['cve'],
                        specimen_id=sample.id,
                        metadata=metadata))
        # Optional complete build archive, not just the objects used for mining.
        # Exact duplicate binary files share the same SHA-256 blob across CVEs.
        for job in spec.get('builds', []):
            folder = output / 'work' / ('build-' + job['name'])
            provenance_file = folder / 'source-provenance.json'
            for pattern in job.get('artifacts', []):
                if Path(pattern).is_absolute() or '..' in Path(pattern).parts:
                    raise ValueError('unsafe artifact glob: ' + pattern)
                for artifact in sorted(folder.glob(pattern)):
                    if not artifact.is_file() or not artifact.resolve(
                    ).is_relative_to(folder.resolve()):
                        continue
                    specimen_id = 'build-' + job['name'] + '-' + artifact.name
                    stored.append(
                        cas.add(
                            artifact,
                            cve=spec['cve'],
                            specimen_id=specimen_id,
                            metadata={
                                'role': 'build_artifact',
                                'state': job.get('state'),
                                'build': {
                                    'job':
                                        job['name'],
                                    'profile':
                                        job.get('profile', {}),
                                    'source':
                                        json.loads(provenance_file.read_text()),
                                    'toolchain':
                                        json.loads((folder /
                                                    'toolchain-provenance.json'
                                                   ).read_text()) if
                                        (folder /
                                         'toolchain-provenance.json').is_file()
                                        else None,
                                    'build_provenance':
                                        json.loads(
                                            (folder / 'build-provenance.json'
                                            ).read_text()) if
                                        (folder /
                                         'build-provenance.json').is_file() else
                                        None
                                }
                            }))
    symbols = spec.get('hints', {}).get('symbols')
    cfg = spec.get('mining', {})
    selected, stats = select(samples, cfg, symbols)
    patterns = [c.pattern for c, _ in selected]
    results = _validate(samples, selected)
    yara_validation = validate_yara_x(spec['cve'], patterns,
                                      samples) if patterns else {
                                          'status': 'NO_PATTERNS',
                                          'mismatches': []
                                      }
    # Reject incorrect detections on *every* supplied control, not just train negatives.
    all_sample_errors = [
        r for r in results if (r['label'] == 'affected') != r['actual']
    ]
    train_neg_errors = [
        r for r in all_sample_errors
        if r['split'] == 'train' and r['label'] != 'affected'
    ]
    holdout_errors = [
        r for r in results if r['split'] == 'holdout' and (
            (r['label'] == 'affected') != r['actual'])
    ]
    holdout_pos = [
        r for r in results
        if r['split'] == 'holdout' and r['label'] == 'affected'
    ]
    holdout_fixed = [
        r for r in results if r['split'] == 'holdout' and r['label'] == 'fixed'
    ]
    independent_holdout = bool(holdout_pos and holdout_fixed and
                               is_independent_holdout(samples))
    if not selected:
        status = 'NO_SIGNATURE'
    elif all_sample_errors or yara_validation['status'] in (
            'MISMATCH', 'COMPILATION_FAILED'):
        status = 'QUALITY_REJECTED'
    elif not independent_holdout:
        status = 'EXPERIMENTAL_NO_BLIND_HOLDOUT'
    elif any(r['label_basis'] in ('upstream_range', 'upstream_release',
                                  'unknown') for r in results):
        status = 'EXPERIMENTAL_VERSION_ASSOCIATED'
    elif yara_validation['status'] != 'PASS':
        status = 'EXPERIMENTAL_YARA_X_UNVERIFIED'
    else:
        status = 'VALIDATED_ON_GIVEN_CORPUS'
    source_builds = []
    for job in spec.get('builds', []):
        f = output / 'work' / ('build-' +
                               str(job['name'])) / 'source-provenance.json'
        if f.is_file():
            source_builds.append({
                'name':
                    job['name'],
                'profile':
                    job.get('profile', {}),
                'source':
                    json.loads(f.read_text()),
                'toolchain':
                    json.loads(
                        (f.parent / 'toolchain-provenance.json').read_text()) if
                    (f.parent /
                     'toolchain-provenance.json').is_file() else None,
                'build_provenance':
                    json.loads(
                        (f.parent / 'build-provenance.json').read_text()) if
                    (f.parent / 'build-provenance.json').is_file() else None,
                'commands':
                    job.get('commands', [])
            })
    out_rules = []
    for i, (c, cover) in enumerate(selected):
        out_rules.append({
            'id': f'{spec["cve"]}-v{i:02d}',
            'hex': c.pattern.to_hex(),
            'file_offset': c.file_offset,
            'source_sample': c.source,
            'train_positive_coverage': sorted(cover),
            'length': len(c.pattern.data),
            'fixed_bytes': c.pattern.fixed,
            'max_fixed_atom': len(c.pattern.atom()[1]),
            'instructions': c.instructions
        })
    from .signature_identity import new_record_id
    platform = {
        'os': 'linux',
        'format': 'ELF',
        'bits': 64,
        'arch': 'x86-64',
        'abi': 'sysv'
    }
    record_key = spec.get('record_key', 'default')
    channel = spec.get('channel', 'test')
    record = {
        'record_id': new_record_id(spec['cve'], record_key),
        'channel': channel,
        'source_type': 'factory',
        'platform': platform,
        'rules': out_rules,
        'supported_profiles': spec.get('supported_profiles', []),
        'scope': 'affected_family_evidence',
        'hints': spec.get('hints', {}),
        'notes': 'Not proof of reachability or absence of backports.'
    }
    pack_path = output / 'pack.json'
    if out_rules:
        pack = {'schema_version': 3, 'cve': spec['cve'], 'records': [record]}
        pack_path.write_text(json.dumps(pack, indent=2, sort_keys=True) + '\n')
        (output / 'rules-exec.yar').write_text(source_from_packs([pack]))
    else:
        pack_path.unlink(missing_ok=True)
        (output / 'rules-exec.yar').write_text('// No machine record\n')
    counts = {
        split:
            dict(
                Counter(r['classification']
                        for r in results
                        if r['split'] == split))
        for split in ('train', 'dev', 'regression', 'holdout')
    }
    summary = {
        'cve': spec['cve'],
        'status': status,
        'mining': stats,
        'independent_holdout': independent_holdout,
        'sample_errors': [{
            'id': r['id'],
            'classification': r['classification'],
            'split': r['split']
        } for r in all_sample_errors],
        'yara_x_validation': yara_validation,
        'metrics': counts,
        'results': results,
        'limitations': [
            'Source version labels do not prove vendor patch state',
            'No blind affected holdout unless manifest supplies one',
            'YARA-X runtime validation is separate and mandatory for deployment',
            'Current backend supports ELF64 x86-64, not PE/Mach-O or LTO',
            'Factory matches executable segments, YARA rule scans file contents'
        ],
        'artifacts': stored,
        'source_builds': source_builds,
        'manifest_sha256': sha256(manifest),
        'environment': environment_versions()
    }
    (output / 'report.json'
    ).write_text(json.dumps(summary, indent=2, sort_keys=True) + '\n')
    return summary


def reference_scan(pack: Path, target: Path):
    from .elf import ELF

    p = json.loads(pack.read_text())
    elf = ELF(target)
    out = []
    for record in p['records']:
        for row in record['rules']:
            pattern = Pattern.from_hex(row['hex'])
            for offset in pattern.search(elf.executable_ranges()):
                out.append({
                    'cve': p['cve'],
                    'record_id': record['record_id'],
                    'pattern': row['id'],
                    'offset': offset,
                })
    return {
        'cve': p['cve'],
        'target': str(target),
        'matches': out,
        'detected': bool(out),
        'engine': 'reference_executable_elf_verifier'
    }


def yara_scan(pack: Path, target: Path):
    obj = json.loads(Path(pack).read_text())
    scanner = YaraXScanner.compile(source_from_packs([obj]))
    result = scanner.scan(target)
    result['cve'] = obj['cve']
    return result
