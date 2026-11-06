#!/usr/bin/env python3
"""Package a verified native scanner, YARA-X library, and pinned database.

The Linux package relies on the documented compatible system runtime; it
never builds from placeholders or silently resolves a missing dependency.
"""
from __future__ import annotations
import argparse
import gzip
import hashlib
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
import re

TAG = re.compile(r"v\d+\.\d+\.\d+\Z")
from tools.production_db import ReleaseRejected, sha256, verify_release


def write_reproducible_archive(root: Path, output: Path) -> None:
    """Pack the installed tree with stable order, metadata and gzip header."""
    try:
        epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    except ValueError as exc:
        raise ReleaseRejected("SOURCE_DATE_EPOCH must be an integer") from exc
    if not 0 <= epoch <= 253402300799:
        raise ReleaseRejected(
            "SOURCE_DATE_EPOCH is outside the supported range")

    def normalize(info: tarfile.TarInfo) -> tarfile.TarInfo:
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        info.mtime = epoch
        info.mode = 0o755 if info.isdir() or info.mode & 0o111 else 0o644
        return info

    with output.open("wb") as destination:
        with gzip.GzipFile(fileobj=destination,
                           filename="",
                           mode="wb",
                           mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed,
                              mode="w",
                              format=tarfile.PAX_FORMAT) as archive:
                archive.add(root,
                            arcname="vulnimprint",
                            recursive=False,
                            filter=normalize)
                for path in sorted(
                        root.rglob("*"),
                        key=lambda p: p.relative_to(root).as_posix()):
                    if path.is_symlink():
                        raise ReleaseRejected(
                            "symlinks are forbidden in the application archive")
                    name = "vulnimprint/" + path.relative_to(root).as_posix()
                    archive.add(path,
                                arcname=name,
                                recursive=False,
                                filter=normalize)


def build_product(database: Path, scanner: Path, library: Path, version: str,
                  out: Path):
    if not TAG.fullmatch(version):
        raise ReleaseRejected('invalid release version')
    verify_release(database, scanner=scanner)
    if not scanner.is_file() or not os.access(scanner, os.X_OK):
        raise ReleaseRejected('native scanner missing')
    if not library.is_file():
        raise ReleaseRejected('actual yara_x_capi library missing')
    with tempfile.TemporaryDirectory(prefix='vulnimprint-pkg-') as tmp:
        root = Path(tmp) / 'vulnimprint'
        (root / 'bin').mkdir(parents=True)
        (root / 'lib').mkdir()
        (root / 'share/vulnimprint').mkdir(parents=True)
        (root / 'licenses/yara-x').mkdir(parents=True)
        shutil.copy2(scanner, root / 'bin/vulnimprint-scan')
        # Include the full SONAME family, preserving names expected by the ELF loader.
        for item in sorted(library.parent.glob('libyara_x_capi.so*')):
            if item.is_file() or item.is_symlink():
                shutil.copy2(item, root / 'lib' / item.name)
        if not list((root / 'lib').iterdir()):
            raise ReleaseRejected('cannot stage YARA-X shared library')
        source = Path(__file__).resolve().parent
        shutil.copy2(source / 'vulnimprint.sh', root / 'bin/vulnimprint')
        project = source.parent
        upstream_license = project / 'external/yara-x/LICENSE'
        if not upstream_license.is_file():
            raise ReleaseRejected(
                'mandatory upstream YARA-X BSD-3-Clause license is missing')
        shutil.copy2(upstream_license, root / 'licenses/yara-x/LICENSE')
        elfio_license = project / 'external/elfio/LICENSE.txt'
        if not elfio_license.is_file():
            raise ReleaseRejected(
                'mandatory pinned ELFIO MIT license is missing')
        (root / 'licenses/elfio').mkdir(parents=True)
        shutil.copy2(elfio_license, root / 'licenses/elfio/LICENSE.txt')
        upstream_lock = project / 'external/yara-x/Cargo.lock'
        if not upstream_lock.is_file():
            raise ReleaseRejected(
                'pinned YARA-X Cargo.lock is required for release SBOM')
        shutil.copy2(upstream_lock, root / 'share/vulnimprint/Cargo.lock')
        shutil.copy2(project / 'LICENSE', root / 'licenses/VulnImprint-MIT.txt')
        shutil.copy2(project / 'THIRD_PARTY_NOTICE.md',
                     root / 'licenses/THIRD_PARTY_NOTICE.md')
        (root / 'bin/vulnimprint').chmod(0o755)
        (root / 'share/vulnimprint/RELEASE_VERSION').write_text(version + '\n')
        shutil.copytree(database, root / 'share/vulnimprint/db')
        # Security invariant: the compiled native binary must load from bundled lib.
        clean_env = os.environ.copy()
        clean_env.pop('LD_LIBRARY_PATH', None)
        ldd = subprocess.run(['ldd', str(root / 'bin/vulnimprint-scan')],
                             capture_output=True,
                             text=True,
                             env=clean_env)
        if ldd.returncode != 0 or 'not found' in ldd.stdout or 'not found' in ldd.stderr:
            raise ReleaseRejected('runtime dependencies unresolved: ' +
                                  ldd.stdout[:800])
        if not any('libyara_x_capi.so' in line and str(root / 'lib') in line
                   for line in ldd.stdout.splitlines()):
            raise ReleaseRejected(
                'scanner did not resolve YARA-X from its bundled lib directory')
        for bundled_library in sorted(
            (root / 'lib').glob('libyara_x_capi.so*')):
            if bundled_library.is_symlink():
                continue
            resolution = subprocess.run(['ldd', str(bundled_library)],
                                        capture_output=True,
                                        text=True,
                                        env=clean_env,
                                        timeout=30)
            if (resolution.returncode != 0 or
                    'not found' in resolution.stdout or
                    'not found' in resolution.stderr):
                raise ReleaseRejected(
                    'YARA-X runtime has unresolved dependencies')
        check = subprocess.run([
            str(root / 'bin/vulnimprint-scan'), 'verify', '--compiled',
            str(root / 'share/vulnimprint/db/database.yarc')
        ],
                               capture_output=True,
                               text=True,
                               env=clean_env,
                               timeout=30)
        if check.returncode != 0:
            raise ReleaseRejected(
                'installed scanner cannot deserialize bundled DB: ' +
                check.stderr[:500])
        out.parent.mkdir(parents=True, exist_ok=True)
        write_reproducible_archive(root, out)
    return {'product': str(out), 'sha256': sha256(out), 'version': version}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--database', type=Path, required=True)
    p.add_argument('--scanner', type=Path, required=True)
    p.add_argument('--yarax-lib', type=Path, required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    try:
        print(
            build_product(a.database, a.scanner, a.yarax_lib, a.version,
                          a.output))
        return 0
    except (ReleaseRejected, OSError) as e:
        print('PRODUCT BLOCKED:', e)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
