#!/usr/bin/env python3
"""Produce an SPDX 2.3 SBOM for the *actual distributable* via Anchore Syft.

The SBOM is not assembled from guesses about Cargo.lock. Syft scans the
finalized archive and its packaged metadata; failure blocks the release.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import tarfile
import tomllib
from pathlib import Path


class SBOMError(ValueError):
    pass


# Expected components are checked against the actual finalized product,
# independently of package names inferred by Syft from Cargo.lock.
REQUIRED_PRODUCT_FILES = (
    'vulnimprint/bin/vulnimprint',
    'vulnimprint/bin/vulnimprint-scan',
    'vulnimprint/lib/libyara_x_capi.so',
    'vulnimprint/share/vulnimprint/db/database.yarc',
    'vulnimprint/share/vulnimprint/Cargo.lock',
)
REQUIRED_UPSTREAM_PACKAGES = frozenset({'yara-x', 'yara-x-capi'})
REQUIRED_RUNTIME_CRATES = frozenset({'serde', 'serde_json', 'regex', 'protobuf'})


def inspect_product_archive(product: Path) -> set[str]:
    try:
        with tarfile.open(product, 'r:gz') as archive:
            members = archive.getmembers()
            entries = {member.name: member for member in members}
            if len(entries) != len(members):
                raise SBOMError('duplicate entries in product archive')
            for name in REQUIRED_PRODUCT_FILES:
                entry = entries.get(name)
                if entry is None or not entry.isfile() or not entry.size:
                    raise SBOMError(f'product archive missing executable component: {name}')
            lock = archive.extractfile(entries['vulnimprint/share/vulnimprint/Cargo.lock'])
            if lock is None:
                raise SBOMError('no upstream Cargo.lock payload')
            manifest = tomllib.loads(lock.read().decode('utf-8'))
            crates = {row['name'] for row in manifest['package']}
            if not (REQUIRED_UPSTREAM_PACKAGES | REQUIRED_RUNTIME_CRATES).issubset(crates):
                raise SBOMError('shipped YARA-X lockfile lacks expected upstream components')
            return crates
    except (tarfile.TarError, OSError, ValueError, KeyError, UnicodeError,
            TypeError) as exc:
        if isinstance(exc, SBOMError):
            raise
        raise SBOMError(f'invalid finalized release archive: {exc}') from exc


def create_sbom(product: Path, out: Path, *, syft: str = 'syft') -> dict:
    product = Path(product).resolve(strict=True)
    if not product.is_file() or product.stat().st_size == 0:
        raise SBOMError('final release product archive is missing or empty')
    locked_crates = inspect_product_archive(product)
    try:
        # Syft's file: source adapter inspects the actual archive contents.
        completed = subprocess.run(
            [syft, 'scan', f'file:{product}', '--output', 'spdx-json'],
            capture_output=True, text=True, check=True, timeout=300)
        sbom = json.loads(completed.stdout)
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
            json.JSONDecodeError) as exc:
        raise SBOMError(f'Syft SBOM creation failed: {exc}') from exc
    if (not isinstance(sbom, dict) or sbom.get('spdxVersion') != 'SPDX-2.3'
            or not isinstance(sbom.get('packages'), list)
            or not sbom.get('SPDXID') == 'SPDXRef-DOCUMENT'
            or not isinstance(sbom.get('creationInfo'), dict)):
        raise SBOMError('Syft did not produce a complete SPDX-2.3 JSON document')
    # Syft can legitimately fail to recognize packages in a bare binary.
    # Our release ships upstream Cargo.lock precisely so Rust dependencies
    # are included in the scan; an empty package list blocks the release.
    if not sbom['packages']:
        raise SBOMError('Syft discovered no packages in the release archive')
    if any(not isinstance(pkg, dict) or not isinstance(pkg.get('name'), str)
           or not isinstance(pkg.get('SPDXID'), str) for pkg in sbom['packages']):
        raise SBOMError('Syft reported packages with invalid SPDX identities')
    names = {pkg['name'] for pkg in sbom['packages']}
    missing = (REQUIRED_UPSTREAM_PACKAGES | REQUIRED_RUNTIME_CRATES) - names
    if missing or not (names & locked_crates):
        raise SBOMError('SBOM missing shipped YARA-X components/crates: ' + ', '.join(sorted(missing)))
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(sbom, sort_keys=True, indent=2) + '\n')
    return {'path': str(out), 'packages': len(sbom['packages']),
            'scanner': 'Anchore Syft', 'spdx_version': 'SPDX-2.3',
            'verified_product_entries': len(REQUIRED_PRODUCT_FILES)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--product', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--syft', default='syft')
    args = parser.parse_args()
    try:
        print(json.dumps(create_sbom(args.product, args.output, syft=args.syft)))
    except (SBOMError, OSError) as exc:
        parser.exit(2, f'SBOM BLOCKED: {exc}\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
