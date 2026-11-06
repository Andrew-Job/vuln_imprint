"""Resolve real GCC/Clang versions before compiling CVE specimens.

The catalog pins a *major version lane*; this module records the exact
binary/target/patch version actually used. A locked environment can also pass
expected_version to require an exact match. Never infer version from 'gcc'.
"""
from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

COMPILER_NAME = re.compile(r'(gcc|clang)(?:-([0-9]+))?\Z')
VERSION = re.compile(r'\d+(?:\.\d+){1,3}')


class ToolchainMismatch(ValueError):
    pass


def _output(*args: str) -> str:
    return subprocess.run(args, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, check=True, timeout=20).stdout.strip()


def _digest(path: Path) -> str:
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def probe_compiler(name: str, *, expected_major: int | None = None,
                   expected_version: str | None = None,
                   optimization: str | None = None) -> dict:
    match = COMPILER_NAME.fullmatch(name)
    if not match:
        raise ToolchainMismatch(f'compiler must be gcc[-major] or clang[-major]: {name}')
    family, name_major = match.groups()
    resolved = shutil.which(name)
    if not resolved:
        raise ToolchainMismatch(f'compiler not installed: {name}')
    binary = Path(resolved).resolve(strict=True)
    banner = _output(str(binary), '--version').splitlines()[0]
    if family == 'gcc':
        raw_version = _output(str(binary), '-dumpfullversion', '-dumpversion').split()[0]
    else:
        version_match = re.search(r'clang version\s+(\d+(?:\.\d+){1,3})', banner)
        if not version_match:
            raise ToolchainMismatch(f'cannot parse Clang version: {banner}')
        raw_version = version_match.group(1)
    if not VERSION.fullmatch(raw_version):
        raise ToolchainMismatch(f'invalid compiler version: {raw_version}')
    major = int(raw_version.split('.')[0])
    if name_major and int(name_major) != major:
        raise ToolchainMismatch(f'compiler filename {name} disagrees with detected version {raw_version}')
    if expected_major is not None and int(expected_major) != major:
        raise ToolchainMismatch(f'{name}: expected major {expected_major}, got {raw_version}')
    if expected_version is not None and str(expected_version) != raw_version:
        raise ToolchainMismatch(f'{name}: expected exact {expected_version}, got {raw_version}')
    target = _output(str(binary), '-dumpmachine')
    if not target:
        raise ToolchainMismatch('compiler target triplet unavailable')
    return {'schema_version': 1, 'family': family, 'requested_executable': name,
            'executable': str(binary), 'binary_sha256': _digest(binary),
            'version': raw_version, 'major': major,
            'expected_major': expected_major, 'expected_version': expected_version,
            'target': target, 'version_banner': banner, 'optimization': optimization}


def check_profile(profile: dict, record: dict) -> None:
    """Require manifest's declared compiler lane to match the actual toolchain."""
    expected = profile.get('compiler')
    if expected and record['family'] != expected:
        raise ToolchainMismatch(f'compiler family drift: {expected} vs {record["family"]}')
    major = profile.get('compiler_major')
    if major is not None and int(major) != record['major']:
        raise ToolchainMismatch(f'compiler version drift: wanted {major}, got {record["version"]}')
    exact = profile.get('compiler_version_exact')
    if exact and exact != record['version']:
        raise ToolchainMismatch(f'compiler patch version drift: wanted {exact}, got {record["version"]}')
    if profile.get('optimization') and profile['optimization'] != record['optimization']:
        raise ToolchainMismatch('optimization profile does not match actual invocation')
