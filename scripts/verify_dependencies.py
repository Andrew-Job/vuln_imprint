#!/usr/bin/env python3
"""Verify reproducible upstream Git submodule pins before native builds.

The Git tree records a *gitlink* (mode 160000), not a floating release tag.
Updating upstream requires a reviewed change to BOTH that gitlink and
external/DEPENDENCIES.json. CI must fetch nested submodules recursively.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HEX40 = re.compile(r"[0-9a-f]{40}\Z")


def git(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args],
                          check=True,
                          capture_output=True,
                          text=True).stdout.rstrip("\r\n")


def verify(*, require_checkout: bool = False) -> dict:
    lock = json.loads((ROOT / "external" / "DEPENDENCIES.json").read_text())
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported dependency lock format")
    entries = lock.get("git_submodules")
    if not isinstance(entries, list) or not entries:
        raise ValueError("dependency lock contains no Git submodules")
    # Keep the Python and SBOM binary version pins tied to a single manifest.
    # Never infer readiness from a floating release or unverified installer.
    expected_python = lock.get('python_factory')
    if not isinstance(expected_python, dict) or not expected_python:
        raise ValueError('missing pinned Factory parser dependencies')
    factory_requirements = (ROOT / 'requirements-factory.txt').read_text()
    factory_pins = dict(
        re.findall(r'^([a-zA-Z0-9_-]+)==([^\s#]+)$',
                   factory_requirements,
                   flags=re.MULTILINE))
    if factory_pins != expected_python:
        raise ValueError('Factory dependency pins drift from dependency lock')
    rust = lock.get('rust_toolchain')
    if not isinstance(rust, str) or not rust:
        raise ValueError('missing pinned Rust toolchain')
    toolchain = tomllib.loads((ROOT / 'rust-toolchain.toml').read_text())
    if toolchain.get('toolchain', {}).get('channel') != rust:
        raise ValueError('Rust toolchain differs from dependency lock')
    if not isinstance(lock.get('cargo_c_version'),
                      str) or not lock['cargo_c_version']:
        raise ValueError('missing pinned cargo-c version')
    if not isinstance(lock.get('maturin_version'),
                      str) or not lock['maturin_version']:
        raise ValueError('missing pinned maturin version')
    sbom = lock.get('release_sbom_tool')
    if (not isinstance(sbom, dict) or sbom.get('name') != 'syft' or
            sbom.get('platform') != 'linux_amd64' or sbom.get('verification')
            != 'github_immutable_release_attestation' or
            not isinstance(sbom.get('version'), str) or
            not isinstance(sbom.get('repository'), str)):
        raise ValueError('pinned Syft SBOM tool is incomplete')
    modules = (ROOT / ".gitmodules").read_text()
    for entry in entries:
        path = entry["path"]
        expected_sha = entry["commit"]
        if not HEX40.fullmatch(expected_sha):
            raise ValueError(f"invalid pinned Git commit: {path}")
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("invalid Git submodule path")
        actual_url = git("config", "-f", ".gitmodules", "--get",
                         f"submodule.{path}.url")
        if actual_url != entry["url"] or entry["url"] not in modules:
            raise ValueError(f"unexpected submodule origin: {path}")
        status = git("ls-files", "--stage", "--", path).splitlines()
        if len(status) != 1:
            raise ValueError(f"missing Git submodule pointer: {path}")
        fields = status[0].split()
        if len(fields) != 4 or fields[0] != "160000" or fields[
                1] != expected_sha or fields[3] != path:
            raise ValueError(f"gitlink does not match committed lock: {path}")
        if require_checkout:
            checkout = ROOT / path
            if not checkout.is_dir():
                raise ValueError(f"submodule not cloned: {path}")
            head = git("-C", str(checkout), "rev-parse", "HEAD")
            if head != expected_sha:
                raise ValueError(
                    f"submodule checkout revision mismatch: {path}")
            required = {
                'external/yara-x': ('Cargo.lock', 'LICENSE'),
                'external/elfio': ('elfio/elfio.hpp', 'LICENSE.txt'),
            }.get(path)
            if not required:
                raise ValueError(f'unknown unreviewed submodule: {path}')
            for filename in required:
                if not (checkout / filename).is_file():
                    raise ValueError(
                        f'missing pinned upstream file: {path}/{filename}')
            dirty = git("-C", str(checkout), "status", "--porcelain",
                        "--untracked-files=no")
            if dirty:
                raise ValueError(f"modified submodule checkout: {path}")
    if require_checkout:
        # `submodules: recursive` must be a verified property, not merely a
        # checkout setting. A leading '-' is an absent nested checkout,
        # '+' denotes a different commit, and 'U' a merge conflict.
        recursive = git('submodule', 'status', '--recursive')
        top_paths = {item['path'] for item in entries}
        observed_top = set()
        for line in recursive.splitlines():
            if not line or line[0] != ' ':
                raise ValueError(
                    f'uninitialized or mismatched recursive Git submodule: {line}'
                )
            fields = line[1:].split()
            if len(fields) < 2 or not HEX40.fullmatch(fields[0]):
                raise ValueError(
                    f'malformed recursive submodule status: {line}')
            if fields[1] in top_paths:
                observed_top.add(fields[1])
        if observed_top != top_paths:
            raise ValueError(
                f'missing recursive submodule checkout: {top_paths - observed_top}'
            )
    return {
        "status": "PASS",
        "submodule_count": len(entries),
        "checkout_checked": require_checkout
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--require-checkout", action="store_true")
    args = ap.parse_args()
    try:
        print(
            json.dumps(verify(require_checkout=args.require_checkout),
                       sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, KeyError,
            json.JSONDecodeError) as exc:
        print(f"DEPENDENCY VERIFICATION FAILED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
