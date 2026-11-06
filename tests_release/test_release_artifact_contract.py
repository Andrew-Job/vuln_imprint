"""First-party release packaging and SBOM outputs, not upstream tool tests."""

import json
import tarfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import create_sbom, package_product
from tools.production_db import ReleaseRejected


def _synthetic_project(tmp_path):
    """Minimal first-party files used to isolate packaging layout decisions."""
    root = tmp_path / "source"
    (root / "tools").mkdir(parents=True)
    (root / "external/yara-x").mkdir(parents=True)
    (root / "external/elfio").mkdir(parents=True)
    (root / "external/elfio/LICENSE.txt").write_text("test ELFIO MIT notice fixture\n")
    (root / "tools/vulnimprint.sh").write_text("#!/bin/sh\nexit 0\n")
    (root / "LICENSE").write_text("test MIT license fixture\n")
    (root / "THIRD_PARTY_NOTICE.md").write_text("test notice fixture\n")
    (root / "external/yara-x/LICENSE").write_text("test BSD notice fixture\n")
    (root / "external/yara-x/Cargo.lock").write_text(
        'version = 3\n[[package]]\nname = "test-crate"\nversion = "0.1.2"\n'
    )
    return root


def test_product_archive_contains_self_contained_layout(tmp_path, monkeypatch):
    root = _synthetic_project(tmp_path)
    db = tmp_path / "db"
    db.mkdir()
    (db / "database.yarc").write_bytes(b"test database only")
    scanner = tmp_path / "scanner"
    scanner.write_bytes(b"test executable fixture")
    scanner.chmod(0o755)
    library = tmp_path / "libyara_x_capi.so"
    library.write_bytes(b"test library fixture")
    monkeypatch.setattr(
        package_product, "__file__", str(root / "tools/package_product.py")
    )
    monkeypatch.setattr(
        package_product, "verify_release", lambda *a, **k: {"status": "PASS"}
    )

    def fake_tool(argv, **kwargs):
        if argv[0] == "ldd":
            bundled_lib = Path(argv[1]).parent.parent / "lib/libyara_x_capi.so"
            return SimpleNamespace(
                returncode=0,
                stdout=f"libyara_x_capi.so => {bundled_lib} (0x1)",
                stderr="",
            )
        if argv[1] == "verify":
            return SimpleNamespace(returncode=0, stdout="{}", stderr="")
        raise AssertionError(f"unexpected external command: {argv}")

    monkeypatch.setattr(package_product.subprocess, "run", fake_tool)
    output = tmp_path / "dist/product.tar.gz"
    result = package_product.build_product(
        db, scanner, library, "v0.1.0", output
    )
    assert result["version"] == "v0.1.0"
    with tarfile.open(output, "r:gz") as archive:
        files = set(archive.getnames())
        for name in (
            "vulnimprint/bin/vulnimprint",
            "vulnimprint/bin/vulnimprint-scan",
            "vulnimprint/lib/libyara_x_capi.so",
            "vulnimprint/share/vulnimprint/db/database.yarc",
            "vulnimprint/licenses/yara-x/LICENSE",
            "vulnimprint/licenses/elfio/LICENSE.txt",
            "vulnimprint/share/vulnimprint/Cargo.lock",
        ):
            assert name in files


def test_product_fails_when_bundled_runtime_cannot_be_verified(
    tmp_path, monkeypatch
):
    root = _synthetic_project(tmp_path)
    monkeypatch.setattr(
        package_product, "__file__", str(root / "tools/package_product.py")
    )
    monkeypatch.setattr(package_product, "verify_release", lambda *a, **k: None)
    db = tmp_path / "db"
    db.mkdir()
    scanner = tmp_path / "scanner"
    scanner.write_bytes(b"fixture")
    scanner.chmod(0o755)
    lib = tmp_path / "libyara_x_capi.so"
    lib.write_bytes(b"fixture")

    def unresolved_ldd(argv, **kwargs):
        return SimpleNamespace(
            returncode=0, stdout="libyara_x_capi.so => not found", stderr=""
        )

    monkeypatch.setattr(package_product.subprocess, "run", unresolved_ldd)
    dest = tmp_path / "dist/product.tar.gz"
    with pytest.raises(
        ReleaseRejected, match="runtime dependencies unresolved"
    ):
        package_product.build_product(db, scanner, lib, "v0.1.0", dest)
    assert not dest.exists()


def _mini_product(tmp_path):
    """Real tar structure, synthetic bytes; SBOM response stays mocked."""
    root = tmp_path / 'contents/vulnimprint'
    for name in ('bin/vulnimprint', 'bin/vulnimprint-scan',
                 'lib/libyara_x_capi.so',
                 'share/vulnimprint/db/database.yarc'):
        file = root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(b'fixture for ' + name.encode())
    lock = root / 'share/vulnimprint/Cargo.lock'
    lock.write_text('version = 3\n' + ''.join(
        f'[[package]]\nname = "{name}"\nversion = "1.23.0"\n'
        for name in ('yara-x', 'yara-x-capi', 'serde', 'serde_json', 'regex', 'protobuf')))
    product = tmp_path / 'product.tar.gz'
    with tarfile.open(product, 'w:gz') as archive:
        archive.add(root, arcname='vulnimprint')
    return product


def test_syft_sbom_scans_actual_product_archive(tmp_path, monkeypatch):
    product = _mini_product(tmp_path)
    output = tmp_path / "SBOM.spdx.json"
    calls = []

    def fake_syft(command, **kwargs):
        calls.append(command)
        assert command == ["syft", "scan", f"file:{product}",
                           "--output", "spdx-json"]
        return SimpleNamespace(stdout=json.dumps({
            "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
            "creationInfo": {"created": "2026-11-05T00:00:00Z"},
            "packages": [
                {"name": name, "SPDXID": f"SPDXRef-{name}"}
                for name in ('yara-x', 'yara-x-capi', 'serde', 'serde_json',
                             'regex', 'protobuf')],
        }))

    monkeypatch.setattr(create_sbom.subprocess, "run", fake_syft)
    result = create_sbom.create_sbom(product, output)
    assert result["scanner"] == "Anchore Syft"
    assert result["packages"] == 6
    assert len(calls) == 1
    assert json.loads(output.read_text())["packages"][0]["name"] == "yara-x"


def test_sbom_rejects_invalid_or_empty_syft_document(tmp_path, monkeypatch):
    product = _mini_product(tmp_path)
    for document in ({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT",
                      "creationInfo": {}, "packages": []},
                     {"spdxVersion": "SPDX-2.2", "packages": [{"name": "x"}]}):
        monkeypatch.setattr(create_sbom.subprocess, "run", lambda *a, **kw:
                            SimpleNamespace(stdout=json.dumps(document)))
        with pytest.raises(create_sbom.SBOMError):
            create_sbom.create_sbom(product, tmp_path / "sbom.json")
        assert not (tmp_path / "sbom.json").exists()


def test_sbom_missing_syft_fails_closed(tmp_path, monkeypatch):
    product = _mini_product(tmp_path)
    def missing(*a, **kw):
        raise FileNotFoundError("syft unavailable")
    monkeypatch.setattr(create_sbom.subprocess, "run", missing)
    with pytest.raises(create_sbom.SBOMError, match="Syft SBOM creation failed"):
        create_sbom.create_sbom(product, tmp_path / "sbom.json")
