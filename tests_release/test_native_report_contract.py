"""Parsing our native scanner report; no YARA-X implementation is mocked or tested."""

import json
from types import SimpleNamespace

import pytest

from tools import production_db


def _scanner_result(matches=None, *, engine="yara-x", truncated=False,
                    error=None):
    return {
        "engine": engine,
        "results": [{
            "error": error,
            "truncated": truncated,
            "matches": matches if matches is not None else [],
        }],
    }


def test_native_scan_preserves_structured_findings(tmp_path, monkeypatch):
    target = tmp_path / "input.elf"
    target.write_bytes(b"synthetic fixture")
    report = _scanner_result([
        {"cve": "CVE-2025-12345", "file_offset": 128, "executable": True},
    ])
    monkeypatch.setattr(
        production_db.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=0, stdout=json.dumps(report), stderr=""
        ),
    )
    result = production_db.native_scan(tmp_path / "scanner", tmp_path / "rules.yar", target)
    assert result["matches"][0]["file_offset"] == 128


@pytest.mark.parametrize("response,exit_code,reason", [
    (_scanner_result(truncated=True), 0, "bad native scan report"),
    (_scanner_result(engine="fake-matcher"), 0, "bad native scan report"),
    (_scanner_result(error="I/O failed"), 0, "bad native scan report"),
    ({"engine": "yara-x", "results": []}, 0, "bad native scan report"),
    (None, 1, "native scan failed"),
])
def test_native_report_rejects_invalid_or_partial_results(
    tmp_path, monkeypatch, response, exit_code, reason
):
    monkeypatch.setattr(
        production_db.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(
            returncode=exit_code,
            stdout=json.dumps(response),
            stderr="synthetic scanner failure",
        ),
    )
    with pytest.raises(production_db.ReleaseRejected, match=reason):
        production_db.native_scan(
            tmp_path / "scanner", tmp_path / "rules.yar", tmp_path / "input.elf"
        )
