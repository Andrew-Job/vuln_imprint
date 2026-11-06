"""Combine independently validated platform CVE packs into a portable snapshot."""
import hashlib
import json
import re
import shutil
from pathlib import Path

_CVE = re.compile(r"CVE-\d{4}-\d{4,}\Z")


def _platform_key(platform: dict) -> str:
    if not isinstance(platform, dict):
        raise ValueError("invalid platform metadata")
    # Every build/profile field is significant, including compiler version,
    # optimization and ABI. The same CVE can be present in many profiles.
    return json.dumps(platform, sort_keys=True, separators=(",", ":"), allow_nan=False)


def merge_packs(pack_dirs: list[Path], output: Path, allow_experimental=False):
    output.mkdir(parents=True, exist_ok=True)
    contents, index, seen = [], [], set()
    for directory in sorted(pack_dirs):
        pack_file = directory / "pack.json"
        if not pack_file.is_file():
            continue
        pack = json.loads(pack_file.read_text())
        cve = pack["cve"]
        if not isinstance(cve, str) or not _CVE.fullmatch(cve):
            raise ValueError("invalid CVE in database pack")
        platform = pack.get("platform", {})
        profile_key = _platform_key(platform)
        key = (cve, profile_key)
        if key in seen:
            raise ValueError(f"duplicate CVE/platform in database: {key}")
        seen.add(key)
        status = pack["status"]
        entry = {"cve": cve, "status": status, "platform": platform,
                 "included": False}
        if (pack.get("rules") and status not in ("NO_SIGNATURE", "QUALITY_REJECTED")
                and (status == "CVE_SPECIFIC_VALIDATED" or allow_experimental)):
            rule_source = directory / "rules-exec.yar"
            source = rule_source.read_text()
            contents.append(source)
            # The CVE ID cannot uniquely identify a platform pack. Include a
            # stable profile hash without embedding arbitrary metadata in paths.
            digest = hashlib.sha256(profile_key.encode()).hexdigest()[:20]
            dest = output / "packs" / f"{cve}-{digest}"
            dest.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(pack_file, dest / "pack.json")
            shutil.copyfile(rule_source, dest / "rules-exec.yar")
            entry.update({"included": True, "pattern_count": len(pack["rules"]),
                          "pack_dir": (Path("packs") / dest.name).as_posix()})
        index.append(entry)
    (output / "database.yar").write_text("\n".join(contents))
    included = {item["cve"] for item in index if item["included"]}
    report = {"schema_version": 1,
              "cve_count": len({item["cve"] for item in index}),
              "platform_pack_count": len(seen),
              "included_cve_count": len(included),
              "included_platform_pack_count": sum(item["included"] for item in index),
              "allow_experimental": allow_experimental, "entries": index}
    (output / "index.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def load_included_packs(directory: Path):
    """Load only validated snapshot packs; indexes cannot read arbitrary paths."""
    root = Path(directory).resolve()
    index = json.loads((root / "index.json").read_text())
    result, seen = [], set()
    for entry in index["entries"]:
        if not entry.get("included"):
            continue
        folder = entry.get("pack_dir")
        if not isinstance(folder, str) or not folder:
            raise ValueError("index entry lacks pack_dir; rerun database command")
        relative = Path(folder)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe pack_dir in database index")
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or not path.is_dir():
            raise ValueError("pack_dir escapes database snapshot or is missing")
        pack = json.loads((path / "pack.json").read_text())
        cve = entry.get("cve")
        profile = _platform_key(pack.get("platform", {}))
        key = (cve, profile)
        if (pack.get("cve") != cve or key in seen
                or _platform_key(entry.get("platform", pack.get("platform", {}))) != profile):
            raise ValueError("database index CVE/platform is inconsistent or duplicated")
        seen.add(key)
        result.append(pack)
    return result
