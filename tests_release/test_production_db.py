"""These are offline negative/packaging tests, NOT CVE proof or YARA-X tests."""
import json
import io
import tarfile
from pathlib import Path
import pytest
from tools.production_db import build_release, ReleaseRejected, verify_release, sha256,validate_case, validate_source_pack


def test_cannot_publish_zero_packs(tmp_path):
    cases=tmp_path/'cases';cases.mkdir()
    with pytest.raises(ReleaseRejected,match='requires >=1000'):
        build_release(cases,tmp_path/'out',Path('/usr/bin/true'),min_cves=1000)
    assert not (tmp_path/'out').exists()


def test_candidate_is_not_admitted(tmp_path):
    case=tmp_path/'CVE-2026-25646';case.mkdir()
    (case/'pack.json').write_text(json.dumps({'cve':'CVE-2026-25646','schema_version':1,
             'rules':[],'status':'EXPERIMENTAL_NO_BLIND_HOLDOUT',
             'platform':{'format':'ELF','arch':'x86-64','bits':64}}))
    with pytest.raises(ReleaseRejected,match='empty patterns'):
        validate_case(case,Path('/usr/bin/true'))


def dummy_db(path):
    """Metadata-only fixture for testing SHA and update transaction logic."""
    path.mkdir()
    for name,content in [('database.yarc',b'not actually compiled'),('database.yar',b'rule fake {}'),
                         ('quality-report.json',b'{}'),('index.json',json.dumps({'cve_count':1,
                          'rule_quality':'CVE_SPECIFIC_VALIDATED','schema_version':1,'yara_rule_count':1,
                          'pattern_count':1,'profile':{'os':'linux','format':'ELF',
                          'arch':'x86-64','bits':64,'abi':'sysv'}}).encode())]:
        (path/name).write_bytes(content)
    files={p.name:sha256(p) for p in path.iterdir()}
    (path/'manifest.json').write_text(json.dumps({'schema_version':2,'artifacts':files,'cve_count':1,
     'profile':'linux-elf64-x86_64-sysv','engine':{'name':'yara-x-capi','version':'1.23.0',
     'serialized_rules_format':'yara-x','scanner_min_version':'0.1.0',
     'scanner_max_exclusive':'0.2.0'}}))
    (path/'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n' for name,digest in sorted(files.items())))
    return path






def test_nonproduction_quality_rejected(tmp_path):
    dummy_db(tmp_path/'db')
    p=tmp_path/'db'/'index.json'
    j=json.loads(p.read_text());j['rule_quality']='AFFECTED_FAMILY_VALIDATED';p.write_text(json.dumps(j))
    m=tmp_path/'db'/'manifest.json'
    j=json.loads(m.read_text());j['artifacts']['index.json']=sha256(p);m.write_text(json.dumps(j))
    (tmp_path/'db'/'SHA256SUMS').write_text(''.join(
        f'{digest}  {name}\n' for name,digest in sorted(j['artifacts'].items())))
    with pytest.raises(ReleaseRejected,match='non-production rules'):
        verify_release(tmp_path/'db')




def test_sha256sums_disagreement_rejected(tmp_path):
    db=dummy_db(tmp_path/'db')
    (db/'SHA256SUMS').write_text('00' + (db/'SHA256SUMS').read_text()[2:])
    with pytest.raises(ReleaseRejected,match='SHA256SUMS'):
        verify_release(db)


def test_forged_fixed_byte_strength_is_rejected(tmp_path):
    case=tmp_path/'CVE-2099-10001'; case.mkdir()
    source=case/'rules-exec.yar'; source.write_text('rule dummy {condition: true}\n')
    fake_pattern=' '.join(['??'] * 64)
    pack={'schema_version':1,'cve':'CVE-2099-10001', 'status':'EXPERIMENTAL',
          'platform':{'os':'linux','format':'ELF','arch':'x86-64','bits':64,'abi':'sysv'},
          'rules':[{'id':'test-0', 'hex':fake_pattern,'length':64,'fixed_bytes':64}]}
    with pytest.raises(ReleaseRejected, match='length/fixed_bytes do not match'):
        validate_source_pack(pack, source, packfile=case/'pack.json')
    pack['rules'][0]['fixed_bytes']=0
    with pytest.raises(ReleaseRejected, match='weak pattern'):
        validate_source_pack(pack, source, packfile=case/'pack.json')


def test_release_contents_binds_embedded_database_and_download_bytes(tmp_path):
    """Our release identity must bind the DB inside the only product archive."""
    from tools.release_approval import make_contents, verify_contents

    database = dummy_db(tmp_path / "db")
    index_path = database / "index.json"
    index = json.loads(index_path.read_text())
    index["entries"] = [{
        "cve": "CVE-2026-12345",
        "quality": "CVE_SPECIFIC_VALIDATED",
        "pack_sha256": "a" * 64,
        "rules_sha256": "b" * 64,
    }]
    index_path.write_text(json.dumps(index))
    manifest_path = database / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["artifacts"]["index.json"] = sha256(index_path)
    manifest_path.write_text(json.dumps(manifest))
    (database / "SHA256SUMS").write_text("".join(
        f"{digest}  {name}\n" for name, digest in sorted(manifest["artifacts"].items())
    ))

    product = tmp_path / "vulnimprint-linux-x86_64.tar.gz"
    def make_product(directory):
        with tarfile.open(product, "w:gz") as archive:
            for file in sorted(directory.iterdir()):
                archive.add(file, arcname="vulnimprint/share/vulnimprint/db/" + file.name)

    make_product(database)
    sbom = tmp_path / "SBOM.spdx.json"
    sbom.write_text('{"spdxVersion": "SPDX-2.3"}')
    contents = make_contents(database, "v0.1.0", "c" * 40, [product, sbom])
    assert [item["cve"] for item in contents["cves"]] == ["CVE-2026-12345"]
    statement_path = tmp_path / "release-contents.json"
    statement_path.write_text(json.dumps(contents))
    assert verify_contents(statement_path, tmp_path)["cve_count"] == 1

    product.write_bytes(b"tampered")
    with pytest.raises(ReleaseRejected, match="digest mismatch"):
        verify_contents(statement_path, tmp_path)

    # Rehashing a different product archive does not make its CVE list match.
    other = tmp_path / "other"
    other.mkdir()
    import shutil
    shutil.copytree(database, other, dirs_exist_ok=True)
    alt_index = json.loads((other / "index.json").read_text())
    alt_index["entries"][0]["rules_sha256"] = "e" * 64
    (other / "index.json").write_text(json.dumps(alt_index))
    alt_manifest = json.loads((other / "manifest.json").read_text())
    alt_manifest["artifacts"]["index.json"] = sha256(other / "index.json")
    (other / "manifest.json").write_text(json.dumps(alt_manifest))
    (other / "SHA256SUMS").write_text("".join(
        f"{digest}  {name}\n" for name, digest in sorted(alt_manifest["artifacts"].items())
    ))
    make_product(other)
    contents["artifacts"][product.name] = sha256(product)
    statement_path.write_text(json.dumps(contents))
    with pytest.raises(ReleaseRejected, match="does not bind embedded DB"):
        verify_contents(statement_path, tmp_path)


def test_release_includes_every_validated_git_case_without_selection(tmp_path):
    """The source of membership is the validated Git tree, never a selector."""
    cases = tmp_path / "cases"
    cases.mkdir()
    git = tmp_path / "validated"
    git.mkdir()
    scanner = tmp_path / "scanner"
    scanner.write_text("#!/bin/sh\nexit 0\n")
    scanner.chmod(0o755)

    for cve in ("CVE-2026-12345", "CVE-2026-67890"):
        case = cases / cve
        case.mkdir()
        canonical = git / cve
        canonical.mkdir()
        for dest in (case, canonical):
            (dest / "pack.json").write_text(json.dumps({"cve": cve}))
            (dest / "rules-exec.yar").write_text("rule example { condition: true }\n")
            (dest / "reviewed-evidence.json").write_text("{}")

    # Both CVEs pass the initial canonical-source membership check. The
    # intentionally incomplete samples then fail independently at validation.
    with pytest.raises(ReleaseRejected, match="unsupported pack schema"):
        build_release(cases, tmp_path / "output", scanner, signatures=git)

    # Missing one Git CVE must never cause the release builder to drop it.
    (git / "CVE-2026-67890" / "pack.json").unlink()
    with pytest.raises(ReleaseRejected, match="differs from version-controlled source"):
        build_release(cases, tmp_path / "output", scanner, signatures=git)


def test_unknown_corpus_cve_cannot_be_auto_published(tmp_path):
    cases = tmp_path / "cases"
    case = cases / "CVE-2026-12345"
    case.mkdir(parents=True)
    (case / "pack.json").write_text('{"cve": "CVE-2026-12345"}')
    canonical = tmp_path / "validated"
    canonical.mkdir()
    with pytest.raises(ReleaseRejected, match="CVE mismatch"):
        build_release(cases, tmp_path / "output", Path("/usr/bin/true"),
                      signatures=canonical)
