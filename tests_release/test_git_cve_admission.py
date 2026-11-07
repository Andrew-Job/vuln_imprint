"""CVE source-tree membership and test/production channel contracts."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts.check_native_cve_corpus import run as run_corpus_check
from scripts.check_cve_source_tree import check
from tools.manual_rules import initialize
from tools import production_db
from tools.production_db import ReleaseRejected

PATTERN = ' '.join(['90'] * 28)


def project(tmp_path):
    target = tmp_path / 'signatures'
    target.mkdir(parents=True)
    return target


def create_record(target, cve='CVE-2026-12345', channel='test', key='default'):
    case = target / cve
    initialize(cve, [PATTERN], case, channel=channel, record_key=key)
    return case


def test_test_and_production_records_are_valid_without_quality_labels(tmp_path):
    target = project(tmp_path)
    assert check(tmp_path) == []
    create_record(target, 'CVE-2026-12345', 'test')
    create_record(target, 'CVE-2026-67890', 'production')
    assert check(tmp_path) == []


def test_research_only_cve_remains_in_source_catalog(tmp_path):
    target = project(tmp_path)
    cve = 'CVE-2026-99999'
    folder = target / cve
    folder.mkdir()
    (folder / 'research.json').write_text(json.dumps({'cve': cve}))
    assert check(tmp_path) == []


def test_untracked_research_directory_cannot_enter_main(tmp_path):
    project(tmp_path)
    (tmp_path / 'research' / 'catalog_recent').mkdir(parents=True)
    with pytest.raises(ReleaseRejected, match='untracked research'):
        check(tmp_path)


def test_fork_research_directory_cannot_enter_main(tmp_path):
    project(tmp_path)
    (tmp_path / 'cve_queue').mkdir()
    with pytest.raises(ReleaseRejected, match='untracked research'):
        check(tmp_path)


def test_source_change_must_preserve_pack_and_canonical_yara(tmp_path):
    target = project(tmp_path)
    case = create_record(target)
    assert check(tmp_path) == []
    rule = case / 'rules-exec.yar'
    rule.write_text(rule.read_text().replace('90 90', '91 90', 1))
    with pytest.raises(ReleaseRejected, match='YARA source differs'):
        check(tmp_path)


def test_invalid_review_artifact_is_rejected_but_not_required(tmp_path):
    target = project(tmp_path)
    case = create_record(target)
    assert check(tmp_path) == []
    (case / 'reviewed-evidence.json').write_text('{}')
    with pytest.raises(ReleaseRejected, match='review artifact'):
        check(tmp_path)


def test_native_corpus_is_optional_until_a_cve_has_review_evidence(tmp_path):
    target = project(tmp_path)
    create_record(target, channel='production')
    lock = tmp_path / 'release'
    lock.mkdir()
    (lock / 'reviewed-corpus.lock.json').write_text(
        json.dumps({
            'schema_version': 3,
            'cases': {},
        }))
    assert run_corpus_check(tmp_path, tmp_path / 'native-scanner',
                            'reviewed.example.org') == {
                                'status': 'NO_REVIEWED_EVIDENCE',
                                'reviewed_cve_count': 0,
                                'cve_accuracy': 'NOT_ESTABLISHED'
                            }


def test_test_database_contains_both_channels_but_production_only_one(
        tmp_path, monkeypatch):
    source = project(tmp_path)
    create_record(source, 'CVE-2026-67890', 'production')
    create_record(source, 'CVE-2026-12345', 'test')
    scanner = tmp_path / 'native-scanner'
    scanner.write_text('#!/bin/sh\nexit 0\n')
    scanner.chmod(0o755)
    commands = []

    # The stub returns the actual count from the most recently compiled source.
    compiled_counts = []

    def scanner_boundary(argv, **kwargs):
        commands.append(argv)
        if argv[1] == 'compile':
            source_bytes = Path(argv[argv.index('--rules') + 1]).read_text()
            compiled_counts.append(source_bytes.count('rule VI_'))
            Path(argv[argv.index('--output') +
                      1]).write_bytes(b'compiled fixture')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        if argv[1] == 'verify':
            return SimpleNamespace(returncode=0,
                                   stdout=json.dumps({
                                       'engine': 'yara-x',
                                       'rules': compiled_counts[-1]
                                   }),
                                   stderr='')
        raise AssertionError(argv)

    monkeypatch.setattr(production_db.subprocess, 'run', scanner_boundary)
    test_out = tmp_path / 'test-db'
    production_db.assemble_git_tree(source, test_out, scanner, channel='test')
    test_index = json.loads((test_out / 'index.json').read_text())
    assert test_index['record_count'] == 2
    assert test_index['cve_count'] == 2

    production_out = tmp_path / 'production-db'
    production_db.assemble_git_tree(source,
                                    production_out,
                                    scanner,
                                    channel='production')
    production_index = json.loads((production_out / 'index.json').read_text())
    assert production_index['record_count'] == 1
    assert production_index['cve_count'] == 1
    assert production_index['entries'][0]['cve'] == 'CVE-2026-67890'
    assert [call[1] for call in commands
           ] == ['compile', 'verify', 'compile', 'verify']


def test_release_assembly_refuses_empty_and_noncanonical_source(tmp_path):
    from tools.production_db import assemble_git_tree

    source = project(tmp_path)
    executable = tmp_path / 'native-scanner'
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    with pytest.raises(ReleaseRejected, match='no production database records'):
        assemble_git_tree(source, tmp_path / 'database', executable)
    assert not (tmp_path / 'database').exists()
    alternative = tmp_path / 'arbitrary-directory'
    alternative.mkdir()
    with pytest.raises(ReleaseRejected, match='Git signatures directory'):
        assemble_git_tree(alternative, tmp_path / 'database', executable)
