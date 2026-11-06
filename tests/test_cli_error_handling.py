"""CLI error propagation when imported as a reusable Python entry point."""

import subprocess

import cli


def test_imported_main_handles_build_subprocess_error(monkeypatch, tmp_path,
                                                      capsys):

    def fail(*args, **kwargs):
        raise subprocess.CalledProcessError(23, ['git', 'ls-remote'])

    monkeypatch.setattr(cli, 'freeze_manifest', fail)
    status = cli.main([
        'freeze',
        '--manifest',
        str(tmp_path / 'source.json'),
        '--output',
        str(tmp_path / 'locked.json'),
    ])
    assert status == 1
    assert 'ERROR:' in capsys.readouterr().err
