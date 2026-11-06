"""Executable security regressions for the production source, release and DB gates."""
from __future__ import annotations
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path
import pytest

from scripts.safe_unpack_corpus import unpack
from tools.production_db import ReleaseRejected, sha256







def test_corpus_duplicates_symlinks_and_traversal_refused(tmp_path):
    for kind in ('duplicate','symlink','traversal'):
        archive=tmp_path/f'{kind}.tar.gz'
        with tarfile.open(archive,'w:gz') as t:
            data=b'demo'
            item=tarfile.TarInfo('../escape' if kind=='traversal' else 'CVE-1234/file')
            item.size=len(data)
            t.addfile(item,io.BytesIO(data))
            if kind=='duplicate':t.addfile(item,io.BytesIO(data))
            if kind=='symlink':
                link=tarfile.TarInfo('CVE-1234/link');link.type=tarfile.SYMTYPE
                link.linkname='../../outside';t.addfile(link)
        with pytest.raises(ValueError):
            unpack(archive,sha256(archive),tmp_path/f'extract-{kind}')
        assert not (tmp_path/f'extract-{kind}').exists()


def test_no_python_required_for_bundled_scan(tmp_path):
    root=tmp_path/'vulnimprint';(root/'bin').mkdir(parents=True)
    db=root/'share/vulnimprint/db';db.mkdir(parents=True)
    (db/'database.yarc').write_bytes(b'compiled database sample')
    (db/'SHA256SUMS').write_text(f"{sha256(db/'database.yarc')}  database.yarc\n")
    (root/'share/vulnimprint/RELEASE_VERSION').write_text('v0.1.0\n')
    source=Path(__file__).resolve().parents[1]/'tools/vulnimprint.sh'
    launcher=root/'bin/vulnimprint';shutil.copy2(source,launcher)
    launcher.chmod(0o755)
    fake=root/'bin/vulnimprint-scan'
    fake.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n')
    fake.chmod(0o755)
    r=subprocess.run([str(launcher),'scan','--json','/tmp/demo.elf'],
                     capture_output=True,text=True,check=True,
                     env={'PATH':'/usr/bin:/bin','HOME':str(tmp_path)})
    assert '--compiled' in r.stdout and '--json /tmp/demo.elf' in r.stdout
    (db/'database.yarc').write_bytes(b'tampered')
    bad=subprocess.run([str(launcher),'scan','/tmp/demo.elf'],capture_output=True,text=True,
                       env={'PATH':'/usr/bin:/bin'})
    assert bad.returncode==2 and 'integrity check failed' in bad.stderr
