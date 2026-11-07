"""Small local content-addressed staging store for reproducible binary specimens.

Local CAS follows the same digest-first model as OCI registries. OCI/ORAS is
recommended for central distribution; this module does not claim to implement
an OCI registry, a Conan cache, or a formal SLSA attestation.
"""
from __future__ import annotations
import hashlib
import json
import os
import re
import shutil
import tempfile
from pathlib import Path


class ArtifactStore:

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def add(self,
            file: Path,
            *,
            cve: str,
            specimen_id: str,
            metadata: dict | None = None):
        if not re.fullmatch(r'CVE-\d{4}-\d{4,}', cve):
            raise ValueError('invalid CVE')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', specimen_id):
            raise ValueError('invalid specimen ID')
        with Path(file).open('rb') as source:
            h = hashlib.file_digest(source, 'sha256').hexdigest()
        blob = self.root / 'blobs' / 'sha256' / h[:2] / h
        blob.parent.mkdir(parents=True, exist_ok=True)
        if not blob.exists():
            fd, temp = tempfile.mkstemp(dir=str(blob.parent),
                                        prefix='.pending-')
            try:
                copied = hashlib.sha256()
                with os.fdopen(fd, 'wb') as dest, Path(file).open('rb') as src:
                    while part := src.read(1 << 20):
                        copied.update(part)
                        dest.write(part)
                    dest.flush()
                    os.fsync(dest.fileno())
                if copied.hexdigest() != h:
                    raise RuntimeError('content changed while ingesting')
                os.replace(temp, blob)
                directory_fd = os.open(blob.parent,
                                       os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            finally:
                if os.path.exists(temp):
                    os.unlink(temp)
        # Existing content is not trusted merely because its filename is a hash.
        if blob.is_symlink() or not blob.is_file():
            raise RuntimeError('invalid content-addressed blob')
        with blob.open('rb') as existing:
            existing_hash = hashlib.file_digest(existing, 'sha256').hexdigest()
        if existing_hash != h:
            raise RuntimeError('content-addressed blob digest corruption')
        record = {
            'schema_version': 1,
            'cve': cve,
            'specimen_id': specimen_id,
            'blob': {
                'algorithm': 'sha256',
                'digest': h,
                'size': blob.stat().st_size,
                'path': str(blob.relative_to(self.root))
            },
            'metadata': metadata or {}
        }
        folder = self.root / 'records' / cve
        folder.mkdir(parents=True, exist_ok=True)
        metadata_digest = hashlib.sha256(
            json.dumps(record['metadata'],
                       sort_keys=True,
                       separators=(',', ':')).encode()).hexdigest()[:10]
        path = folder / f'{specimen_id}--{h[:12]}--{metadata_digest}.json'
        # Atomic metadata publication: concurrent users must not observe
        # truncated or partially written JSON files.
        fd, temp = tempfile.mkstemp(dir=folder, prefix='.record-')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as output:
                output.write(
                    json.dumps(record, indent=2, sort_keys=True) + '\n')
                output.flush()
                os.fsync(output.fileno())
            os.replace(temp, path)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
        return record

    def verify(self, record: dict) -> bool:
        """Verify a recorded blob without following paths outside the CAS root."""
        try:
            item = record['blob']
            digest = item['digest']
            if (item['algorithm'] != 'sha256' or not isinstance(digest, str) or
                    not re.fullmatch(r'[0-9a-f]{64}', digest)):
                return False
            relative = Path(item['path'])
            expected_path = Path('blobs') / 'sha256' / digest[:2] / digest
            if relative != expected_path:
                return False
            untrusted = self.root / relative
            if untrusted.is_symlink():
                return False
            blob = untrusted.resolve(strict=True)
            if not blob.is_relative_to(self.root) or not blob.is_file():
                return False
            if blob.stat().st_size != item['size']:
                return False
            with blob.open('rb') as source:
                actual = hashlib.file_digest(source, 'sha256').hexdigest()
            return actual == item['digest']
        except (OSError, KeyError, TypeError, ValueError):
            return False
