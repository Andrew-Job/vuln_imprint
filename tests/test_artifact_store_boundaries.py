"""First-party CAS verifies only blobs within its own storage root."""

import copy
import hashlib

from factory.artifact_store import ArtifactStore


def test_cas_record_cannot_read_outside_store(tmp_path):
    store = ArtifactStore(tmp_path / "cas")
    source = tmp_path / "source.bin"
    source.write_bytes(b"valid binary specimen")
    record = store.add(source, cve="CVE-2026-12345", specimen_id="case1")
    assert store.verify(record)

    outside = tmp_path / "foreign.bin"
    outside.write_bytes(b"outside CAS")
    attacker = copy.deepcopy(record)
    attacker["blob"]["path"] = "../../foreign.bin"
    attacker["blob"]["digest"] = hashlib.sha256(outside.read_bytes()).hexdigest()
    attacker["blob"]["size"] = outside.stat().st_size
    assert not store.verify(attacker)

    outside_link = store.root / "foreign"
    outside_link.symlink_to(outside)
    attacker["blob"]["path"] = "foreign"
    assert not store.verify(attacker)

    attacker["blob"]["path"] = 42
    assert not store.verify(attacker)
