"""Independent CVE holdout isolation, without relying on declared names alone."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Iterable


def sha256(path: Path) -> str:
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def is_independent_holdout(samples: Iterable) -> bool:
    """All holdouts need lineage, distinct bytes, and disjoint prior evidence.

    Previous exposure in a dev/regression split invalidates *blind* status just
    as previous training does. This does not establish source or label truth.
    """
    samples = list(samples)
    holdouts = [sample for sample in samples if sample.split == 'holdout']
    if not holdouts or any(not sample.provenance.get('lineage') for sample in holdouts):
        return False
    prior = [sample for sample in samples if sample.split != 'holdout']
    prior_lineages = {str(sample.provenance['lineage']) for sample in prior
                      if sample.provenance.get('lineage')}
    holdout_lineages = {str(sample.provenance['lineage']) for sample in holdouts}
    if prior_lineages & holdout_lineages:
        return False
    # File-content comparison is mandatory; lineage strings alone are claims.
    previous_sha = {sha256(sample.path) for sample in prior}
    heldout_sha = [sha256(sample.path) for sample in holdouts]
    return (len(heldout_sha) == len(set(heldout_sha)) and
            not previous_sha.intersection(heldout_sha))
