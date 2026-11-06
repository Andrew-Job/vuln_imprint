"""Functional reference matcher contracts for short fixed atoms."""
from factory.patterns import Pattern


def test_short_atom_does_not_silently_drop_match():
    pattern = Pattern.from_hex('90 ?? 91 ?? 92')
    assert pattern.matches_at(bytes.fromhex('90 FF 91 AA 92'), 0)
    assert pattern.search([(100, bytes.fromhex('00 90 FF 91 AA 92'))]) == [101]
    assert pattern.search([(100, bytes.fromhex('00 90 FF 91 AA 92'))],
                          first_only=True) == [101]


def test_all_wildcards_matches_every_valid_position():
    pattern = Pattern.from_hex('?? ??')
    assert pattern.search([(7, b'ABC')]) == [7, 8]
