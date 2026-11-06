"""Masked binary patterns, deterministic atom-accelerated reference verifier.

Do not use this as a replacement for the YARA-X production runtime. It verifies
our emitted subset without requiring network access or third-party packages.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Sequence


@dataclass(frozen=True)
class Pattern:
    data: bytes
    mask: bytes  # 0xFF: fixed byte; 0x00: wildcard byte

    def __post_init__(self):
        if len(self.data) != len(self.mask) or not self.data:
            raise ValueError('invalid pattern lengths')
        if any(m not in (0, 255) for m in self.mask):
            raise ValueError('mask must contain 0x00 or 0xff')

    @classmethod
    def from_hex(cls, expr: str):
        chunks = expr.split()
        return cls(bytes(0 if ch == '??' else int(ch, 16) for ch in chunks),
                   bytes(0 if ch == '??' else 255 for ch in chunks))

    def to_hex(self):
        return ' '.join(
            f'{b:02X}' if m else '??' for b, m in zip(self.data, self.mask))

    @property
    def fixed(self):
        return self.mask.count(255)

    def atom(self):
        best = (0, b'')
        start = 0
        for i in range(len(self.mask) + 1):
            if i == len(self.mask) or self.mask[i] == 0:
                if i - start > len(best[1]):
                    best = start, self.data[start:i]
                start = i + 1
        return best

    def matches_at(self, data: bytes, pos: int):
        if pos < 0 or pos + len(self.data) > len(data):
            return False
        return all(not mask or data[pos + i] == value
                   for i, (value, mask) in enumerate(zip(self.data, self.mask)))

    def search(self, regions: Sequence[tuple[int, bytes]], first_only=False):
        start, atom = self.atom()
        if len(atom) < 5:
            return []
        results = []
        for base, data in regions:
            at = 0
            while True:
                at = data.find(atom, at)
                if at == -1:
                    break
                loc = at - start
                if self.matches_at(data, loc):
                    results.append(base + loc)
                    if first_only:
                        return results
                at += 1
        return results
