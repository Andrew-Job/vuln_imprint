"""Reject GitHub CLI builds with known unsafe attestation-ref comparison."""
import re
import subprocess


def check_version(raw: str) -> tuple[int, int, int]:
    match = re.search(r'gh version (\d+)\.(\d+)\.(\d+)', raw)
    if not match:
        raise ValueError('cannot identify GitHub CLI version')
    version = tuple(int(x) for x in match.groups())
    if version < (2, 102, 0):
        raise ValueError(
            'GitHub CLI >= 2.102.0 required for attestation ref verification')
    return version


if __name__ == '__main__':
    print(
        check_version(
            subprocess.check_output(['gh', '--version'], text=True,
                                    timeout=10)))
