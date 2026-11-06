#!/usr/bin/env python3
"""Import reviewed binary evidence only from a release-approved HTTPS host.

No executable from the downloaded archive is run by this ingestion workflow.
The signature + independent-control gate occurs in the separate release job.
"""
from __future__ import annotations
import argparse
import hashlib
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class NoRedirect(urllib.request.HTTPRedirectHandler):

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        raise ValueError('corpus redirects are not permitted')


def fetch(url: str, expected: str, host: str, output: Path) -> None:
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or parsed.hostname != host or
            parsed.port not in (None, 443) or parsed.username or
            parsed.password or not re.fullmatch(r'[0-9a-f]{64}', expected)):
        raise ValueError('untrusted corpus URL, host or digest')
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(
        url, headers={'User-Agent': 'VulnImprint-corpus-import/1'})
    h = hashlib.sha256()
    total = 0
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        with opener.open(req, timeout=90) as inp, output.open('xb') as out:
            while block := inp.read(1 << 20):
                total += len(block)
                if total > 2 * 1024**3:
                    raise ValueError('reviewed archive exceeds 2 GiB limit')
                h.update(block)
                out.write(block)
        if h.hexdigest() != expected:
            raise ValueError('corpus digest mismatch')
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument('--url', required=True)
    p.add_argument('--sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        host = os.environ.get('VULNIMPRINT_CORPUS_HOST', '')
        if not host:
            raise ValueError('approved corpus host not configured')
        fetch(args.url, args.sha256, host, args.output)
        return 0
    except (OSError, ValueError, urllib.error.URLError) as exc:
        print('CORPUS IMPORT REJECTED:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
