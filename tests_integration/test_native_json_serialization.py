"""Validate VulnImprint's JSON/path contract with its native C++20 code."""

import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_native_json_preserves_raw_linux_paths(tmp_path):
    source = tmp_path / 'json_contract.cc'
    source.write_text(r'''
#include "vulnimprint/json.h"
#include <iostream>
#include <string>

int main() {
  const std::string raw = std::string("valid_\xc3\xa9_bad_\xff_\xed\xa0\x80");
  std::cout << "{\"file\":" << vulnimprint::JsonString(raw)
            << ",\"file_bytes_hex\":"
            << vulnimprint::JsonString(vulnimprint::HexBytes(raw))
            << "}\n";
  std::cout << "{\"value\":"
            << vulnimprint::JsonString("line\nquote\"\\\\") << "}\n";
}
''')
    executable = tmp_path / 'json_contract'
    subprocess.run([
        'c++', '-std=c++20', '-Wall', '-Wextra', '-Werror',
        '-I', str(ROOT / 'scanner/include'), str(source), '-o', str(executable),
    ], check=True, capture_output=True, text=True, timeout=60)
    result = subprocess.run([str(executable)], check=True, capture_output=True,
                            timeout=10)
    lines = result.stdout.decode('utf-8').splitlines()
    record = json.loads(lines[0])
    assert record['file'].startswith('valid_é_bad_')
    assert '�' in record['file']
    assert bytes.fromhex(record['file_bytes_hex']) == (
        b'valid_\xc3\xa9_bad_\xff_\xed\xa0\x80'
    )
    assert json.loads(lines[1])['value'] == 'line\nquote"\\\\'
