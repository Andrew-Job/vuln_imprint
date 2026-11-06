"""Sanitizer fuzzing of VulnImprint executable-range selection over ELFIO."""

from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_elfio_adapter_sanitized_fuzz(tmp_path):
    header = ROOT / "external/elfio/elfio/elfio.hpp"
    assert header.is_file(), "Pinned ELFIO submodule is mandatory for native fuzzing"
    compiler = shutil.which("clang++")
    cc = shutil.which("cc")
    assert compiler and cc, "Native clang++ and C compiler are mandatory"

    corpus = tmp_path / "corpus"
    corpus.mkdir()
    source = tmp_path / "sample.c"
    source.write_text("int main(void) { return 0; }\n")
    for extra, name in ((["-c"], "object.o"),
                        (["-no-pie"], "executable"),
                        (["-shared", "-fPIC"], "library.so")):
        subprocess.run([cc, *extra, str(source), "-o", str(corpus / name)],
                       check=True, timeout=45)
    (corpus / "truncated").write_bytes(b"\x7fELF\x02\x01\x01")

    fuzz = tmp_path / "elfio-adapter-fuzz"
    subprocess.run([
        compiler, "-std=c++20", "-g", "-O1", "-fno-omit-frame-pointer",
        "-fsanitize=fuzzer,address,undefined", "-Wall", "-Wextra", "-Werror",
        "-I", str(ROOT / "scanner/include"),
        "-isystem", str(ROOT / "external/elfio"),
        str(ROOT / "scanner/src/elf.cc"),
        str(ROOT / "scanner/fuzz/elfio_adapter_fuzzer.cc"),
        "-o", str(fuzz),
    ], check=True, timeout=120)
    subprocess.run([str(fuzz), "-runs=3000", "-max_len=65536",
                    "-rss_limit_mb=1024", "-timeout=5", str(corpus)],
                   check=True, timeout=120, capture_output=True, text=True)
