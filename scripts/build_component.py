#!/usr/bin/env python3
"""Trusted CI-only build recipes for source snapshots, not CVE-specific signature logic.

Linux/ELF64/x86-64 is the implemented backend. The object named module.o is
selected by the catalogue; full static library and independently linked
stripped hosts are saved for regression checking.
"""
import argparse
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from factory.toolchains import probe_compiler
from factory.build_provenance import write_record

RECORDED_COMMANDS: list[list[str]] = []


def call(args, cwd):
    argv = [str(a) for a in args]
    subprocess.run(argv, cwd=cwd, check=True, timeout=180)
    RECORDED_COMMANDS.append(argv)


def build_zlib(source, output, compiler, opt, module):
    names = 'adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil'.split(
    )
    objs = []
    for name in names:
        obj = output / (name + '.o')
        call([
            compiler, opt, '-fPIC', '-g', '-I', source, '-c', source /
            (name + '.c'), '-o', obj
        ], output)
        objs.append(obj)
    call(['ar', 'rcs', output / 'libcomponent.a', *objs], output)
    selected = output / (Path(module).stem + '.o')
    if not selected.is_file():
        raise FileNotFoundError(f'missing requested zlib module: {module}.o')
    shutil.copy2(selected, output / 'module.o')
    (output / 'host.c').write_text(
        '''#include "zlib.h"\n#include <stdio.h>\nint main(void) { z_stream s={0}; int rc=inflateInit(&s); if(rc==Z_OK){gz_header h={0}; inflateGetHeader(&s,&h);inflateEnd(&s);} printf("%s\\n",zlibVersion());return rc != Z_OK;}\n'''
    )
    for i, extra in enumerate([['-no-pie'],
                               ['-fPIE', '-pie', '-fno-omit-frame-pointer']]):
        exe = output / ('host_' + str(i))
        call([
            compiler, opt, *extra, '-I', source, output / 'host.c',
            '-Wl,--whole-archive', output / 'libcomponent.a',
            '-Wl,--no-whole-archive', '-o', exe
        ], output)
        call(['strip', '-s', exe], output)


def _verify_cmake_optimization(config: Path, module: str,
                               expected: str) -> None:
    """Check the actual compile commands, not merely the requested CMake flags.

    CMake's default Release flags contain -O3 and can silently override the
    requested compiler profile (-O0/-O2/-O3). This would invalidate every
    affected/fixed signature train/holdout profile in that lane.
    """
    db = config / 'compile_commands.json'
    if not db.is_file():
        raise RuntimeError('CMake did not generate compile_commands.json')
    entries = json.loads(db.read_text())
    matched = [
        row for row in entries if Path(row['file']).name == Path(module).name
    ]
    if not matched:
        raise RuntimeError(f'cannot verify compile flags for {module}')
    for row in matched:
        args = row.get('arguments') or shlex.split(row['command'])
        optimizations = [
            arg for arg in args
            if re.fullmatch(r'-O(?:0|1|2|3|s|z|g|fast)', arg)
        ]
        if not optimizations or optimizations[-1] != expected:
            raise RuntimeError(
                f'actual CMake compilation for {module}: expected {expected}, '
                f'observed optimization flags {optimizations}')


def build_libpng(source, output, compiler, opt, module):
    config = output / 'config'
    call([
        'cmake', '-S', source, '-B', config, '-G', 'Ninja',
        '-DCMAKE_C_COMPILER=' + compiler, '-DCMAKE_C_FLAGS=' + opt +
        ' -g -fPIC', '-DCMAKE_C_FLAGS_RELEASE=-DNDEBUG',
        '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON', '-DCMAKE_BUILD_TYPE=Release',
        '-DPNG_SHARED=OFF', '-DPNG_STATIC=ON', '-DPNG_TESTS=OFF',
        '-DPNG_BUILD_ZLIB=OFF', '-DCMAKE_POLICY_VERSION_MINIMUM=3.5'
    ], output)
    call(['cmake', '--build', config, '--parallel', '2'], output)
    archives = sorted(
        p for p in config.rglob('*.a') if 'png' in p.name and p.is_file())
    if not archives:
        raise FileNotFoundError(
            'libpng static library missing from CMake build')
    # Depend on CMake output filenames, not absolute build directory names.
    objs = sorted(p for p in config.rglob(module + '.o') if p.is_file())
    if not objs:
        raise FileNotFoundError(
            f'compiled object {module}.o absent in {config}')
    _verify_cmake_optimization(config, module, opt)
    shutil.copy2(objs[0], output / 'module.o')
    shutil.copy2(archives[0], output / 'libcomponent.a')
    (output / 'host.c').write_text(
        '''#include "png.h"\n#include <stdio.h>\nint main(void) { printf("%lu\\n",(unsigned long)png_access_version_number());return 0;}\n'''
    )
    for i, extra in enumerate([['-no-pie'],
                               ['-fPIE', '-pie', '-fno-omit-frame-pointer']]):
        exe = output / ('host_' + str(i))
        call([
            compiler, opt, *extra, '-I', source, '-I', config,
            output / 'host.c', '-Wl,--whole-archive', output / 'libcomponent.a',
            '-Wl,--no-whole-archive', '-lz', '-lm', '-o', exe
        ], output)
        call(['strip', '-s', exe], output)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--component', choices=['zlib', 'libpng'], required=True)
    p.add_argument('--source', type=Path, required=True)
    p.add_argument('--workspace', type=Path, required=True)
    p.add_argument('--compiler', default='gcc')
    p.add_argument('--compiler-major', type=int)
    p.add_argument('--compiler-version-exact')
    p.add_argument('--opt', choices=['-O0', '-O2', '-O3'], default='-O2')
    p.add_argument('--module', required=True)
    a = p.parse_args()
    src = a.source.resolve()
    out = a.workspace.resolve()
    out.mkdir(parents=True, exist_ok=True)
    toolchain = probe_compiler(a.compiler,
                               expected_major=a.compiler_major,
                               expected_version=a.compiler_version_exact,
                               optimization=a.opt)
    cc = toolchain['executable']
    if a.component == 'zlib':
        build_zlib(src, out, cc, a.opt, a.module)
    else:
        build_libpng(src, out, cc, a.opt, a.module)
    toolchain['component'] = a.component
    toolchain['requested_module'] = a.module
    (out / 'toolchain-provenance.json'
    ).write_text(json.dumps(toolchain, sort_keys=True, indent=2) + '\n')
    write_record(out, toolchain, RECORDED_COMMANDS)
    print('built', a.component, 'module', a.module, 'compiler', a.compiler,
          'version', toolchain['version'], 'flags', a.opt)


if __name__ == '__main__':
    main()
