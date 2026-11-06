"""Offline build-provider smoke tests; synthetic sources are NOT real CVEs."""
from pathlib import Path
import subprocess
import sys
import json
import shutil
from factory.toolchains import probe_compiler
from scripts.build_component import build_zlib, build_libpng, _verify_cmake_optimization


def test_zlib_adapter_builds_objects_archive_and_two_hosts(tmp_path):
    src=tmp_path/'src';src.mkdir();out=tmp_path/'out';out.mkdir()
    (src/'zlib.h').write_text('''typedef struct {int dummy;} z_stream;
typedef struct {int dummy;} gz_header;
#define Z_OK 0
int inflateInit(z_stream*);int inflateGetHeader(z_stream*,gz_header*);int inflateEnd(z_stream*);const char* zlibVersion(void);
''')
    names='adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil'.split()
    for name in names:
        if name=='inflate':
            code='''#include "zlib.h"
int inflateInit(z_stream *s){return 0;}int inflateGetHeader(z_stream *s,gz_header*h){return 0;}
int inflateEnd(z_stream*s){return 0;}const char*zlibVersion(void){return "fixture";}
'''
        else:code=f'int mock_{name}(void){{return 7;}}\n'
        (src/(name+'.c')).write_text(code)
    build_zlib(src,out,'gcc','-O2','inflate')
    assert (out/'module.o').is_file()
    assert (out/'libcomponent.a').is_file()
    assert all((out/f'host_{i}').is_file() for i in range(2))
    # Same entry point used by the CVE batch. Verify its version guard +
    # emitted exact toolchain binary provenance, including .c module argument.
    script=Path(__file__).resolve().parents[1]/'scripts/build_component.py'
    actual=probe_compiler('gcc')
    cmd=[sys.executable,str(script),'--component','zlib','--source',str(src),
         '--workspace',str(out),'--compiler','gcc',
         '--compiler-major',str(actual['major']),'--opt=-O2','--module','inflate.c']
    subprocess.run(cmd,cwd=out,check=True,capture_output=True,text=True)
    toolchain=json.loads((out/'toolchain-provenance.json').read_text())
    assert toolchain['version']==actual['version']
    assert toolchain['binary_sha256']==actual['binary_sha256']
    bad=cmd[:]
    bad[bad.index('--compiler-major')+1]=str(actual['major']+1)
    invalid=subprocess.run(bad,cwd=out,capture_output=True,text=True)
    assert invalid.returncode!=0 and 'expected major' in invalid.stderr
    for i in range(2):
        assert subprocess.run([out/f'host_{i}'],capture_output=True).returncode==0


def test_cmake_libpng_adapter_exports_module_and_linked_hosts(tmp_path):
    src=tmp_path/'src';src.mkdir();out=tmp_path/'out';out.mkdir()
    (src/'png.h').write_text('unsigned long png_access_version_number(void);\n')
    (src/'png.c').write_text('unsigned long png_access_version_number(void){return 1661UL;}\n')
    (src/'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.5)
project(pngstub C)
add_library(png_static STATIC png.c)
set_target_properties(png_static PROPERTIES OUTPUT_NAME png16)
''')
    build_libpng(src,out,'gcc','-O2','png.c')
    assert (out/'module.o').is_file()
    assert (out/'libcomponent.a').is_file()
    _verify_cmake_optimization(out/'config', 'png.c', '-O2')
    import shlex
    rows=json.loads((out/'config/compile_commands.json').read_text())
    selected=[r for r in rows if Path(r['file']).name=='png.c']
    assert selected, 'missing real compiler command'
    for row in selected:
        args=row.get('arguments') or shlex.split(row['command'])
        assert '-O2' in args and '-O3' not in args
    for i in range(2):
        proc=subprocess.run([out/f'host_{i}'],capture_output=True,text=True)
        assert proc.returncode==0 and '1661' in proc.stdout


def test_wrong_cmake_optimization_is_rejected(tmp_path):
    config=tmp_path/'config'; config.mkdir()
    (config/'compile_commands.json').write_text(json.dumps([
        {'file':str(config/'png.c'), 'arguments':['cc','-O2','-O3','-c','png.c']},
    ]))
    import pytest
    with pytest.raises(RuntimeError, match='observed optimization flags'):
        _verify_cmake_optimization(config,'png.c','-O2')
