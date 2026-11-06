from __future__ import annotations
import json, subprocess, textwrap, shutil
from pathlib import Path
import pytest
from factory.patterns import Pattern
from factory.elf import ELF, UnsupportedBinary
from factory.disasm import disassemble
from factory.pipeline import run, reference_scan, acquire


def cc(cmd,cwd): subprocess.run(cmd,cwd=cwd,check=True,capture_output=True)


def test_reference_pattern_exact_and_wildcard():
    pat=Pattern.from_hex('48 83 ?? 10 0F 1E FA 48 85 FF')
    assert pat.fixed==9
    assert pat.search([(100,b'zz\x48\x83\x80\x10\x0f\x1e\xfa\x48\x85\xffzz')])==[102]
    assert not pat.search([(0,b'\x48\x83\x80\x12\x0f\x1e\xfa\x48\x85\xff')])


def test_unsupported_format(tmp_path):
    f=tmp_path/'bad';f.write_bytes(b'not an elf')
    with pytest.raises(UnsupportedBinary): ELF(f)


def test_compile_mine_static_link_and_scan(tmp_path):
    # Synthetic test only: specifically exercises .o relocations and linker
    # movement, not proof of the quality of any actual CVE.
    vulnerable='''\nextern int helper(int x);
__attribute__((noinline)) int check_count(int x) {
 int y = x < 11 ? x * 13 : x - 7;
 if (x > 19) return helper(x) + y;
 return y;
}
'''
    fixed=vulnerable.replace('x < 11','x < 9')
    (tmp_path/'bad.c').write_text(vulnerable)
    (tmp_path/'good.c').write_text(fixed)
    for name,source in [('bad','bad.c'),('good','good.c')]:
        cc(['gcc','-O2','-fno-pie','-c','-g',source,'-o',name+'.o'],tmp_path)
    host_a='''
#include <stdio.h>
int check_count(int);
int helper(int x){return x*5;}
int main(void){printf("%d\\n",check_count(24));return 0;}
'''
    host_b='''
#include <stdio.h>
int check_count(int);
int helper(int x){return x*5;}
int unused(int a) {return a+1;}
int main(void){printf("%d\\n",check_count(10));return 0;}
'''
    (tmp_path/'host_a.c').write_text(host_a)
    (tmp_path/'host_b.c').write_text(host_b)
    for source,obj,out in [('host_a.c','bad.o','host_v1'),('host_b.c','bad.o','host_v2'),
                           ('host_a.c','good.o','host_fixed')]:
        cc(['gcc','-O2','-no-pie',source,obj,'-o',out],tmp_path)
        cc(['strip',out],tmp_path)
    data={'schema_version':1,'cve':'CVE-2099-12345','hints':{'symbols':['check_count']},
          'mining':{'min_bytes':16,'min_fixed':14,'min_instructions':3,'max_rules':4},
          'samples':[{'id':'obj_bad','path':'bad.o','label':'affected','split':'train'},
                     {'id':'obj_good','path':'good.o','label':'fixed','split':'train'},
                     {'id':'host_v1','path':'host_v1','label':'affected','split':'holdout',
                      'label_basis':'verified_synthetic'},
                     {'id':'host_v2','path':'host_v2','label':'affected','split':'holdout',
                      'label_basis':'verified_synthetic'},
                     {'id':'host_fixed','path':'host_fixed','label':'fixed','split':'holdout',
                      'label_basis':'verified_synthetic'}]}
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(data))
    report=run(manifest,tmp_path/'out')
    assert report['mining']['extracted']['obj_bad']['candidate_windows']>0
    assert report['metrics']['train'].get('TN')==1
    # The experiment is intended to catch ABI / linker mismatch regressions.
    assert report['metrics']['holdout']=={'TP':2,'TN':1},report['results']
    for name in ('host_v1','host_v2'):
        assert reference_scan(tmp_path/'out/pack.json',tmp_path/name)['detected']
    assert not reference_scan(tmp_path/'out/pack.json',tmp_path/'host_fixed')['detected']
