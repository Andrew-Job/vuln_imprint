"""Synthetic ABI/toolchain matrix, clearly NOT a real CVE evaluation."""
import json, shutil, subprocess
from pathlib import Path
import pytest
from factory.pipeline import run

def test_multiple_compilers_and_optimizations(tmp_path):
    bad='''extern int helper(int); __attribute__((noinline)) int affected(int n) {
      int a = (n < 173) ? (n * 37 + 1111) : (n - 47);
      if (n > 221) return a + helper(n);
      return a;
    }'''
    (tmp_path/'bad.c').write_text(bad)
    (tmp_path/'good.c').write_text(bad.replace('n < 173','n < 91'))
    rows=[]
    def add(name, label, split, filename, version):
        rows.append({'id':name,'path':filename,'label':label,'split':split,
                     'version':version,'label_basis':'verified_synthetic',
                     'toolchain':name.split('_')[0]})
    (tmp_path/'host.c').write_text('''
      int affected(int n); int helper(int n){return n*5;}
      int main(int argc,char **argv){return affected(argc+89)==7;}
    ''')
    for tool in ('gcc','clang'):
        for opt in ('O0','O2','O3'):
            for typ,src in (('bad','bad.c'),('fixed','good.c')):
                name=f'{tool}_{opt}_{typ}'
                obj=f'{name}.o'
                subprocess.run([tool,'-'+opt,'-c',src,'-o',obj],cwd=tmp_path,check=True,
                               capture_output=True)
                add(name,'affected' if typ=='bad' else 'fixed','train',obj,typ)
                if typ=='bad':
                    host=f'{name}_host'
                    subprocess.run([tool,'-'+opt,'-no-pie','host.c',obj,'-o',host],
                                   cwd=tmp_path,check=True,capture_output=True)
                    subprocess.run(['strip',host],cwd=tmp_path,check=True)
                    add(host,'affected','holdout',host,typ)
    data={'schema_version':1,'cve':'CVE-2099-56789',
          'hints':{'symbols':['affected']},
          'mining':{'min_instructions':3,'min_bytes':16,'min_fixed':14,'max_rules':15},
          'samples':rows}
    manifest=tmp_path/'manifest.json';manifest.write_text(json.dumps(data))
    report=run(manifest,tmp_path/'out')
    assert report['metrics']['train']=={'TP':6,'TN':6},report['results']
    assert report['metrics']['holdout']=={'TP':6},report['results']
