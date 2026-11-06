#!/usr/bin/env python3
"""Generate experimental CVE recipes from fork-local JSON input records.

This tool accepts contributor-supplied records; it does not admit candidates
into the production database. Research in signatures/candidates/ is allowed
but excluded from releases. The batch pipeline pins source tags to commits.
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path

DEFAULT_COMPILER_LANES = ('gcc-11','gcc-12','clang-14','clang-15')


def parse_compiler_lanes(names):
    """Versioned toolchains are configurable; no new CVE code is needed."""
    result=[]
    for name in names:
        m=re.fullmatch(r'(gcc|clang)-([1-9][0-9]?)',name)
        if not m:raise ValueError(f'invalid versioned compiler lane: {name}')
        result.append((m.group(1),int(m.group(2))))
    if len(set(result))!=len(result):
        raise ValueError('duplicate compiler/version lane')
    if {f for f,v in result}!={'gcc','clang'}:
        raise ValueError('first pipeline requires both GCC and Clang')
    return tuple(result)


def make_manifest(rec, *, compiler_lanes=DEFAULT_COMPILER_LANES):
    cve,component,affected,fixed,module,symbol,advisory=rec
    url={'libpng':'https://github.com/pnggroup/libpng.git',
         'zlib':'https://github.com/madler/zlib.git'}[component]
    # Full factorial from the first pipeline: GCC and Clang, two major
    # versions each, both optimization levels; full exact patch versions are
    # recorded and hashed when the build is actually run.
    toolchain_lanes=parse_compiler_lanes(compiler_lanes)
    profiles=[(f'{cc}{major}-{opt.lower().lstrip("-")}',cc,major,opt)
              for cc,major in toolchain_lanes for opt in ('-O2','-O3')]
    builds=[];samples=[]
    for state,version in [('affected',affected),('fixed',fixed)]:
        for label,cc,major,opt in profiles:
            name=f'{state}-{label}'
            builds.append({'name':name,'state':state,
                 'profile':{'os':'linux','format':'ELF','arch':'x86_64','abi':'sysv',
                            'compiler':cc,'compiler_major':major,
                            'compiler_executable':f'{cc}-{major}',
                            'optimization':opt},
                 'source':{'git':url,'ref':'v'+version},
                 'commands':[['python3','{repo}/scripts/build_component.py',
                     '--component',component,'--source','{source_dir}',
                     '--workspace','{workspace}',
                     '--compiler',f'{cc}-{major}','--compiler-major',str(major),
                     '--opt='+opt,
                     '--module',module]],
                 'artifacts':['module.o','libcomponent.a','host_0','host_1',
                              'toolchain-provenance.json']})
            for artifact,split in [('module.o','train'),('host_0','regression'),('host_1','dev')]:
                samples.append({'id':f'{name}-{artifact.replace(".","_")}',
                   'path':f'{{work}}/build-{name}/{artifact}',
                   'label':state,'split':split,'version':version,
                   'origin':url,'toolchain':f'{cc}-{major} {opt}',
                   'compiler_family':cc,'compiler_major':major,
                   'compiler_version_basis':'runtime-provenance',
                   'profile':label,'label_basis':'upstream_release',
                   'lineage':f'{state}-{label}'})
    return {'schema_version':1,'cve':cve,
        'description':f'{component} {affected} vs {fixed}; upstream-tag paired contrast',
        'source_component':component,'advisory':advisory,
        'experimental_notice':'Upstream-version contrast, not proof of vendor patch state. No blind holdout.',
        'hints':{'symbols': [symbol] if symbol else None, 'source_files':[module]},
        'mining':{'max_rules':20,'min_instructions':6,'min_bytes':28,'min_fixed':24,
                  'max_instructions':150000,'max_candidates_per_sample':50000},
        'builds':builds,'samples':samples}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--output-dir',type=Path,
                        default=Path('run/research-catalog'))
    parser.add_argument('--records', type=Path, required=True,
                        help='fork-local JSON list of [CVE,component,affected,fixed,module,symbol,advisory]')
    parser.add_argument('--compiler-lanes',nargs='+',default=list(DEFAULT_COMPILER_LANES))
    args=parser.parse_args()
    source_records=json.loads(args.records.read_text(encoding='utf-8'))
    if not isinstance(source_records,list) or not source_records:
        parser.error('--records must contain a nonempty JSON array')
    unique=set()
    for item in source_records:
        if (not isinstance(item,list) or len(item)!=7
                or not isinstance(item[0],str)
                or not re.fullmatch(r'CVE-\d{4}-\d{4,}',item[0])
                or item[1] not in ('libpng','zlib')
                or item[0] in unique):
            parser.error('invalid or duplicate source record')
        unique.add(item[0])
    root=args.output_dir
    root.mkdir(parents=True, exist_ok=True)
    for item in source_records:
        out=root/(item[0]+'.json')
        out.write_text(json.dumps(make_manifest(item,compiler_lanes=args.compiler_lanes),indent=2,sort_keys=True)+'\n')
    print('Created',len(source_records),'CVE recipes in',root)
if __name__=='__main__':main()
