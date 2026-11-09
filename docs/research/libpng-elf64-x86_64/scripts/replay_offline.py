#!/usr/bin/env python3
"""Fail-closed CVE research-rule validation with existing VulnImprint reference matcher.

No separate ELF parser is implemented; reads ELF load segments using GNU readelf.
No YARA-X compilation is performed or implied. Only supported Linux ELF64-x86-64.
The full binary SHA-256, not a filename or version, is the specimen identity.
"""
from __future__ import annotations
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path


def load_exec_ranges(path:Path):
    lines=subprocess.check_output(['readelf','-Wl',str(path)],text=True,stderr=subprocess.PIPE).splitlines()
    raw=path.read_bytes(); out=[]
    for line in lines:
        x=line.split()
        if len(x)>=8 and x[0]=='LOAD' and 'E' in x[6:-1]:
            offset=int(x[1],16); size=int(x[4],16)
            if offset<0 or size<0 or offset+size>len(raw):
                raise ValueError('readelf returned out of bounds segment')
            if size:out.append((offset,raw[offset:offset+size]))
    if not out:raise ValueError('ELF has no executable PT_LOAD segment')
    return out


def sha256(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def replay(db_root:Path,source_root:Path):
    sys.path.insert(0,str(source_root))
    from factory.patterns import Pattern
    from factory.yara_engine import source_from_packs
    from tools.manual_rules import check_manual_source
    packs=[];pats={}
    baseline = ('CVE-2026-22695', 'CVE-2026-22801', 'CVE-2026-25646',
                'CVE-2026-33416', 'CVE-2026-34757')
    for cve in baseline:
        directory = source_root / 'signatures' / cve
        if not directory.is_dir() or not (directory/'pack.json').is_file():continue
        pack=json.loads((directory/'pack.json').read_text())
        check_manual_source(pack,(directory/'rules-exec.yar').read_text())
        if any(record['channel'] != 'production' for record in pack['records']):
            raise ValueError('source record channel differs from the research fixture')
        packs.append(pack)
        pats[pack['cve']]=[Pattern.from_hex(x['hex']) for record in pack['records'] for x in record['rules']]
    if len(packs)!=5 or sum(map(len,pats.values()))!=25:raise ValueError('database count drift')
    rendered=source_from_packs(packs)
    if rendered!=(db_root/'database-exec.yar').read_text():
        raise ValueError('generated YARA source drift')
    # Same explicit positive/fixed controls for two new semantic candidates.
    positives={'rdkit','fiona','cadquery','opencv','rasterio','torchvision','pedalboard'}
    fixes={'debian','pillow'}
    matrix=json.loads((db_root/'validation-matrix.json').read_text())
    indexed={case['cve']:case for case in matrix['cases']}
    if set(indexed) != set(pats):
        raise ValueError('reference observation CVEs differ from rules')
    samples=json.loads((db_root/'evidence/specimen-inventory.json').read_text())
    observed={cve:{} for cve in pats}
    checked=0
    for record in samples:
        path=Path(record['local_path']);name=record['id']
        if not path.exists() or sha256(path)!=record['sha256']:
            raise ValueError(f'missing/modified specimen: {name}')
        regions=load_exec_ranges(path)
        for cve,patterns in pats.items():
            hits=[(i,pos) for i,p in enumerate(patterns) for pos in p.search(regions)]
            match=bool(hits)
            observed[cve][name]={'detected':match,'pattern_hits':len(hits),
                                'file_offsets':[f'0x{pos:x}' for _,pos in hits]}
            # These observations check repeatability, not independent affected
            # or fixed provenance. Exactly which rule indices hit is recorded.
            expected_indices=indexed[cve]['results'][name]
            actual_indices=sorted({i for i, _ in hits})
            checked+=1
            if actual_indices!=expected_indices:
                raise ValueError(f'expected mask indices {expected_indices} for '
                                 f'{cve}/{name}; got {actual_indices}')
            if cve in {'CVE-2026-33416','CVE-2026-34757'}:
                if name in positives and not match:
                    raise ValueError(f'{cve}/{name}: missing affected machine behavior')
                if name in fixes and match:
                    raise ValueError(f'{cve}/{name}: hit on known patched behavior')
    hold=json.loads((db_root/'evidence/extended-unrelated-elf-holdout.json').read_text())
    unrelated=0
    for record in hold['samples']:
        path=Path(record['path'])
        if not path.is_file() or sha256(path)!=record['sha256']:
            raise ValueError(f'missing/modified unrelated holdout: {path}')
        regions=load_exec_ranges(path)
        for cve,patterns in pats.items():
            if any(p.search(regions,first_only=True) for p in patterns):
                raise ValueError(f'unrelated false positive: {cve}/{path}')
        unrelated+=1
    if unrelated!=230 or len(samples)!=9:raise ValueError('specimen total drift')
    return {'analysis_scope':'OFFLINE_REFERENCE_ANALYSIS_ONLY',
        'cve_count':len(packs),'machine_patterns':sum(len(v) for v in pats.values()),
        'reference_mask_observations_checked':checked,'libpng_specimens':len(samples),
        'unrelated_elf':unrelated,'unexpected_matches':0,
        'native_yara_x_compiler_executed':False,'observed':observed}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--db-root',type=Path,default=Path(__file__).resolve().parents[1])
    ap.add_argument('--project-root',type=Path,required=True)
    args=ap.parse_args()
    try:
        result=replay(args.db_root,args.project_root)
    except (ValueError,IndexError,KeyError,RuntimeError,ImportError,OSError,subprocess.CalledProcessError) as e:
        print(f'OFFLINE CVE REPLAY FAILED: {e}',file=sys.stderr)
        return 2
    print(json.dumps(result,indent=2,ensure_ascii=False))
    return 0

if __name__=='__main__':sys.exit(main())
