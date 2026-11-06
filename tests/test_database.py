import json
from pathlib import Path
from factory.database import merge_packs

def test_quality_gate(tmp_path):
    root=tmp_path/'packs';root.mkdir()
    a=root/'cve';a.mkdir()
    (a/'pack.json').write_text(json.dumps({'cve':'CVE-2022-12345','status':'EXPERIMENTAL_NO_BLIND_HOLDOUT',
                                          'rules':[{'hex':'01 02 03 04'}]}))
    (a/'rules-exec.yar').write_text('rule CVE_2022_12345_ELF64_x86_64 { condition: false }')
    denied=merge_packs([a],tmp_path/'db1')
    assert denied['included_cve_count']==0
    allowed=merge_packs([a],tmp_path/'db2',allow_experimental=True)
    assert allowed['included_cve_count']==1
