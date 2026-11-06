from factory.yara_engine import source_from_packs
from factory.patterns import Pattern


def test_yara_exec_region_source_has_no_file_offset_conditions():
    sample={'cve':'CVE-2099-99999','platform':{'format':'ELF','arch':'x86-64','bits':64},
            'rules':[{'id':'CVE-2099-99999-v00',
                      'hex':Pattern.from_hex('48 8b ?? 33 44 55 66').to_hex()}]}
    text=source_from_packs([sample])
    assert 'rule CVE_2099_99999_ELF64_x86_64' in text
    assert '{ 48 8B ?? 33 44 55 66 }' in text
    assert 'any of them' in text
    assert 'uint32(' not in text
    assert 'import "elf"' not in text
