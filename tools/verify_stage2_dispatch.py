#!/usr/bin/env python3
"""Reproduce first computed ScreenWings stage-two indirect dispatch.
All observations are *static/model-derived*. This does not execute the EXE.
"""
import argparse,hashlib,json,pathlib,struct

SHA='2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420'
REGION_BASE=0x492000
IMAGE_BASE=0x400000
TABLE_VA=0x6471D3
TABLE_COUNT=0x4F3
CONTEXT_BASE=0x4C19BC
VIP=0x4AAD06
DISPATCH_VA=0x541ED7
HANDLER=0x4DB0E0

def verify(source):
    data=source.read_bytes()
    if len(data)!=0x672000 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError('Stage-one image digest/length mismatch')
    def read(addr,length):
        offset=addr-REGION_BASE
        if offset<0 or offset+length>len(data):
            raise ValueError(f'Outside image: {addr:#x}')
        return data[offset:offset+length]
    def u16(addr):return struct.unpack('<H',read(addr,2))[0]
    def u32(addr):return struct.unpack('<I',read(addr,4))[0]
    # Verify exact instruction bytes, not only guessed control flow.
    checks={
      0x541EA7:'668b0f',  # mov cx,[edi]
      0x541EAA:'c1e102',  # shl ecx,2
      0x541EB7:'81c304000000',  # add ebx,4
      0x541EBD:'8b03',  # mov eax,[ebx]
      0x541EC7:'0103',  # add [ebx],eax
      0x541ED1:'8b1a',  # mov ebx,[edx]
      0x541ED3:'01cb',  # add ebx,ecx
      0x541ED5:'8b13',  # mov edx,[ebx]
      0x541ED7:'ffe2',  # jmp edx
      0x4DB0F0:'0fb717',  # movzx edx,word ptr [edi] (next handler)
    }
    for addr,hexvalue in checks.items():
        expected=bytes.fromhex(hexvalue)
        if read(addr,len(expected))!=expected:
            raise ValueError(f'Dispatch instruction mismatch at {addr:#x}')
    selector=u16(VIP)
    delta=u32(VIP+4)
    assert selector==803 and delta==0x000BF0BD
    offset=selector*4
    assert 0<=offset<TABLE_COUNT*4
    table_entry_va=TABLE_VA+offset
    original_rva=u32(table_entry_va)
    stub_va=IMAGE_BASE+original_rva
    assert stub_va==0x4F464D
    jmp=read(stub_va,5)
    assert jmp[0]==0xE9
    landing=(stub_va+5+struct.unpack('<i',jmp[1:])[0])&0xffffffff
    assert landing==HANDLER
    # The table base in the first-stage raw bytes is an RVA; Stage 2 added image base.
    unrebased_ptr=u32(CONTEXT_BASE+0x52)
    assert unrebased_ptr==TABLE_VA-IMAGE_BASE
    next_vip=VIP+delta
    assert next_vip==0x569DC3 and read(next_vip,1)
    result={
      'stage1_sha256':SHA,'method':'Read-only exact-byte validation plus previously modeled runtime register/context values',
      'context_base_in_static_model':f'0x{CONTEXT_BASE:08X}',
      'virtual_ip_field':f'0x{CONTEXT_BASE+0x22:08X}',
      'dispatch_table_pointer_field':f'0x{CONTEXT_BASE+0x52:08X}',
      'original_reloc_table_rva':f'0x{unrebased_ptr:08X}',
      'rebased_table_va':f'0x{TABLE_VA:08X}',
      'first_virtual_ip_model':f'0x{VIP:08X}',
      'selector_u16':selector,
      'selector_times_4':f'0x{offset:08X}',
      'table_entry_va':f'0x{table_entry_va:08X}',
      'entry_rva':f'0x{original_rva:08X}',
      'reconstructed_stub_va':f'0x{stub_va:08X}',
      'stub_E9_target':f'0x{landing:08X}',
      'virtual_ip_delta_u32':f'0x{delta:08X}',
      'next_virtual_ip_model':f'0x{next_vip:08X}',
      'next_handler_reads_selector_at':f'0x{0x4DB0F0:08X}',
      'current_handoff_status':'PROTECTOR DISPATCH CONFIRMED; ORIGINAL APPLICATION ENTRY NOT IDENTIFIED',
      'runtime_logs':'not available'
    }
    return result

if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('stage1_bin',type=pathlib.Path)
    p.add_argument('--out',type=pathlib.Path)
    a=p.parse_args()
    result=verify(a.stage1_bin)
    output=json.dumps(result,indent=2)+'\n'
    if a.out:a.out.write_text(output,encoding='utf8')
    else:print(output)
