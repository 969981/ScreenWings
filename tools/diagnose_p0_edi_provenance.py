#!/usr/bin/env python3
"""Explain 0x53D2EF model cutoff using SHA-locked bytes and model-write provenance.

This is a *conditional static model* proof, NOT a native Windows register trace.
The CSV is produced by the previously executed bounded VM model.
"""
import argparse,csv,hashlib,json,pathlib

SHA="2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE=0x492000
CTX=0x4C19BC
OPCODES={
  0x5C3000:"2b02",  # sub eax,[edx]
  0x5C3033:"2b06",  # sub eax,[esi]
  0x5C30B8:"0106",  # add [esi],eax
  0x5C3118:"8b36",  # mov esi,[esi]
  0x5C3123:"0132",  # add [edx],esi
  0x53D2DB:"01ef",  # add edi,ebp
  0x53D2ED:"8b3f",  # mov edi,[edi]
  0x53D2EF:"8b3f"   # mov edi,[edi]
}
# Recorder PCs are post-instruction positions; NOT the actual store op addresses.
REQUIRED=[
 ("ctx_3b_cleared",0x5933CB,CTX+0x3B,0),
 ("ctx_7e",0x5C2F1C,CTX+0x7E,0xE8480977),
 ("ctx_09",0x5C2F32,CTX+0x09,0x92A45B90),
 ("ctx_7a",0x5C30BA,CTX+0x7A,0x18),
 ("ctx_3b",0x5C3125,CTX+0x3B,0x18)
]

def inspect(image: pathlib.Path, csvpath: pathlib.Path):
    data=image.read_bytes()
    if len(data)!=0x672000 or hashlib.sha256(data).hexdigest()!=SHA:
        raise ValueError("Unknown restored Stage-1 image SHA256 or length")
    for addr,hexbytes in OPCODES.items():
        n=len(hexbytes)//2
        if data[addr-BASE:addr-BASE+n].hex()!=hexbytes:
            raise ValueError(f"Opcode mismatch: {addr:#x}")
    with csvpath.open(newline="",encoding="utf-8-sig") as f:
        writes=[dict(ip=int(r["instruction_va"],16),
                     addr=int(r["destination_va"],16),
                     bits=int(r["width_bits"]),
                     value=int(r["written_value"],16)) for r in csv.DictReader(f)]
    if len(writes)!=37:
        raise ValueError(f"Expected 37 bounded model writes, not {len(writes)}")
    proven=[]
    for label,ip,addr,value in REQUIRED:
        matches=[w for w in writes if w==dict(ip=ip,addr=addr,bits=32,value=value)]
        if len(matches)!=1:
            raise ValueError(f"Required modeled write missing: {label}")
        proven.append(dict(label=label,post_instruction_pc=f"0x{ip:08X}",
                            address=f"0x{addr:08X}",value=f"0x{value:08X}"))
    covering=[r for r in writes if r["addr"]<=CTX+0x3B<r["addr"]+r["bits"]//8]
    if covering[-1]["ip"]!=0x5C3125:
        raise ValueError("Newer write aliases context+0x3B")
    # The model snapshot EAX=0x7AEC651F precedes the first SUB; this is
    # a model assumption, not a independently recorded real-process register.
    model_eax_at_5c3000=0x7AEC651F
    after_sub_1=(model_eax_at_5c3000-0xE8480977)&0xffffffff
    after_sub_2=(after_sub_1-0x92A45B90)&0xffffffff
    if (after_sub_1,after_sub_2)!=(0x92A45BA8,0x18):
        raise ValueError("Arithmetic mismatch")
    return dict(
        stage1_sha256=SHA,
        interpretation="Conditional static-model data provenance; no Windows process launched",
        model_context_base=f"0x{CTX:08X}",
        model_eax_before_0x5c3000=f"0x{model_eax_at_5c3000:08X}",
        after_0x5c3000_sub=f"0x{after_sub_1:08X}",
        after_0x5c3033_sub=f"0x{after_sub_2:08X}",
        validated_opcode_sites=len(OPCODES),
        validated_write_events=proven,
        last_writer_to_ctx_plus_3b="0x5C3123 (recorder pc 0x5C3125)",
        first_load="0x53D2ED loads 0x18 from [CTX+0x3B], if the modeled state applies",
        second_load="0x53D2EF dereferences 0x18, unmapped in the research emulator",
        disproven_claim="The halt is NOT explained by an uninitialized CTX+0x3B in the model",
        unresolved="The initial model context, earlier branch semantics, or native VM exit must be measured independently",
        real_runtime_proof=False)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("stage1_bin",type=pathlib.Path)
    p.add_argument("model_writes_csv",type=pathlib.Path)
    p.add_argument("--out",type=pathlib.Path)
    a=p.parse_args()
    result=json.dumps(inspect(a.stage1_bin,a.model_writes_csv),indent=2)+"\n"
    if a.out:a.out.write_text(result,encoding="utf-8")
    else:print(result)
