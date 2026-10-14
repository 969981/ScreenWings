#!/usr/bin/env python3
"""P0 static audit: 0x18 pointer provenance and FS:[0] exception-chain candidates.
Reads a SHA-256-locked recovered section and prior modeled writes. Never executes
the specimen; raw-pattern locations are NOT proven reachable code.
"""
import argparse, csv, hashlib, json, pathlib
IMAGE_SHA="2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE=0x492000
CTX=0x4C19BC
OPS={
0x53D25F:"89ef",0x53D268:"81c766000000",0x53D2A5:"0fb73f",
0x53D2C3:"6681c74ac7",0x53D2DB:"01ef",0x53D2ED:"8b3f",
0x53D2EF:"8b3f",0x5C3000:"2b02",0x5C3033:"2b06",
0x5C30B8:"0106",0x5C3118:"8b36",0x5C3123:"0132"
}
def scan(data, needle):
    out=[];pos=0
    while (k:=data.find(needle,pos))>=0:
        out.append(BASE+k);pos=k+1
    return out
def inspect(stage1,writes_csv):
    b=pathlib.Path(stage1).read_bytes()
    if len(b)!=0x672000 or hashlib.sha256(b).hexdigest()!=IMAGE_SHA:
        raise ValueError("Restored image SHA256 or length mismatch")
    def at(va,n):
        i=va-BASE
        if i<0 or i+n>len(b):raise ValueError("Unmapped VA "+hex(va))
        return b[i:i+n]
    for va,h in OPS.items():
        if at(va,len(h)//2)!=bytes.fromhex(h):
            raise ValueError("Native instruction mismatch at "+hex(va))
    with pathlib.Path(writes_csv).open(newline="",encoding="utf-8-sig") as f:
        records=[{"ip":int(r["instruction_va"],16),
                  "addr":int(r["destination_va"],16),
                  "bits":int(r["width_bits"]),
                  "value":int(r["written_value"],16)} for r in csv.DictReader(f)]
    if len(records)!=37:raise ValueError("Expected 37 modeled writes")
    def last(addr):
        c=[r for r in records if r["addr"]<=addr<r["addr"]+r["bits"]//8]
        if not c:raise ValueError("No modeled writer at "+hex(addr))
        return c[-1]
    word=last(CTX+0x66); pointer=last(CTX+0x3b)
    assert (word["ip"],word["bits"],word["value"]) == (0x53D24E,16,0x38F1)
    assert (pointer["ip"],pointer["bits"],pointer["value"]) == (0x5C3125,32,0x18)
    off=(word["value"]+0xC74A)&0xffff
    assert off==0x3B
    fs_push=scan(b,bytes.fromhex("64ff3500000000"))
    fs_write_esp=scan(b,bytes.fromhex("64892500000000"))
    fs_write_eax=scan(b,bytes.fromhex("64a300000000"))
    double=scan(b,bytes.fromhex("8b3f8b3f"))
    candidate_sequences=[]
    for addr in fs_push:
        mid=addr+7
        if at(mid,5)==bytes.fromhex("e900000000") and mid+5 in fs_write_esp:
            candidate_sequences.append({"push_fs0":hex(addr),
                                        "jmp_next":hex(mid),
                                        "mov_fs0_esp":hex(mid+5)})
    if tuple(map(len,(fs_push,fs_write_esp,fs_write_eax,double,candidate_sequences)))!=(5,5,1,13,2):
        raise ValueError("FS exception-chain / pointer-pattern counts changed")
    return {
      "stage1_sha256":IMAGE_SHA,
      "modeled_context_base":hex(CTX),
      "field_offset_calculation":"(0x38F1+0xC74A) & 0xFFFF = 0x3B",
      "first_read_va":hex(CTX+off),
      "first_read_model_value":hex(pointer["value"]),
      "next_read_va":hex(pointer["value"]),
      "last_0x66_word_write_pc":hex(word["ip"]),
      "last_0x3b_dword_write_pc":hex(pointer["ip"]),
      "model_writes":len(records),
      "fs_previous_exception_chain_push_raw_hits":[hex(i) for i in fs_push],
      "fs_exception_chain_set_esp_raw_hits":[hex(i) for i in fs_write_esp],
      "fs_exception_chain_set_eax_raw_hits":[hex(i) for i in fs_write_eax],
      "direct_seh_candidate_sequences":candidate_sequences,
      "double_mov_edi_from_edi_raw_hits":[hex(i) for i in double],
      "interpretation":"Evidence of exception-chain manipulation patterns in the restored image; NOT proven reachable during the specific 0x18 read",
      "SEH_handled_0x18_fault_confirmed":False,
      "original_app_OEP_confirmed":False,
      "SetWindowDisplayAffinity_confirmed":False
    }
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("stage1_bin")
    p.add_argument("model_writes_csv")
    p.add_argument("--out",default="-")
    args=p.parse_args()
    s=json.dumps(inspect(args.stage1_bin,args.model_writes_csv),ensure_ascii=False,indent=2)+"\n"
    if args.out=="-":print(s,end="")
    else:pathlib.Path(args.out).write_text(s,encoding="utf-8")
