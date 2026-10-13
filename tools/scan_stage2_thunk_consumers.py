#!/usr/bin/env python3
"""Read-only candidate inbound-xref scan and layout clustering for ScreenWings.

CAUTION: raw x86 opcode matching is not a disassembler. Results are candidates;
manually validate instruction boundaries and reachability with Ghidra/IDA.
"""
import argparse, collections, csv, hashlib, json, pathlib, struct

SHA256 = "2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE = 0x492000
IMAGE_BASE = 0x400000
TABLE = 0x60976C
COUNT = 43

def scan(data, opcode, addrset, displacement_start, insn_size, name, predicate=None):
    offset=0
    hits=[]
    while True:
        offset=data.find(opcode,offset)
        if offset<0:break
        pos=offset
        offset+=1
        if pos+insn_size>len(data) or (predicate and not predicate(data,pos)):
            continue
        fmt="<b" if insn_size-displacement_start==1 else "<i"
        rel=struct.unpack_from(fmt,data,pos+displacement_start)[0]
        dest=BASE+pos+insn_size+rel
        if dest in addrset:
            hits.append(dict(source_va=f"0x{BASE+pos:08X}",instruction=name,
                             destination_va=f"0x{dest:08X}",
                             bytes=data[pos:pos+insn_size].hex()))
    return hits

def inspect(data):
    if len(data)!=0x672000 or hashlib.sha256(data).hexdigest()!=SHA256:
        raise ValueError("First-stage image size or digest does not match the specimen")
    entries=[]
    for i in range(COUNT):
        rva=struct.unpack_from("<I",data,TABLE-BASE+4*i)[0]
        stub=IMAGE_BASE+rva
        o=stub-BASE
        if data[o]!=0xe9:raise ValueError(f"No E9 at {stub:#x}")
        target=stub+5+struct.unpack_from("<i",data,o+1)[0]
        if not BASE<=target<BASE+len(data) or data[target-BASE]!=0x9c:
            raise ValueError(f"Landing is not PUSHF at {target:#x}")
        entries.append(dict(index=i,rva=rva,stub=stub,target=target))
    stubs={e["stub"]:e["index"] for e in entries}
    targets={e["target"]:e["index"] for e in entries}
    if len(stubs)!=43 or len(targets)!=43:raise ValueError("Expected 43 distinct addresses")
    clusters=[]
    for va in sorted(stubs):
        if not clusters or va!=clusters[-1][-1]+5:clusters.append([])
        clusters[-1].append(va)
    groups=[]
    for n,group in enumerate(clusters,1):
        o=group[0]-BASE
        prev=data[o-2:o]
        groups.append(dict(group=n,first_va=f"0x{group[0]:08X}",
                last_va=f"0x{group[-1]:08X}",members=len(group),
                entry_indices=[stubs[x] for x in group],
                preceding_bytes=data[o-16:o].hex(),
                immediately_after_jmp_reg=(len(prev)==2 and prev[0]==0xff and 0xe0<=prev[1]<=0xe7),
                add22_memory_update_jump_pattern=(
                    len(prev)==2 and prev[0]==0xff and 0xe0<=prev[1]<=0xe7
                    and data[o-4]==0x01 and b"\x22\x00\x00\x00" in data[o-16:o-4])))
    shapes=dict(collections.Counter(str(len(g)) for g in clusters))
    if shapes!={"4":3,"2":15,"1":1}:raise ValueError("Unexpected 19-cluster shape")
    specs=[("CALL rel32",b"\xe8",1,5,None),("JMP rel32",b"\xe9",1,5,None),
           ("Jcc rel32",b"\x0f",2,6,lambda d,p:0x80<=d[p+1]<=0x8f),
           ("JMP rel8",b"\xeb",1,2,None)]
    for op in range(0x70,0x80):specs.append(("Jcc rel8",bytes([op]),1,2,None))
    for op in range(0xe0,0xe4):specs.append(("LOOP/JCXZ rel8",bytes([op]),1,2,None))
    branches=[]
    for kind,lookups in (("stub",stubs),("landing",targets)):
        for name,op,d,size,predicate in specs:
            for hit in scan(data,op,lookups,d,size,name,predicate):
                hit.update(kind=kind,entry_index=lookups[int(hit["destination_va"],16)])
                branches.append(hit)
    # Two extra short-jcc raw matches have been independently inspected:
    # 0x60658d is inside the immediate of 'mov esi,0x77e788a1'
    # 0x644584 is in a UTF-16-ish data stream before landing 0x644586.
    for x in branches:
        va=int(x["source_va"],16)
        if x["instruction"]=="JMP rel32" and x["kind"]=="landing" and va in stubs:
            x["classification"]="verified table thunk to landing"
        elif va==0x60658d:
            x["classification"]="false positive: opcode bytes inside MOV immediate"
        elif va==0x644584:
            x["classification"]="false positive: opcode-like UTF-16/data bytes"
        else:
            x["classification"]="unverified branch-byte candidate"
    unexpected=[x for x in branches if x["classification"]=="unverified branch-byte candidate"]
    if unexpected:raise ValueError(f"Unexpected branch candidates: {unexpected}")
    def literal_count(d):
        count=0;outside=[]
        for value in d:
            start=0;needle=struct.pack("<I",value)
            while (p:=data.find(needle,start))!=-1:
                count+=1
                if not TABLE-BASE<=p<TABLE-BASE+4*COUNT:outside.append(f"0x{BASE+p:08X}")
                start=p+1
        return dict(total=count,outside_table=outside)
    # Frequency control: this template may be general protector boilerplate.
    # These are byte hits, not independently decoded/reachable instructions.
    global_jmp_reg_candidates=0
    global_plus22_memadd_jmp_candidates=0
    for pos in range(16,len(data)-1):
        if data[pos]==0xff and 0xe0<=data[pos+1]<=0xe7:
            global_jmp_reg_candidates+=1
            if data[pos-2]==0x01 and b"\x22\x00\x00\x00" in data[pos-14:pos-2]:
                global_plus22_memadd_jmp_candidates+=1
    if (global_jmp_reg_candidates,global_plus22_memadd_jmp_candidates)!=(3645,1167):
        raise ValueError("Unexpected global protection-template frequency")
    report=dict(image_sha256=SHA256,table=f"0x{TABLE:08X}",entry_count=43,
      clusters=groups,cluster_sizes=shapes,
      clusters_preceded_by_jmp_reg=sum(x["immediately_after_jmp_reg"] for x in groups),
      clusters_with_add22_write_then_indirect_jump=sum(x["add22_memory_update_jump_pattern"] for x in groups),
      global_raw_ff_e0_to_e7_candidate_count=global_jmp_reg_candidates,
      global_raw_add22_memory_add_jump_candidate_count=global_plus22_memadd_jmp_candidates,
      relative_branch_raw_candidates=branches,
      counts=dict(collections.Counter(x["classification"] for x in branches)),
      literal_pointer_search={
        "stub_va":literal_count(stubs),"landing_va":literal_count(targets),
        "stub_rva":literal_count({e["rva"] for e in entries}),
        "landing_rva":literal_count({e["target"]-IMAGE_BASE for e in entries})},
      note="Negative direct-branch scan cannot exclude computed/indirect or runtime-generated xrefs.")
    return report

def main():
    p=argparse.ArgumentParser()
    p.add_argument("stage1_bin",type=pathlib.Path)
    p.add_argument("--out",type=pathlib.Path,default=pathlib.Path("analysis/stage2-consumers"))
    a=p.parse_args(); report=inspect(a.stage1_bin.read_bytes())
    a.out.mkdir(parents=True,exist_ok=True)
    (a.out/"consumer_scan.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    with (a.out/"thunk_clusters.csv").open("w",encoding="utf-8",newline="") as f:
        w=csv.DictWriter(f,fieldnames=["group","first_va","last_va","members","entry_indices",
                   "preceding_bytes","immediately_after_jmp_reg","add22_memory_update_jump_pattern"])
        w.writeheader()
        for row in report["clusters"]:
            w.writerow(dict(row,entry_indices=";".join(map(str,row["entry_indices"]))))
    print(json.dumps({k:report[k] for k in ("cluster_sizes","clusters_preceded_by_jmp_reg","counts","literal_pointer_search")},indent=2))
if __name__=="__main__":main()
