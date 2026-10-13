#!/usr/bin/env python3
"""ScreenWings exact-image second relocation table. Static ONLY; never executes PE."""
import argparse,csv,hashlib,json,pathlib,struct,collections
SHA='2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420'
BASE=0x492000
PE_BASE=0x400000
START=0x6471d3
COUNT=0x4f3
OLD=0x60976c

def extract(src,out):
    b=src.read_bytes()
    if len(b)!=0x672000 or hashlib.sha256(b).hexdigest()!=SHA:
        raise ValueError("Mismatching stage-one image SHA256/length")
    def at(va,n):
        off=va-BASE
        if off<0 or off+n>len(b):raise ValueError(f"Unmapped VA {va:#x}")
        return b[off:off+n]
    # The actual reachable loop uses 0x13CC bytes / 4 and writes +ImageBase
    # into consecutive DWORD entries, using a 4-byte step.
    for va,expected in [(0x63c500,'bdcc130000'),(0x63c520,'c1eb02'),
                        (0x63c53e,'85db'),(0x63c55f,'010b'),
                        (0x63c589,'01d0'),(0x63c5b6,'e983ffffff')]:
        if at(va,len(expected)//2).hex()!=expected:
            raise ValueError(f"Unexpected loop instruction at {va:#x}")
    tab=at(START,COUNT*4)
    rvas=struct.unpack('<'+'I'*COUNT,tab)
    previous=struct.unpack('<'+'I'*43,at(OLD,43*4))
    old_addresses={v+PE_BASE for v in previous}
    rows=[]
    for index,rva in enumerate(rvas):
        va=PE_BASE+rva
        op=at(va,5)
        if op[0]!=0xe9:raise ValueError(f"Not E9: {va:#x}")
        rel=struct.unpack_from('<i',op,1)[0]
        dst=(va+5+rel)&0xffffffff
        first=at(dst,1)[0]
        rows.append(dict(index=index,table_entry_va=f"0x{START+index*4:08X}",
             original_rva=f"0x{rva:08X}",thunk_va=f"0x{va:08X}",
             relative_delta=rel,target_va=f"0x{dst:08X}",
             target_first_opcode=f"0x{first:02X}"))
    vs=[int(r['thunk_va'],16) for r in rows]
    dest=[int(r['target_va'],16) for r in rows]
    if len(set(vs))!=COUNT or len(set(dest))!=COUNT or set(vs)&old_addresses:
        raise ValueError("Expected unique, disjoint relocation addresses")
    clusters=[]
    for va in sorted(vs):
        if not clusters or va!=clusters[-1][-1]+5:clusters.append([])
        clusters[-1].append(va)
    if len(clusters)!=230:raise ValueError("Expected 230 physical clusters")
    first_opcodes=collections.Counter(r['target_first_opcode'] for r in rows)
    out.mkdir(parents=True,exist_ok=True)
    with (out/'stage2_reloc1267.csv').open('w',newline='',encoding='utf8') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    idx={v:i for i,v in enumerate(vs)}
    with (out/'stage2_reloc1267_clusters.csv').open('w',newline='',encoding='utf8') as f:
        w=csv.writer(f);w.writerow(['cluster','start_va','end_va','entries','table_indices'])
        for i,group in enumerate(clusters):
            w.writerow([i,f'0x{group[0]:08X}',f'0x{group[-1]:08X}',len(group),
                        ';'.join(str(idx[v]) for v in group)])
    report={
      'sample_stage1_sha256':SHA,'table_va':f'0x{START:08X}',
      'table_end_exclusive':f'0x{START+COUNT*4:08X}',
      'table_bytes':len(tab),'table_sha256':hashlib.sha256(tab).hexdigest(),
      'entries':COUNT,'unique_thunks':len(set(vs)),'unique_targets':len(set(dest)),
      'cluster_count':len(clusters),'cluster_sizes':dict(sorted(collections.Counter(map(len,clusters)).items())),
      'overlap_with_43_table':len(set(vs)&old_addresses),
      'landing_opcode_counts':dict(sorted(first_opcodes.items())),
      'observed_target_va_min':f'0x{min(dest):08X}','observed_target_va_max':f'0x{max(dest):08X}',
      'notes':'Static RVA table + E9-relative destinations; cannot prove business function identities or runtime capture protection'}
    (out/'stage2_reloc1267_summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':
    p=argparse.ArgumentParser()
    p.add_argument('stage1_bin',type=pathlib.Path)
    p.add_argument('--out',type=pathlib.Path,default=pathlib.Path('analysis/stage2_reloc1267'))
    a=p.parse_args()
    extract(a.stage1_bin,a.out)
