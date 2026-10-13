#!/usr/bin/env python3
"""Read-only PE section/resource/overlay extraction. Not a runtime unpacker."""
import argparse, csv, hashlib, json, math, pathlib, re, struct

def H(b): return hashlib.sha256(b).hexdigest()
def U16(b,p): return struct.unpack_from("<H",b,p)[0]
def U32(b,p): return struct.unpack_from("<I",b,p)[0]
def save(p,b):
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(b)

def entropy(b):
    if not b: return 0
    counts=[0]*256
    for x in b: counts[x]+=1
    n=len(b)
    return round(-sum((k/n)*math.log2(k/n) for k in counts if k),4)

def main(src,out):
    b=src.read_bytes()
    if len(b)<512 or b[:2]!=b"MZ": raise ValueError("not MZ")
    nt=U32(b,0x3c)
    if nt+256>len(b) or b[nt:nt+4]!=b"PE\0\0": raise ValueError("not PE")
    coff=nt+4
    n=U16(b,coff+2)
    opt=coff+20
    magic=U16(b,opt)
    if magic not in (0x10b,0x20b): raise ValueError("unsupported optional header")
    is64=magic==0x20b
    entry=U32(b,opt+16)
    base=struct.unpack_from("<Q" if is64 else "<I",b,opt+(24 if is64 else 28))[0]
    headers=opt+U16(b,coff+16)
    sections=[]
    for i in range(n):
        p=headers+i*40
        if p+40>len(b): raise ValueError("section header truncated")
        name=b[p:p+8].split(b"\0")[0].decode("latin1").strip() or "unnamed"
        vs,va,sz,raw=struct.unpack_from("<IIII",b,p+8)
        if raw+sz>len(b): raise ValueError("section data truncated")
        data=b[raw:raw+sz]
        filename=f"{i:02d}_{re.sub('[^A-Za-z0-9_.-]','_',name)}.bin"
        save(out/"sections"/filename,data)
        sections.append(dict(name=name,virtual_address=va,virtual_size=vs,raw_offset=raw,raw_size=sz,
                             entropy=entropy(data),sha256=H(data),dump=f"sections/{filename}"))
    def at(rva):
        for s in sections:
            va,sz,vs=s["virtual_address"],s["raw_size"],s["virtual_size"]
            if va<=rva<va+max(sz,vs) and rva-va<sz:
                return s["raw_offset"]+rva-va
        if 0<=rva<min((s["raw_offset"] for s in sections if s["raw_offset"]),default=0):
            return rva
        raise ValueError("unmapped RVA %x"%rva)

    dd=opt+(112 if is64 else 96)
    directories=[]
    for i in range(min(16,U32(b,opt+(108 if is64 else 92)))):
        rva,size=struct.unpack_from("<II",b,dd+i*8)
        directories.append(dict(index=i,rva_or_file_offset=rva,size=size))
    imports=[]
    if len(directories)>1 and directories[1]["rva_or_file_offset"]:
        try:
            p=at(directories[1]["rva_or_file_offset"])
            for i in range(1024):
                oft,_,_,name,ft=struct.unpack_from("<IIIII",b,p+i*20)
                if not (oft or name or ft): break
                dll=b[at(name):at(name)+256].split(b"\0")[0].decode("latin1")
                funcs=[]
                q=at(oft or ft)
                step=8 if is64 else 4
                for j in range(32768):
                    v=struct.unpack_from("<Q" if is64 else "<I",b,q+j*step)[0]
                    if not v: break
                    if v&(1<<(63 if is64 else 31)): funcs.append("ordinal_%d"%(v&65535))
                    else:
                        pos=at(v)+2
                        funcs.append(b[pos:pos+256].split(b"\0")[0].decode("latin1"))
                imports.append(dict(dll=dll,functions=funcs))
        except (ValueError,struct.error) as e: imports.append(dict(error=str(e)))

    resources=[]
    if len(directories)>2 and directories[2]["rva_or_file_offset"]:
        root=at(directories[2]["rva_or_file_offset"])
        visited=set()
        def recurse(rel,keys,depth):
            if rel in visited or depth>4: return
            visited.add(rel)
            p=root+rel
            if p+16>len(b): return
            entries=U16(b,p+12)+U16(b,p+14)
            if entries>8192: return
            for j in range(entries):
                x=p+16+j*8
                if x+8>len(b): return
                key,link=struct.unpack_from("<II",b,x)
                if key&0x80000000:
                    pos=root+(key&0x7fffffff)
                    length=min(U16(b,pos),256)
                    k=b[pos+2:pos+2+length*2].decode("utf-16le","replace")
                else: k=str(key)
                if link&0x80000000: recurse(link&0x7fffffff,keys+[k],depth+1)
                else:
                    pos=root+link
                    if pos+16>len(b): continue
                    rva,size,page,_=struct.unpack_from("<IIII",b,pos)
                    try: start=at(rva)
                    except ValueError: continue
                    if size>len(b)-start: continue
                    data=b[start:start+size]
                    safe="_".join(re.sub("[^A-Za-z0-9_.-]","_",v)[:50] for v in keys+[k])
                    filename=f"{len(resources):04d}_{safe}.bin"
                    save(out/"resources"/filename,data)
                    resources.append(dict(keys=keys+[k],rva=rva,raw_offset=start,size=size,
                                          codepage=page,dump=f"resources/{filename}",sha256=H(data)))
        recurse(0,[],0)

    last=max((s["raw_offset"]+s["raw_size"] for s in sections),default=0)
    if last<len(b): save(out/"other"/"overlay.bin",b[last:])
    cert=directories[4] if len(directories)>4 else {"rva_or_file_offset":0,"size":0}
    start,size=cert["rva_or_file_offset"],cert["size"]
    if start and size and start+size<=len(b):
        save(out/"other"/"authenticode_win_certificate.bin",b[start:start+size])
    hits=[]
    for match in re.finditer(rb"[\x20-\x7e]{6,}",b):
        hits.append((match.start(),"ascii",match.group()[:2048].decode("ascii")))
    for match in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}",b):
        hits.append((match.start(),"utf16le",match.group()[:4096].decode("utf-16le")))
    hits.sort()
    out.mkdir(parents=True,exist_ok=True)
    with (out/"strings.csv").open("w",encoding="utf-8",newline="") as f:
        writer=csv.writer(f)
        writer.writerow(["offset","encoding","string"])
        writer.writerows(("0x%x"%p,kind,value) for p,kind,value in hits)
    manifest=dict(sample=src.name,sha256=H(b),length=len(b),machine=hex(U16(b,coff)),
                  format="PE32+" if is64 else "PE32",entry_rva=hex(entry),
                  entry_va=hex(base+entry),image_base=hex(base),
                  clr_runtime_directory_present=bool(len(directories)>14 and directories[14]["rva_or_file_offset"]),
                  directories=directories,sections=sections,imports=imports,resources=resources,
                  string_rows=len(hits),overlay_offset=last,overlay_size=len(b)-last,
                  limitation="Static raw extraction only: packed code is NOT restored/decrypted")
    (out/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"sha256":H(b),"sections":len(sections),"resources":len(resources),
                      "strings":len(hits),"entry_va":hex(base+entry)},indent=2))

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("sample",type=pathlib.Path)
    parser.add_argument("--out",type=pathlib.Path,default=pathlib.Path("analysis/extracted"))
    args=parser.parse_args()
    main(args.sample,args.out)
