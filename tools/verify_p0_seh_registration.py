#!/usr/bin/env python3
"""Static byte-verified Win32 SEH install chains, not proof of runtime execution."""
import argparse,hashlib,json,pathlib,struct
EXPECTED="2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE=0x492000
CHAINS=[
 ("A",0xAC7032,0x2D910E,0xA5528B,0xAAA446,0xAAA44D,0xAAA452,0xAAA459,0xAC701C),
 ("B",0xAAAE7E,0x2871BE,0xAC9102,0xAD0E54,0xAD0E5B,0xAD0E60,0xAD0E67,0xAB8158)
]
def analyze(b):
 if len(b)!=0x672000 or hashlib.sha256(b).hexdigest()!=EXPECTED:
  raise ValueError("Wrong restored image length/SHA256")
 def get(va,n):
  off=va-BASE
  if off<0 or off+n>len(b):raise ValueError("VA outside image: "+hex(va))
  return b[off:off+n]
 def assert_bytes(va,h):
  if get(va,len(h)//2)!=bytes.fromhex(h):raise ValueError("Opcode mismatch: "+hex(va))
 def jump(src,dst):
  raw=get(src,5)
  if raw[0]!=0xE9 or (src+5+struct.unpack_from("<i",raw,1)[0])&0xffffffff!=dst:
   raise ValueError(f"Invalid E9 {src:#x} -> {dst:#x}")
  return {"source":hex(src),"target":hex(dst)}
 results=[]
 for label,lea,addend,push,old,skip,store,tail,exitva in CHAINS:
  assert_bytes(lea,"8d85")
  if struct.unpack("<I",get(lea+2,4))[0]!=addend:raise ValueError("LEA offset mismatch")
  assert_bytes(push,"50")
  assert_bytes(old,"64ff3500000000")
  assert_bytes(store,"64892500000000")
  if skip!=old+7 or tail!=store+7:raise ValueError("Noncontiguous SEH transfer")
  edges=[jump(lea+6,push),jump(push+1,old),jump(skip,store),jump(tail,exitva)]
  results.append({"chain":label,"handler_formula":f"EBP_at_LEA + 0x{addend:08X}",
                  "lea":hex(lea),"push_handler":hex(push),"push_fs0":hex(old),
                  "store_fs0":hex(store),"after_install":hex(exitva),"verified_jumps":edges,
                  "expected_SEH_record":{"ESP":"previous SEH head","ESP+4":"EAX candidate handler"},
                  "runtime_observed":False})
 return {"stage1_sha256":EXPECTED,"verified_registration_chains":results,
         "not_proven":["that either chain executes","dynamic EBP/handler values",
                       "an AV at 0x53D2EF being handled by these chains","original OEP",
                       "SetWindowDisplayAffinity implementation"]}
if __name__=="__main__":
 p=argparse.ArgumentParser()
 p.add_argument("stage1_bin",type=pathlib.Path)
 p.add_argument("--out",type=pathlib.Path)
 a=p.parse_args()
 output=json.dumps(analyze(a.stage1_bin.read_bytes()),indent=2)+"\n"
 if a.out:a.out.write_text(output,encoding="utf-8")
 else:print(output,end="")
