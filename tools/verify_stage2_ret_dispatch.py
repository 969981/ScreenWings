#!/usr/bin/env python3
"""Read-only static verification of ScreenWings stage-2 RET and JMP dispatch.
Does not run the target. Values depending on VM context are model-conditional.
"""
import argparse,hashlib,json,pathlib,struct
SHA="2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE=0x492000
IMAGEBASE=0x400000
TABLE=0x6471d3

def verify(file):
 b=file.read_bytes()
 if len(b)!=0x672000 or hashlib.sha256(b).hexdigest()!=SHA:
  raise ValueError("Unexpected stage-one section SHA256 or size")
 def get(addr,n):
  pos=addr-BASE
  if pos<0 or pos+n>len(b):raise ValueError(f"Out of range VA {addr:#x}")
  return b[pos:pos+n]
 def w(addr):return struct.unpack("<H",get(addr,2))[0]
 def d(addr):return struct.unpack("<I",get(addr,4))[0]
 def jmp(stub):
  op=get(stub,5)
  if op[0]!=0xe9:raise ValueError(f"Expected E9 at {stub:#x}")
  return (stub+5+struct.unpack_from("<i",op,1)[0])&0xffffffff
 checks={
  0x5303f3:"89e8",0x530400:"89e9",0x5304c6:"ffe1",
  0x593063:"0fb703",0x5930e1:"0107",0x5932aa:"0302",
  0x5932df:"3102",0x5932f6:"c1e002",0x593310:"8b3b",
  0x593340:"893e",0x593436:"8b31",0x593453:"53",
  0x593454:"53",0x593455:"893c24",0x59346a:"893424",
  0x5934c5:"8b3a",0x5934da:"0138",0x593508:"c20000",
  0x5c32f1:"0107",0x5c32f3:"ffe2",
  0x53d2ed:"8b3f",0x53d2ef:"8b3f"}
 for addr,h in checks.items():
  if get(addr,len(h)//2).hex()!=h:raise ValueError(f"Opcode mismatch: {addr:#x}")
 vip=0x4a1366
 # Assumes context+0x7E initialized to zero by handler 570, and that
 # handler 893 begins with the prior model's register/context state.
 key=w(vip+6)
 idx=(w(vip+8)+key)&0xffff
 if (key,idx)!=(0xcea2,1059):raise ValueError("Unexpected encoded selector")
 slot=TABLE+idx*4
 stub=IMAGEBASE+d(slot)
 target=jmp(stub)
 if (slot,stub,target)!=(0x64825f,0x4d289f,0x5c2e23):
  raise ValueError("RET-dispatch map mismatch")
 following_vip=(vip+d(vip+2))&0xffffffff
 if following_vip!=0x5974f1:raise ValueError("VIP advance mismatch")
 further_vip=(following_vip+d(following_vip))&0xffffffff
 if further_vip!=0x4a1370:raise ValueError("Further VIP advance mismatch")
 idx2=518
 slot2=TABLE+idx2*4
 stub2=IMAGEBASE+d(slot2)
 target2=jmp(stub2)
 if (slot2,stub2,target2)!=(0x6479eb,0x4c1b9a,0x53ce97):
  raise ValueError("JMP-dispatch map mismatch")
 return {
  "stage1_sha256":SHA,
  "scope":"Verified PE bytes plus conditional context model, NOT native Windows execution",
  "seed_assumptions":"Handler 570 reset context+0x7E, stage-two table was rebased, register/context state comes from bounded model",
  "ret_dispatch":{"handler_va":"0x593011","selector":idx,
   "slot_va":hex(slot),"RET_instruction_va":"0x593508",
   "constructed_return_va":hex(stub),"E9_landing_va":hex(target),
   "VIP_after":hex(following_vip)},
  "next_dispatch":{"handler_va":"0x5C2E23","model_selector":idx2,
   "slot_va":hex(slot2),"JMP_EDX_instruction_va":"0x5C32F3",
   "thunk_va":hex(stub2),"E9_landing_va":hex(target2),
   "VIP_after":hex(further_vip)},
  "stop_reason":"A broader bounded model reaches 0x53D2EF, then attempts an uninitialized/unmapped read at 0x18. Context state is incomplete.",
  "original_application_entry_confirmed":False,
  "capture_API_confirmed":False}
if __name__=="__main__":
 p=argparse.ArgumentParser()
 p.add_argument("stage1_bin",type=pathlib.Path)
 p.add_argument("--out",type=pathlib.Path)
 a=p.parse_args()
 content=json.dumps(verify(a.stage1_bin),indent=2)+"\n"
 if a.out:a.out.write_text(content,encoding="utf-8")
 else:print(content)
