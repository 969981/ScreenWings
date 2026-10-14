#!/usr/bin/env python3
"""Generate three read-only WinDbg x86 observation scripts. NEVER runs target PE."""
import argparse,json,pathlib
REF_BASE=0x400000
PHASES={
 "seh_install":[(0xAC7032,"HANDLER_A_LEA"),(0xAAA459,"CHAIN_A_INSTALLED"),
                (0xAAAE7E,"HANDLER_B_LEA"),(0xAD0E67,"CHAIN_B_INSTALLED")],
 "pointer_path":[(0x5C3033,"SUBTRACT_TO_0X18"),(0x5C3123,"CTX_3B_STORE"),
                 (0x53D2ED,"FIRST_DEREF"),(0x53D2EF,"SECOND_DEREF")]
}
def generate(base,out):
 if base<0x10000 or base>0xffffffff-0x704108:raise ValueError("Invalid x86 image base")
 out.mkdir(parents=True,exist_ok=True)
 summary={"runtime_imagebase":hex(base),"not_runtime_verified":True,"phases":{}}
 for phase,spots in PHASES.items():
  cmds=[
    "$$ Run one breakpoint phase at a time in an isolated Windows VM.",
    "$$ Check lm m ScreenWings and verify every u instruction before g.",
    ".effmach x86",f".logopen /t C:\\Temp\\ScreenWings-{phase}.txt",
    "sxe av","lm m ScreenWings"]
  entries=[]
  for static,label in spots:
   addr=(static-REF_BASE+base)&0xffffffff
   cmd='.printf \\"[P0 '+label+' EIP=%p EBP=%p EAX=%p EDI=%p ESP=%p]\\\\n\\", @eip, @ebp, @eax, @edi, @esp; r; dd @ebp+0x3b L1; dd @ebp+0x66 L1; dd @esp L2; !exchain'
   cmds.append(f"u 0x{addr:08X} L1")
   cmds.append(f'ba e 1 0x{addr:08X} "{cmd}"')
   entries.append({"label":label,"static_va":hex(static),"runtime_va":hex(addr)})
  cmds+=["bl","$$ Hardware break: inspect and type g. First-chance AV: .exr -1; !exchain; then gn (NOT gh).",
         "$$ When done: .logclose"]
  (out/f"p0_{phase}.windbgcmd").write_text("\r\n".join(cmds)+"\r\n",encoding="utf-8")
  summary["phases"][phase]=entries
 av=["$$ First-chance AV-only phase. Do not combine with 8 hardware breakpoints.",
     ".effmach x86",".logopen /t C:\\Temp\\ScreenWings-av-only.txt","sxe av","lm m ScreenWings",
     "$$ Type g. On first-chance AV: r; u @eip L4; .exr -1; !exchain; !teb; k",
     "$$ Type gn to let the app SEH handle the fault; do not use gh.",
     "$$ Close with .logclose"]
 (out/"p0_av_only.windbgcmd").write_text("\r\n".join(av)+"\r\n",encoding="utf-8")
 (out/"p0_probe_manifest.json").write_text(json.dumps(summary,indent=2)+"\n",encoding="utf-8")
 return summary
if __name__=="__main__":
 p=argparse.ArgumentParser()
 p.add_argument("--runtime-base",default="0x400000")
 p.add_argument("--out",type=pathlib.Path,default=pathlib.Path("windbg"))
 a=p.parse_args()
 print(json.dumps(generate(int(a.runtime_base,0),a.out),indent=2))
