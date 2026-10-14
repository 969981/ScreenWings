#!/usr/bin/env python3
"""Generate non-executing x86 WinDbg exception-proof scripts for ScreenWings.
The REAL loaded image base is REQUIRED. Commands never auto-resume execution.
"""
import argparse
import json
import pathlib

PREFERRED_BASE = 0x400000
IMAGE_SIZE = 0xAA0000
PROBES = {
    "seh_install": [
        ("A_LEA_HANDLER", 0xAC7032, "8d850e912d00"),
        ("A_SEH_INSTALLED", 0xAAA459, "e9becb0100"),
        ("B_LEA_HANDLER", 0xAAAE7E, "8d85be712800"),
        ("B_SEH_INSTALLED", 0xAD0E67, "e9ec72feff"),
    ],
    "pointer_path": [
        ("SUBTRACT_TO_0X18", 0x5C3033, "2b06"),
        ("WRITE_CTX_PLUS_3B", 0x5C3123, "0132"),
        ("FIRST_EDI_DEREF", 0x53D2ED, "8b3f"),
        ("SECOND_EDI_DEREF", 0x53D2EF, "8b3f"),
    ],
}

def generate(base, directory):
    if not 0x10000 <= base <= 0xffffffff-IMAGE_SIZE:
        raise ValueError("Invalid Win32 image base: obtain it using 'lm m ScreenWings'")
    directory.mkdir(parents=True, exist_ok=True)
    manifest={"kind":"PROBE_CONFIGURATION_ONLY","native_log_collected":False,
              "runtime_base":hex(base),"preferred_base":hex(PREFERRED_BASE),
              "aslr_dynamic_base_enabled":True,"phases":{}}
    for phase, probes in PROBES.items():
        lines=[
            "$$ Isolated VM only; this phase may use four x86 hardware breakpoints.",
            "$$ Do not issue g until every db/u byte check matches the expected bytes.",
            ".effmach x86",
            ".logopen /t C:\\Temp\\ScreenWings-"+phase+".txt",
            "lm m ScreenWings", "sxe av", "bc *",
        ]
        spots=[]
        for label, va, expected in probes:
            rva=va-PREFERRED_BASE
            addr=base+rva
            tag="P0_"+label
            lines.extend([
                f".echo EXPECTED_{tag} static_VA=0x{va:08X} RVA=0x{rva:08X} bytes={expected}",
                f"db 0x{addr:08X} L{len(expected)//2}",
                f"u 0x{addr:08X} L1",
                # No nested escaped quotes or automatic go in breakpoint commands.
                f'ba e 1 0x{addr:08X} ".echo {tag}; r; dd @esp L8; !teb; !exchain; k"',
            ])
            spots.append({"label":label,"static_va":hex(va),"rva":hex(rva),
                          "runtime_va":hex(addr),"expected_bytes":expected})
        lines.extend([
            "bl",
            "$$ Human: inspect db/u, then type g if ALL byte checks match.",
            "$$ First chance AV: r; .exr -1; !exchain; !teb; k; then gn to dispatch.",
            "$$ End this session with .logclose.",
        ])
        (directory / ("p0_"+phase+".windbgcmd")).write_text("\r\n".join(lines)+"\r\n",encoding="utf-8")
        manifest["phases"][phase]=spots
    av=[
        "$$ AV-only mode: first/second chance handled separately, no HW breakpoints.",
        ".effmach x86", ".logopen /t C:\\Temp\\ScreenWings-av-only.txt",
        "bc *", "lm m ScreenWings",
        'sxe -c ".echo P0_FIRST_CHANCE_AV; r; u @eip L4; .exr -1; !exchain; !teb; k" -c2 ".echo P0_SECOND_CHANCE_AV; r; .exr -1; !exchain; k" av',
        "sx",
        "$$ Human: type g. On first-chance c0000005, note EIP and !exchain.",
        "$$ Optional: ba e 1 <verified-SEH-handler-VA> to catch handler entry.",
        "$$ Type gn (not gh) to allow application's exception handlers to run.",
        "$$ Inspect handler EIP, thread identity, stack, and next instruction path.",
        "$$ A handler hit alone is NOT proof of recovery or the original app OEP.",
        "$$ Finish: .logclose",
    ]
    (directory/"p0_av_only.windbgcmd").write_text("\r\n".join(av)+"\r\n",encoding="utf-8")
    (directory/"p0_probe_manifest.json").write_text(json.dumps(manifest,indent=2)+"\n",encoding="utf-8")
    return manifest

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime-base",required=True,type=lambda s:int(s,0),
                   help="ACTUAL image base from WinDbg lm m ScreenWings; no default")
    p.add_argument("--out",type=pathlib.Path,default=pathlib.Path("p0probe"))
    a=p.parse_args()
    print(json.dumps(generate(a.runtime_base,a.out),indent=2))
