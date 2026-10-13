#!/usr/bin/env python3
"""Deterministic x86 trampoline/register trace. No code execution or emulation.
Stops on the first opcode whose semantics were not explicitly modeled.
"""
import argparse, hashlib, json, pathlib, struct

EXPECTED = "2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
BASE = 0x492000
START = 0x70909A

def trace(image):
    if len(image) != 0x672000 or hashlib.sha256(image).hexdigest() != EXPECTED:
        raise ValueError("Unrecognized first-stage image")
    pc = START
    stack = []
    regs = {"eax": None, "ebp": None}
    events = []
    visited = set()
    def read(count):
        at = pc - BASE
        if not 0 <= at <= len(image) - count:
            raise ValueError("Address outside reconstructed section: " + hex(pc))
        return image[at:at+count]
    for _ in range(500):
        if pc in visited:
            reason = "Repeat address (cycle)"
            break
        visited.add(pc)
        b = read(8)
        op = b[0]
        at = pc
        if op == 0x55:
            stack.append(regs["ebp"]); size = 1; effect = "push ebp"; dest = pc+size
        elif op in (0x58, 0x5D):
            name = "eax" if op == 0x58 else "ebp"
            if not stack: raise ValueError("Unbalanced pop " + name)
            regs[name] = stack.pop(); size = 1; effect = "pop " + name; dest = pc+size
        elif op in (0xE8, 0xE9):
            size = 5; dest = (pc + size + struct.unpack_from("<i", b, 1)[0]) & 0xffffffff
            effect = "call rel32" if op == 0xE8 else "jmp rel32"
            if op == 0xE8: stack.append(pc+size)
        elif op == 0xEB:
            size = 2; dest = (pc+size+struct.unpack_from("<b", b, 1)[0]) & 0xffffffff
            effect = "jmp rel8"
        elif b[:2] == b"\x81\xED" and regs["ebp"] is not None:
            size=6; imm=struct.unpack_from("<I",b,2)[0]; regs["ebp"]=(regs["ebp"]-imm)&0xffffffff
            effect=f"sub ebp,{imm:#x}";dest=pc+size
        elif op == 0x2D and regs["eax"] is not None:
            size=5; imm=struct.unpack_from("<I",b,1)[0]; regs["eax"]=(regs["eax"]-imm)&0xffffffff
            effect=f"sub eax,{imm:#x}";dest=pc+size
        elif b[:2] == b"\x89\xC0":
            size=2; effect="mov eax,eax";dest=pc+size
        else:
            reason=f"unmodeled opcode {b.hex()} at {pc:#x}"
            break
        events.append(dict(address=f"0x{at:08X}",bytes=b[:size].hex(),instruction=effect,
            next_address=f"0x{dest:08X}",eax=regs["eax"],ebp=regs["ebp"],stack_depth=len(stack)))
        pc=dest
    else: reason="Safety step budget reached"
    result=dict(input_sha256=EXPECTED,entry=f"0x{START:X}",end=f"0x{pc:X}",
                halt_reason=reason,registers=regs,instruction_count=len(events),trace=events)
    if result["instruction_count"] < 20 or regs["ebp"] != 0x492000 or regs["eax"] != 0x400000 or pc != 0x7B06A8:
        raise ValueError("Observed bytes no longer match verified trampoline")
    return result

if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("restored_bin", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path)
    args=parser.parse_args()
    result=trace(args.restored_bin.read_bytes())
    output=json.dumps(result,ensure_ascii=False,indent=2)+"\n"
    if args.out: args.out.write_text(output,encoding="utf-8")
    else: print(output)
