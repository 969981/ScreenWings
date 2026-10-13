#!/usr/bin/env python3
"""Recover stage-two near-jump thunk table from ScreenWings restored stage-one bytes.

Read-only byte inspection; never loads or executes the original EXE.
"""
import argparse
import csv
import hashlib
import json
import pathlib
import struct

IMAGE_SHA = "2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420"
REGION_BASE = 0x492000
PE_BASE = 0x400000
TABLE_VA = 0x60976C
COUNT = 43

def inspect(path: pathlib.Path, out: pathlib.Path):
    data = path.read_bytes()
    if len(data) != 0x672000 or hashlib.sha256(data).hexdigest() != IMAGE_SHA:
        raise ValueError("Unknown stage-one image: length/SHA-256 do not match")
    def at(va: int, length: int) -> int:
        offset = va - REGION_BASE
        if offset < 0 or offset + length > len(data):
            raise ValueError(f"VA outside restored section: {va:#x}")
        return offset

    # Assert instruction bytes of the count setup, loop head and table rebasing operation.
    for va, expected in [
        (0x65E4CC, bytes.fromhex("68 ac 00 00 00")),  # push 0xAC
        (0x65E4EE, bytes.fromhex("c1 eb 02")),        # shr ebx, 2
        (0x65E50D, bytes.fromhex("85 db")),           # test ebx, ebx
        (0x65E530, bytes.fromhex("01 08")),           # add DWORD PTR [eax], ecx
    ]:
        if data[at(va, len(expected)):at(va, len(expected)) + len(expected)] != expected:
            raise ValueError(f"Expected original loop instructions missing at {va:#x}")

    records = []
    for index in range(COUNT):
        entry_va = TABLE_VA + index * 4
        rva = struct.unpack_from("<I", data, at(entry_va, 4))[0]
        thunk_va = (PE_BASE + rva) & 0xffffffff
        location = at(thunk_va, 5)
        if data[location] != 0xE9:
            raise ValueError(f"Expected near jump E9 at {thunk_va:#x}")
        displacement = struct.unpack_from("<i", data, location + 1)[0]
        destination = (thunk_va + 5 + displacement) & 0xffffffff
        opcode = data[at(destination, 1)]
        records.append({
            "index": index,
            "table_entry_va": f"0x{entry_va:08X}",
            "entry_rva": f"0x{rva:08X}",
            "thunk_va": f"0x{thunk_va:08X}",
            "jmp_disp_signed": displacement,
            "target_va": f"0x{destination:08X}",
            "target_first_opcode": f"0x{opcode:02X}",
            "adjacent_plus5_with_previous": bool(index and thunk_va == int(records[-1]["thunk_va"], 16) + 5)
        })

    n_pairs = sum(r["adjacent_plus5_with_previous"] for r in records)
    n_pushf = sum(r["target_first_opcode"] == "0x9C" for r in records)
    unique_targets = len({r["target_va"] for r in records})
    if (n_pairs, n_pushf, unique_targets) != (21, 43, 43):
        raise ValueError("Unexpected thunk table shape")

    report = {
        "stage1_sha256": IMAGE_SHA,
        "table_va": f"0x{TABLE_VA:08X}",
        "table_rva": f"0x{TABLE_VA - PE_BASE:08X}",
        "count": COUNT,
        "bytes": COUNT * 4,
        "rebasing_delta": f"0x{PE_BASE:08X}",
        "thunk_opcode": "E9 rel32",
        "landing_opcode": "9C (PUSHF)",
        "adjacent_plus5_pairs": n_pairs,
        "unique_targets": unique_targets,
        "scope": "Static evidence of table addresses and thunk destinations; business function and anti-capture APIs not proven",
        "records": records,
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "stage2_jump_thunks.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    with (out / "stage2_jump_thunks.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0]))
        writer.writeheader()
        writer.writerows(records)
    print(f"Validated {COUNT} E9 thunks, {n_pairs} adjacent +5 pairs, {unique_targets} unique PUSHF targets")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("stage1_bin", type=pathlib.Path)
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path("analysis/stage2_thunks"))
    args = parser.parse_args()
    inspect(args.stage1_bin, args.out)
