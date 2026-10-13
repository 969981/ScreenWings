# ScreenWings 4.1 MB specimen — the 43 protection thunks' potential consumers

Date: 2026-10-13

## Evidence, identity and scope

- Source: `ScreenWings.exe` SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`
- Examined restored bytes: `schiffer_stage1.bin`, exactly `0x672000` bytes at mapped image VA `0x492000`, SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`
- Original image base `0x400000`; the 43-entry RVA table starts at `0x60976C`.
- This pass scans **actual restored bytes**, but does not execute ScreenWings or obtain a true native function call stack.

## Important correction to the table-order interpretation

Sorting the 43 RVA-rebased `E9 rel32` addresses **by code VA**, rather than enumerating them in the relocation table's original order, yields exactly **19 contiguous clusters**, distributed as:

| Cluster length | Cluster count | Total thunks |
|---|---:|---:|
| Four contiguous E9 instructions (20 bytes) | 3 | 12 |
| Two contiguous E9 instructions (10 bytes) | 15 | 30 |
| Single E9 instruction (5 bytes) | 1 | 1 |
| **Total** | **19** | **43** |

The earlier reported *21 adjacent +5 pairs* counted only neighboring entries **in table order**; it did not group all neighbors by their physical code addresses. Both counts are true, but answer different questions. Every one of the 43 E9 destinations still begins with a `PUSHF` byte (`0x9C`).

**Frequency-control correction (important):** extending the same byte-pattern search to the whole restored section finds **3,645** raw occurrences of `FF E0..E7`; **1,167** also match an immediate `0x22`, a memory `ADD`, and a following indirect jump within the tested 16-byte window. These are **unvalidated raw-byte candidates**—many are likely the widespread code-obfuscation boilerplate and some may not be reachable instructions. Thus the 13-of-13 signature is real, but **not unique to the 43 thunk table or evidence of a screenshot-related object field**. Give higher priority to the protector-to-application control transfer and actual API resolution than to generic `+0x22` templates.

**13/19 code clusters** have the exact two bytes `FF E0` … `FF E7` immediately before their first jump stub, encoding an unconditional `JMP r32`. Examples:

```asm
00569120  add dword ptr [ecx],eax
00569122  jmp esi
00569124  jmp 0x4A4CAE     ; thunk index 1
00569129  jmp 0x55E367     ; thunk index 2

0049413C  add dword ptr [esi],ecx
0049413E  jmp ebx
00494140  jmp 0x617A8A     ; index 19
00494145  jmp 0x4ACE9C     ; index 20
0049414A  jmp 0x5E9DE0     ; index 27
0049414F  jmp 0x64468C     ; index 28
```

All **13** of those `JMP r32` predecessors also share a stronger byte-verified template within the preceding 16 bytes: an immediate `0x22` added to a register, a `01 /r` (`ADD r/m32,r32`) operation on a computed memory location, and an indirect `FF E0..E7` jump. This is a concrete repeated **memory-write + computed transfer** pattern, but the object whose field is addressed with `+0x22` is not yet known. It may be a protection-layer control/context record; calling it a business object would be premature.

The unconditionally dispatched register jump has no ordinary sequential fallthrough to the thunks. That makes `JMP reg`/runtime-calculated addresses and protection-mediated transitions appropriate next investigation targets, *not* proof that any `E9` is a separate business function or hook.

Full sorted list: [`analysis/stage2_thunk_clusters.csv`](../analysis/stage2_thunk_clusters.csv).

## Inbound direct relative branch scan

A byte-oriented pass scanned the entire 6,758,400-byte section for the forms:

- `E8 rel32` (CALL), `E9 rel32` (JMP), `0F 80..8F rel32` (near conditional)
- `EB rel8` (short JMP), `70..7F rel8` (short conditional)
- `E0..E3 rel8` (loop and conditional counter jumps)

Candidates landing **at exactly one of the 43 thunk VAs**: **zero**.

Candidates landing **at exactly one of the 43 E9 target VAs**: **45** total, of which **43 are the E9 instructions already listed in the relocation table**. The remaining two candidates require instruction-boundary examination:

1. `0x60658D` contains `77 81`, which looks like short `JA rel8` pointing back to `0x606510`. But the bytes are **inside the immediate operand** of the verified `0x606589: mov esi,0x77E788A1` followed by `xor esi,0x77E788A5`. It is **not a decoded branch in that instruction stream**.
2. `0x644584` contains `70 00` that would decode as `JO +0` to landing `0x644586`, but nearby bytes show apparent UTF-16/data and no established path treats `0x644584` as an instruction boundary. Classify as **unverified, likely data** rather than a proven caller.

A separate 4-byte literal search found the **43 thunk RVAs once each in the relocation table**; no literal complete `thunk VA` or `landing VA` is in the original restored section. One occurrence matching a landing RVA appears inside a likely non-code region near `0x4E61D7`, not a validated reference.

**Conclusion of this constrained pass:** there are no *verified static direct relative branch instructions* entering the thunk addresses. This does **not** show the entries are never used. Protected code may compute addresses, access a rebased table, dynamically rewrite pointers, or jump indirectly. Neither raw-byte matching nor straight-line `objdump` can prove the absence of indirect callers.

## What can and cannot be concluded

| Question | Evidence-backed answer |
|---|---|
| Are 43 entries 43 business functions? | No evidence for that interpretation |
| Do the entries cluster? | Yes, 19 physical clusters (3 quadruples, 15 pairs, 1 singleton) |
| Are all 43 branch targets PUSHF blocks? | Yes, verified at byte level |
| Any obvious static direct relative caller into a thunk? | No validated one in the scanned forms |
| Are indirect dispatches plausible? | Yes, based on nearby JMP r32 and the rebased table; *consumer identity unresolved* |
| Can any entry be identified as ScreenWings screenshot protection? | Not yet |
| Are `SetWindowDisplayAffinity(hwnd,1)`, `CreateWindowEx` and a fullscreen overlay proven? | No, runtime observations and genuine application code remain missing |

## Reproduce

```sh
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/scan_stage2_thunk_consumers.py analysis/stage1/schiffer_stage1.bin --out analysis/stage2-consumers
```

The scanner is read-only, checks the SHA-256 before analysis, emits `consumer_scan.json` and a `thunk_clusters.csv` inventory, and labels byte-level candidates separately from validated caller paths. The data can be loaded into IDA/Ghidra as named protected thunks or used for a bounded indirect-branch investigation.

## Next work: identify real consumers, not just catalog more thunks

Use the **13 sites implementing the shared `+0x22` write / `JMP reg` boilerplate** to calibrate and understand the obfuscator, but do not assume they are application-specific. Prioritize locating the post-protector dispatch and inspect the **three quadruple groups** `0x494140`, `0x499B94`, `0x52B698`. For each, track how the branch-register value is constructed and whether it is sourced from the rebased `0x60976C` table, a computed pointer, or a runtime-modified memory cell. Distinguish code bytes from encrypted payload/data using valid control-flow entry points.

Only once a reachable non-protector path is found should we link Windows business functionality: native `CreateWindowExA/W`, `SetWindowDisplayAffinity`, `GetProcAddress` resolution, HWND ownership and display-affinity flags. A confirmed real Windows invocation inside an isolated VM remains necessary to close the specific screenshot-prevention mechanism.

This work does not include a live Windows VM test or claim a complete WinLicense/TLS protector removal.
