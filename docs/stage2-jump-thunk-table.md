# ScreenWings Stage Two — 43 relocation entries and JMP/PUSHF thunk graph

Date: 2026-10-13. **All facts in this report come from bytes in the verified restored first-stage section**, not from running ScreenWings.

## Identity

- Original specimen SHA-256: `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`
- Recovered `schiffer`: `0x672000` bytes, mapped at VA `0x492000`
- Recovered-image SHA-256: `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`
- Original PE ImageBase: `0x400000`

## Newly identified table and consumers

The second-stage bootstrap contains this instruction sequence:

```asm
65E4CC  push 0xAC                ; 172 bytes
65E4EE  shr ebx, 2              ; 172 / 4 = 43 DWORDs
65E50D  test ebx, ebx
65E50F  je 65E572
65E530  add dword ptr [eax], ecx
65E565  sub ebx, edi            ; EDI is set to 1 on the loop path
65E56D  jmp 65E50D
```

A restricted model of the pre-loop straight-line register and stack code, initialized with `EAX=0x400000` and `EBP=0x492000` from the previously verified entry sequence, reaches `0x65E50D` with `EAX=0x60976C`, `EBX=43`, `ECX=0x400000`, and `EDX=0x20976C`.

**Direct byte evidence**: 43 consecutive little-endian DWORDs at image VA `0x60976C` (RVA `0x20976C`) contain code RVAs. Adding `0x400000` to each produces **43 distinct addresses beginning with opcode `E9`** (`jmp rel32`). Following each jump instruction produces **43 distinct destinations, all beginning with opcode `9C`** (`pushf`). Of the 43 thunk addresses, 21 adjacent pairs are exactly 5 bytes apart (the size of an `E9 rel32` instruction). This pairing is structural evidence of neighboring two-entry thunk sites, not yet evidence of which game/application feature references each entry.

| Record | Original RVA | JMP thunk VA | First jump destination | Landing |
|---|---|---|---|---|
| 0 | `0x000A1C1F` | `0x004A1C1F` | `0x005EA038` | `PUSHF` |
| 1 | `0x00169124` | `0x00569124` | `0x004A4CAE` | `PUSHF` |
| 2 | `0x00169129` | `0x00569129` | `0x0055E367` | `PUSHF` |
| 3 | `0x00191998` | `0x00591998` | `0x00639096` | `PUSHF` |
| 42 | `0x000F3F1C` | `0x004F3F1C` | `0x005ECF66` | `PUSHF` |

**Full 43-row machine-readable dataset:** [`analysis/stage2_jump_thunks.csv`](../analysis/stage2_jump_thunks.csv).

## Initialization lock observed along this static path

```asm
65E1F4 xor eax, eax
65E1F6 lock cmpxchg dword ptr [ebp+ebx], ecx
65E1FC je 65E209
65E202 pause
65E204 jmp 65E1F4
```

The pre-lock code produces `EBP=0x5AD798`, `EBX=0x5F`, and `ECX=1`, so the operand points to `0x5AD7F7`, where the restored bytes initially contain zero. The instruction implements a zero-to-one atomic acquisition attempt and a retry loop when it fails. On the initial-zero modeled path, writes of `0x400000` occur at `0x5AD7AB` and `0x5AD831`. This resembles a protected initialization gate, but the flag's broader lifetime has not been established.

## Exact reproducible extraction

```shell
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/extract_stage2_jump_thunks.py analysis/stage1/schiffer_stage1.bin --out analysis/stage2_thunks
```

The second tool checks the entire restored image digest, the four decisive loop instruction encodings, **every** E9 jump and its decoded relative target, every PUSHF landing, and the 21 adjacent +5 pairs. It outputs both CSV and JSON, without executing the target.

## Interpretation boundaries

This is a **verified native data and code structure**, not a fully devirtualized application. The table is consistent with a dispersed set of protection-mediated control-flow entry points. It does **not** prove that any of those 43 functions implement screenshot blocking, or that the application uses `SetWindowDisplayAffinity`, overlays, DXGI, BitBlt/PrintWindow hooks, or a kernel driver.

The subsequent consumer of each entry remains a separate research task. A good next static task is to inspect xrefs to the table and the 43 E9 thunks, identify a specific path that reaches genuine window creation or API resolution, and distinguish runtime-generated vs static caller references. Runtime proof will still require an isolated Windows session with actual HWND/call recordings.

No Windows VM or native dynamic call logs were available during this pass. The limited static model does not substitute for runtime behavior.
