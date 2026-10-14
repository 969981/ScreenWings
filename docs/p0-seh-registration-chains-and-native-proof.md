# P0: Two complete x86 SEH registration chains; Windows handling not yet observed

**2026-10-14.** Reconstructed `schiffer_stage1.bin`: 6,758,400 bytes, mapped VA `0x492000`, SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`. Original specimen SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`.

## Newly established static control flow

The previous raw `FS:[0]` patterns can now be joined to **two complete, independently byte-verified registration paths**. Every `E9 rel32` hop below has been decoded from the recovered image (not inferred from a search hit).

**Chain A**

```asm
AC7032 lea eax,[ebp+0x2D910E]
AC7038 jmp 0xA5528B
A5528B push eax
A5528C jmp 0xAAA446
AAA446 push dword ptr fs:[0]
AAA44D jmp 0xAAA452
AAA452 mov dword ptr fs:[0],esp
AAA459 jmp 0xAC701C
```

**Chain B**

```asm
AAAE7E lea eax,[ebp+0x2871BE]
AAAE84 jmp 0xAC9102
AC9102 push eax
AC9103 jmp 0xAD0E54
AD0E54 push dword ptr fs:[0]
AD0E5B jmp 0xAD0E60
AD0E60 mov dword ptr fs:[0],esp
AD0E67 jmp 0xAB8158
```

After the `MOV FS:[0],ESP`, the **candidate** x86 exception registration record has `[ESP]=previous FS:[0]`, `[ESP+4]=EAX handler candidate`, and `FS:[0]=ESP`. The handler pointers are **`EBP_at_LEA + 0x2D910E`** and **`EBP_at_LEA + 0x2871BE`**. These are *formulas*, not known runtime VAs: `EBP` may differ at each location. Because protected code contains decoys and nonreachable instruction streams, even complete static code paths do **not** show that either chain executes in a real session.

Additionally, the previously recovered 1,267-entry VM dispatch table targets all lie below or equal to VA `0x621E20`. Neither high-address SEH chain is a direct target of that table; some other indirect/conditional path could still reach it, but this correspondence has not been recovered.

## Falsifiable native evidence requirements

First observe the actual module loading base with `lm m ScreenWings` and confirm that in-memory instruction bytes at the candidate RVA addresses match this report. Never assume `0x400000` after ASLR or that Stage-1 code is restored before the debugger attaches.

Use `tools/make_p0_windbg_probe.py` to generate **three mutually exclusive WinDbg sessions** with correct base-adjusted VAs. The generator doesn't execute the target:

```powershell
py -3 tools\make_p0_windbg_probe.py --runtime-base 0x400000 --out C:\Temp\p0probe
```

In the isolated Windows VM, attach to the original 32-bit process, and paste one of:

```text
$$<C:\Temp\p0probe\p0_seh_install.windbgcmd
$$<C:\Temp\p0probe\p0_pointer_path.windbgcmd
$$<C:\Temp\p0probe\p0_av_only.windbgcmd
```

Only the chosen phase's four hardware breakpoints should be active (use `bc *` before switching). The installation phase checks `LEA EBP` values and the **post-registration** `FS:[0]` chain at `0xAAA459` and `0xAD0E67`; the pointer phase checks `0x5C3033`, `0x5C3123`, `0x53D2ED`, `0x53D2EF`. The AV-only phase uses `sxe av` and no hardware breakpoints.

When a **first-chance AV** actually occurs, record `r`, `u @eip L4`, `.exr -1`, `!exchain`, `!teb`, `k`. To allow the application's exception handler to run, use **`gn`** (go with exception not handled), not **`gh`**, which marks it handled by the debugger. Then record whether a handler executes and where control resumes. A handler registration in any unrelated thread does not establish ownership of the faulting thread. Debugging can trigger WinLicense antidebug logic, so no hits or different behavior are inconclusive.

**Still unproven:** `0x53D2EF` causing a native AV; any of the candidate handlers catching it; original ScreenWings business OEP; actual `SetWindowDisplayAffinity`/WDA flags; or screenshots blocked through overlays/API hooks.

## Reproduce without executing sample

```bash
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/verify_p0_seh_registration.py analysis/stage1/schiffer_stage1.bin --out analysis/p0_seh_registration_static.json
python3 tools/make_p0_windbg_probe.py --out windbg
```

Documentation: [Microsoft ba](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/ba--break-on-access-), [!exchain](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-exchain), [gn](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gn--gn--go-with-exception-not-handled-), [gh](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/gh--go-with-exception-handled-).
