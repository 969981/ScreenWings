# ScreenWings capture-protection mechanism — evidence log

Date: 2026-10-13. Specimen SHA-256: `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`.

## Confidence / provenance

| Question | Finding | Evidence | Confidence |
|---|---|---|---|
| Portable executable type | Windows 32-bit (x86) PE, 4,159,512 bytes | PE headers of supplied sample | **Verified** |
| Obfuscated/packed entry | Entry RVA `0x704108`, VA `0xB04108` lies in `.boot` | PE headers, entrypoint disassembly | **Verified** |
| Bootstrap decompression | Call at `0xB04108` to `0xB04258`; nearby bit-buffer and `rep movsb` decoder | x86 disassembly at `0xB04108-0xB04255` | **Strong static evidence** |
| Managed/.NET | Imports `mscoree!_CorExeMain` but no CLR data directory | IAT and PE data directories | **Verified**; ordinary .NET IL is *not* established |
| API imports | `GetModuleHandleA`, `_CorExeMain` only | PE IAT | **Verified**, but packed code can dynamically resolve API names |
| Screenshot protection | Possible window capture exclusion with `SetWindowDisplayAffinity` | [Independent ScreenWings test (Stack Overflow, Feb 2021)](https://stackoverflow.com/questions/66068530/how-does-screenwings-stop-every-screenshot) | **Unverified for this build** |
| Overlay/whole-screen approach | A program-owned, fullscreen display-affinity window could theoretically affect full-frame capture | Working architecture hypothesis | **Not verified** |

## Recoverable static artifacts

The included `tools/pe_unpack.py` extracts the *original bytes* of every PE section, enumerated Win32 resource, overlay, and certificate, and inventories ASCII and UTF-16LE printable strings; all outputs have recorded SHA-256 hashes and offsets.

For this sample:
- Seven PE sections: three anonymous sections, `.idata`, `.rsrc`, `schiffer` (zero raw bytes), and `.boot`.
- Four Win32 resource leaves, corresponding to icon, icon group, version info, and manifest.
- `.boot`: raw size 3,780,096 bytes; entropy ~7.9538 bits/byte.
- PE overlay 16,408 bytes, including the WIN_CERTIFICATE signature bytes.
- 6,018 ASCII/UTF-16 string records, most of which are meaningless packer/high-entropy matches.

This is **complete bytewise PE raw section/resource extraction**, NOT a complete runtime unpack or recovery of the original internal source code. Even a successful Ghidra analysis of the packed input will initially describe the unpacking wrapper.

## Main reverse-engineering checkpoints

1. **Unpack boundary:** identify the compressed stream source/destination and the post-unpacking transfer of control. Investigate `0xB04108`, `0xB04258`, and `0xB0429D`; observe any virtual memory allocations and decrypted code only inside a controlled isolated Windows environment.
2. **Window topology:** after restoration of business code, locate `CreateWindowExA/W`, `SetWindowPos`, extended window styles such as layered/transparent/topmost/toolwindow, and monitor enumeration. Confirm whether it owns one screen-sized overlay per monitor.
3. **Capture-affinity setter:** resolve `SetWindowDisplayAffinity` and inspect the actual HWND, flag (`WDA_MONITOR=1` or `WDA_EXCLUDEFROMCAPTURE=0x11`), return value, OS checks and any fallback.
4. **Alternative mechanism:** search for `BitBlt`, `PrintWindow`, API interception, `Dwm*`, DXGI and desktop-duplication handling. Search results alone are not implementation evidence.
5. **Behavioral matrix:** record results for PrintScreen, Snipping Tool, GDI capture, Desktop Duplication, and Windows Graphics Capture, with and without protection. Note black / transparent / screen not captured and compare with display-only imagery.
6. **Multi-monitor and toggle:** investigate `-Ghost` startup option, protected monitor count, enable/disable path, and window lifecycle.

## REA invocation

The workflow uses REA `6.4.0`, Ghidra `12.1.4`, Node `24.11.0`, and JDK `21`, pinned to the tool versions checked when the document was written.

```sh
rea doctor --provider ghidra --json
rea analyze samples/ScreenWings.exe --provider ghidra --json
rea decompile samples/ScreenWings.exe 0xB04108 --provider ghidra --json
rea search samples/ScreenWings.exe SetWindowDisplayAffinity --provider ghidra --json
```

REA requires a configured Ghidra installation and does not itself decrypt a custom packer. Unsuccessful searches do not refute a dynamically resolved API.

## Reproduction caution

Do not execute the specimen on a host workstation or GitHub-hosted runner. A static PE scanner and a read-only Ghidra import do not require program execution. Runtime experiments require a disposable, offline, snapshotted VM and an explicit safety review. Respect the executable publisher's rights before publicly redistributing its raw binary assets.


## Stage-one update (2026-10-13)

The complete `schiffer` region has been recovered with an aPLib-compatible decoder, and the static-analysis OEP is `0x70909A`. See [the stage-one technical guide](stage1-unpack-technical.md). Additional Oreans / WinLicense components and heavily obfuscated branch paths remain. No literal ASCII/UTF-16 match for `SetWindowDisplayAffinity` or `CreateWindowEx` was observed in the recovered first-stage binary. This is a negative **string** search, not proof that their runtime calls do not exist.

### Windows display-affinity hypothesis — important version distinction

Microsoft's official documentation: [SetWindowDisplayAffinity (winuser.h)](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity).

- `WDA_MONITOR = 0x1` is supported on Windows 7 and later: protected top-level-window contents appear without content in supported captures.
- `WDA_EXCLUDEFROMCAPTURE = 0x11` is supported starting Windows 10 version 2004 (older Windows treats the value as `WDA_MONITOR`).
- The `HWND` must belong to the calling process and be top-level; DWM desktop composition is required.
- The sample's April 2020 build timestamp and documented Windows 7 support make `WDA_MONITOR` an especially relevant **test candidate**, not a proven argument. The actual constant must be observed in the unpacked application call.

An overlay strategy would additionally require evidence of ownership, coverage of the monitor rectangle, layered/transparency or topmost behavior, and the corresponding protected HWND. Plain use of `SetWindowDisplayAffinity` on a small application window does not independently explain whole-desktop black captures. Alternative hook/capture strategies remain open until real callsite and runtime HWND data are obtained.
