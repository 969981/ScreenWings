# ScreenWings 2.16.1430 — stage-one static unpacking

## Verified evidence

Original specimen: `ScreenWings.exe` (`4,159,512` bytes), SHA-256:

`481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`

The packed PE32 entry (`0xB04108`) calls the bootstrap routine at `0xB04258`. It computes the destination `0x492000`, invokes the decoder at `0xB0410D` with compressed source at **VA `0xB0429F`** (raw file offset `0x58C9F`) and finally jumps via a calculated entry pointer.

### Recovery results

| Item | Value |
|---|---|
| Compression | aPLib-compatible, independently verified against instruction branches `0xB0410D–0xB04255` |
| PE destination section | `schiffer`, RVA `0x92000`, original raw length 0, declared virtual size `0x672000` |
| Restored length | `6,758,400` bytes (`0x672000`) — exact declared virtual section size |
| Compressed bytes consumed | `3,779,275` bytes |
| Residual input bytes in `.boot` | `150` bytes |
| Restored section SHA-256 | `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420` |
| Candidate stage-one OEP | `0x70909A` (RVA `0x30909A`), at `schiffer+0x27709A` |
| Entry disassembly | `push ebp; jmp 0x74B680` |
| First transfer at `0x74B680` | `call 0x7653A0; jmp 0x7090A0` |

**Status:** stage one is fully reconstructed byte-for-byte. This is **not** a claim to have removed all protectors, reconstructed the original C# / C++ source, or determined how screenshots are prevented.

The original `.boot` entry does not directly reveal normal program imports. After stage-one restoration, the section still includes indications of Oreans/WinLicense protection:

- `RWinLicenseVersion` at section-relative offset `0x21280` (string presence).
- `Z:\\Oreans Projects\\SecureEngine\\src\\plugins_manager\\internal_plugins\\embedded dlls\\TlsHelperXBundler` at a separate section-relative location.
- A complete x86 PE header beginning at section-relative offset `0x2664C`; PE has `.text`, `.rdata`, `.data`, `.tls`, `.CRT`, `.rsrc`, and `.reloc` sections. This appears to be a bundled TLS/helper component rather than proof of ScreenWings core business logic.

A search for literal ASCII/UTF-16 strings `SetWindowDisplayAffinity`, `BitBlt`, `CreateWindowEx`, `GetProcAddress` and `PrintWindow` in the raw first-stage output produced **no matches**. These negative searches do **not** rule out dynamic import resolution, encrypted names, virtualization or API interception.

## Reproducible artifacts

Run:
```sh
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
```

Output:

- `schiffer_stage1.bin` — the `0x672000` byte restored memory region at image VA `0x492000`.
- `ScreenWings_stage1_for_Ghidra_DO_NOT_RUN.exe` — a static-analysis-only PE with this section populated; its section file pointers, certificate offset and entry RVA are rewritten. **Do not execute it**, and do not expect its original Authenticode signature to remain valid.
- `report.json` — source/restored hashes, compressed stream consumption, reconstruction OEP and decoder operation statistics.

The workflow installs REA 6.4.0, Ghidra 12.1.4, Java 21 and Node 24.11 and targets the reconstructed stage-one entry with REA; full offline downloads are available as GitHub Actions artifacts after a successful run.

## What remains to prove screenshot blocking

1. **Stage two:** resolve the WinLicense / SecureEngine runtime boundary (and, if present, encrypted business-code pages). Static recovery of stage one does not remove this protector.
2. **Window creation:** locate real `CreateWindowExA/W`, window styles `WS_EX_LAYERED` and `WS_EX_TRANSPARENT`, topmost/fullscreen topology, and per-monitor window enumeration.
3. **Display affinity:** locate runtime `SetWindowDisplayAffinity` resolution/call, identify owned `HWND`, flags `WDA_MONITOR=1` or `WDA_EXCLUDEFROMCAPTURE=0x11`, OS-dependent behavior and return codes.
4. **Alternative capture pathways:** check for GDI `BitBlt` / `PrintWindow` interception, DXGI duplication, DWM and capture overlays. Names alone aren't evidence that a call occurs.
5. **Behavioral proof:** under an isolated Windows VM, compare GDI, Snipping Tool, PrintScreen and Windows Graphics Capture, recording actual HWND and affinity before/after the toggle.

Do not conflate an independent third-party ScreenWings behavior demonstration with this binary's Native function-level implementation. Whether `SetWindowDisplayAffinity` is actually used remains **unverified**.
