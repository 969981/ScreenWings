# ScreenWings Stage-2 Bootstrap Trace — 2026-10-13

## Performed in this environment

Using the attached `ScreenWings.exe`, verified the original 4,159,512-byte PE SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`, and independently re-read the extracted 6,758,400-byte `schiffer` buffer SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`.

A non-executing, bounded Python tracer followed **20 validated x86 instructions** from restored VA `0x70909A` to `0x7B06A8`, and halted when encountering the first unmodeled opcode (`pushf`). Nothing from the sample was launched.

### Two direct address computations

| Address | Real instruction | Reconstructed effect |
|---|---|---|
| `0x70909A` | `push ebp` | Saves caller frame |
| `0x74B680` | `call 0x7653A0` | Pushes return VA `0x74B685` |
| `0x7653A0` | `jmp 0x7090A0` | Reaches return-address extraction |
| `0x7090A0` | `pop ebp` | `EBP=0x74B685` |
| `0x6366D9` | `sub ebp,0x2B9685` | **`EBP=0x492000`**, reconstructed `schiffer` VA |
| `0x74B68A` | `call 0x7802A9` | Pushes `0x74B68F` |
| `0x7802A9` | `jmp 0x74B694` | Reaches second pop |
| `0x74B694` | `pop eax` | `EAX=0x74B68F` |
| `0x7B0694` | `sub eax,0x34B68F` | **`EAX=0x400000`**, PE ImageBase |
| `0x706D09` | `jmp 0x7028D6` | Direct trampoline |
| `0x7028D6` | `jmp 0x7B06A8` | Enters stack/flags manipulation |
| `0x7B06A8` | `pushf` | Static tracer stops here, without guessing the stack transformations |

**Inference supported by instruction bytes:** the second stage establishes both reconstructed-section and original-PE base addresses by using call/return-address arithmetic and dispersed branch gadgets. It is position-independent bootstrap/protector initialization, not a demonstrated anti-screenshot function.

### Negative and positive static searches

- Only declared imports in the packed PE: `kernel32!GetModuleHandleA`, `mscoree!_CorExeMain`.
- No literal ASCII `SetWindowDisplayAffinity`, `GetWindowDisplayAffinity`, `CreateWindowEx`, `BitBlt`, `PrintWindow`, `GetProcAddress` in `schiffer_stage1.bin`. No `BSJB` CLR metadata signature. These findings **do not exclude** encrypted/dynamically resolved APIs.
- Authenticated embedded PE helper at `schiffer+0x2664C`, with `XBundlerTlsHelper.pdb` path and an ordinary `Sleep` import; identifies an Oreans SecureEngine component, not capture-defense logic.
- 0x40000-byte sliding-block entropy ranges from approximately 4.22 to 7.86 bits/byte. High entropy near the end may reflect remaining packing/obfuscation but is not evidence of a particular decrypted payload.

### Runtime capability check — clear limitation

The provided environment is Linux, **without Windows VM, Wine, or QEMU Windows guest**, and does not have access to the user's Windows desktop. Therefore there is **no** successful ScreenWings runtime launch, real HWND inventory, actual `SetWindowDisplayAffinity` event, or live capture test in this report. The Frida JS syntax passed Node checking and the window JSONL diff script passed a synthetic OFF/ON test; those are instrumentation unit checks, *not runtime evidence*.

Microsoft [GetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowdisplayaffinity) reads affinity on windows of any process but returns success only for layered windows under DWM composition. An unsuccessful call cannot be construed as WDA_NONE. The [setter](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity) must run for a calling-process-owned top-level HWND. `WDA_MONITOR=1` is supported from Windows 7; `WDA_EXCLUDEFROMCAPTURE=0x11` from Windows 10 version 2004.

### Running the reproducer (static only)

```sh
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
python3 tools/trace_stage2_bootstrap.py analysis/stage1/schiffer_stage1.bin --out analysis/stage2_trampoline_trace.json
```

The second command checks the restored bytes' SHA-256 before tracing and rejects unexpected opcode/control-flow changes. It does not execute the PE.

**Remaining question:** Which protection-path transition eventually reaches the actual application code, and which window-creation/affinity/capture-hook functions does that code call? This cannot be answered from the recovered first-stage address computation alone.
