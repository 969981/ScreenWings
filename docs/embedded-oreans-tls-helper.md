# ScreenWings TLS helper: independently recovered PE analysis

**Source:** `analysis/stage1/schiffer_stage1.bin` from the exact ScreenWings specimen (SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`).

The embedded PE begins at **`schiffer+0x2664C`**, its complete on-disk footprint is **8,704 bytes**, and its SHA-256 is:

`dcb842f5e0da9d486cad34d4b809dcaadf9ec4d6991fdb22bdc9aea66489ad1a`.

Independent `objdump -x` findings:

| Property | Result |
|---|---|
| Image type | PE32 i386 **DLL** |
| ImageBase | `0x10000000` |
| Entry RVA | `0x1000` |
| Timestamp in PE header | 2019-03-28 12:45:01 (not independently authenticated) |
| `.text` virtual size | `0x34` |
| Imported DLL | `KERNEL32.dll` |
| Imported symbol | **`Sleep`** |
| TLS directory RVA | `0x2080` |
| PDB basename | `XBundlerTlsHelper.pdb` |

CodeView/RSDS PDB path recovered directly:

```text
Z:\Oreans Projects\SecureEngine\src\plugins_manager\internal_plugins\embedded dlls\TlsHelperXBundler\Release\XBundlerTlsHelper.pdb
```

## Short entrypoint analysis

At entry RVA `0x1000`, the DLL reads `[ebp+0x0c]` (DLL process/thread attach/detach reason), branches through a four-entry table, calls imported `Sleep` with argument `1` in one case, and returns success (`eax = 1`) to its caller. The ordinary `Sleep` import and tiny startup routine **do not** represent screenshot-blocking implementation.

The evidence supports an **Oreans SecureEngine XBundler/TLS component** in the first-stage recovered image, not a ScreenWings business-logic function and not the identity of an API interception strategy.

## Outstanding questions

- Where does the protector reconstruct its remaining program segments and restore its genuine entry point?
- Does it dynamically import or virtualize `SetWindowDisplayAffinity`, `SetWindowPos`, `CreateWindowEx`, `BitBlt`, or other display-capture functions?
- Which top-level `HWND` receives which display-affinity flag, and does this correlate with per-monitor black captures?

Answers require controlled runtime observations in an isolated Windows VM (see `docs/runtime-capture-validation.md`), or a separately verified further unpacked binary. Absence of literal static API names in the currently recovered stage is not proof that those API calls cannot occur.
