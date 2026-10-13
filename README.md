# ScreenWings reverse-engineering research

Static and reproducible analysis of a supplied ScreenWings Windows executable, using [REA](https://github.com/morluto/rea) with Ghidra and a zero-dependency Python PE extractor and a verified first-stage aPLib decompressor.

## Target identity

| Field | Observed |
|---|---|
| File | `ScreenWings.exe` |
| SHA-256 | `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214` |
| Length | 4,159,512 bytes |
| Format | PE32 x86 GUI |
| Entry | VA `0xB04108` (RVA `0x704108`), section `.boot` |
| Interesting sections | `schiffer`, `.boot`, three unnamed sections |

The target has a high-entropy `.boot` section with its entry point inside an apparent decompression stub. Static imports are `kernel32!GetModuleHandleA` and `mscoree!_CorExeMain`. The PE CLR directory is **absent**, so this is **not proof of an ordinary CLR executable**. Raw extraction does not imply decryption or recovery of the original protected implementation.

## Usage

The specimen is not redistributed by default. Provide your legally obtained specimen at `samples/ScreenWings.exe`, or run the GitHub Actions workflow. The workflow now attempts the historical vendor download (EXE or ZIP), verifies the exact SHA-256, and fails closed if the historical version is unavailable. The specimen is never executed.

```bash
python3 tools/resolve_sample.py --sample samples/ScreenWings.exe
python3 tools/pe_unpack.py samples/ScreenWings.exe --out analysis/extracted
python3 tools/unpack_stage1.py samples/ScreenWings.exe --out analysis/stage1
```

See [the workflow](.github/workflows/reverse-screenwings.yml) for automated REA + Ghidra processing, file extraction, manifests, analysis artifacts and optional publishing of extracted results. **Do not run the protected program in a regular workstation or CI runner.** This workflow uses static analysis only.

## Findings

**Stage one is now fully recovered.** The aPLib-compatible bootstrap restores exactly **6,758,400 bytes** into `schiffer`, SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`, and reaches stage-one entry `0x70909A`. The remaining Oreans/WinLicense protection has not been lifted. Read [the stage-one technical analysis](docs/stage1-unpack-technical.md) and [ScreenWings protection investigation](docs/protection-mechanism.md). The mechanism is an evidence-based **working hypothesis**, not yet a function-level reconstruction: some public testing suggests `SetWindowDisplayAffinity`, but the packed sample's import table does not expose it. A full claim requires the unpacked code, the window creation / display affinity call arguments, and a Windows capture-method comparison.

## Scope and limitations

- Raw PE sections, resources, overlay, signature, import metadata and strings can be extracted without running the specimen.
- REA/Ghidra now analyze a **reconstructed stage-one PE image** with populated `schiffer` bytes and entry RVA `0x30909A`, not merely the packed stub. This is not the original unprotected business executable.
- Stage-two WinLicense runtime behaviors, encrypted API names and any virtualized business logic still need to be resolved. No program execution occurs in CI.
- Third-party files and assets remain subject to the original authors' licenses. Only publish a full payload dump if redistribution is authorized.
