# ScreenWings reverse-engineering research

Static and reproducible analysis of a supplied ScreenWings Windows executable, using [REA](https://github.com/morluto/rea) with Ghidra and a zero-dependency Python PE extractor.

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

The specimen is not redistributed by default. Provide your legally obtained specimen at `samples/ScreenWings.exe`, or dispatch the GitHub Actions workflow with an HTTPS sample URL, and check that its SHA-256 equals the expected digest above.

```bash
python3 tools/pe_unpack.py samples/ScreenWings.exe --out analysis/extracted
```

See [the workflow](.github/workflows/reverse-screenwings.yml) for automated REA + Ghidra processing, file extraction, manifests, analysis artifacts and optional publishing of extracted results. **Do not run the protected program in a regular workstation or CI runner.** This workflow uses static analysis only.

## Findings

Read [ScreenWings protection investigation](docs/protection-mechanism.md). The mechanism is an evidence-based **working hypothesis**, not yet a function-level reconstruction: some public testing suggests `SetWindowDisplayAffinity`, but the packed sample's import table does not expose it. A full claim requires the unpacked code, the window creation / display affinity call arguments, and a Windows capture-method comparison.

## Scope and limitations

- Raw PE sections, resources, overlay, signature, import metadata and strings can be extracted without running the specimen.
- REA/Ghidra initially analyze the **packed stub**, not automatically the decrypted business code.
- Dynamic in-memory unpacking must occur in a separate sandbox with appropriate authorization and is not attempted by this CI workflow.
- Third-party files and assets remain subject to the original authors' licenses. Only publish a full payload dump if redistribution is authorized.
