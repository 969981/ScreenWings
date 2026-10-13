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

The specimen is not redistributed by default. Provide your legally obtained specimen at `samples/ScreenWings.exe`, or run the GitHub Actions workflow. A workflow can accept an explicitly provided HTTPS direct download URL, but will not silently use the historical vendor endpoint: Actions run #4 confirmed it did not deliver a valid EXE/ZIP. All supplied samples are pinned to their exact SHA-256. The specimen is never executed.

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


## Fixing the GitHub Actions missing-sample failure

Actions triggered by edits to workflow/tool source previously failed within seconds because the repository did not contain `samples/ScreenWings.exe`. The workflow now starts **only** on pushes to `samples/ScreenWings.exe` or explicit `workflow_dispatch`. Editing documents or tools will no longer trigger a specimen-dependent job.

For an authorized public sample upload (PowerShell 7 and GitHub CLI):

```powershell
pwsh -File .\tools\publish_sample.ps1 -Sample "C:\path\to\ScreenWings.exe" -ConfirmYouMayRedistribute
```

That script verifies the exact SHA-256 before committing the **original, unchanged file**. This action publicly redistributes a third-party executable; do not run without permission. As an alternative, manually dispatch Actions with a legally hosted HTTPS `sample_url` and exact expected SHA-256. The workflow intentionally fails with a clear message if neither a checked-in sample nor a supplied URL is present.

After a verified sample is available, use the workflow's manual run with `publish_extracted=true` only if redistribution of the extraction outputs is authorized. Raw stage-one extraction continues even if an optional deep REA decompilation reports errors; logs and offline artifacts are uploaded when available.

## Capture-prevention function-level validation

The verified static stage-one control flow and read-only Windows instrumentation are documented in [runtime capture validation](docs/runtime-capture-validation.md). Run `tools/observe_windows.py` and optional `tools/capture_trace.frida.js` only in a disposable Windows VM. These tools can correlate owned HWNDs, `WDA_MONITOR`/other flags, topmost/layered windows, and dynamic API resolution; **there is still no first-hand runtime proof that this version calls `SetWindowDisplayAffinity`**.

## Complete research package, release upload, and reproducing the static data

The original **34-file offline research ZIP** is 19,965,016 bytes, SHA-256:
`2ef547e00335c475bdca13c2df6360de2bb7c5ec1cccafcde3ff55b78f5e9287`.
It includes the original specimen, unpacked `schiffer` section, analysis-only reconstructed PE, embedded Oreans helper, raw sections/resources, strings, disassemblies, scripts, and full file manifest.

For a one-command public GitHub Release publication after obtaining redistribution permission:

```powershell
pwsh -File .\tools\publish_research.ps1 -Archive "C:\path\ScreenWings_Actions_Fix_Runtime_Research_20261013.zip" -ConfirmRedistributionRights
```

To also publish **all 34 extracted files individually** under `research/2026-10-13-stage1/`, add `-PublishExpandedFiles`. The script verifies the archive, original EXE, and restored section SHA-256 before touching the GitHub repository. The connected GitHub application cannot transfer the user's local ZIP bytes directly: do not interpret a commit of scripts or reports as confirmation that the ZIP/release has been published.

Alternatively, [Package ScreenWings Stage-1 Research](.github/workflows/package-research.yml) re-creates a complete ZIP as a GitHub Actions artifact **after** receiving an authorized specimen in `samples/ScreenWings.exe` or an explicit direct HTTPS URL with the exact matching checksum. Public GitHub Releases are opt-in and require a redistribution confirmation.

## Isolated Windows VM collection (unverified until actual measurement)

The offline VM helper `tools/collect_runtime_evidence.ps1` captures protection **OFF** and **ON** HWND/affinity snapshots, environment build information, before/after deltas, and SHA-256 checksums to a ZIP without collecting desktop images. For a ScreenWings PID `1234`:

```powershell
pwsh -File .\tools\collect_runtime_evidence.ps1 -TargetPid 1234
```

The optional Frida tracer `tools/capture_trace.frida.js` can complement this with arguments to `SetWindowDisplayAffinity`, `CreateWindowEx`, `SetWindowPos`, and `GetProcAddress`. **No runtime VM logs have been collected in this environment** and there is no function-level proof of the exact anti-screenshot implementation yet. See [runtime methodology](docs/runtime-capture-validation.md).
