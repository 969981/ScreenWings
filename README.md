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

## 2026-10-13: independently executed stage-two STATIC trace

Ran the local first-stage bytes through a bounded, no-execution branch tracer. The 20 decoded instructions reconstruct `EBP=0x492000` (restored `schiffer` base) and `EAX=0x400000` (PE image base), through two call/pop/sub address calculations and direct jumps. The trace stops at `0x7B06A8` on an unmodeled `pushf`/stack-manipulation sequence instead of inventing deeper control flow.

- [Reproducible Python tracer](tools/trace_stage2_bootstrap.py)
- [Stage-two bootstrap report and runtime caveats](docs/stage2-bootstrap-static-analysis.md)
- [Windows VM validation method](docs/runtime-capture-validation.md)

**Not a runtime proof:** this execution environment is Linux and does not offer a Windows VM or access to a running ScreenWings process. No actual HWND, `SetWindowDisplayAffinity` flag, user32 caller or screen capture result has been collected. A matching negative static API string scan cannot disprove dynamic API resolution.

## Stage-two branch-thunk table verified (2026-10-13)

A static reconstruction extended the 20-instruction bootstrap into its initialized protection code. In the verified first-stage image:

- `0x65E1F6`: `LOCK CMPXCHG` at the computed `0x5AD7F7` memory location; initial value is zero, with a `PAUSE` retry path.
- `0x65E4CC`/`0x65E4EE`: derives `0xAC/4=43` entries.
- `0x65E530`: `ADD DWORD PTR [EAX], ECX` rebases a 43-entry DWORD table at `0x60976C` by the original PE ImageBase `0x400000`.
- Every rebased address begins with an `E9 rel32` x86 near jump, and **all 43** resolve to **distinct `PUSHF` landing blocks**. **21** pairs of neighboring thunk locations differ by exactly 5 bytes.

The 43-row dataset is checked into [analysis/stage2_jump_thunks.csv](analysis/stage2_jump_thunks.csv), together with [the byte-validating extractor](tools/extract_stage2_jump_thunks.py) and [technical write-up](docs/stage2-jump-thunk-table.md). CI has been updated to regenerate these files only when an authorized exact-match sample is available. This is a discovery of a protected control-flow structure, **not proof** of a screenshot-blocking API.


## 2026-10-13: 43-thunk inbound-consumer analysis

Byte-verified sorting reveals **19 physical clusters** (3 groups of four E9 thunks, 15 pairs, 1 singleton), not 43 independent functions. **13 cluster heads** follow `FF E0..E7` indirect `JMP reg` instructions, and all thirteen share a `+0x22` memory-update template before the jump. However, the whole-image control scan found **1,167 other raw matches to this template** out of 3,645 `FF E0..E7` byte sequences: the template is generic obfuscation and must not be attributed to anti-screenshot code.

A read-only whole-section scan did **not** identify a validated direct relative branch *into* the 43 thunk addresses. Two short-Jcc candidate byte sequences are not established callers (one is inside an immediate operand; the other is apparent data). These negative results do not eliminate dynamically constructed indirect transfers.

- [19 physical clusters CSV](analysis/stage2_thunk_clusters.csv)
- [Read-only raw candidate scanner](tools/scan_stage2_thunk_consumers.py)
- [Detailed 43-entry consumer investigation](docs/stage2-thunk-consumers.md)

Both Actions workflows have been updated to run this scanner once they receive a matching original specimen. No Windows VM capture or verified user32 call trace is available.


## 2026-10-13: second protection relocation table and actual dispatcher

A **second RVA relocation table** was independently decoded at VA `0x6471D3`: **1,267 entries** (5,068 bytes), **230 physical E9 jump clusters**, and no overlap with the earlier 43-entry table. All 1,267 raw RVA entries point after rebasing to distinct valid `E9 rel32` instructions with distinct destinations inside the restored section.

Crucially, a concrete *consumer* of this table has been traced from the second-stage bootstrap, through an instruction-stream selector **803** (`0x4AAD06` -> table entry `0x647E5F` -> thunk `0x4F464D` -> handler `0x4DB0E0`). That handler then selects entry **570** (`0x647ABB` -> `0x496308` -> handler `0x5303F3`) and updates the instruction-stream pointer. The model-derived context has pointer fields at `+0x22` and `+0x52`. This is positive evidence of **protector-side virtualized dispatch**, not yet ScreenWings' actual GUI or screenshot-protection business logic.

- [Full 1,267-row CSV](analysis/stage2_reloc1267.csv)
- [230 physical cluster records](analysis/stage2_reloc1267_clusters.csv)
- [Reproducible stage-two large table extractor](tools/extract_stage2_reloc1267.py)
- [Two consecutive dispatcher proof script](tools/verify_stage2_dispatch.py)
- [Chinese technical investigation and evidence limitations](docs/stage2-virtual-dispatch-1267.md)

Three initial-register seed configurations yielded the same bounded research-model loop entry/exit. The original Windows program has **not** been executed in this analysis environment; neither the original business OEP nor `SetWindowDisplayAffinity` is confirmed. Both Actions pipelines now include these static verification steps, conditional on a correct specimen being supplied.


## 2026-10-13 P0: non-exit RET transition identified, original OEP still unknown

A limited, SHA-256-locked static x86 model advanced from the third virtualized handler to a deceptively normal-looking `RET 0` at **`0x593508`**. The return slot is deliberately populated with **`0x4D289F`** (relocation-table index **1059**), whose `E9` target is handler **`0x5C2E23`**. Thus `RET` is a *VM dispatch mechanism*, not established transfer into original application code. The following handler uses `JMP EDX` at `0x5C32F3`, table index **518**, stub **`0x4C1B9A`**, target **`0x53CE97`**.

A bounded subset model tracked 852 instruction/thunk steps, 32 context writes and 5 synthetic stack writes; **zero writes outside those regions in the modeled prefix**. It stopped strictly at `0x53D2EF` upon an unmapped read from `0x18`. Do not treat predictions past that address as validated—the initial register/context state is conditional, not captured from Windows.

- [P0 technical report](docs/p0-vm-ret-dispatch-and-handoff.md)
- [Raw-byte RET/JMP verifier](tools/verify_stage2_ret_dispatch.py)
- [Bounded model results and assumptions](analysis/p0_stage2_handoff_trace.json)

Both Actions workflows now run the P0 verifier after prior stage-two steps, **only if the exact-matching specimen is available**. No native ScreenWings runtime log, original OEP, executable page decryption or screenshot-protection API has been confirmed.
