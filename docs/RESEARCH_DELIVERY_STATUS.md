# ScreenWings research delivery and evidence status — 2026-10-13

## Verified files and outputs

- Original provided EXE: `ScreenWings.exe`, 4,159,512 bytes, SHA-256 `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`.
- Stage-one aPLib-restored `schiffer`: 6,758,400 bytes, SHA-256 `2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420`.
- Rebuilt static-analysis PE: 10,917,912 bytes, SHA-256 `702c44fd64cec556dbc03ff5ae7ae504c482b97fc11629373b212d8de05106e9`.
- Embedded Oreans SecureEngine `XBundlerTlsHelper` candidate PE: 8,704 bytes, SHA-256 `dcb842f5e0da9d486cad34d4b809dcaadf9ec4d6991fdb22bdc9aea66489ad1a`.
- Existing complete 34-file offline archive: `ScreenWings_Actions_Fix_Runtime_Research_20261013.zip`, **19,965,016** bytes, SHA-256 `2ef547e00335c475bdca13c2df6360de2bb7c5ec1cccafcde3ff55b78f5e9287`; ZIP CRC test passed.

## Repository publication status

- **Published:** Source scripts, reverse-engineering documentation, SHA-256 references, optional Release/upload automation and read-only VM observation tools.
- **Not yet published as GitHub binaries:** Full 34-file ZIP and its individual third-party binary artifacts. A GitHub connector's text/blob-writing methods do not automatically have access to local conversation ZIP bytes. Avoid claiming the files have been uploaded.
- **As of latest check:** Public repository has **no Release** and only four earlier failed Actions runs.
- **Exact cause of run #4:** `ValueError: Download is neither a PE EXE nor a ZIP containing one`. Earlier attempts stopped at sample acquisition, not Ghidra decompilation. The historical vendor download is **not** an authenticated replacement for this exact uploaded specimen.

## How to publish the complete research archive

After obtaining permission to publicly redistribute the program and recovered code, download the exact 34-file ZIP locally, clone the repository, and from PowerShell 7 run:

```powershell
pwsh -File .\tools\publish_research.ps1 -Archive "C:\Downloads\ScreenWings_Actions_Fix_Runtime_Research_20261013.zip" -PublishExpandedFiles -ConfirmRedistributionRights
```

This checks the archive, EXE and recovered `schiffer` SHA-256 digests, publishes every file under `research/2026-10-13-stage1/` and attaches the complete ZIP to the GitHub Release. Omit `-PublishExpandedFiles` if a GitHub Release asset alone is desired. GitHub CLI and Git must be installed, with `gh auth login` completed. These uploads have **not** been executed by the authoring environment.

For an independent Actions-side re-build, provide `samples/ScreenWings.exe` or an explicit HTTPS direct download of the exact digest to [Package Stage-1 Research](../.github/workflows/package-research.yml). The workflow does not execute the specimen.

## Runtime capture implementation status

- **Observed:** A first-stage decompression routine, WinLicense/Oreans references, and the embedded `XBundlerTlsHelper.pdb` path.
- **Not yet observed:** App-owned HWND affinity value or any actual `SetWindowDisplayAffinity` call; Windows fullscreen layered/transparent protection topology; separate captures through GDI, Windows Graphics Capture or DXGI.
- **VM collection ready:** `tools/collect_runtime_evidence.ps1 -TargetPid 1234` records OFF/ON window-affinity state; optional `tools/capture_trace.frida.js` records key user32 calls. These tools are **untested on a live ScreenWings VM session** and no runtime logs are present.
- A `GetWindowDisplayAffinity` failure means **unknown** (Microsoft documents that the query is only successful for layered windows when DWM composes), not `WDA_NONE`.

No claim of complete WinLicense devirtualization or anti-screenshot function-level proof is made.
