# ScreenWings Win32 Screenshot-Protection: Native Proof Plan

Target SHA-256: `481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214`

## Proven static path after aPLib unpacking

```
0xB04108 (packed entry, .boot)
  -> aPLib unpack to schiffer, 0x672000 bytes
  -> 0x70909A  push ebp; jmp 0x74B680
  -> 0x74B680  call 0x7653A0; jmp 0x7090A0
  -> 0x7653A0  jmp 0x7090A0
  -> 0x7090A0  pop ebp; jmp 0x6366D9
  -> 0x6366D9  sub ebp,0x2B9685; jmp 0x74B68A
  -> 0x74B68A  call 0x7802A9; jmp 0x74B694
  -> 0x7802A9  jmp 0x74B694
  -> 0x74B694  pop eax; jmp 0x7B0694
```

Note: the two calls return through forward jumps. Most of the apparent sequential disassembly outside the traced blocks is data or mixed obfuscated code, **not** a reliable ordinary function disassembly. This chain still is not a business-code entry point or proof of a screenshot API call.

## Runtime evidence plan — Windows VM only

Do not execute the unknown protected executable on your main machine. Use a throwaway offline Windows VM, snapshot, and only your legally obtained specimen. Install Python and, if desired, Frida tools.

**Part A: compare actual top-level HWNDs and affinity.** Start the original, unmodified ScreenWings.exe inside the VM. During **protection OFF**, find its process ID and run:

```powershell
py -3 tools/observe_windows.py --pid <PID> --all --output off.jsonl
```

Enable protection for one monitor and run:

```powershell
py -3 tools/observe_windows.py --pid <PID> --all --output on.jsonl
```

The JSONL entries record HWND, owning PID, classname, visible/hidden state, window rectangle, extended styles, and (if the OS permits querying) affinity value/error. Repeat with two monitors. Interpret failed GetWindowDisplayAffinity calls as **unavailable**, not WDA_NONE.

**Part B: capture the actual setter, and its arguments**, optionally:

```powershell
py -3 -m pip install frida-tools
frida -n ScreenWings.exe -l tools/capture_trace.frida.js
```

Start tracing before toggling; for startup-only calls, collect with Frida spawn/early instrumentation in the disposable VM. Hooking may be detected or prevented by WinLicense; absence of events **does not** prove a call never happens. Capture original module + offset, caller backtrace, HWND and affinity flag, and correlate matching HWND with the Part A enumeration.

The Frida observer instruments calls (to measure them) but does not request screenshots, bypass protection, or change API return values.

### Decision matrix

| Observation | Interpretation |
|---|---|
| Actual app-originated setter on owned top-level HWND with flag `1`; protected rectangle becomes black | Direct support for `SetWindowDisplayAffinity(WDA_MONITOR)` mechanism |
| Flag `0x11`, and fully absent capture pixels on Windows 10 >=2004 | Direct support for `WDA_EXCLUDEFROMCAPTURE` mechanism on that Windows version |
| One full-display layered/topmost window per monitor, each protected by affinity | Strong support for fullscreen protection-overlay topology |
| Setter not seen, but OS GetWindowDisplayAffinity reports protected HWND | Attach timing / dynamic resolution / instrumentation gap; extend capture window |
| No protected HWND and GDI-only black capture | Explore capture hook/driver/Desktop Window Manager alternatives |
| One API name appears in strings or import metadata | **Insufficient** to identify actual implementation |

### Known Windows API boundaries

Microsoft documentation: [SetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity) and [GetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getwindowdisplayaffinity). The setter is for process-owned top-level windows; DWM composition must be present. WDA_MONITOR=1 is supported from Windows 7. WDA_EXCLUDEFROMCAPTURE=0x11 is effective on Windows 10 version 2004 onward and is treated as WDA_MONITOR on older Windows. The APIs aren't comprehensive DRM protection and do not prevent all acquisition modes.

## GitHub Actions input correction

The previous three screenshot runs were triggered by commits to the workflow itself despite the repository missing `samples/ScreenWings.exe`. The workflow now triggers on **specimen commits** or **manual dispatch only**. Publishing a third-party executable to a public repository requires redistribution permission. For an authorized copy, use `tools/publish_sample.ps1`; otherwise provide a lawfully hosted HTTPS URL through workflow_dispatch, with the exact pinned checksum.

If the workflow still fails after having a matching specimen, inspect the "Resolve specimen" and subsequent "REA/Ghidra static analysis" step logs; the former's failure is different from the native analysis provider's failure.
