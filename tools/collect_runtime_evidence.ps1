#requires -Version 7.0
<#
Read-only ScreenWings runtime evidence collection INSIDE AN ISOLATED WINDOWS VM.
Manual protection OFF/ON checkpoints; never launches or modifies the target.
No screenshots or private desktop contents are collected.
#>
param(
  [Parameter(Mandatory=$true)][int]$TargetPid,
  [string]$OutputDir = (Join-Path (Get-Location) 'ScreenWings_Runtime_Evidence')
)
$ErrorActionPreference = 'Stop'
$Tools = Split-Path -Parent $MyInvocation.MyCommand.Path
$Observe = Join-Path $Tools 'observe_windows.py'
$Diff = Join-Path $Tools 'compare_window_snapshots.py'
foreach($file in @($Observe,$Diff)) { if(-not (Test-Path -LiteralPath $file)){throw "Missing tool: $file"}}
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Install Python 3 and the Windows py launcher in your isolated VM' }
if (-not (Get-Process -Id $TargetPid -ErrorAction SilentlyContinue)) { throw "No such ScreenWings process PID: $TargetPid" }
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
$OutputDir = (Resolve-Path -LiteralPath $OutputDir).Path
$before = Join-Path $OutputDir 'affinity_off.jsonl'
$after = Join-Path $OutputDir 'affinity_on.jsonl'
$diffPath = Join-Path $OutputDir 'affinity_diff.json'
$metadataPath = Join-Path $OutputDir 'environment.json'
$ver = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$metadata = [ordered]@{
    utc = [DateTime]::UtcNow.ToString('o')
    target_pid = $TargetPid
    os_build = [string]$ver.CurrentBuild
    os_ubr = $ver.UBR
    os_display_version = $ver.DisplayVersion
    architecture = $env:PROCESSOR_ARCHITECTURE
    experiment = 'Windows HWND-affinity OFF vs ON only; no image capture, API alteration, or program execution by this script'
}
$metadata | ConvertTo-Json | Set-Content -LiteralPath $metadataPath -Encoding utf8
Write-Host 'Ensure ScreenWings is running with protection DISABLED.'
Read-Host 'Press Enter to collect OFF snapshot'
& py -3 $Observe --pid $TargetPid --all --output $before
if ($LASTEXITCODE -ne 0) { throw 'OFF snapshot failed' }
Write-Host 'Enable protection for ONE monitor in ScreenWings.'
Read-Host 'Press Enter to collect ON snapshot'
& py -3 $Observe --pid $TargetPid --all --output $after
if ($LASTEXITCODE -ne 0) { throw 'ON snapshot failed' }
& py -3 $Diff $before $after --json | Set-Content -LiteralPath $diffPath -Encoding utf8
if ($LASTEXITCODE -ne 0) { throw 'Diff failed' }
$manifest = foreach($file in @($before,$after,$diffPath,$metadataPath)){
    [pscustomobject]@{
        name = [IO.Path]::GetFileName($file)
        bytes = (Get-Item -LiteralPath $file).Length
        sha256 = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
    }
}
$manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDir 'files.json') -Encoding utf8
$archive = "$OutputDir.zip"
if(Test-Path -LiteralPath $archive){Remove-Item -LiteralPath $archive -Force}
Compress-Archive -Path (Join-Path $OutputDir '*') -DestinationPath $archive -CompressionLevel Optimal
Write-Host "Captured read-only HWND state evidence: $archive"
Write-Host 'Inspect for sensitive window titles before sharing.'
