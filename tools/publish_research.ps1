#requires -Version 7.0
<#
Upload complete research ZIP to a GitHub Release, and optionally expand all 34
files to a versioned research/ directory on main. Never executes a PE binary.
Public redistribution of third-party binary assets requires authorization.
#>
param(
  [Parameter(Mandatory=$true)][string]$Archive,
  [switch]$PublishExpandedFiles,
  [switch]$ConfirmRedistributionRights
)
$ErrorActionPreference = 'Stop'
$ExpectedZip = '2ef547e00335c475bdca13c2df6360de2bb7c5ec1cccafcde3ff55b78f5e9287'
$ExpectedExe = '481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214'
$ExpectedStage1 = '2a1185bbcc93a049d413a71104ed41623bae61cf2412de5ea015564ea8b4d420'
$Repo = '969981/ScreenWings'
$Tag = 'research-2026-10-13-stage1'
if (-not $ConfirmRedistributionRights) {
  throw "The ZIP contains third-party software, packed code and a restored executable. Public redistribution requires permission. Only use -ConfirmRedistributionRights once authorized."
}
if (-not (Test-Path -LiteralPath $Archive -PathType Leaf)) { throw "Research archive not found: $Archive" }
$Archive = (Resolve-Path -LiteralPath $Archive).Path
$sha = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sha -ne $ExpectedZip) { throw "Research ZIP digest mismatch: $sha" }
foreach ($name in 'gh','git') {
  if (-not (Get-Command $name -ErrorAction SilentlyContinue)) { throw "Missing: $name" }
}
gh auth status --hostname github.com | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Log in with gh auth login" }
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("sw-research-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $root = Join-Path $tmp 'extracted'
  Expand-Archive -LiteralPath $Archive -DestinationPath $root
  $sample = Join-Path $root 'samples/ScreenWings.exe'
  $stage = Join-Path $root 'analysis/stage1/schiffer_stage1.bin'
  foreach ($pair in @(@($sample,$ExpectedExe), @($stage,$ExpectedStage1))) {
    $got = (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($got -ne $pair[1]) { throw "Payload SHA mismatch: $($pair[0]) got $got" }
  }
  if ($PublishExpandedFiles) {
    $checkout = Join-Path $tmp 'repo'
    gh repo clone $Repo $checkout -- --depth=1
    if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
    $dest = Join-Path $checkout 'research/2026-10-13-stage1'
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Path (Join-Path $root '*') -Destination $dest -Recurse -Force
    Push-Location $checkout
    try {
      git add -f research/2026-10-13-stage1
      if ($LASTEXITCODE -ne 0) { throw 'git add failed' }
      git -c user.name='ScreenWings research' -c user.email='researcher@users.noreply.github.com' commit -m 'research: publish verified ScreenWings full stage-one package'
      if ($LASTEXITCODE -ne 0) { throw 'git commit failed' }
      git push origin HEAD:main
      if ($LASTEXITCODE -ne 0) { throw 'git push failed (may need latest main)' }
    } finally { Pop-Location }
  }
  gh release view $Tag --repo $Repo *> $null
  if ($LASTEXITCODE -eq 0) {
    gh release upload $Tag $Archive --repo $Repo --clobber
    if ($LASTEXITCODE -ne 0) { throw 'Release upload failed' }
  } else {
    gh release create $Tag $Archive --repo $Repo --title 'ScreenWings Stage-1 Research (2026-10-13)' --notes 'Contains sample, stage-one restored image, analysis-only PE, raw resource extracts, helper DLL, disassembly and tools. This is not a fully unprotected business application or validated anti-screenshot API implementation.'
    if ($LASTEXITCODE -ne 0) { throw 'Release creation failed' }
  }
  Write-Host "Published release: https://github.com/$Repo/releases/tag/$Tag"
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force
}
