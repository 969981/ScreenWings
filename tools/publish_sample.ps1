#requires -Version 7.0
# Upload only if you have permission to redistribute this third-party executable.
param(
    [Parameter(Mandatory=$true)][string]$Sample,
    [switch]$ConfirmYouMayRedistribute
)
$ErrorActionPreference = 'Stop'
$Expected = '481ecd41bef2a33076729680747eb92e4e2964bed89c58825d80f602de19f214'
if (-not (Test-Path -LiteralPath $Sample -PathType Leaf)) {
    throw "Sample path does not exist: $Sample"
}
$actual = (Get-FileHash -LiteralPath $Sample -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $Expected) { throw "Wrong sample SHA256: $actual" }
if (-not $ConfirmYouMayRedistribute) {
    throw 'A public repository upload redistributes a third-party EXE. Continue only with authorization using -ConfirmYouMayRedistribute'
}
foreach ($cmd in 'gh', 'git') {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) { throw "Missing $cmd" }
}
gh auth status --hostname github.com | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Run gh auth login first' }
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("screenwings-" + [guid]::NewGuid().ToString('N'))
try {
    gh repo clone 969981/ScreenWings "$temp" -- --depth=1
    if ($LASTEXITCODE -ne 0) { throw 'Clone failed' }
    $dir = Join-Path $temp 'samples'
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    Copy-Item -LiteralPath $Sample -Destination (Join-Path $dir 'ScreenWings.exe')
    Push-Location $temp
    try {
        git add -f samples/ScreenWings.exe
        if ($LASTEXITCODE -ne 0) { throw 'git add failed' }
        git -c user.name='ScreenWings researcher' -c user.email='researcher@users.noreply.github.com' commit -m 'Add SHA256-verified ScreenWings specimen for static analysis'
        if ($LASTEXITCODE -ne 0) { throw 'git commit failed or no changes' }
        git push origin HEAD:main
        if ($LASTEXITCODE -ne 0) { throw 'git push failed' }
        Write-Host 'Published verified specimen. ScreenWings Actions is triggered automatically.'
    } finally { Pop-Location }
} finally {
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
