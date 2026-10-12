[CmdletBinding()]
param([switch]$NoColor)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'
if ($NoColor) { $env:NO_COLOR = '1' }
$testRoot = Join-Path $repoRoot 'tests'
$powerShellTests = @(Get-ChildItem -Path $testRoot -Filter '*.Tests.ps1' -File -Recurse -ErrorAction SilentlyContinue)
$testFiles = @(Get-ChildItem -Path $testRoot -Filter '*.py' -File -Recurse -ErrorAction SilentlyContinue)

if (-not (Test-Path $python -PathType Leaf)) {
    Write-Information -InformationAction Continue '[ERROR] Python local absent; lancez scripts/bootstrap.ps1.'
    exit 2
}

Push-Location $repoRoot
try {
    foreach ($test in $powerShellTests) {
        & powershell -NoProfile -ExecutionPolicy Bypass -File $test.FullName
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    }
    & (Join-Path $PSScriptRoot 'vscode-extension.ps1') -Action Test
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    if ($testFiles.Count -eq 0) {
        Write-Information -InformationAction Continue '[SKIP] Aucun test Python; les tests PowerShell du socle ont été exécutés.'
        exit 0
    }
    $sourceFiles = @(Get-ChildItem -Path (Join-Path $repoRoot 'src') -Filter '*.py' -File -Recurse -ErrorAction SilentlyContinue)
    $pytestArguments = @('-m', 'pytest')
    if ($sourceFiles.Count -gt 0) { $pytestArguments += @('--cov=src', '--cov-report=term-missing', '--cov-fail-under=80') }
    & $python @pytestArguments
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
