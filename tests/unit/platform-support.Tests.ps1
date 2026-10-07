[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platformRoot 'src/Platform.Support.psm1') -Force
$matrixPath = Join-Path $platformRoot '.config/platform-support.json'
$matrix = Import-PlatformSupportMatrix -Path $matrixPath
$expected = @('windows-x64', 'windows-arm64', 'linux-x64', 'linux-arm64', 'macos-x64', 'macos-arm64')
if ((@($matrix.platforms.id | Sort-Object) -join ',') -ne (@($expected | Sort-Object) -join ',')) { throw 'The six targeted platforms must be defined exactly once.' }
if (($matrix.platforms | Where-Object id -eq 'windows-x64').status -ne 'experimental') { throw 'Windows x64 ne reflète pas les gates actuels.' }
if (@($matrix.platforms | Where-Object status -eq 'targeted').Count -ne 5) { throw 'Les plateformes sans qualification doivent rester targeted.' }

$temporaryPath = Join-Path $platformRoot ('.tools/test-workspaces/platform-support-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $invalid = $matrix | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $invalid.platforms[0].architecture = 'arm64'
    $invalid | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    $rejected = $false
    try { $null = Import-PlatformSupportMatrix -Path $temporaryPath } catch { $rejected = $_.Exception.Message -match 'incoherent' }
    if (-not $rejected) { throw 'La matrice a accepte un couple OS/architecture incoherent.' }

    $invalid = $matrix | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $invalid.platforms[0].status = 'qualified'
    $invalid.platforms[0].evidence = @()
    $invalid | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporaryPath -Encoding UTF8
    $rejected = $false
    try { $null = Import-PlatformSupportMatrix -Path $temporaryPath } catch { $rejected = $_.Exception.Message -match 'sans preuve' }
    if (-not $rejected) { throw 'Une plateforme qualifiee sans preuve a ete acceptee.' }
} finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}

Write-Information -InformationAction Continue '[SUMMARY] Platform support unit PASS=4 FAIL=0'
