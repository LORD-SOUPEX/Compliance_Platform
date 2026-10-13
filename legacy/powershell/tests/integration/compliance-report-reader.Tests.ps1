[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platform = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platform 'src/Compliance.Engine.psm1') -Force
$workspace = Join-Path $platform ('.tools/test-workspaces/reader-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace | Out-Null
$file = Join-Path $workspace 'report.json'
$passed = 0
try {
    $discovery = [pscustomobject]@{ scan_complete = $true; technologies = @() }
    $plan = [pscustomobject]@{ schema_version = 1; repository = $workspace; budgets = [pscustomobject]@{}; permissions = [pscustomobject]@{ network = $false; code_execution = $false }; controls = @() }
    $report = New-ComplianceReport -Discovery $discovery -Matrix @() -Resolver @() -Plan $plan -Results @()
    $report.PSObject.Properties.Remove('metrics')
    $report.metadata.PSObject.Properties.Remove('catalog_sha256')
    [IO.File]::WriteAllText($file, ($report | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    $output = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $platform 'scripts/compliance-adapter.ps1') -ValidateReportPath $file
    if ($LASTEXITCODE -ne 0) { throw 'Rapport historique v1 valide refuse.' }
    $envelope = ($output -join "`n") | ConvertFrom-Json
    if ($envelope.schema_version -ne 1 -or $envelope.report_sha256 -ne (Get-FileHash $file).Hash.ToLowerInvariant()) { throw 'Validation non rattachee aux octets du rapport.' }
    $passed++
    foreach ($content in @('', '{invalid', '[]', '{"schema_version":2}')) {
        [IO.File]::WriteAllText($file, $content, [Text.UTF8Encoding]::new($false))
        $previousPreference = $ErrorActionPreference
        try {
            $ErrorActionPreference = 'Continue'
            $null = & (Join-Path $PSHOME 'powershell.exe') -NoProfile -ExecutionPolicy Bypass -File (Join-Path $platform 'scripts/compliance-adapter.ps1') -ValidateReportPath $file 2>&1
            $code = $LASTEXITCODE
        } finally { $ErrorActionPreference = $previousPreference }
        if ($code -ne 2) { throw 'Rapport invalide accepte.' }
        $passed++
    }
} finally { Remove-Item -LiteralPath $workspace -Recurse -Force }
Write-Information -InformationAction Continue "[SUMMARY] Report reader integration PASS=$passed FAIL=0"
