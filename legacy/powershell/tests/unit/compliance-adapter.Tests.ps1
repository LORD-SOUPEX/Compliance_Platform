[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platformRoot 'src/Compliance.Adapter.psm1') -Force
$workspace = Join-Path $platformRoot ('.tools/test-workspaces/adapter-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
$passed = 0
function Assert-AdapterContract { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
try {
    foreach ($adapter in @('PowerShell', 'Bash', 'VSCode', 'GitLab')) {
        $request = New-ComplianceAdapterRequest -Adapter $adapter -RepositoryPath $workspace -PlanOnly -HumanSummary -AllowNetwork
        $metadata = Get-ComplianceAdapterMetadata -Adapter $adapter
        Assert-AdapterContract ($request.schema_version -eq 1 -and $request.adapter -eq $adapter -and $request.mode -eq 'Compliance') "Contrat incomplet: $adapter"
        Assert-AdapterContract ($request.permissions.network -and -not $request.permissions.code_execution -and -not $request.source_transmitted -and -not $request.secrets_transmitted) "Permissions/donnees incorrectes: $adapter"
        Assert-AdapterContract ($request.presentation.human_summary) "Presentation humaine perdue: $adapter"
        Assert-AdapterContract ($metadata.contract_version -eq 1 -and $metadata.platforms -contains 'windows-x64') "Compatibilite non declaree: $adapter"
        $passed++
    }
    $externalReportRejected = $false
    try { New-ComplianceAdapterRequest -Adapter GitLab -RepositoryPath $workspace -ReportPath 'https://example.invalid/report.json' }
    catch { $externalReportRejected = $_.Exception.Message -match 'rapports distants' }
    Assert-AdapterContract $externalReportRejected 'Un emplacement distant est accepte comme fichier local.'
    Assert-AdapterContract ((ConvertTo-ComplianceAdapterExitCode -Adapter GitLab -EngineCode 1 -Verdict FAIL) -eq 0) 'Le verdict FAIL devient bloquant dans GitLab.'
    Assert-AdapterContract ((ConvertTo-ComplianceAdapterExitCode -Adapter GitLab -EngineCode 1 -Verdict $null) -eq 1) 'Un rapport absent masque le code technique.'
    Assert-AdapterContract ((ConvertTo-ComplianceAdapterExitCode -Adapter GitLab -EngineCode 2 -Verdict $null) -eq 2) 'Une erreur technique est masquee par GitLab.'
    Assert-AdapterContract ((ConvertTo-ComplianceAdapterExitCode -Adapter VSCode -EngineCode 1 -Verdict FAIL) -eq 1) 'Le code Compliance direct est perdu.'
    $tasks = Get-Content -LiteralPath (Join-Path $platformRoot '.vscode/tasks.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-AdapterContract (@($tasks.tasks | Where-Object label -eq 'Compliance v1').Count -eq 1) 'Tache VS Code Compliance absente.'
    $gitlab = Get-Content -LiteralPath (Join-Path $platformRoot '.gitlab-ci.yml') -Raw -Encoding UTF8
    $adapterScript = Get-Content -LiteralPath (Join-Path $platformRoot 'scripts/compliance-adapter.ps1') -Raw -Encoding UTF8
    Assert-AdapterContract ($gitlab -match 'COMPLIANCE_ADAPTER_ENABLED' -and $gitlab -match 'allow_failure:\s*true' -and $adapterScript -match 'COMPLIANCE_ALLOW_NETWORK' -and $adapterScript -match 'COMPLIANCE_ALLOW_CODE_EXECUTION') 'Job GitLab non optionnel, bloquant ou sans configuration de permission.'
    $passed += 7
    Write-Information -InformationAction Continue "[SUMMARY] Compliance adapter unit PASS=$passed FAIL=0"
} finally {
    if (Test-Path $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
