[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$gatePath = Join-Path $platformRoot 'scripts/quality-gate.ps1'
$tokens = $null
$parseErrors = $null
$gateAst = [Management.Automation.Language.Parser]::ParseFile($gatePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Syntaxe du gate invalide.' }
foreach ($definition in $gateAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$workspace = Join-Path $platformRoot ('.tools/test-workspaces/compliance-' + [guid]::NewGuid().ToString('N'))
$repoRoot = Join-Path $workspace 'fixture'
$toolRoot = Join-Path $platformRoot '.tools/bin'
if (-not (Test-Path -LiteralPath $toolRoot -PathType Container)) { throw 'Outils partages absents; executer le bootstrap.' }
$processHost = Join-Path $PSHOME 'powershell.exe'
$script:Passed = 0
$script:Failed = 0

function Assert-ComplianceIntegration {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-ComplianceFixture {
    param([string]$RelativePath, [string]$Content)
    $destination = Join-Path $repoRoot $RelativePath
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    [IO.File]::WriteAllText($destination, $Content, [Text.UTF8Encoding]::new($false))
}

function Invoke-ComplianceCase {
    param([string]$Name, [scriptblock]$Body)
    if (Test-Path $repoRoot) { Remove-Item -LiteralPath $repoRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $repoRoot -Force | Out-Null
    try {
        & $Body
        $script:Passed++
        Write-Information -InformationAction Continue "[PASS] Compliance integration : $Name"
    } catch {
        $script:Failed++
        Write-Information -InformationAction Continue "[FAIL] Compliance integration : $Name : $($_.Exception.Message)"
    }
}

function Invoke-ComplianceFixture {
    param([switch]$PlanOnly, [switch]$AllowCodeExecution, [switch]$HumanSummary)
    $reportPath = Join-Path $repoRoot 'reports/compliance-report.json'
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gatePath, '-Compliance', '-RepositoryPath', $repoRoot, '-ReportPath', $reportPath, '-NoColor')
    if ($PlanOnly) { $arguments += '-PlanOnly' }
    if ($AllowCodeExecution) { $arguments += '-AllowCodeExecution' }
    if ($HumanSummary) { $arguments += '-HumanSummary' }
    $output = & $processHost @arguments
    $code = $LASTEXITCODE
    try { $report = ($output -join "`n") | ConvertFrom-Json -ErrorAction Stop }
    catch { throw "Sortie Compliance non JSON (code $code): $($output -join "`n")" }
    Assert-ComplianceIntegration (Test-Path $reportPath) 'Rapport non ecrit.'
    $saved = Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-ComplianceIntegration ($saved.verdict -eq $report.verdict -and $saved.schema_version -eq 1) 'Rapport sur disque incoherent.'
    return [pscustomobject]@{ code = $code; report = $report }
}

try {
    Invoke-ComplianceCase 'Sorties separees et code non nul' {
        Write-ComplianceFixture 'output.ps1' '[Console]::Out.WriteLine("sortie"); [Console]::Error.WriteLine("diagnostic"); exit 7'
        $execution = Invoke-BoundedProcess -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'output.ps1')) -WorkingDirectory $repoRoot -Timeout 10
        Assert-ComplianceIntegration ($execution.exit_code -eq 7 -and $execution.stdout.Trim() -eq 'sortie' -and $execution.stderr.Trim() -eq 'diagnostic' -and -not $execution.error) 'Capture des sorties incorrecte.'
        Assert-ComplianceIntegration ([DateTimeOffset]::Parse($execution.execution_end) -ge [DateTimeOffset]::Parse($execution.execution_start) -and $execution.duration_ms -ge 0) 'Horodatage incorrect.'
    }
    Invoke-ComplianceCase 'Erreur de lancement normalisee' {
        $execution = Invoke-BoundedProcess -Executable (Join-Path $repoRoot 'absent.exe') -WorkingDirectory $repoRoot -Timeout 1
        Assert-ComplianceIntegration ($execution.error -and $null -eq $execution.exit_code -and -not $execution.timed_out) 'Erreur technique perdue.'
    }
    Invoke-ComplianceCase 'Timeout conserve les sorties partielles' {
        Write-ComplianceFixture 'timeout.ps1' '[Console]::Out.WriteLine("avant"); Start-Sleep -Seconds 5'
        $execution = Invoke-BoundedProcess -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'timeout.ps1')) -WorkingDirectory $repoRoot -Timeout 1
        Assert-ComplianceIntegration ($execution.timed_out -and $execution.error -and $execution.stdout -match 'avant') 'Timeout ou sortie partielle perdus.'
    }
    Invoke-ComplianceCase 'Sorties conservees bornees par flux' {
        Write-ComplianceFixture 'large-output.ps1' '[Console]::Out.Write(("x" * 10000)); [Console]::Error.Write(("y" * 10000))'
        $execution = Invoke-BoundedProcess -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'large-output.ps1')) -WorkingDirectory $repoRoot -Timeout 10 -MaxOutputBytes 1024
        Assert-ComplianceIntegration ($execution.output_truncated -and [Text.Encoding]::UTF8.GetByteCount($execution.stdout) -le 1024 -and [Text.Encoding]::UTF8.GetByteCount($execution.stderr) -le 1024) 'Les sorties conservent plus que le budget.'
    }
    Invoke-ComplianceCase 'Plan seul sans execution ni verdict' {
        Write-ComplianceFixture 'nested/app/main.ps1' "param()`nWrite-Output 'ok'`n"
        $execution = Invoke-ComplianceFixture -PlanOnly -HumanSummary
        Assert-ComplianceIntegration ($execution.code -eq 0 -and $execution.report.execution_status -eq 'planned' -and $null -eq $execution.report.verdict -and $execution.report.execution_results.Count -eq 0) 'Plan seul execute ou qualifie.'
        Assert-ComplianceIntegration (@($execution.report.execution_plan.controls | Where-Object { $_.technology -eq 'powershell' -and $_.root -eq 'nested/app' -and $_.applicability -eq 'applicable' }).Count -eq 1) 'Controle PowerShell ou racine absents.'
    }
    Invoke-ComplianceCase 'Audit externe PowerShell produit PASS' {
        Write-ComplianceFixture 'nested/app/main.ps1' "param()`nWrite-Output 'ok'`n"
        $execution = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($execution.code -eq 0 -and $execution.report.verdict -eq 'PASS' -and $execution.report.summary.success -eq 1) 'Audit valide non reussi.'
        $expectedCatalogHash = (Get-FileHash -LiteralPath (Join-Path $platformRoot '.config/control-catalog.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-ComplianceIntegration ($execution.report.metadata.catalog_sha256 -eq $expectedCatalogHash) 'Empreinte du catalogue non propagee au rapport.'
        $result = $execution.report.execution_results | Where-Object status -eq 'success'
        Assert-ComplianceIntegration ($result.root -eq 'nested/app' -and $result.capability -eq 'linting' -and $result.tool_version -eq '1.25.0') 'Resultat de controle incomplet.'
        Assert-ComplianceIntegration (-not (Test-Path (Join-Path $repoRoot '.venv')) -and -not (Test-Path (Join-Path $repoRoot '.tools'))) 'Outils installes dans le consommateur.'
    }
    Invoke-ComplianceCase 'Defaut PowerShell produit FAIL et conserve le rapport' {
        Write-ComplianceFixture 'broken.ps1' "function Broken {`n"
        $execution = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($execution.code -eq 1 -and $execution.report.verdict -eq 'FAIL' -and $execution.report.summary.fail -gt 0) 'Defaut de conformite masque.'
        $result = $execution.report.execution_results | Where-Object status -eq 'fail' | Select-Object -First 1
        Assert-ComplianceIntegration ($result.exit_code -ne 0 -and $result.diagnostics.Count -gt 0) 'Preuve d echec absente.'
    }
    Invoke-ComplianceCase 'Audit Python respecte les fichiers decouverts' {
        Write-ComplianceFixture 'app.py' "value = 1`n"
        Write-ComplianceFixture '.tools/cache/generated.py' "def broken(:`n"
        $execution = Invoke-ComplianceFixture
        $details = @($execution.report.execution_results | Where-Object { $_.status -in @('fail', 'error') } | Select-Object control_id, status, stdout, stderr, diagnostics) | ConvertTo-Json -Depth 5 -Compress
        Assert-ComplianceIntegration ($execution.code -eq 0 -and $execution.report.verdict -eq 'PASS' -and $execution.report.summary.success -eq 3) "Controles Python applicables non executes: $details"
        Assert-ComplianceIntegration (-not $execution.report.coverage.complete -and $execution.report.coverage.omitted_required_controls -gt 0) 'Controles soumis a permission masques.'
        foreach ($result in $execution.report.execution_results) { Assert-ComplianceIntegration (($result.stdout + $result.stderr) -notmatch 'generated\.py') 'Cache genere analyse.' }
        Assert-ComplianceIntegration (-not (Test-Path (Join-Path $repoRoot '.ruff_cache'))) 'Cache Ruff cree dans le consommateur.'
    }
    Invoke-ComplianceCase 'Parite Quick historique et Compliance sur Python' {
        Write-ComplianceFixture 'app.py' "value = 1`n"
        $legacyArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gatePath, '-Mode', 'Quick', '-Category', 'Python', '-RepositoryPath', $repoRoot, '-NoColor')
        $null = & $processHost @legacyArguments
        $legacyValidCode = $LASTEXITCODE
        $complianceValid = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($legacyValidCode -eq 0 -and $complianceValid.code -eq 0 -and $complianceValid.report.verdict -eq 'PASS') 'Verdicts divergents sur Python valide.'
        Write-ComplianceFixture 'app.py' "value=1`n"
        $null = & $processHost @legacyArguments
        $legacyInvalidCode = $LASTEXITCODE
        $complianceInvalid = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($legacyInvalidCode -ne 0 -and $complianceInvalid.code -eq 1 -and $complianceInvalid.report.verdict -eq 'FAIL') 'Verdicts divergents sur Python mal formate.'
    }
    Invoke-ComplianceCase 'Syntaxe Python invalide ne produit pas PASS' {
        Write-ComplianceFixture 'app.py' "def broken(:`n"
        $execution = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($execution.code -eq 1 -and $execution.report.verdict -eq 'FAIL' -and $execution.report.summary.fail -gt 0) 'Source Python explicite ignoree ou acceptee.'
    }
    Invoke-ComplianceCase 'Capacite requise indisponible donne erreur critique' {
        Write-ComplianceFixture 'index.ts' "export const value = 1;`n"
        $execution = Invoke-ComplianceFixture
        Assert-ComplianceIntegration ($execution.code -eq 1 -and $execution.report.verdict -eq 'FAIL' -and $execution.report.summary.critical_errors -gt 0) 'Capacite absente acceptee.'
        Assert-ComplianceIntegration (@($execution.report.execution_plan.controls | Where-Object applicability -eq 'capability_unavailable').Count -gt 0) 'Applicabilite non explicite.'
    }
    Invoke-ComplianceCase 'Scan incomplet bloque avant execution' {
        Write-ComplianceFixture 'deployment.yaml' "apiVersion: v1`nkind: Pod`n"
        $locked = [IO.File]::Open((Join-Path $repoRoot 'deployment.yaml'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $execution = Invoke-ComplianceFixture
            Assert-ComplianceIntegration ($execution.code -eq 2 -and $execution.report.verdict -eq 'FAIL' -and $execution.report.execution_status -eq 'blocked' -and $execution.report.execution_results.Count -eq 0) 'Scan incomplet execute ou perdu.'
            Assert-ComplianceIntegration ($execution.report.discovery.scan_errors.Count -eq 1) 'Diagnostic Discovery absent.'
            Assert-ComplianceIntegration ($execution.report.findings.Count -eq 1 -and $execution.report.findings[0].technology -eq 'engine' -and $execution.report.diagnostics[0].critical) 'Erreur Discovery absente des findings normalises.'
        } finally { $locked.Dispose() }
    }
    Invoke-ComplianceCase 'Markdown unique utilise le cache partage' {
        & git -C $repoRoot init --quiet | Out-Null
        Assert-ComplianceIntegration ($LASTEXITCODE -eq 0) 'Git de fixture non initialise.'
        Write-ComplianceFixture 'README.md' "# Fixture`n"
        $execution = Invoke-ComplianceFixture -AllowCodeExecution
        Assert-ComplianceIntegration ($execution.code -eq 0 -and $execution.report.verdict -eq 'PASS' -and $execution.report.summary.success -eq 1) 'Markdown unique non execute correctement.'
        $result = $execution.report.execution_results | Where-Object status -eq 'success'
        Assert-ComplianceIntegration (-not [string]::IsNullOrWhiteSpace($result.tool_version)) 'Version effective pre-commit absente.'
    }
    Write-Information -InformationAction Continue "[SUMMARY] Compliance integration PASS=$script:Passed FAIL=$script:Failed"
    if ($script:Failed) { exit 1 }
    exit 0
} finally {
    if (Test-Path $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
