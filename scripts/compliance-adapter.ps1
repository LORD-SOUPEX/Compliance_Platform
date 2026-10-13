[CmdletBinding(DefaultParameterSetName = 'Audit')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Audit')][ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter,
    [Parameter(Mandatory = $true, ParameterSetName = 'Audit')][string]$RepositoryPath,
    [Parameter(Mandatory = $true, ParameterSetName = 'Read')][string]$ValidateReportPath,
    [string]$ReportPath,
    [switch]$PlanOnly,
    [switch]$HumanSummary,
    [switch]$AllowNetwork,
    [switch]$AllowCodeExecution,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$ProgressRunId,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedCatalogSha256,
    [string]$ReportRedactionPattern
)

# [DEPRECATED / HÉRITÉ] Ce script PowerShell est déprécié.
# L'adaptateur d'exécution et la validation des rapports sont assurés par le démon Go ('compliance daemon').
Write-Warning "[DEPRECATED] compliance-adapter.ps1 est déprécié. Utilisez le démon autonome Go."

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ($PSCmdlet.ParameterSetName -eq 'Read') {
    try {
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $file = Get-Item -LiteralPath $ValidateReportPath -ErrorAction Stop
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $file.Length -eq 0 -or $file.Length -gt 32MB) { throw 'Rapport vide, trop volumineux ou redirige par un lien.' }
        $bytes = [IO.File]::ReadAllBytes($file.FullName)
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF)
        $report = $text | ConvertFrom-Json -ErrorAction Stop
        if ($report -isnot [pscustomobject]) { throw 'La racine du rapport doit etre un objet.' }
        Import-Module (Join-Path $platformRoot 'src/Compliance.Engine.psm1') -Force -ErrorAction Stop
        Import-Module (Join-Path $platformRoot 'src/Compliance.Session.psm1') -Force -ErrorAction Stop
        Test-ComplianceReport -Report $report | Out-Null
        $presentations = @($report.execution_results | ForEach-Object {
            $presentation = Get-CompliancePresentation -Result $_
            [pscustomobject]@{ control_id = $_.control_id; status = $presentation.status; reason = $presentation.reason }
        })
        foreach ($control in $report.execution_plan.controls) {
            if (@($report.execution_results | Where-Object control_id -eq $control.id).Count -gt 0) { continue }
            $code = if (-not $report.discovery.scan_complete) { 'incomplete_scan' } elseif ($control.PSObject.Properties.Name -contains 'reason_code') { $control.reason_code } else { $control.applicability }
            $status = if (-not $report.discovery.scan_complete) { 'Blocked' } elseif ($report.execution_status -ne 'planned') { 'Error' }
                elseif ($control.applicability -eq 'applicable') { 'Pending' } elseif ($code -eq 'permission_denied') { 'Skipped' }
                elseif ($control.applicability -in @('ambiguous', 'capability_unavailable', 'tool_unavailable')) { 'Blocked' } else { 'Not applicable' }
            $presentations += [pscustomobject]@{ control_id = $control.id; status = $status; reason = if ($status -eq 'Pending') { $null } else { [pscustomobject]@{ code = $code; message = 'Controle non execute selon le plan backend.' } } }
        }
        $sha = [Security.Cryptography.SHA256]::Create()
        try { $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
        finally { $sha.Dispose() }
        [Console]::Out.WriteLine(([pscustomobject]@{ schema_version = 1; report_sha256 = $hash; presentations = $presentations } | ConvertTo-Json -Depth 8 -Compress))
        exit 0
    } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 2 }
}
Import-Module (Join-Path $platformRoot 'src/Compliance.Adapter.psm1') -Force -ErrorAction Stop
$request = New-ComplianceAdapterRequest -Adapter $Adapter -RepositoryPath $RepositoryPath -ReportPath $ReportPath -PlanOnly:$PlanOnly -HumanSummary:$HumanSummary -AllowNetwork:$AllowNetwork -AllowCodeExecution:$AllowCodeExecution
$gate = Join-Path $platformRoot 'scripts/quality-gate.ps1'
$engineExecutable = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { Join-Path $PSHOME 'powershell.exe' } else { Join-Path $PSHOME 'pwsh' }
if (-not (Test-Path -LiteralPath $engineExecutable -PathType Leaf)) { throw 'Executable PowerShell du moteur introuvable.' }
$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $gate, '-Compliance', '-RepositoryPath', $request.repository, '-Adapter', $request.adapter, '-NoColor')
if ($request.report_path) { $arguments += @('-ReportPath', $request.report_path) }
if ($request.plan_only) { $arguments += '-PlanOnly' }
if ($request.presentation.human_summary) { $arguments += '-HumanSummary' }
if ($request.permissions.network) { $arguments += '-AllowNetwork' }
if ($request.permissions.code_execution) { $arguments += '-AllowCodeExecution' }
if ($ProgressRunId) {
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    $arguments += @('-ProgressRunId', $ProgressRunId)
}
if ($ExpectedCatalogSha256) { $arguments += @('-ExpectedCatalogSha256', $ExpectedCatalogSha256) }
if ($ReportRedactionPattern) { $arguments += @('-ReportRedactionPattern', $ReportRedactionPattern) }
if ($Adapter -eq 'GitLab') {
    if ($env:COMPLIANCE_ALLOW_NETWORK -ceq 'true') { $arguments += '-AllowNetwork' }
    if ($env:COMPLIANCE_ALLOW_CODE_EXECUTION -ceq 'true') { $arguments += '-AllowCodeExecution' }
}
& $engineExecutable @arguments
$engineCode = $LASTEXITCODE
if ($ProgressRunId) { exit $engineCode }
$reportPathResolved = if ($request.report_path) { if ([IO.Path]::IsPathRooted($request.report_path)) { $request.report_path } else { Join-Path $platformRoot (Join-Path 'reports' $request.report_path) } } else { Join-Path $platformRoot 'reports/compliance-report.json' }
$verdict = $null
if (Test-Path -LiteralPath $reportPathResolved -PathType Leaf) {
    try { $verdict = (Get-Content -LiteralPath $reportPathResolved -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop).verdict }
    catch { Write-Warning "Rapport Compliance illisible; code moteur conserve: $($_.Exception.Message)" }
}
exit (ConvertTo-ComplianceAdapterExitCode -Adapter $Adapter -EngineCode $engineCode -Verdict $verdict)
