[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter,
    [Parameter(Mandatory = $true)][string]$RepositoryPath,
    [string]$ReportPath,
    [switch]$PlanOnly,
    [switch]$HumanSummary,
    [switch]$AllowNetwork,
    [switch]$AllowCodeExecution
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
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
if ($Adapter -eq 'GitLab') {
    if ($env:COMPLIANCE_ALLOW_NETWORK -ceq 'true') { $arguments += '-AllowNetwork' }
    if ($env:COMPLIANCE_ALLOW_CODE_EXECUTION -ceq 'true') { $arguments += '-AllowCodeExecution' }
}
& $engineExecutable @arguments
$engineCode = $LASTEXITCODE
$reportPathResolved = if ($request.report_path) { if ([IO.Path]::IsPathRooted($request.report_path)) { $request.report_path } else { Join-Path $platformRoot (Join-Path 'reports' $request.report_path) } } else { Join-Path $platformRoot 'reports/compliance-report.json' }
$verdict = $null
if (Test-Path -LiteralPath $reportPathResolved -PathType Leaf) {
    try { $verdict = (Get-Content -LiteralPath $reportPathResolved -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop).verdict }
    catch { Write-Warning "Rapport Compliance illisible; code moteur conserve: $($_.Exception.Message)" }
}
exit (ConvertTo-ComplianceAdapterExitCode -Adapter $Adapter -EngineCode $engineCode -Verdict $verdict)
