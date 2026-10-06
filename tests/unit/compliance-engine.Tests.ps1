[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platformRoot 'src/Compliance.Engine.psm1') -Force
$passed = 0

function Assert-Compliance {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$discoveries = @()
$matrix = @()
$resolver = @()
foreach ($state in @('applicable', 'not_applicable', 'capability_unavailable', 'tool_unavailable', 'technology_absent', 'ambiguous')) {
    $technologyStatus = if ($state -eq 'technology_absent') { 'absent' } elseif ($state -eq 'ambiguous') { 'ambiguous' } else { 'detected' }
    $candidate = [pscustomobject]@{ name = 'fixture'; command = 'fixture'; source = 'fixture.exe'; version = '1.0.0'; status = if ($state -eq 'tool_unavailable') { 'not_installed' } else { 'available' }; reason = 'Fixture' }
    $discoveries += [pscustomobject]@{ technology = $state; status = $technologyStatus; roots = @('services/app', 'services/worker'); ambiguities = @('Fixture ambiguite') }
    $matrix += [pscustomobject]@{
        technology = $state
        technology_status = $technologyStatus
        capabilities = @([pscustomobject]@{
            name = 'linting'
            required = ($state -ne 'not_applicable')
            availability = if ($state -eq 'capability_unavailable') { 'unconfigured' } elseif ($state -eq 'tool_unavailable') { 'partially_available' } else { 'available' }
            candidate_tools = @($candidate)
            reasons = @('Fixture capacite')
        })
    }
    $resolver += [pscustomobject]@{ technology = $state; technology_status = $technologyStatus; selected_tools = @([pscustomobject]@{ command = 'fixture'; capabilities = @('linting'); source = 'fixture.exe' }) }
}
$plan = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot -Timeout 7
Assert-Compliance ($plan.controls.Count -eq 12) 'Un controle par racine manque.'
foreach ($state in @('applicable', 'not_applicable', 'capability_unavailable', 'tool_unavailable', 'technology_absent', 'ambiguous')) {
    $controls = @($plan.controls | Where-Object technology -eq $state)
    Assert-Compliance ($controls.Count -eq 2 -and @($controls | Where-Object applicability -ne $state).Count -eq 0) "Etat incorrect: $state"
    $passed++
}
$serialized = $plan | ConvertTo-Json -Depth 12 | ConvertFrom-Json
Assert-Compliance ($serialized.schema_version -eq 1 -and $serialized.controls[0].timeout -eq 7 -and $serialized.controls[-1].execution_order -eq 12) 'Serialisation ou ordre incorrect.'
Assert-Compliance (@($serialized.controls | Select-Object -ExpandProperty id -Unique).Count -eq 12) 'Identifiants de controle dupliques.'
$passed++
$discoveries[0].roots = @('../outside')
$rejected = $false
try { $null = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot }
catch { $rejected = $_.Exception.Message -match 'sort du depot' }
Assert-Compliance $rejected 'Racine externe acceptee.'
$passed++
Write-Information -InformationAction Continue "[SUMMARY] Compliance unit PASS=$passed FAIL=0"
