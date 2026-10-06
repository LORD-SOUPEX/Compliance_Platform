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
$control = ($serialized.controls | Where-Object applicability -eq 'applicable' | Select-Object -First 1)
$control.root = '.'
$control.technology = 'python'
$control.tool.command = 'ruff'
$control.files = @('fixture.py')
$executionPlan = [pscustomobject]@{ schema_version = 1; repository = $platformRoot; controls = @($control) }
$runner = {
    param($executable, $arguments, $root, $timeout)
    if (-not $executable -or $arguments.Count -eq 0 -or -not (Test-Path $root) -or $timeout -ne 7) { throw 'Invocation mal construite.' }
    if ($arguments[0] -ne 'check' -or $arguments -notcontains '--no-cache' -or $arguments -notcontains (Join-Path $root 'fixture.py')) { throw 'Arguments Ruff concatenes ou perimetre incorrect.' }
    [pscustomobject]@{ execution_start = '2026-10-06T12:00:00Z'; execution_end = '2026-10-06T12:00:01Z'; duration_ms = 1000; stdout = 'sortie'; stderr = 'diagnostic'; exit_code = 0; error = $null; timed_out = $false }
}
$results = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $runner -PlatformRoot $platformRoot)
Assert-Compliance ($results[0].status -eq 'success' -and $results[0].stdout -eq 'sortie' -and $results[0].stderr -eq 'diagnostic' -and $results[0].tool_version -eq '1.0.0') 'Resultat normalise incorrect.'
Assert-Compliance ((Get-ComplianceVerdict -Results $results).verdict -eq 'PASS') 'Verdict succes incorrect.'
$passed++
$results[0].status = 'fail'
Assert-Compliance ((Get-ComplianceVerdict -Results $results).verdict -eq 'FAIL') 'Echec de conformite masque.'
$results[0].status = 'error'
$results[0].critical = $true
Assert-Compliance ((Get-ComplianceVerdict -Results $results).verdict -eq 'FAIL') 'Erreur critique masquee.'
$results[0].critical = $false
Assert-Compliance ((Get-ComplianceVerdict -Results $results).verdict -eq 'PASS') 'Erreur non critique rendue bloquante.'
Assert-Compliance ((Get-ComplianceVerdict -Results @() -ScanComplete $false).verdict -eq 'FAIL') 'Scan incomplet accepte.'
$passed++
$control.applicability = 'tool_unavailable'
$results = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner { throw 'Ne doit pas executer.' } -PlatformRoot $platformRoot)
Assert-Compliance ($results[0].status -eq 'error' -and $results[0].critical) 'Outil requis absent ignore.'
$control.applicability = 'technology_absent'
$results = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner { throw 'Ne doit pas executer.' } -PlatformRoot $platformRoot)
Assert-Compliance ($results[0].status -eq 'skipped' -and -not $results[0].critical) 'Technologie absente mal restituee.'
$passed++
$discoveryReport = [pscustomobject]@{ scan_complete = $true; technologies = @() }
$report = New-ComplianceReport -Discovery $discoveryReport -Matrix @() -Resolver @() -Plan $executionPlan -Results $results
$roundTrip = $report | ConvertTo-Json -Depth 20 | ConvertFrom-Json
Assert-Compliance ($roundTrip.verdict -eq 'PASS' -and $roundTrip.execution_results.Count -eq 1 -and $roundTrip.advisory) 'Rapport Compliance incomplet.'
$planned = New-ComplianceReport -Discovery $discoveryReport -Matrix @() -Resolver @() -Plan $executionPlan -Results @() -PlanOnly
Assert-Compliance ($null -eq $planned.verdict -and $planned.execution_status -eq 'planned') 'Un plan seul a produit un verdict de conformite.'
$passed++
$effectsDiscovery = @([pscustomobject]@{ technology = 'python'; status = 'detected'; roots = @('.'); ambiguities = @(); evidence = @('fixture.py') })
foreach ($command in @('pytest', 'pip-audit', 'pylint', 'pre-commit', 'checkov')) {
    $tool = [pscustomobject]@{ name = $command; command = $command; source = 'fixture.exe'; version = '1.0.0'; status = 'available'; reason = '' }
    $effectsMatrix = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; capabilities = @([pscustomobject]@{ name = 'testing'; required = $true; availability = 'available'; candidate_tools = @($tool); reasons = @() }) })
    $effectsResolver = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; selected_tools = @([pscustomobject]@{ command = $command; capabilities = @('testing'); source = 'fixture.exe' }) })
    $blocked = New-CompliancePlan -Discovery $effectsDiscovery -CapabilityMatrix $effectsMatrix -Resolver $effectsResolver -RepositoryRoot $platformRoot
    Assert-Compliance ($blocked.controls[0].applicability -eq 'not_applicable' -and $blocked.controls[0].reason -match 'non autorise') "Effet non autorise: $command"
    $allowed = New-CompliancePlan -Discovery $effectsDiscovery -CapabilityMatrix $effectsMatrix -Resolver $effectsResolver -RepositoryRoot $platformRoot -AllowNetwork -AllowCodeExecution
    Assert-Compliance ($allowed.controls[0].applicability -eq 'applicable') "Autorisation ignoree: $command"
    if ($command -eq 'checkov') {
        $networkOnly = New-CompliancePlan -Discovery $effectsDiscovery -CapabilityMatrix $effectsMatrix -Resolver $effectsResolver -RepositoryRoot $platformRoot -AllowNetwork
        Assert-Compliance ($networkOnly.controls[0].applicability -eq 'not_applicable') 'Checkov a execute du code avec la seule autorisation reseau.'
    }
    $passed++
}
$partialReport = New-ComplianceReport -Discovery $discoveryReport -Matrix $effectsMatrix -Resolver $effectsResolver -Plan $blocked -Results @()
Assert-Compliance (-not $partialReport.coverage.complete -and $partialReport.coverage.omitted_required_controls -eq 1) 'Couverture partielle masquee.'
$passed++
$missingReport = New-ComplianceReport -Discovery $discoveryReport -Matrix @() -Resolver @() -Plan $executionPlan -Results @()
Assert-Compliance ($missingReport.verdict -eq 'FAIL' -and $missingReport.execution_results[0].diagnostics[0].code -eq 'result_contract_error') 'Resultat manquant transforme en PASS.'
$duplicateReport = New-ComplianceReport -Discovery $discoveryReport -Matrix @() -Resolver @() -Plan $executionPlan -Results @($results[0], $results[0])
Assert-Compliance ($duplicateReport.verdict -eq 'FAIL') 'Resultats dupliques acceptes.'
$passed++
$control.applicability = 'applicable'
$control.tool.version = $null
$timedRunner = {
    param($executable, $arguments, $root, $timeout)
    if (-not $executable -or $arguments[0] -ne '--version' -or -not (Test-Path $root) -or $timeout -ne 7) { throw 'Sonde de version mal configuree.' }
    [pscustomobject]@{ execution_start = '2026-10-06T12:00:00Z'; execution_end = '2026-10-06T12:00:01Z'; duration_ms = 1000; stdout = 'partiel'; stderr = ''; exit_code = $null; error = 'Delai'; timed_out = $true }
}
$timedResults = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $timedRunner -PlatformRoot $platformRoot)
Assert-Compliance ($timedResults[0].status -eq 'error' -and $timedResults[0].diagnostics[0].code -eq 'timeout' -and $timedResults[0].stdout -eq 'partiel') 'Timeout de sonde mal normalise.'
$passed++
$primary = [pscustomobject]@{ name = 'ruff'; command = 'ruff'; source = 'fixture.exe'; version = '1.0.0'; status = 'available'; reason = '' }
$secondary = [pscustomobject]@{ name = 'fallback'; command = 'fallback'; source = $null; version = $null; status = 'not_installed'; reason = 'Alternative absente' }
$alternativeMatrix = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; capabilities = @([pscustomobject]@{ name = 'linting'; required = $true; selection_policy = 'alternative'; availability = 'available'; candidate_tools = @($primary, $secondary); reasons = @() }) })
$alternativeResolver = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; selected_tools = @([pscustomobject]@{ command = 'ruff'; capabilities = @('linting'); source = 'fixture.exe' }) })
$alternativePlan = New-CompliancePlan -Discovery $effectsDiscovery -CapabilityMatrix $alternativeMatrix -Resolver $alternativeResolver -RepositoryRoot $platformRoot -Timeout 7
$discarded = $alternativePlan.controls | Where-Object { $_.tool.command -eq 'fallback' }
Assert-Compliance ($discarded.applicability -eq 'not_applicable' -and -not $discarded.required) 'Alternative ecartee rendue obligatoire.'
$alternativeResults = @(Invoke-CompliancePlan -Plan $alternativePlan -ProcessRunner $runner -PlatformRoot $platformRoot)
$alternativeReport = New-ComplianceReport -Discovery $discoveryReport -Matrix $alternativeMatrix -Resolver $alternativeResolver -Plan $alternativePlan -Results $alternativeResults
Assert-Compliance ($alternativeReport.verdict -eq 'PASS' -and $alternativeReport.coverage.complete) 'Alternative satisfaite rendue incomplete.'
$passed++
Write-Information -InformationAction Continue "[SUMMARY] Compliance unit PASS=$passed FAIL=0"
