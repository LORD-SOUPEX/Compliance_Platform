[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platformRoot 'src/Compliance.Engine.psm1') -Force
Import-Module (Join-Path $platformRoot 'src/Control.Catalog.psm1') -Force
$catalog = Import-ControlCatalog -Path (Join-Path $platformRoot '.config/control-catalog.json')
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
$serializedControls = @($serialized.controls)
Assert-Compliance ($serialized.schema_version -eq 1 -and $serializedControls[0].timeout -eq 7 -and $serializedControls[$serializedControls.Count - 1].execution_order -eq 12) 'Serialisation ou ordre incorrect.'
Assert-Compliance (@($serializedControls | Select-Object -ExpandProperty id -Unique).Count -eq 12) 'Identifiants de controle dupliques.'
$passed++
$discoveries[0].roots = @('../outside')
$rejected = $false
try { $null = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot }
catch { $rejected = $_.Exception.Message -match 'sort du depot' }
Assert-Compliance $rejected 'Racine externe acceptee.'
$discoveries[0].roots = @('services/app', 'services/worker')
$passed++
$dependencyMap = @{}
$dependencyMap[$plan.controls[0].id] = @($plan.controls[-1].id)
$dependencyPlan = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot -Dependencies $dependencyMap -GlobalTimeout 19 -MaxOutputBytes 4096
Assert-Compliance ($dependencyPlan.budgets.timeout_seconds -eq 19 -and $dependencyPlan.budgets.max_output_bytes_per_stream -eq 4096) 'Budgets du plan non serialises.'
$dependent = $dependencyPlan.controls | Where-Object id -eq $plan.controls[0].id
$prerequisite = $dependencyPlan.controls | Where-Object id -eq $plan.controls[-1].id
Assert-Compliance ($prerequisite.execution_order -lt $dependent.execution_order -and $dependent.dependencies -contains $prerequisite.id) 'Ordre topologique non applique.'
$cycle = @{}
$cycle[$plan.controls[0].id] = @($plan.controls[-1].id)
$cycle[$plan.controls[-1].id] = @($plan.controls[0].id)
$cycleRejected = $false
try { $null = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot -Dependencies $cycle }
catch { $cycleRejected = $_.Exception.Message -match 'cycle' }
Assert-Compliance $cycleRejected 'Cycle de dependances accepte.'
$missingDependencyRejected = $false
try { $null = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot -Dependencies @{ $plan.controls[0].id = @('control-absent') } }
catch { $missingDependencyRejected = $_.Exception.Message -match 'Prerequis absent' }
Assert-Compliance $missingDependencyRejected 'Dependance absente acceptee.'
$maximumControlsRejected = $false
try { $null = New-CompliancePlan -Discovery $discoveries -CapabilityMatrix $matrix -Resolver $resolver -RepositoryRoot $platformRoot -MaximumControls 1 }
catch { $maximumControlsRejected = $_.Exception.Message -match 'Limite du plan' }
Assert-Compliance $maximumControlsRejected 'Budget maximal de controles ignore.'
$passed++
$control = ($serialized.controls | Where-Object applicability -eq 'applicable' | Select-Object -First 1)
$control.root = '.'
$control.technology = 'python'
$control.tool.command = 'ruff'
$control.files = @('fixture.py')
$control.parameters = [pscustomobject]@{ arguments = @('check', '--no-cache') }
$executionPlan = [pscustomobject]@{ schema_version = 1; repository = $platformRoot; controls = @($control) }
$runner = {
    param($executable, $arguments, $root, $timeout)
    if (-not $executable -or $arguments.Count -eq 0 -or -not (Test-Path $root) -or $timeout -le 0 -or $timeout -gt 7) { throw 'Invocation mal construite.' }
    if ($arguments[0] -ne 'check' -or $arguments -notcontains '--no-cache' -or $arguments -notcontains (Join-Path $root 'fixture.py')) { throw 'Arguments Ruff concatenes ou perimetre incorrect.' }
    [pscustomobject]@{ execution_start = '2026-10-06T12:00:00Z'; execution_end = '2026-10-06T12:00:01Z'; duration_ms = 1000; stdout = 'sortie'; stderr = 'diagnostic'; exit_code = 0; error = $null; timed_out = $false }
}
$results = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $runner -PlatformRoot $platformRoot)
Assert-Compliance ($results[0].status -eq 'success' -and $results[0].stdout -eq 'sortie' -and $results[0].stderr -eq 'diagnostic' -and $results[0].tool_version -eq '1.0.0') 'Resultat normalise incorrect.'
Assert-Compliance ($results[0].control_catalog_id -eq $control.control_catalog_id -and $results[0].severity -eq $control.severity) 'Metadonnees catalogue absentes du resultat.'
$truncatingRunner = { param($executable, $arguments, $root, $timeout, $maxBytes) [pscustomobject]@{ exit_code = 0; stdout = 'borne'; stderr = ''; error = $null; timed_out = $false; output_truncated = $true } }
$truncatedResults = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $truncatingRunner -PlatformRoot $platformRoot)
Assert-Compliance ($truncatedResults[0].status -eq 'success' -and $truncatedResults[0].diagnostics[0].code -eq 'output_truncated') 'Troncature des diagnostics non restituee.'
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
$reportSchema = Get-Content -LiteralPath (Join-Path $platformRoot '.config/compliance-report.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
foreach ($field in @('findings', 'diagnostics', 'coverage', 'limitations', 'metadata', 'verdict')) {
    Assert-Compliance ($reportSchema.required -contains $field -and $roundTrip.PSObject.Properties.Name -contains $field) "Champ report/schema absent: $field"
}
$invalidReport = $roundTrip | ConvertTo-Json -Depth 20 | ConvertFrom-Json
$invalidReport.verdict = 'SUCCESS'
$schemaRejected = $false
try { Test-ComplianceReport -Report $invalidReport | Out-Null }
catch { $schemaRejected = $_.Exception.Message -match 'Verdict Compliance invalide' }
Assert-Compliance $schemaRejected 'Verdict non canonique accepte par le validateur.'
$invalidSummary = $roundTrip | ConvertTo-Json -Depth 20 | ConvertFrom-Json
$invalidSummary.summary.success++
$schemaRejected = $false
try { Test-ComplianceReport -Report $invalidSummary | Out-Null }
catch { $schemaRejected = $_.Exception.Message -match 'Resume Compliance incoherent' }
Assert-Compliance $schemaRejected 'Resume de rapport incoherent accepte.'
$passed++
$planned = New-ComplianceReport -Discovery $discoveryReport -Matrix @() -Resolver @() -Plan $executionPlan -Results @() -PlanOnly
Assert-Compliance ($null -eq $planned.verdict -and $planned.execution_status -eq 'planned') 'Un plan seul a produit un verdict de conformite.'
$passed++
$effectsDiscovery = @([pscustomobject]@{ technology = 'python'; status = 'detected'; roots = @('.'); ambiguities = @(); evidence = @('fixture.py') })
foreach ($command in @('pytest', 'pip-audit', 'pylint', 'pre-commit', 'checkov')) {
    $catalogControl = @($catalog.controls | Where-Object { $_.tool -and $_.tool.command -eq $command } | Select-Object -First 1)[0]
    $evidenceName = $catalogControl.applicability.evidence_extensions[0]
    $effectsDiscovery[0].evidence = @(if ($evidenceName.StartsWith('.')) { "fixture$evidenceName" } else { $evidenceName })
    $tool = [pscustomobject]@{ name = $catalogControl.tool.name; command = $command; source = 'fixture.exe'; version = '1.0.0'; status = 'available'; reason = ''; catalog_id = $catalogControl.id; severity = $catalogControl.severity; side_effect_level = $catalogControl.side_effect_level; permissions = $catalogControl.permissions; timeout_seconds = $catalogControl.timeout_seconds; cost = $catalogControl.cost; parameters = $catalogControl.parameters; dependencies = $catalogControl.dependencies }
    $effectsMatrix = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; capabilities = @([pscustomobject]@{ name = 'testing'; required = $true; selection_policy = $catalogControl.selection_policy; availability = 'available'; candidate_tools = @($tool); catalog_controls = @($catalogControl); reasons = @() }) })
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
    if (-not $executable -or $arguments[0] -ne '--version' -or -not (Test-Path $root) -or $timeout -le 0 -or $timeout -gt 7) { throw 'Sonde de version mal configuree.' }
    [pscustomobject]@{ execution_start = '2026-10-06T12:00:00Z'; execution_end = '2026-10-06T12:00:01Z'; duration_ms = 1000; stdout = 'partiel'; stderr = ''; exit_code = $null; error = 'Delai'; timed_out = $true }
}
$timedResults = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $timedRunner -PlatformRoot $platformRoot)
Assert-Compliance ($timedResults[0].status -eq 'error' -and $timedResults[0].diagnostics[0].code -eq 'timeout' -and $timedResults[0].stdout -eq 'partiel') 'Timeout de sonde mal normalise.'
$passed++
$globalControls = @()
foreach ($index in 1..2) {
    $copy = $control | ConvertTo-Json -Depth 8 | ConvertFrom-Json
    $copy.id = "global/$index"
    $copy.tool.version = '1.0.0'
    $copy.timeout = 5
    $copy.max_output_bytes = 4096
    $copy.dependencies = @()
    $copy.execution_order = $index
    $globalControls += $copy
}
$globalPlan = [pscustomobject]@{ repository = $platformRoot; budgets = [pscustomobject]@{ timeout_seconds = 1 }; controls = $globalControls }
$slowRunner = { param($executable, $arguments, $root, $timeout, $maxBytes) Start-Sleep -Milliseconds 1100; [pscustomobject]@{ exit_code = 0; stdout = ''; stderr = ''; error = $null; timed_out = $false } }
$globalResults = @(Invoke-CompliancePlan -Plan $globalPlan -ProcessRunner $slowRunner -PlatformRoot $platformRoot)
Assert-Compliance ($globalResults[0].status -eq 'success' -and $globalResults[1].status -eq 'error' -and $globalResults[1].diagnostics[0].code -eq 'global_timeout') 'Budget global non applique entre controles.'
$failedPlan = [pscustomobject]@{ repository = $platformRoot; controls = @($globalControls) }
$failedPlan.controls[0].dependencies = @()
$failedPlan.controls[1].dependencies = @($failedPlan.controls[0].id)
$script:dependencyRunnerCalls = 0
$failThenSuccess = { param($executable, $arguments, $root, $timeout, $maxBytes) $script:dependencyRunnerCalls++; [pscustomobject]@{ exit_code = if ($script:dependencyRunnerCalls -eq 1) { 1 } else { 0 }; stdout = ''; stderr = ''; error = $null; timed_out = $false } }
$failedDependencies = @(Invoke-CompliancePlan -Plan $failedPlan -ProcessRunner $failThenSuccess -PlatformRoot $platformRoot)
Assert-Compliance ($failedDependencies[0].status -eq 'fail' -and $failedDependencies[1].status -eq 'error' -and $failedDependencies[1].diagnostics[0].code -eq 'dependency_failed') 'Echec du prerequis non propage.'
$passed++
$primary = [pscustomobject]@{ name = 'ruff'; command = 'ruff'; source = 'fixture.exe'; version = '1.0.0'; status = 'available'; reason = ''; severity = 'medium'; side_effect_level = 'read_only'; permissions = @(); timeout_seconds = 7; cost = 'low'; parameters = [pscustomobject]@{ arguments = @('check', '--no-cache') }; dependencies = @() }
$effectsDiscovery[0].evidence = @('fixture.py')
$secondary = [pscustomobject]@{ name = 'fallback'; command = 'fallback'; source = $null; version = $null; status = 'not_installed'; reason = 'Alternative absente' }
$alternativeMatrix = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; capabilities = @([pscustomobject]@{ name = 'linting'; required = $true; selection_policy = 'alternative'; availability = 'available'; candidate_tools = @($primary, $secondary); reasons = @() }) })
$alternativeResolver = @([pscustomobject]@{ technology = 'python'; technology_status = 'detected'; selected_tools = @([pscustomobject]@{ command = 'ruff'; capabilities = @('linting'); source = 'fixture.exe' }) })
$alternativePlan = New-CompliancePlan -Discovery $effectsDiscovery -CapabilityMatrix $alternativeMatrix -Resolver $alternativeResolver -RepositoryRoot $platformRoot -Timeout 7
$discarded = $alternativePlan.controls | Where-Object { $_.tool.command -eq 'fallback' }
Assert-Compliance ($discarded.applicability -eq 'not_applicable' -and -not $discarded.required) 'Alternative ecartee rendue obligatoire.'
$alternativeResults = @(Invoke-CompliancePlan -Plan $alternativePlan -ProcessRunner $runner -PlatformRoot $platformRoot)
$alternativeReport = New-ComplianceReport -Discovery $discoveryReport -Matrix $alternativeMatrix -Resolver $alternativeResolver -Plan $alternativePlan -Results $alternativeResults
Assert-Compliance ($alternativeReport.verdict -eq 'PASS' -and $alternativeReport.coverage.complete) ("Alternative satisfaite rendue incomplete: " + ($alternativeReport | ConvertTo-Json -Depth 8 -Compress))
$passed++
$singleCatalogControl = $catalog.controls | Where-Object id -eq 'javascript.lint.unconfigured'
$singleCatalogCapability = [pscustomobject]@{ name = 'linting'; required = $true; availability = 'unconfigured'; candidate_tools = @(); catalog_controls = @($singleCatalogControl); reasons = @('Outil non configure') }
$singleCatalogDiscovery = @([pscustomobject]@{ technology = 'javascript'; status = 'detected'; roots = @('.'); evidence = @('app.js'); ambiguities = @() })
$singleCatalogMatrix = @([pscustomobject]@{ technology = 'javascript'; technology_status = 'detected'; capabilities = @($singleCatalogCapability) })
$singleCatalogResolver = @([pscustomobject]@{ technology = 'javascript'; technology_status = 'detected'; selected_tools = @() })
$singleCatalogPlan = New-CompliancePlan -Discovery $singleCatalogDiscovery -CapabilityMatrix $singleCatalogMatrix -Resolver $singleCatalogResolver -RepositoryRoot $platformRoot
Assert-Compliance ($singleCatalogPlan.controls[0].control_catalog_id -eq 'javascript.lint.unconfigured' -and $singleCatalogPlan.controls[0].applicability -eq 'capability_unavailable') 'Controle catalogue scalaire non projete dans le plan.'
$passed++
$prerequisiteControl = [pscustomobject]@{ id = 'fixture.quality.first'; name = 'First'; technology = 'fixture'; capability = 'quality'; tool = [pscustomobject]@{ name = 'first'; command = 'first' }; severity = 'medium'; side_effect_level = 'read_only'; permissions = @(); selection_policy = 'all'; dependencies = @(); timeout_seconds = 10; cost = 'low'; parameters = [pscustomobject]@{}; applicability = [pscustomobject]@{ evidence_extensions = @() } }
$dependentControl = [pscustomobject]@{ id = 'fixture.quality.second'; name = 'Second'; technology = 'fixture'; capability = 'quality'; tool = [pscustomobject]@{ name = 'second'; command = 'second' }; severity = 'high'; side_effect_level = 'read_only'; permissions = @(); selection_policy = 'all'; dependencies = @('fixture.quality.first'); timeout_seconds = 10; cost = 'low'; parameters = [pscustomobject]@{}; applicability = [pscustomobject]@{ evidence_extensions = @() } }
$catalogDependencyMatrix = @([pscustomobject]@{ technology = 'fixture'; technology_status = 'detected'; capabilities = @([pscustomobject]@{ name = 'quality'; required = $true; selection_policy = 'all'; availability = 'available'; catalog_controls = @($prerequisiteControl, $dependentControl); candidate_tools = @([pscustomobject]@{ name = 'first'; command = 'first'; source = 'first.exe'; version = '1.0.0'; status = 'available'; catalog_id = $prerequisiteControl.id; severity = 'medium'; side_effect_level = 'read_only'; permissions = @(); timeout_seconds = 10; cost = 'low'; parameters = [pscustomobject]@{}; dependencies = @() }, [pscustomobject]@{ name = 'second'; command = 'second'; source = 'second.exe'; version = '1.0.0'; status = 'available'; catalog_id = $dependentControl.id; severity = 'high'; side_effect_level = 'read_only'; permissions = @(); timeout_seconds = 10; cost = 'low'; parameters = [pscustomobject]@{}; dependencies = @($prerequisiteControl.id) }); reasons = @() }) })
$catalogDependencyDiscovery = @([pscustomobject]@{ technology = 'fixture'; status = 'detected'; roots = @('.'); evidence = @('input.fixture'); ambiguities = @() })
$catalogDependencyResolver = @([pscustomobject]@{ technology = 'fixture'; technology_status = 'detected'; selected_tools = @([pscustomobject]@{ command = 'first'; source = 'first.exe'; capabilities = @('quality') }, [pscustomobject]@{ command = 'second'; source = 'second.exe'; capabilities = @('quality') }) })
$catalogDependencyPlan = New-CompliancePlan -Discovery $catalogDependencyDiscovery -CapabilityMatrix $catalogDependencyMatrix -Resolver $catalogDependencyResolver -RepositoryRoot $platformRoot
$dependentInstance = $catalogDependencyPlan.controls | Where-Object control_catalog_id -eq $dependentControl.id
$prerequisiteInstance = $catalogDependencyPlan.controls | Where-Object control_catalog_id -eq $prerequisiteControl.id
Assert-Compliance ($dependentInstance.dependencies -contains $prerequisiteInstance.id -and $prerequisiteInstance.execution_order -lt $dependentInstance.execution_order) 'Dependance du catalogue non mappee sur les instances de controles.'
$passed++
$engineModule = Get-Module Compliance.Engine
$adapterRoot = Join-Path $platformRoot ('.tools/test-workspaces/adapters-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $adapterRoot -Force | Out-Null
try {
    foreach ($catalogControl in @($catalog.controls | Where-Object { $null -ne $_.tool })) {
        $evidence = @($catalogControl.applicability.evidence_extensions)
        $marker = if ($evidence.Count -gt 0) { $evidence[0] } else { 'fixture.py' }
        $relativeFile = if ($marker.StartsWith('.')) { "fixture$marker" } else { $marker }
        [IO.File]::WriteAllText((Join-Path $adapterRoot $relativeFile), "fixture`n", [Text.UTF8Encoding]::new($false))
        if ($catalogControl.tool.command -eq 'pip-audit') { [IO.File]::WriteAllText((Join-Path $adapterRoot 'requirements.txt'), "ruff==0.0.0`n", [Text.UTF8Encoding]::new($false)) }
        $source = if ($catalogControl.tool.command -eq 'checkov') { '.venv/Scripts/checkov.cmd' } else { 'fixture.exe' }
        $adapterControl = [pscustomobject]@{
            tool = [pscustomobject]@{ source = $source; command = $catalogControl.tool.command }
            technology = $catalogControl.technology
            capability = $catalogControl.capability
            root = '.'
            files = @($relativeFile)
            parameters = $catalogControl.parameters
        }
        $invocation = & $engineModule { param($control, $root, $platform) Get-ComplianceInvocation -Control $control -Root $root -PlatformRoot $platform -Repository $root } $adapterControl $adapterRoot $platformRoot
        Assert-Compliance ($invocation.executable -and @($invocation.arguments).Count -gt 0) "Adaptateur absent/incomplet pour $($catalogControl.id)"
    }
} finally { Remove-Item -LiteralPath $adapterRoot -Recurse -Force }
$passed++
Write-Information -InformationAction Continue "[SUMMARY] Compliance unit PASS=$passed FAIL=0"
