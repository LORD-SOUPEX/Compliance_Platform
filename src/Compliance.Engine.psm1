Set-StrictMode -Version Latest

function New-CompliancePlan {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Discovery,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$CapabilityMatrix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resolver,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [ValidateRange(1, 3600)][int]$Timeout = 300,
        [ValidateRange(1, 86400)][int]$GlobalTimeout = 1800,
        [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576,
        [ValidateRange(1, 5000)][int]$MaximumControls = 5000,
        [hashtable]$Dependencies = @{},
        [switch]$AllowNetwork,
        [switch]$AllowCodeExecution
    )
    if (-not $PSCmdlet.ShouldProcess($RepositoryRoot, 'Construire le plan Compliance en memoire')) { return }
    $repository = [IO.Path]::GetFullPath($RepositoryRoot)
    if ($repository -ne [IO.Path]::GetPathRoot($repository)) { $repository = $repository.TrimEnd('\', '/') }
    $prefix = $repository.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $controls = New-Object System.Collections.Generic.List[object]
    foreach ($technology in @($Discovery | Sort-Object technology)) {
        $matrixEntry = @($CapabilityMatrix | Where-Object technology -eq $technology.technology)
        $resolution = @($Resolver | Where-Object technology -eq $technology.technology)
        if ($matrixEntry.Count -ne 1 -or $resolution.Count -ne 1) { throw 'Discovery, Matrix et Resolver doivent correspondre par technologie.' }
        if ($technology.status -ne $matrixEntry[0].technology_status -or $technology.status -ne $resolution[0].technology_status) {
            throw 'Statuts de technologie incoherents entre les contrats.'
        }
        $roots = @($technology.roots | Sort-Object -Unique)
        if ($roots.Count -eq 0) { $roots = @('.') }
        foreach ($capability in @($matrixEntry[0].capabilities | Sort-Object name)) {
            $alternative = $capability.PSObject.Properties.Name -contains 'selection_policy' -and $capability.selection_policy -eq 'alternative'
            $hasAlternative = $alternative -and @($resolution[0].selected_tools | Where-Object { $_.capabilities -contains $capability.name }).Count -gt 0
            $candidates = @($capability.candidate_tools)
            if ($candidates.Count -eq 0) { $candidates = @($null) }
            foreach ($root in $roots) {
                if ([IO.Path]::IsPathRooted($root)) { throw 'Une racine de controle doit etre relative au depot.' }
                $absoluteRoot = [IO.Path]::GetFullPath((Join-Path $repository $root))
                if ($absoluteRoot -ne $repository -and -not $absoluteRoot.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    throw 'Une racine de controle sort du depot.'
                }
                foreach ($candidate in $candidates) {
                    $selected = @()
                    if ($candidate) {
                        $selected = @($resolution[0].selected_tools | Where-Object {
                            $_.command -eq $candidate.command -and $_.capabilities -contains $capability.name
                        })
                        if ($selected.Count -gt 1 -or ($selected.Count -eq 1 -and $selected[0].source -ne $candidate.source)) { throw 'Sources de selection incoherentes entre Matrix et Resolver.' }
                    }
                    $reason = ''
                    $applicability = if ($technology.status -eq 'absent') { 'technology_absent' }
                        elseif ($technology.status -eq 'ambiguous') { 'ambiguous' }
                        elseif (-not $capability.required) { 'not_applicable' }
                        elseif ($hasAlternative -and $selected.Count -eq 0) { 'not_applicable' }
                        elseif (-not $candidate -or $capability.availability -in @('unavailable', 'unconfigured')) { 'capability_unavailable' }
                        elseif ($candidate.status -ne 'available') { 'tool_unavailable' }
                        elseif ($selected.Count -eq 0) { 'not_applicable' }
                        else { 'applicable' }
                    if ($candidate -and $candidate.PSObject.Properties.Name -contains 'reason') { $reason = $candidate.reason }
                    if ($applicability -eq 'not_applicable') { $reason = 'Capacite non requise ou candidat non retenu par le resolver.' }
                    if ($applicability -eq 'ambiguous') { $reason = @($technology.ambiguities) -join '; ' }
                    if ($applicability -eq 'capability_unavailable') { $reason = @($capability.reasons) -join '; ' }
                    $command = if ($candidate) { $candidate.command } else { 'none' }
                    $catalogControls = if ($capability.PSObject.Properties.Name -contains 'catalog_controls') { @($capability.catalog_controls) } else { @() }
                    $catalogControlCount = @($catalogControls).Count
                    $catalogControl = if ($candidate -and $candidate.PSObject.Properties.Name -contains 'catalog_id') { $catalogControls | Where-Object id -eq $candidate.catalog_id | Select-Object -First 1 } else { $null }
                    if (-not $catalogControl -and -not $candidate -and $catalogControlCount -eq 1) { $catalogControl = @($catalogControls)[0] }
                    $evidence = if ($technology.PSObject.Properties.Name -contains 'evidence') { @($technology.evidence) } else { @() }
                    $rootEvidence = if ($root -eq '.') { $evidence } else { @($evidence | Where-Object { $_.StartsWith($root.TrimEnd('/') + '/', [StringComparison]::OrdinalIgnoreCase) }) }
                    $evidenceExtensions = if ($catalogControl) { @($catalogControl.applicability.evidence_extensions) } else { @() }
                    $evidenceMatches = @($evidenceExtensions).Count -eq 0 -or @($rootEvidence | Where-Object {
                        $evidenceName = [IO.Path]::GetFileName($_)
                        $evidenceExtension = [IO.Path]::GetExtension($_)
                        $evidenceExtensions -contains $evidenceName -or $evidenceExtensions -contains $evidenceExtension
                    }).Count -gt 0
                    if (-not $evidenceMatches -and $catalogControl) {
                        foreach ($marker in $evidenceExtensions | Where-Object { -not $_.StartsWith('.') }) {
                            if (Test-Path -LiteralPath (Join-Path $absoluteRoot $marker) -PathType Leaf) { $evidenceMatches = $true; break }
                        }
                    }
                    if ($applicability -eq 'applicable' -and -not $evidenceMatches) {
                        $applicability = 'not_applicable'
                        $reason = 'Aucune preuve du catalogue ne correspond a cette racine.'
                    }
                    $metadata = if ($candidate -and $candidate.PSObject.Properties.Name -contains 'severity') { $candidate } else { $catalogControl }
                    $sideEffect = if ($metadata) { $metadata.side_effect_level } else { 'read_only' }
                    $controlTimeout = if ($metadata) { [Math]::Min($Timeout, $metadata.timeout_seconds) } else { $Timeout }
                    $catalogDependencies = if ($metadata) { @($metadata.dependencies) } else { @() }
                    $permissions = if ($metadata) { @($metadata.permissions) } else { @() }
                    $catalogLimitations = if ($metadata -and $metadata.PSObject.Properties.Name -contains 'limitations') { @($metadata.limitations) } else { @() }
                    $platformSupport = if ($metadata -and $metadata.PSObject.Properties.Name -contains 'platform_support') { @($metadata.platform_support) } else { @() }
                    $severity = if ($metadata) { $metadata.severity } else { 'medium' }
                    $cost = if ($metadata) { $metadata.cost } else { 'low' }
                    $parameters = if ($metadata) { $metadata.parameters } else { [pscustomobject]@{} }
                    if ($applicability -eq 'applicable' -and (($sideEffect -in @('network', 'network_code_execution') -and -not $AllowNetwork) -or ($sideEffect -in @('code_execution', 'network_code_execution') -and -not $AllowCodeExecution))) {
                        $applicability = 'not_applicable'
                        $reason = "Effet $sideEffect non autorise pour cette execution."
                    }
                    $controlId = "$($technology.technology)/$($capability.name)/$command/$root"
                    if (@($controls | Where-Object id -eq $controlId).Count -gt 0) { throw "Identifiant de controle duplique: $controlId" }
                    $controls.Add([pscustomobject]@{
                        id = $controlId
                        name = "$($technology.technology): $($capability.name) ($command)"
                        technology = $technology.technology
                        capability = $capability.name
                        tool = $candidate
                        control_catalog_id = if ($catalogControl) { $catalogControl.id } elseif ($candidate -and $candidate.PSObject.Properties.Name -contains 'catalog_id') { $candidate.catalog_id } else { $null }
                        root = $root
                        applicability = $applicability
                        execution_order = $controls.Count + 1
                        timeout = $controlTimeout
                        max_output_bytes = $MaxOutputBytes
                        dependencies = @()
                        catalog_dependencies = @($catalogDependencies)
                        side_effect_level = $sideEffect
                        severity = $severity
                        cost = $cost
                        permissions = @($permissions)
                        platform_support = @($platformSupport)
                        limitations = @($catalogLimitations)
                        parameters = $parameters
                        required = ([bool]$capability.required -and -not ($hasAlternative -and $selected.Count -eq 0))
                        reason = $reason
                        files = if ($technology.PSObject.Properties.Name -contains 'evidence') { @($technology.evidence) } else { @() }
                    })
                }
            }
        }
    }
    if ($controls.Count -gt $MaximumControls) { throw "Limite du plan depassee: $MaximumControls controles maximum." }
    $controlsById = @{}
    foreach ($control in $controls) { $controlsById[$control.id] = $control }
    foreach ($control in $controls) {
        foreach ($dependencyCatalogId in @($control.catalog_dependencies)) {
            $prerequisite = @($controls | Where-Object { $_.technology -eq $control.technology -and $_.root -eq $control.root -and $_.control_catalog_id -eq $dependencyCatalogId })
            if ($prerequisite.Count -ne 1) { throw "Prerequis catalogue absent ou ambigu: $dependencyCatalogId pour $($control.id)" }
            $control.dependencies += $prerequisite[0].id
        }
        $control.dependencies = @($control.dependencies | Sort-Object -Unique)
    }
    foreach ($controlId in $Dependencies.Keys) {
        if (-not $controlsById.ContainsKey($controlId)) { throw "Dependance configuree sur un controle absent: $controlId" }
        foreach ($prerequisite in @($Dependencies[$controlId])) {
            if (-not $controlsById.ContainsKey($prerequisite)) { throw "Prerequis absent du plan: $prerequisite" }
            if ($prerequisite -eq $controlId) { throw "Dependance cyclique sur le controle: $controlId" }
        }
        $controlsById[$controlId].dependencies = @($Dependencies[$controlId] | Sort-Object -Unique)
    }
    $indegree = @{}
    $dependents = @{}
    foreach ($control in $controls) {
        $indegree[$control.id] = $control.dependencies.Count
        foreach ($dependency in $control.dependencies) {
            if (-not $dependents.ContainsKey($dependency)) { $dependents[$dependency] = New-Object System.Collections.Generic.List[string] }
            $dependents[$dependency].Add($control.id)
        }
    }
    $ready = New-Object System.Collections.Generic.List[object]
    foreach ($control in $controls) { if ($indegree[$control.id] -eq 0) { $ready.Add($control) } }
    $ordered = New-Object System.Collections.Generic.List[object]
    while ($ready.Count -gt 0) {
        $next = $ready | Sort-Object execution_order | Select-Object -First 1
        $null = $ready.Remove($next)
        $ordered.Add($next)
        if ($dependents.ContainsKey($next.id)) {
            foreach ($dependent in $dependents[$next.id]) {
                $indegree[$dependent]--
                if ($indegree[$dependent] -eq 0) { $ready.Add($controlsById[$dependent]) }
            }
        }
    }
    if ($ordered.Count -ne $controls.Count) { throw 'Le plan contient un cycle de dependances.' }
    for ($index = 0; $index -lt $ordered.Count; $index++) { $ordered[$index].execution_order = $index + 1 }
    return [pscustomobject]@{
        schema_version = 1
        repository = $repository
        budgets = [pscustomobject]@{ timeout_seconds = $GlobalTimeout; max_output_bytes_per_stream = $MaxOutputBytes; max_controls = $MaximumControls }
        permissions = [pscustomobject]@{ network = [bool]$AllowNetwork; code_execution = [bool]$AllowCodeExecution }
        controls = @($ordered.ToArray())
    }
}

function Get-ComplianceInvocation {
    param([pscustomobject]$Control, [string]$Root, [string]$PlatformRoot, [string]$Repository)
    $executable = $Control.tool.source
    if ([string]::IsNullOrWhiteSpace($executable)) { throw 'Source executable absente du plan.' }
    $arguments = @()
    [string[]]$catalogArguments = @()
    $catalogArgumentCount = 0
    if ($Control.parameters) {
        foreach ($parameter in $Control.parameters.PSObject.Properties) {
            if ($parameter.Name -eq 'arguments') {
                $catalogArgumentCount = ($parameter.Value | Measure-Object).Count
                $catalogArguments = @($parameter.Value)
                break
            }
        }
    }
    [string[]]$files = @($Control.files | ForEach-Object {
        $path = [IO.Path]::GetFullPath((Join-Path $Repository $_))
        $prefix = $Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $path }
    })
    switch ($Control.tool.command) {
        'ruff' {
            [string[]]$pythonFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' })
            if (@($pythonFiles).Count -eq 0) { throw 'Aucune source Python pour Ruff.' }
            if ($catalogArgumentCount -eq 0) { throw 'Arguments Ruff absents du catalogue.' }
            $arguments = @($catalogArguments) + $pythonFiles
        }
        'pylint' { [string[]]$pythonFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' }); if (@($pythonFiles).Count -eq 0) { throw 'Aucune source Python pour Pylint.' }; $arguments = @($catalogArguments) + $pythonFiles }
        'bandit' {
            [string[]]$pythonFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' })
            if (@($pythonFiles).Count -eq 0) { throw 'Aucune source Python pour Bandit.' }
            $arguments = @($catalogArguments) + $pythonFiles
        }
        'pytest' { $arguments = @($catalogArguments) + @($Root) }
        'pip-audit' {
            $requirements = Join-Path $Root 'requirements.txt'
            if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) { throw 'Audit consommateur: requirements.txt requis; le runtime de la plateforme n est pas audite a sa place.' }
            $arguments = @($catalogArguments) + @('-r', $requirements)
        }
        'terraform' { $arguments = @($catalogArguments) }
        'tofu' { $arguments = @($catalogArguments) }
        'terragrunt' { $arguments = @($catalogArguments) }
        'tflint' { $arguments = @($catalogArguments) }
        'shellcheck' { [string[]]$shellFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.sh' }); if (@($shellFiles).Count -eq 0) { throw 'Aucun script Shell pour ShellCheck.' }; $arguments = @($catalogArguments) + $shellFiles }
        'hadolint' { [string[]]$containerFiles = @($files | Where-Object { [IO.Path]::GetFileName($_) -match '^(Dockerfile|Containerfile)(\..+)?$' }); if (@($containerFiles).Count -eq 0) { throw 'Validation Compose non implementee par Hadolint.' }; $arguments = $containerFiles }
        'ansible-lint' { $arguments = @($catalogArguments) + @($Root) }
        'yamllint' { $arguments = @('-c', (Join-Path $PlatformRoot $Control.parameters.configuration), $Root) }
        'pre-commit' {
            $arguments = @('run', $Control.parameters.hook, '--config', (Join-Path $PlatformRoot '.pre-commit-config.yaml'), '--files') + @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.md' })
            if (@($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.md' }).Count -eq 0) { throw 'Aucun fichier Markdown pour le controle.' }
        }
        'checkov' {
            $framework = $Control.parameters.framework
            if (-not $framework) { throw 'Framework Checkov absent du catalogue.' }
            $arguments = @('-d', $Root, '--framework', $framework, '--quiet')
            if ([IO.Path]::GetExtension($executable) -eq '.cmd') {
                $arguments = @('-x', $executable) + $arguments
                $executable = Join-Path $PlatformRoot '.venv/Scripts/python.exe'
            }
        }
        'trivy' { $arguments = @('fs', '--scanners', (@($Control.parameters.scanners) -join ','), '--exit-code', '1', '--no-progress', '--skip-dirs', '.git', '--skip-dirs', '.venv', '--skip-dirs', '.tools', '--skip-dirs', 'reports', $Root) }
        'Invoke-ScriptAnalyzer' {
            if (@($files).Count -eq 0) { throw 'Aucun fichier PowerShell pour le controle.' }
            $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PlatformRoot 'scripts/invoke-compliance-powershell.ps1'), '-ModulePath', $executable, '-SettingsPath', (Join-Path $PlatformRoot $Control.parameters.settings), '-FilesJson', (ConvertTo-Json -InputObject $files -Compress))
            $executable = Join-Path $PSHOME 'powershell.exe'
        }
        default { throw "Adaptateur de controle non implemente: $($Control.tool.command)" }
    }
    return [pscustomobject]@{ executable = $executable; arguments = @($arguments) }
}

function New-ComplianceResult {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([pscustomobject]$Control)
    if (-not $PSCmdlet.ShouldProcess($Control.id, 'Construire le resultat Compliance en memoire')) { return }
    $now = [DateTimeOffset]::UtcNow.ToString('o')
    $version = if ($Control.tool -and $Control.tool.PSObject.Properties.Name -contains 'version') { $Control.tool.version } else { $null }
    return [pscustomobject]@{
        control_id = $Control.id
        control_catalog_id = if ($Control.PSObject.Properties.Name -contains 'control_catalog_id') { $Control.control_catalog_id } else { $null }
        name = if ($Control.PSObject.Properties.Name -contains 'name') { $Control.name } else { $Control.id }
        technology = $Control.technology
        capability = $Control.capability
        root = $Control.root
        severity = if ($Control.PSObject.Properties.Name -contains 'severity') { $Control.severity } else { 'medium' }
        status = 'skipped'
        execution_start = $now
        execution_end = $now
        duration_ms = 0
        tool_version = $version
        stdout = ''
        stderr = ''
        exit_code = $null
        output_truncated = $false
        critical = $false
        diagnostics = @()
    }
}

function Invoke-CompliancePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][scriptblock]$ProcessRunner,
        [Parameter(Mandatory = $true)][string]$PlatformRoot,
        [int]$GlobalTimeout = 0
    )
    if ($GlobalTimeout -eq 0) { $GlobalTimeout = if ($Plan.PSObject.Properties.Name -contains 'budgets') { $Plan.budgets.timeout_seconds } else { 1800 } }
    if ($GlobalTimeout -lt 1 -or $GlobalTimeout -gt 86400) { throw 'Budget global hors limites.' }
    $planTimer = [Diagnostics.Stopwatch]::StartNew()
    $completed = @{}
    foreach ($control in @($Plan.controls | Sort-Object execution_order)) {
        $controlTimer = [Diagnostics.Stopwatch]::StartNew()
        $result = New-ComplianceResult -Control $control
        $dependencies = if ($control.PSObject.Properties.Name -contains 'dependencies') { @($control.dependencies) } else { @() }
        $failedDependencies = @($dependencies | Where-Object { -not $completed.ContainsKey($_) -or $completed[$_].status -ne 'success' })
        if ($control.applicability -eq 'applicable' -and $failedDependencies.Count -gt 0) {
            if ($control.required) { $result.status = 'error'; $result.critical = $true } else { $result.status = 'skipped' }
            $result.diagnostics = @([pscustomobject]@{ code = 'dependency_failed'; message = "Prerequis non satisfaits: $($failedDependencies -join ', ')"; critical = $result.critical })
        } elseif ($control.applicability -eq 'applicable' -and $planTimer.Elapsed.TotalSeconds -ge $GlobalTimeout) {
            $result.status = 'error'
            $result.critical = [bool]$control.required
            $result.diagnostics = @([pscustomobject]@{ code = 'global_timeout'; message = "Budget global depasse: $GlobalTimeout secondes."; critical = $result.critical })
        } elseif ($control.applicability -ne 'applicable') {
            if ($control.applicability -eq 'ambiguous' -or ($control.required -and $control.applicability -in @('capability_unavailable', 'tool_unavailable'))) {
                $result.status = 'error'
                $result.critical = $true
            }
            $result.diagnostics = @([pscustomobject]@{ code = $control.applicability; message = $control.reason; critical = $result.critical })
        } else {
            try {
                $root = [IO.Path]::GetFullPath((Join-Path $Plan.repository $control.root))
                $prefix = $Plan.repository.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                if ($root -ne $Plan.repository -and -not $root.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Racine d execution hors depot.' }
                if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Racine d execution absente.' }
                $invocation = Get-ComplianceInvocation -Control $control -Root $root -PlatformRoot $PlatformRoot -Repository $Plan.repository
                $remaining = [Math]::Min(($control.timeout - $controlTimer.Elapsed.TotalSeconds), ($GlobalTimeout - $planTimer.Elapsed.TotalSeconds))
                if ($remaining -le 0) { throw [TimeoutException]::new('Budget du controle depasse avant execution.') }
                if ([string]::IsNullOrWhiteSpace($result.tool_version)) {
                    $versionArguments = if ($control.tool.command -eq 'checkov' -and [IO.Path]::GetExtension($control.tool.source) -eq '.cmd') { @('-x', $control.tool.source, '--version') } else { @('--version') }
                    $probe = & $ProcessRunner $invocation.executable @($versionArguments) $root $remaining $control.max_output_bytes
                    if ($probe -and $probe.timed_out) {
                        $result.stdout = $probe.stdout
                        $result.stderr = $probe.stderr
                        throw [TimeoutException]::new('Delai depasse pendant la verification de version.')
                    }
                    if (-not $probe -or $probe.error -or $probe.exit_code -ne 0) { throw 'Verification de version de l outil impossible avant execution.' }
                    $versionMatch = [regex]::Match(($probe.stdout + $probe.stderr), '\b\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9.+-]*)')
                    if (-not $versionMatch.Success) { throw 'Version de l outil non identifiable.' }
                    $result.tool_version = $versionMatch.Value
                }
                $remaining = [Math]::Min(($control.timeout - $controlTimer.Elapsed.TotalSeconds), ($GlobalTimeout - $planTimer.Elapsed.TotalSeconds))
                if ($remaining -le 0) { throw [TimeoutException]::new('Budget du controle depasse avant execution.') }
                $execution = & $ProcessRunner $invocation.executable @($invocation.arguments) $root $remaining $control.max_output_bytes
                if (-not $execution) { throw 'Executeur sans resultat.' }
                foreach ($property in @('stdout', 'stderr', 'exit_code', 'output_truncated')) {
                    if ($execution.PSObject.Properties.Name -contains $property) { $result.$property = $execution.$property }
                }
                if ($result.output_truncated) { $result.diagnostics += [pscustomobject]@{ code = 'output_truncated'; message = 'Sorties tronquees par la limite de capture du controle.'; critical = $false } }
                if ($execution.error) {
                    $result.status = 'error'
                    $result.critical = [bool]$control.required
                    $result.diagnostics = @([pscustomobject]@{ code = if ($execution.timed_out) { 'timeout' } else { 'process_error' }; message = $execution.error; critical = $result.critical })
                } elseif ($null -eq $execution.exit_code) { throw 'Code de sortie absent du resultat de processus.' }
                elseif ($execution.exit_code -eq 0) { $result.status = 'success' }
                else {
                    $result.status = 'fail'
                    $result.diagnostics = @([pscustomobject]@{ code = 'exit_nonzero'; message = "Controle en echec (code $($execution.exit_code))."; critical = $false })
                }
            } catch {
                $result.status = 'error'
                $result.critical = [bool]$control.required
                $result.execution_end = [DateTimeOffset]::UtcNow.ToString('o')
                $result.diagnostics = @([pscustomobject]@{ code = if ($_.Exception -is [TimeoutException]) { 'timeout' } else { 'execution_error' }; message = $_.Exception.Message; critical = $result.critical })
            }
        }
        $controlTimer.Stop()
        $result.execution_end = [DateTimeOffset]::UtcNow.ToString('o')
        $result.duration_ms = $controlTimer.ElapsedMilliseconds
        $completed[$control.id] = $result
        $result
    }
    $planTimer.Stop()
}

function Get-ComplianceVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results, [bool]$ScanComplete = $true)
    $summary = [pscustomobject]@{
        success = @($Results | Where-Object status -eq 'success').Count
        fail = @($Results | Where-Object status -eq 'fail').Count
        error = @($Results | Where-Object status -eq 'error').Count
        skipped = @($Results | Where-Object status -eq 'skipped').Count
        critical_errors = @($Results | Where-Object { $_.status -eq 'error' -and $_.critical }).Count
    }
    $reasons = @()
    if (-not $ScanComplete) { $summary.critical_errors++; $reasons += 'Scan incomplet: erreur critique de preparation.' }
    if ($summary.fail -gt 0) { $reasons += 'Au moins un controle de conformite echoue.' }
    if ($summary.critical_errors -gt 0) { $reasons += 'Au moins une erreur critique empeche une evaluation complete.' }
    return [pscustomobject]@{ verdict = if ($summary.fail -gt 0 -or $summary.critical_errors -gt 0) { 'FAIL' } else { 'PASS' }; summary = $summary; reasons = @($reasons) }
}

function ConvertTo-ComplianceReportFromChecks {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object[]]$Checks,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][pscustomobject]$Discovery,
        [Parameter(Mandatory = $true)][object[]]$Matrix,
        [Parameter(Mandatory = $true)][object[]]$Resolver,
        [Parameter(Mandatory = $true)][string]$Mode,
        [string]$CatalogSha256 = $null,
        [string]$PlatformQualificationStatus = $null
    )
    $normalized = New-Object System.Collections.Generic.List[object]
    $controls = New-Object System.Collections.Generic.List[object]
    foreach ($check in $Checks) {
        $index = $normalized.Count + 1
        $status = switch ($check.statut) {
            'PASS' { 'success' }
            'FAIL' { 'fail' }
            'ERROR' { 'error' }
            default { 'skipped' }
        }
        $critical = ($check.statut -eq 'ERROR')
        $duration = [Math]::Max(0, [long]$check.duree_ms)
        $ended = [DateTimeOffset]::UtcNow
        $started = $ended.AddMilliseconds(-$duration)
        $diagnostics = @()
        if ($check.statut -in @('FAIL', 'ERROR', 'WARN', 'SKIP')) {
            $diagnosticCode = switch ($check.statut) { 'FAIL' { 'legacy_noncompliance' }; 'ERROR' { 'legacy_technical_error' }; 'WARN' { 'legacy_warning' }; default { 'legacy_skipped' } }
            $diagnostics = @([pscustomobject]@{ code = $diagnosticCode; message = $check.message; critical = $critical })
        }
        $controlId = 'legacy/{0}/{1}' -f $index, ([string]$check.nom -replace '[^a-zA-Z0-9._-]', '-')
        $controls.Add([pscustomobject]@{
            id = $controlId
            control_catalog_id = $null
            name = $check.nom
            technology = 'legacy'
            capability = 'legacy-check'
            tool = $null
            root = '.'
            applicability = if ($status -eq 'skipped') { 'not_applicable' } else { 'applicable' }
            execution_order = $index
            timeout = 0
            max_output_bytes = 0
            dependencies = @()
            side_effect_level = 'unknown'
            severity = 'medium'
            cost = 'unknown'
            permissions = @()
            parameters = [pscustomobject]@{}
            required = ($status -ne 'skipped')
            reason = $check.message
            files = @()
        })
        $normalized.Add([pscustomobject]@{
            control_id = $controlId
            control_catalog_id = $null
            name = $check.nom
            technology = 'legacy'
            capability = 'legacy-check'
            root = '.'
            severity = 'medium'
            status = $status
            execution_start = $started.ToString('o')
            execution_end = $ended.ToString('o')
            duration_ms = $duration
            tool_version = $null
            stdout = ''
            stderr = ''
            exit_code = if ($status -eq 'success') { 0 } elseif ($status -in @('fail', 'error')) { 1 } else { $null }
            output_truncated = $false
            critical = $critical
            diagnostics = $diagnostics
        })
    }
    $plan = [pscustomobject]@{
        schema_version = 1
        repository = [IO.Path]::GetFullPath($RepositoryRoot)
        budgets = [pscustomobject]@{ timeout_seconds = 0; max_output_bytes_per_stream = 0; max_controls = $controls.Count }
        permissions = [pscustomobject]@{ network = $false; code_execution = $false }
        controls = @($controls.ToArray())
    }
    return New-ComplianceReport -Discovery $Discovery -Matrix $Matrix -Resolver $Resolver -Plan $plan -Results @($normalized.ToArray()) -SourceMode $Mode -CatalogSha256 $CatalogSha256 -PlatformQualificationStatus $PlatformQualificationStatus
}

function Test-ComplianceReport {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][pscustomobject]$Report)
    $requiredFields = @('schema_version', 'engine_version', 'generated_at', 'metadata', 'repository', 'execution_status', 'discovery', 'matrix', 'resolver', 'execution_plan', 'execution_results', 'findings', 'diagnostics', 'summary', 'coverage', 'limitations', 'verdict', 'verdict_reasons', 'advisory')
    foreach ($field in $requiredFields) {
        if ($Report.PSObject.Properties.Name -notcontains $field) { throw "Champ Compliance report absent: $field" }
    }
    foreach ($field in @('run_id', 'source_mode', 'source_adapter', 'platform', 'catalog_schema_version', 'network_authorized', 'code_execution_authorized')) {
        if ($Report.metadata.PSObject.Properties.Name -notcontains $field) { throw "Metadata Compliance absente: $field" }
    }
    if ($Report.metadata.PSObject.Properties.Name -contains 'catalog_sha256' -and $null -ne $Report.metadata.catalog_sha256 -and ($Report.metadata.catalog_sha256 -isnot [string] -or $Report.metadata.catalog_sha256 -notmatch '^[a-f0-9]{64}$')) { throw 'Empreinte Control Catalog invalide.' }
    if ($Report.metadata.PSObject.Properties.Name -contains 'platform_qualification_status' -and $null -ne $Report.metadata.platform_qualification_status -and $Report.metadata.platform_qualification_status -notin @('targeted', 'experimental', 'qualified')) { throw 'Statut de qualification plateforme invalide.' }
    if ($Report.schema_version -ne 1 -or $Report.execution_status -notin @('planned', 'completed', 'blocked', 'error')) { throw 'Version ou execution_status Compliance invalide.' }
    if ($Report.verdict -notin @('PASS', 'FAIL', $null)) { throw 'Verdict Compliance invalide.' }
    $generatedAt = [DateTimeOffset]::MinValue
    if (-not [DateTimeOffset]::TryParse($Report.generated_at, [ref]$generatedAt)) { throw 'generated_at Compliance invalide.' }
    if ($Report.execution_status -eq 'planned' -and $null -ne $Report.verdict) { throw 'Un plan seul ne peut pas porter un verdict.' }
    foreach ($result in $Report.execution_results) {
        if ($result.status -notin @('success', 'fail', 'error', 'skipped')) { throw "Statut resultat invalide: $($result.control_id)" }
        if ($result.severity -notin @('low', 'medium', 'high', 'critical')) { throw "Severite resultat invalide: $($result.control_id)" }
        if ($result.duration_ms -lt 0 -or -not $result.execution_start -or -not $result.execution_end) { throw "Metadonnees temporelles resultat invalides: $($result.control_id)" }
        if ($result.status -in @('fail', 'error') -and @($Report.findings | Where-Object control_id -eq $result.control_id).Count -eq 0) { throw "Finding absent pour le resultat $($result.control_id)" }
    }
    foreach ($finding in $Report.findings) {
        $findingDiagnosticCount = @($finding.diagnostics).Count
        if ($finding.status -notin @('fail', 'error') -or $finding.severity -notin @('low', 'medium', 'high', 'critical') -or $findingDiagnosticCount -eq 0) { throw "Finding Compliance invalide: $($finding.control_id); status=$($finding.status); severity=$($finding.severity); diagnostics=$findingDiagnosticCount" }
    }
    if ($Report.coverage.planned_controls -ne $Report.execution_plan.controls.Count) { throw 'Coverage/planned_controls incoherent.' }
    $expectedSummary = Get-ComplianceVerdict -Results $Report.execution_results -ScanComplete ($Report.discovery.scan_complete -ne $false)
    foreach ($field in @('success', 'fail', 'error', 'skipped', 'critical_errors')) {
        if ($Report.summary.$field -ne $expectedSummary.summary.$field) { throw 'Resume Compliance incoherent avec les resultats.' }
    }
    $expectedFindings = @($Report.execution_results | Where-Object status -in @('fail', 'error')).Count
    if ($Report.discovery.PSObject.Properties.Name -contains 'scan_complete' -and -not $Report.discovery.scan_complete) {
        $expectedFindings += if ($Report.discovery.PSObject.Properties.Name -contains 'scan_errors') { @($Report.discovery.scan_errors).Count } else { 0 }
    }
    if (@($Report.findings).Count -ne $expectedFindings) { throw 'Findings Compliance incoherents avec les resultats et Discovery.' }
    if ($Report.execution_status -ne 'planned') {
        $expectedVerdict = if ($Report.summary.fail -gt 0 -or $Report.summary.critical_errors -gt 0) { 'FAIL' } else { 'PASS' }
        if ($Report.verdict -ne $expectedVerdict) { throw 'Verdict Compliance incoherent avec le resume.' }
    }
    return $true
}

function New-ComplianceReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Discovery,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Matrix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resolver,
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results,
        [switch]$PlanOnly,
        [string]$SourceMode = 'Compliance',
        [ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab', 'Legacy')][string]$SourceAdapter = 'PowerShell',
        [string]$CatalogSha256 = $null,
        [string]$PlatformQualificationStatus = $null
    )
    if (-not $PSCmdlet.ShouldProcess($Plan.repository, 'Construire le rapport Compliance en memoire')) { return }
    $discoveryScanComplete = if ($Discovery.PSObject.Properties.Name -contains 'scan_complete') { [bool]$Discovery.scan_complete } else { $true }
    $discoveryScanErrors = if ($Discovery.PSObject.Properties.Name -contains 'scan_errors') { @($Discovery.scan_errors) } else { @() }
    $normalizedResults = @($Results)
    if (-not $PlanOnly -and $discoveryScanComplete) {
        foreach ($control in $Plan.controls) {
            $matching = @($Results | Where-Object control_id -eq $control.id)
            if ($matching.Count -ne 1) {
                $missing = New-ComplianceResult -Control $control
                $missing.status = 'error'
                $missing.critical = $true
                $missing.diagnostics = @([pscustomobject]@{ code = 'result_contract_error'; message = 'Resultat manquant ou duplique pour un controle du plan.'; critical = $true })
                $normalizedResults += $missing
            }
        }
    }
    $scanDiagnostics = @()
    $scanFindings = @()
    if (-not $discoveryScanComplete) {
        foreach ($scanError in $discoveryScanErrors) {
            $scanDiagnostic = [pscustomobject]@{
                control_id = 'engine/discovery'
                code = "scan_$($scanError.operation)_failed"
                severity = 'critical'
                critical = $true
                message = $scanError.message
                path = $scanError.path
            }
            $scanDiagnostics += $scanDiagnostic
            $scanFindings += [pscustomobject]@{
                id = "engine/discovery/$($scanError.operation)/$($scanError.path)"
                control_id = 'engine/discovery'
                name = 'Discovery scan error'
                technology = 'engine'
                capability = 'discovery'
                root = [IO.Path]::GetDirectoryName($scanError.path)
                severity = 'critical'
                status = 'error'
                diagnostics = @($scanDiagnostic)
            }
        }
    }
    $decision = Get-ComplianceVerdict -Results $normalizedResults -ScanComplete $discoveryScanComplete
    $omitted = @($Plan.controls | Where-Object { $_.required -and $_.applicability -eq 'not_applicable' })
    $dependencySkips = @($normalizedResults | Where-Object {
        @($_.diagnostics | Where-Object { $_.PSObject.Properties.Name -contains 'code' -and $_.code -eq 'dependency_failed' }).Count -gt 0
    }).Count
    $findings = @($normalizedResults | Where-Object status -in @('fail', 'error') | ForEach-Object {
        [pscustomobject]@{
            id = $_.control_catalog_id
            control_id = $_.control_id
            name = $_.name
            technology = $_.technology
            capability = $_.capability
            root = $_.root
            severity = $_.severity
            status = $_.status
            diagnostics = @($_.diagnostics)
        }
    })
    $findings += $scanFindings
    $diagnostics = @($normalizedResults | ForEach-Object {
        $result = $_
        foreach ($diagnostic in @($result.diagnostics)) {
            [pscustomobject]@{
                control_id = $result.control_id
                code = $diagnostic.code
                severity = $result.severity
                critical = [bool]$diagnostic.critical
                message = $diagnostic.message
            }
        }
    })
    $diagnostics += $scanDiagnostics
    $limitations = @($Plan.controls | Where-Object { $_.applicability -ne 'applicable' } | ForEach-Object {
        [pscustomobject]@{ control_id = $_.id; status = $_.applicability; reason = $_.reason }
    })
    $limitations += @($Plan.controls | Where-Object { $_.PSObject.Properties.Name -contains 'limitations' -and @($_.limitations).Count -gt 0 } | ForEach-Object {
        [pscustomobject]@{ control_id = $_.id; status = 'catalog_limit'; reason = @($_.limitations) -join '; '; platforms = if ($_.PSObject.Properties.Name -contains 'platform_support') { @($_.platform_support) } else { @() } }
    })
    $limitations += @($normalizedResults | Where-Object status -eq 'skipped' | ForEach-Object {
        [pscustomobject]@{ control_id = $_.control_id; status = 'skipped'; reason = @($_.diagnostics | ForEach-Object message) -join '; ' }
    }) + @($discoveryScanErrors | ForEach-Object { [pscustomobject]@{ control_id = 'engine/discovery'; status = 'incomplete_scan'; reason = $_.message; path = $_.path } })
    $runtimePlatform = @()
    if ($Discovery.PSObject.Properties.Name -contains 'capability_matrix') { $runtimePlatform = @($Discovery.capability_matrix | Select-Object -First 1 | ForEach-Object platform) }
    $catalogIds = @($Plan.controls | Where-Object control_catalog_id | Select-Object -ExpandProperty control_catalog_id -Unique)
    $permissions = if ($Plan.PSObject.Properties.Name -contains 'permissions') { $Plan.permissions } else { [pscustomobject]@{ network = $false; code_execution = $false } }
    $nonApplicableControlIds = @($Plan.controls | Where-Object { $_.applicability -eq 'not_applicable' } | ForEach-Object id)
    $blockingSkippedResults = @($normalizedResults | Where-Object {
        $_.status -eq 'skipped' -and $_.control_id -notin $nonApplicableControlIds
    })
    $report = [pscustomobject]@{
        schema_version = 1
        engine_version = '0.1.0'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        metadata = [pscustomobject]@{
            run_id = [guid]::NewGuid().ToString('N')
            source_mode = $SourceMode
            source_adapter = $SourceAdapter
            platform = if ($runtimePlatform.Count -gt 0) { $runtimePlatform[0] } else { $null }
            catalog_schema_version = if ($catalogIds.Count -gt 0 -or $CatalogSha256) { 1 } else { $null }
            catalog_sha256 = if ([string]::IsNullOrWhiteSpace($CatalogSha256)) { $null } else { $CatalogSha256 }
            platform_qualification_status = if ([string]::IsNullOrWhiteSpace($PlatformQualificationStatus)) { $null } else { $PlatformQualificationStatus }
            network_authorized = [bool]$permissions.network
            code_execution_authorized = [bool]$permissions.code_execution
        }
        repository = $Plan.repository
        execution_status = if ($PlanOnly) { 'planned' } elseif (-not $discoveryScanComplete) { 'blocked' } else { 'completed' }
        discovery = $Discovery
        matrix = @($Matrix)
        resolver = @($Resolver)
        execution_plan = $Plan
        execution_results = @($normalizedResults)
        findings = $findings
        diagnostics = $diagnostics
        summary = $decision.summary
        verdict = if ($PlanOnly) { $null } else { $decision.verdict }
        verdict_reasons = @($decision.reasons)
        coverage = [pscustomobject]@{
            complete = (-not $PlanOnly -and $Discovery.scan_complete -and $omitted.Count -eq 0 -and $normalizedResults.Count -eq $Plan.controls.Count -and $decision.summary.error -eq 0 -and $blockingSkippedResults.Count -eq 0)
            planned_controls = $Plan.controls.Count
            executed_controls = @($normalizedResults | Where-Object { $null -ne $_.exit_code }).Count
            omitted_required_controls = $omitted.Count
            dependency_skips = $dependencySkips
            limitations = @($omitted | ForEach-Object { [pscustomobject]@{ control_id = $_.id; reason = $_.reason } })
        }
        limitations = @($limitations)
        advisory = $true
    }
    Test-ComplianceReport -Report $report | Out-Null
    return $report
}

Export-ModuleMember -Function New-CompliancePlan, Invoke-CompliancePlan, Get-ComplianceVerdict, New-ComplianceReport, Test-ComplianceReport, ConvertTo-ComplianceReportFromChecks
