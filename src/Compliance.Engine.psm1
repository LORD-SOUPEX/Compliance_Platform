Set-StrictMode -Version Latest

function New-CompliancePlan {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Discovery,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$CapabilityMatrix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resolver,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [ValidateRange(1, 3600)][int]$Timeout = 300,
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
                    $sideEffect = switch ($command) {
                        'pytest' { 'code_execution' }
                        'pylint' { 'code_execution' }
                        'ansible-lint' { 'code_execution' }
                        'pre-commit' { 'code_execution' }
                        'tflint' { 'code_execution' }
                        'checkov' { 'network_code_execution' }
                        'trivy' { 'network' }
                        'pip-audit' { 'network' }
                        default { 'read_only' }
                    }
                    if ($applicability -eq 'applicable' -and (($sideEffect -in @('network', 'network_code_execution') -and -not $AllowNetwork) -or ($sideEffect -in @('code_execution', 'network_code_execution') -and -not $AllowCodeExecution))) {
                        $applicability = 'not_applicable'
                        $reason = "Effet $sideEffect non autorise pour cette execution."
                    }
                    $controls.Add([pscustomobject]@{
                        id = "$($technology.technology)/$($capability.name)/$command/$root"
                        name = "$($technology.technology): $($capability.name) ($command)"
                        technology = $technology.technology
                        capability = $capability.name
                        tool = $candidate
                        root = $root
                        applicability = $applicability
                        execution_order = $controls.Count + 1
                        timeout = $Timeout
                        side_effect_level = $sideEffect
                        required = ([bool]$capability.required -and -not ($hasAlternative -and $selected.Count -eq 0))
                        reason = $reason
                        files = if ($technology.PSObject.Properties.Name -contains 'evidence') { @($technology.evidence) } else { @() }
                    })
                }
            }
        }
    }
    return [pscustomobject]@{
        schema_version = 1
        repository = $repository
        permissions = [pscustomobject]@{ network = [bool]$AllowNetwork; code_execution = [bool]$AllowCodeExecution }
        controls = @($controls.ToArray())
    }
}

function Get-ComplianceInvocation {
    param([pscustomobject]$Control, [string]$Root, [string]$PlatformRoot, [string]$Repository)
    $executable = $Control.tool.source
    if ([string]::IsNullOrWhiteSpace($executable)) { throw 'Source executable absente du plan.' }
    $arguments = @()
    $files = @($Control.files | ForEach-Object {
        $path = [IO.Path]::GetFullPath((Join-Path $Repository $_))
        $prefix = $Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $path }
    })
    switch ($Control.tool.command) {
        'ruff' {
            $operation = if ($Control.capability -eq 'formatting') { @('format', '--check') } else { @('check') }
            $pythonFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' })
            if ($pythonFiles.Count -eq 0) { throw 'Aucune source Python pour Ruff.' }
            $arguments = @($operation) + @('--no-cache') + $pythonFiles
        }
        'pylint' { $arguments = @('--persistent=n') + @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' }); if ($arguments.Count -eq 1) { throw 'Aucune source Python pour Pylint.' } }
        'bandit' {
            $pythonFiles = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.py' })
            if ($pythonFiles.Count -eq 0) { throw 'Aucune source Python pour Bandit.' }
            $arguments = @('-q') + $pythonFiles
        }
        'pytest' { $arguments = @('-p', 'no:cacheprovider', $Root) }
        'pip-audit' {
            $requirements = Join-Path $Root 'requirements.txt'
            if (-not (Test-Path -LiteralPath $requirements -PathType Leaf)) { throw 'Audit consommateur: requirements.txt requis; le runtime de la plateforme n est pas audite a sa place.' }
            $arguments = @('--no-deps', '--disable-pip', '--strict', '-r', $requirements)
        }
        'terraform' { $arguments = @('fmt', '-check', '-diff', '-recursive') }
        'tofu' { $arguments = @('fmt', '-check', '-diff', '-recursive') }
        'terragrunt' { $arguments = @('hcl', 'fmt', '--check') }
        'tflint' { $arguments = @('--no-color') }
        'shellcheck' { $arguments = @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.sh' }); if ($arguments.Count -eq 0) { throw 'Aucun script Shell pour ShellCheck.' } }
        'hadolint' { $arguments = @($files | Where-Object { [IO.Path]::GetFileName($_) -match '^(Dockerfile|Containerfile)(\..+)?$' }); if ($arguments.Count -eq 0) { throw 'Validation Compose non implementee par Hadolint.' } }
        'ansible-lint' { $arguments = @('--profile', 'production', '--strict', $Root) }
        'yamllint' { $arguments = @('-c', (Join-Path $PlatformRoot '.yamllint.yml'), $Root) }
        'pre-commit' {
            $arguments = @('run', 'markdownlint', '--config', (Join-Path $PlatformRoot '.pre-commit-config.yaml'), '--files') + @($files | Where-Object { [IO.Path]::GetExtension($_) -eq '.md' })
            if ($arguments.Count -eq 5) { throw 'Aucun fichier Markdown pour le controle.' }
        }
        'checkov' {
            $framework = switch ($Control.technology) { 'terraform' { 'terraform' }; 'opentofu' { 'terraform' }; 'kubernetes' { 'kubernetes' }; 'helm' { 'helm' }; default { throw 'Framework Checkov non configure.' } }
            $arguments = @('-d', $Root, '--framework', $framework, '--quiet')
            if ([IO.Path]::GetExtension($executable) -eq '.cmd') {
                $arguments = @('-x', $executable) + $arguments
                $executable = Join-Path $PlatformRoot '.venv/Scripts/python.exe'
            }
        }
        'trivy' { $arguments = @('fs', '--scanners', 'vuln,misconfig,secret', '--exit-code', '1', '--no-progress', '--skip-dirs', '.git', '--skip-dirs', '.venv', '--skip-dirs', '.tools', '--skip-dirs', 'reports', $Root) }
        'Invoke-ScriptAnalyzer' {
            if ($files.Count -eq 0) { throw 'Aucun fichier PowerShell pour le controle.' }
            $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PlatformRoot 'scripts/invoke-compliance-powershell.ps1'), '-ModulePath', $executable, '-SettingsPath', (Join-Path $PlatformRoot '.config/PSScriptAnalyzerSettings.psd1'), '-FilesJson', (ConvertTo-Json -InputObject $files -Compress))
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
        technology = $Control.technology
        capability = $Control.capability
        root = $Control.root
        status = 'skipped'
        execution_start = $now
        execution_end = $now
        duration_ms = 0
        tool_version = $version
        stdout = ''
        stderr = ''
        exit_code = $null
        critical = $false
        diagnostics = @()
    }
}

function Invoke-CompliancePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][scriptblock]$ProcessRunner,
        [Parameter(Mandatory = $true)][string]$PlatformRoot
    )
    foreach ($control in @($Plan.controls | Sort-Object execution_order)) {
        $controlTimer = [Diagnostics.Stopwatch]::StartNew()
        $result = New-ComplianceResult -Control $control
        if ($control.applicability -ne 'applicable') {
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
                if ([string]::IsNullOrWhiteSpace($result.tool_version)) {
                    $versionArguments = if ($control.tool.command -eq 'checkov' -and [IO.Path]::GetExtension($control.tool.source) -eq '.cmd') { @('-x', $control.tool.source, '--version') } else { @('--version') }
                    $probe = & $ProcessRunner $invocation.executable @($versionArguments) $root $control.timeout
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
                $remaining = $control.timeout - $controlTimer.Elapsed.TotalSeconds
                if ($remaining -le 0) { throw [TimeoutException]::new('Budget du controle depasse avant execution.') }
                $execution = & $ProcessRunner $invocation.executable $invocation.arguments $root ([int][Math]::Ceiling($remaining))
                if (-not $execution) { throw 'Executeur sans resultat.' }
                foreach ($property in @('stdout', 'stderr', 'exit_code')) { $result.$property = $execution.$property }
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
        $result
    }
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

function New-ComplianceReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][pscustomobject]$Discovery,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Matrix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resolver,
        [Parameter(Mandatory = $true)][pscustomobject]$Plan,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Results,
        [switch]$PlanOnly
    )
    if (-not $PSCmdlet.ShouldProcess($Plan.repository, 'Construire le rapport Compliance en memoire')) { return }
    $normalizedResults = @($Results)
    if (-not $PlanOnly -and $Discovery.scan_complete) {
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
    $decision = Get-ComplianceVerdict -Results $normalizedResults -ScanComplete $Discovery.scan_complete
    $omitted = @($Plan.controls | Where-Object { $_.required -and $_.applicability -eq 'not_applicable' })
    return [pscustomobject]@{
        schema_version = 1
        engine_version = '0.1.0'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        repository = $Plan.repository
        execution_status = if ($PlanOnly) { 'planned' } elseif (-not $Discovery.scan_complete) { 'blocked' } else { 'completed' }
        discovery = $Discovery
        matrix = @($Matrix)
        resolver = @($Resolver)
        execution_plan = $Plan
        execution_results = @($normalizedResults)
        summary = $decision.summary
        verdict = if ($PlanOnly) { $null } else { $decision.verdict }
        verdict_reasons = @($decision.reasons)
        coverage = [pscustomobject]@{
            complete = (-not $PlanOnly -and $Discovery.scan_complete -and $omitted.Count -eq 0 -and $normalizedResults.Count -eq $Plan.controls.Count -and $decision.summary.error -eq 0)
            planned_controls = $Plan.controls.Count
            executed_controls = @($normalizedResults | Where-Object { $null -ne $_.exit_code }).Count
            omitted_required_controls = $omitted.Count
            limitations = @($omitted | ForEach-Object { [pscustomobject]@{ control_id = $_.id; reason = $_.reason } })
        }
        advisory = $true
    }
}

Export-ModuleMember -Function New-CompliancePlan, Invoke-CompliancePlan, Get-ComplianceVerdict, New-ComplianceReport
