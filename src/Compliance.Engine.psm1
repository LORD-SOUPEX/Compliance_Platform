Set-StrictMode -Version Latest

function New-CompliancePlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Discovery,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$CapabilityMatrix,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Resolver,
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [ValidateRange(1, 3600)][int]$Timeout = 300
    )
    $repository = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/')
    $prefix = $repository + [IO.Path]::DirectorySeparatorChar
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
                    }
                    $reason = ''
                    $applicability = if ($technology.status -eq 'absent') { 'technology_absent' }
                        elseif ($technology.status -eq 'ambiguous') { 'ambiguous' }
                        elseif (-not $capability.required) { 'not_applicable' }
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
                        'tflint' { 'code_execution' }
                        'checkov' { 'network' }
                        'trivy' { 'network' }
                        'pip-audit' { 'network' }
                        default { 'read_only' }
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
                        required = [bool]$capability.required
                        reason = $reason
                    })
                }
            }
        }
    }
    return [pscustomobject]@{
        schema_version = 1
        repository = $repository
        controls = @($controls.ToArray())
    }
}

Export-ModuleMember -Function New-CompliancePlan
