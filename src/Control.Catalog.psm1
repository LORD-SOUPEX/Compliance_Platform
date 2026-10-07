Set-StrictMode -Version Latest

function Import-ControlCatalog {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $catalog = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($catalog.schema_version -ne 1 -or -not $catalog.controls -or $catalog.controls.Count -eq 0) { throw 'Schema Control Catalog invalide.' }
    $ids = @{}
    $allowedFields = @('id', 'name', 'objective', 'technology', 'capability', 'tool', 'severity', 'selection_policy', 'applicability', 'parameters', 'dependencies', 'timeout_seconds', 'cost', 'side_effect_level', 'permissions', 'platform_support', 'limitations')
    foreach ($control in $catalog.controls) {
        foreach ($field in @('id', 'name', 'objective', 'technology', 'capability', 'severity', 'selection_policy', 'applicability', 'parameters', 'dependencies', 'timeout_seconds', 'cost', 'side_effect_level', 'permissions', 'platform_support', 'limitations')) {
            if ($control.PSObject.Properties.Name -notcontains $field) { throw "Champ Control Catalog absent: $field" }
        }
        if (@($control.PSObject.Properties | Where-Object { $_.Name -notin $allowedFields }).Count -gt 0) { throw "Champ Control Catalog non autorise: $($control.id)" }
        if ($control.id -isnot [string] -or $control.name -isnot [string] -or $control.objective -isnot [string] -or $control.technology -isnot [string] -or $control.capability -isnot [string]) { throw 'Identite Control Catalog invalide.' }
        if ($control.name.Length -eq 0 -or $control.objective.Length -eq 0 -or $control.technology.Length -eq 0 -or $control.capability.Length -eq 0) { throw "Nom, objectif ou capacite vide: $($control.id)" }
        if ($control.id -notmatch '^[a-z0-9][a-z0-9._-]*$' -or $ids.ContainsKey($control.id)) { throw "Identifiant Control Catalog invalide ou duplique: $($control.id)" }
        $ids[$control.id] = $control
        if ($control.severity -notin @('low', 'medium', 'high', 'critical')) { throw "Severite Control Catalog invalide: $($control.id)" }
        if ($control.selection_policy -notin @('all', 'alternative')) { throw "Politique de selection invalide: $($control.id)" }
        if ($control.side_effect_level -notin @('read_only', 'code_execution', 'network', 'network_code_execution')) { throw "Effet de bord invalide: $($control.id)" }
        if ($control.cost -notin @('low', 'medium', 'high') -or $control.timeout_seconds -lt 1 -or $control.timeout_seconds -gt 3600) { throw "Cout ou timeout invalide: $($control.id)" }
        if ($control.applicability.technology_status -notcontains 'detected') { throw "Applicabilite detected absente: $($control.id)" }
        $applicabilityFields = @('technology_status', 'evidence_extensions')
        if (@($control.applicability.PSObject.Properties | Where-Object { $_.Name -notin $applicabilityFields }).Count -gt 0) { throw "Champ applicability non autorise: $($control.id)" }
        if ($control.applicability.technology_status -isnot [array] -or $control.applicability.evidence_extensions -isnot [array]) { throw "Types applicability invalides: $($control.id)" }
        if ($control.parameters -isnot [pscustomobject]) { throw "Parameters doit etre un objet: $($control.id)" }
        if ($control.dependencies -isnot [array] -or $control.permissions -isnot [array] -or $control.platform_support -isnot [array] -or $control.limitations -isnot [array]) { throw "Les dependances, permissions, plateformes et limitations doivent etre des tableaux: $($control.id)" }
        if ($control.dependencies | Where-Object { $_ -isnot [string] }) { throw "Reference de dependance non textuelle: $($control.id)" }
        $expectedPermissions = @()
        if ($control.side_effect_level -in @('network', 'network_code_execution')) { $expectedPermissions += 'network' }
        if ($control.side_effect_level -in @('code_execution', 'network_code_execution')) { $expectedPermissions += 'code_execution' }
        if (@(Compare-Object @($expectedPermissions | Sort-Object) @($control.permissions | Sort-Object)).Count -gt 0) { throw "Permissions incoherentes avec les effets: $($control.id)" }
        if ($null -ne $control.tool) {
            if (@($control.tool.PSObject.Properties | Where-Object Name -notin @('name', 'command')).Count -gt 0 -or $control.tool.name -isnot [string] -or $control.tool.command -isnot [string] -or -not $control.tool.name -or -not $control.tool.command) { throw "Outil invalide: $($control.id)" }
        }
    }
    foreach ($control in $catalog.controls) {
        foreach ($dependency in $control.dependencies) {
            if (-not $ids.ContainsKey($dependency)) { throw "Dependance Control Catalog absente: $dependency" }
        }
    }
    foreach ($control in $catalog.controls) {
        $visited = @{}
        $pending = New-Object System.Collections.Generic.Stack[string]
        $pending.Push($control.id)
        while ($pending.Count -gt 0) {
            $current = $pending.Pop()
            if ($current -eq $control.id -and $visited.Count -gt 0) { throw "Cycle Control Catalog: $($control.id)" }
            if ($visited.ContainsKey($current)) { continue }
            $visited[$current] = $true
            foreach ($dependency in $ids[$current].dependencies) { $pending.Push($dependency) }
        }
    }
    $catalog | Add-Member -MemberType NoteProperty -Name content_sha256 -Value ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant())
    return $catalog
}

function Get-CatalogCapabilityProfile {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][pscustomobject]$Catalog, [Parameter(Mandatory = $true)][string]$Technology)
    $technologyControls = @($Catalog.controls | Where-Object technology -eq $Technology)
    foreach ($group in @($technologyControls | Group-Object capability | Sort-Object Name)) {
        $controls = @($group.Group | Sort-Object id)
        $policies = @($controls | Select-Object -ExpandProperty selection_policy -Unique)
        if ($policies.Count -ne 1) { throw "Politiques concurrentes pour $Technology/$($group.Name)." }
        [pscustomobject]@{
            name = $group.Name
            selection_policy = $policies[0]
            controls = $controls
            tools = @($controls | Where-Object { $null -ne $_.tool } | ForEach-Object {
                [pscustomobject]@{
                    name = $_.tool.name
                    command = $_.tool.command
                    catalog_id = $_.id
                    severity = $_.severity
                    side_effect_level = $_.side_effect_level
                    permissions = @($_.permissions)
                    timeout_seconds = $_.timeout_seconds
                    cost = $_.cost
                    parameters = $_.parameters
                    dependencies = @($_.dependencies)
                    limitations = @($_.limitations)
                }
            })
        }
    }
}

Export-ModuleMember -Function Import-ControlCatalog, Get-CatalogCapabilityProfile
