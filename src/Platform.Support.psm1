Set-StrictMode -Version Latest

function Import-PlatformSupportMatrix {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $matrix = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $expectedPlatforms = @{
        'windows-x64' = @('windows', 'x64')
        'windows-arm64' = @('windows', 'arm64')
        'linux-x64' = @('linux', 'x64')
        'linux-arm64' = @('linux', 'arm64')
        'macos-x64' = @('macos', 'x64')
        'macos-arm64' = @('macos', 'arm64')
    }
    if ($matrix.schema_version -ne 1 -or $matrix.platforms -isnot [array] -or $matrix.platforms.Count -ne $expectedPlatforms.Count) {
        throw 'Matrice de support plateforme invalide: version ou nombre de plateformes.'
    }

    $seen = @{}
    foreach ($platform in $matrix.platforms) {
        $fields = @('id', 'os', 'architecture', 'status', 'evidence', 'limitations')
        foreach ($field in $fields) {
            if ($platform.PSObject.Properties.Name -notcontains $field) { throw "Champ plateforme absent: $field" }
        }
        if (-not $expectedPlatforms.ContainsKey($platform.id) -or $seen.ContainsKey($platform.id)) {
            throw "Plateforme inconnue ou dupliquee: $($platform.id)"
        }
        if ($platform.os -ne $expectedPlatforms[$platform.id][0] -or $platform.architecture -ne $expectedPlatforms[$platform.id][1]) {
            throw "OS ou architecture incoherent pour $($platform.id)."
        }
        if ($platform.status -notin @('targeted', 'experimental', 'qualified')) { throw "Statut plateforme invalide: $($platform.id)" }
        if ($platform.evidence -isnot [array] -or $platform.limitations -isnot [array]) { throw "Preuves et limites doivent etre des tableaux: $($platform.id)" }
        if (@($platform.evidence | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0 -or @($platform.limitations | Where-Object { $_ -isnot [string] -or [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
            throw "Preuve ou limite vide/invalide: $($platform.id)"
        }
        if ($platform.status -eq 'qualified' -and $platform.evidence.Count -eq 0) { throw "Qualification sans preuve: $($platform.id)" }
        if ($platform.status -ne 'qualified' -and $platform.limitations.Count -eq 0) { throw "Limite non documentee: $($platform.id)" }
        $seen[$platform.id] = $true
    }
    return $matrix
}

Export-ModuleMember -Function Import-PlatformSupportMatrix
