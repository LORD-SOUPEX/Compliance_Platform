function Test-ProvenanceTimestamp {
    param([AllowNull()][string]$Value)
    $timestamp = [DateTimeOffset]::MinValue
    return [DateTimeOffset]::TryParse($Value, [ref]$timestamp)
}

function Get-ToolArtifactProvenanceError {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record)
    $provenance = $Record.provenance
    if (-not $provenance -or $provenance.status -ne 'official_checksum_verified') { return 'Provenance éditeur du binaire absente ou non vérifiée.' }
    if ($provenance.source_version -ne $Record.version -or $provenance.runtime_artifact_sha256 -ne $Record.sha256) { return 'Version ou hash du binaire runtime divergent.' }
    foreach ($uriValue in @($provenance.source_uri, $provenance.checksum_uri)) {
        $uri = $null
        if (-not [Uri]::TryCreate([string]$uriValue, [UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') { return 'URL de provenance binaire invalide.' }
    }
    if ([string]::IsNullOrWhiteSpace($provenance.publisher) -or $provenance.checksum_asset_sha256 -notmatch '^[a-f0-9]{64}$' -or $provenance.published_artifact_sha256 -notmatch '^[a-f0-9]{64}$') { return 'Éditeur ou hash du manifeste/artefact binaire absent.' }
    if (-not (Test-ProvenanceTimestamp -Value $provenance.acquired_at) -or -not (Test-ProvenanceTimestamp -Value $provenance.verified_at)) { return 'Date d’acquisition ou de validation binaire invalide.' }
    if ($provenance.validation_method -ne 'official_checksum_manifest_and_runtime_copy_sha256') { return 'Méthode de validation binaire inconnue.' }
}

function Get-PythonWheelProvenanceError {
    param([Parameter(Mandatory = $true)][pscustomobject]$Record, [Parameter(Mandatory = $true)][string]$RepositoryRoot)
    $provenance = $Record.provenance
    if (-not $provenance -or $provenance.registry -ne 'PyPI') { return 'Provenance PyPI de la roue absente.' }
    if ($provenance.source_version -ne $Record.version -or [string]::IsNullOrWhiteSpace($provenance.publisher)) { return 'Éditeur ou version de roue invalide.' }
    $sourceUri = $null
    if (-not [Uri]::TryCreate([string]$provenance.source_url, [UriKind]::Absolute, [ref]$sourceUri) -or $sourceUri.Scheme -ne 'https' -or $sourceUri.Host -ne 'files.pythonhosted.org') { return 'URL de roue hors de l’origine PyPI officielle.' }
    if ($provenance.artifact_sha256 -notmatch '^[a-f0-9]{64}$' -or [string]::IsNullOrWhiteSpace($provenance.artifact_filename) -or [IO.Path]::GetExtension($provenance.artifact_filename) -ne '.whl') { return 'Hash ou nom de roue invalide.' }
    if (-not (Test-ProvenanceTimestamp -Value $provenance.acquired_at) -or -not (Test-ProvenanceTimestamp -Value $provenance.verified_at)) { return 'Date d’acquisition ou de validation de roue invalide.' }
    if ($provenance.validation_method -ne 'pip_download_sha256_verified_against_official_index') { return 'Méthode de validation de roue inconnue.' }
    if ([string]::IsNullOrWhiteSpace($provenance.artifact_path) -or [IO.Path]::IsPathRooted($provenance.artifact_path)) { return 'Chemin de roue non relatif.' }
    $repositoryFullPath = [IO.Path]::GetFullPath($RepositoryRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $artifactFullPath = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $provenance.artifact_path))
    $artifactPrefix = [IO.Path]::GetFullPath((Join-Path $RepositoryRoot '.tools/cache/wheels')).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $artifactFullPath.StartsWith($artifactPrefix, [StringComparison]::OrdinalIgnoreCase) -or -not $artifactFullPath.StartsWith($repositoryFullPath, [StringComparison]::OrdinalIgnoreCase)) { return 'Chemin de roue sortant du cache local autorisé.' }
    if ([IO.Path]::GetFileName($artifactFullPath) -ne $provenance.artifact_filename -or -not (Test-Path -LiteralPath $artifactFullPath -PathType Leaf)) { return 'Roue acquise absente ou incohérente.' }
    $actualHash = (Get-FileHash -LiteralPath $artifactFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $provenance.artifact_sha256) { return 'SHA-256 de la roue acquise divergent.' }
}

Export-ModuleMember -Function Get-ToolArtifactProvenanceError, Get-PythonWheelProvenanceError
