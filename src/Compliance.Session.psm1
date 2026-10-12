Set-StrictMode -Version Latest

function Write-ComplianceSessionJson {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$Path, [object]$Value)
    if (-not $PSCmdlet.ShouldProcess($Path, 'Ecrire un artefact local atomiquement')) { return }
    if (Test-Path -LiteralPath $Path) {
        if ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Artefact de session redirige par un lien.' }
    }
    $temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $backup = "$temporary.bak"
    try {
        [IO.File]::WriteAllText($temporary, ($Value | ConvertTo-Json -Depth 30), [Text.UTF8Encoding]::new($false))
        if (Test-Path -LiteralPath $Path) { [IO.File]::Replace($temporary, $Path, $backup) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        foreach ($artifact in @($temporary, $backup)) { if (Test-Path -LiteralPath $artifact) { Remove-Item -LiteralPath $artifact -Force } }
    }
}

function New-ComplianceSession {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$PlatformRoot, [string]$Repository, [ValidatePattern('^[a-f0-9]{32}$')][string]$RunId, [bool]$Network, [bool]$CodeExecution, [string]$CatalogHash)
    if (-not $PSCmdlet.ShouldProcess($PlatformRoot, 'Creer une session Compliance locale')) { return }
    $directory = $PlatformRoot
    foreach ($part in @('.tools', 'state', 'runs', $RunId, 'logs')) {
        $directory = Join-Path $directory $part
        if (Test-Path -LiteralPath $directory) {
            $item = Get-Item -LiteralPath $directory
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Dossier de session invalide ou redirige par un lien.' }
        } else { New-Item -ItemType Directory -Path $directory | Out-Null }
    }
    $directory = Split-Path -Parent $directory
    $initial = $null
    if (Test-Path (Join-Path $directory 'session.json')) {
        $initial = Get-Content (Join-Path $directory 'session.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($initial.run_id -ne $RunId -or $initial.state -ne 'preparing' -or $initial.target -ne $Repository -or $initial.pipeline_source -ne $PlatformRoot) { throw 'Une session existante ne peut pas etre reutilisee.' }
    }
    if ((Test-Path (Join-Path $directory 'compliance-report.json')) -or (Test-Path (Join-Path $directory 'events.ndjson'))) { throw 'Une session existante ne peut pas etre reutilisee.' }
    $session = [pscustomobject]@{
        schema_version = 1; run_id = $RunId; target = $Repository; pipeline_source = $PlatformRoot
        started_at = if ($initial) { $initial.started_at } else { [DateTimeOffset]::UtcNow.ToString('o') }; ended_at = $null; state = 'running'
        permissions = [pscustomobject]@{ network = $Network; code_execution = $CodeExecution }
        catalog_sha256 = $CatalogHash; report_path = (Join-Path $directory 'compliance-report.json')
        directory = $directory; sequence = 0
    }
    Write-ComplianceSessionJson -Path (Join-Path $directory 'session.json') -Value $session
    return $session
}

function Write-ComplianceEvent {
    [CmdletBinding()]
    param([pscustomobject]$Session, [string]$Type, [object]$Data, [object]$Control)
    $Session.sequence++
    $event = [pscustomobject]@{
        schema_version = 1; run_id = $Session.run_id; sequence = $Session.sequence
        timestamp = [DateTimeOffset]::UtcNow.ToString('o'); type = $Type
        control_id = if ($Control) { $Control.id } else { $null }
        technology = if ($Control) { $Control.technology } else { $null }
        root = if ($Control) { $Control.root } else { $null }; data = $Data
    }
    $json = $event | ConvertTo-Json -Depth 30 -Compress
    [IO.File]::AppendAllText((Join-Path $Session.directory 'events.ndjson'), ($json + "`n"), [Text.UTF8Encoding]::new($false))
    [Console]::Out.WriteLine($json)
}

function Test-ComplianceCancellation {
    param([pscustomobject]$Session)
    $heartbeat = Join-Path $Session.directory 'heartbeat'
    $cancel = (Test-Path -LiteralPath (Join-Path $Session.directory 'cancel')) -or
        ((Test-Path -LiteralPath $heartbeat) -and (([DateTime]::UtcNow - (Get-Item -LiteralPath $heartbeat).LastWriteTimeUtc).TotalSeconds -gt 15))
    if ($cancel -and $Session.state -eq 'running') {
        $Session.state = 'cancelling'
        Write-ComplianceSessionJson -Path (Join-Path $Session.directory 'session.json') -Value $Session
        Write-ComplianceEvent -Session $Session -Type 'session_cancelling' -Data ([pscustomobject]@{ reason = [pscustomobject]@{ code = 'session_interrupted'; message = 'Annulation demandee ou host absent.' } })
    }
    return $cancel
}

function Get-CompliancePresentation {
    param([pscustomobject]$Result)
    $diagnostics = @($Result.diagnostics)
    $code = if ($diagnostics.Count) { $diagnostics[0].code } else { $null }
    $status = if ($code -in @('dependency_failed', 'ambiguous', 'capability_unavailable', 'tool_unavailable')) { 'Blocked' }
        elseif ($code -in @('permission_denied', 'cancelled_before_start', 'cancelled_during_execution')) { 'Skipped' }
        elseif ($code -eq 'legacy_warning') { 'Warning' }
        elseif ($code -eq 'legacy_skipped') { 'Skipped' }
        elseif ($Result.status -eq 'error') { 'Error' }
        elseif ($Result.status -eq 'fail') { 'Failed' }
        elseif ($Result.status -eq 'skipped') { 'Not applicable' }
        elseif ($Result.output_truncated -or $diagnostics.Count -gt 0) { 'Warning' }
        else { 'Succeeded' }
    $reason = if ($diagnostics.Count) { [pscustomobject]@{ code = $code; message = $diagnostics[0].message } }
        elseif ($status -eq 'Not applicable') { [pscustomobject]@{ code = 'not_applicable'; message = 'Controle non applicable selon le backend.' } }
        else { $null }
    if ($reason -and [string]::IsNullOrWhiteSpace($reason.message)) { $reason.message = 'Controle non execute selon le motif structure du backend.' }
    return [pscustomobject]@{ status = $status; reason = $reason }
}

function Complete-ComplianceSession {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([pscustomobject]$Session, [ValidateSet('completed', 'cancelled', 'failed')][string]$State)
    if (-not $PSCmdlet.ShouldProcess($Session.run_id, 'Finaliser la session locale')) { return }
    $Session.state = $State
    $Session.ended_at = [DateTimeOffset]::UtcNow.ToString('o')
    Write-ComplianceSessionJson -Path (Join-Path $Session.directory 'session.json') -Value $Session
}

Export-ModuleMember -Function Write-ComplianceSessionJson, New-ComplianceSession, Write-ComplianceEvent, Test-ComplianceCancellation, Get-CompliancePresentation, Complete-ComplianceSession
