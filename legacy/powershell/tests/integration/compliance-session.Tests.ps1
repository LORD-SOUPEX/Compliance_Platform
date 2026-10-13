[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platform = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platform 'src/Compliance.Session.psm1') -Force
Import-Module (Join-Path $platform 'src/Compliance.Engine.psm1') -Force
$target = Join-Path ([IO.Path]::GetTempPath()) ('compliance-session-' + [guid]::NewGuid().ToString('N'))
$runId = [guid]::NewGuid().ToString('N')
$directory = Join-Path $platform ".tools/state/runs/$runId"
$hostPath = Join-Path $PSHOME 'powershell.exe'
$passed = 0
function Assert-Session { param([bool]$Condition, [string]$Message); if (-not $Condition) { throw $Message } }
New-Item -ItemType Directory -Path $target | Out-Null
try {
    [IO.File]::WriteAllText((Join-Path $target 'main.ps1'), "Write-Output 'ok'`n", [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $target 'app.py'), "value = 1`n", [Text.UTF8Encoding]::new($false))
    $hash = (Get-FileHash (Join-Path $platform '.config/control-catalog.json')).Hash.ToLowerInvariant()
    $output = & $hostPath -NoProfile -ExecutionPolicy Bypass -File (Join-Path $platform 'scripts/compliance-adapter.ps1') -Adapter VSCode -RepositoryPath $target -ProgressRunId $runId -ExpectedCatalogSha256 $hash
    $code = $LASTEXITCODE
    try { $events = @($output | ForEach-Object { $_ | ConvertFrom-Json -ErrorAction Stop }) }
    catch { throw "Transport non JSON (code $code): $($output -join ' ')" }
    $report = Get-Content (Join-Path $directory 'compliance-report.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    $snapshot = Get-Content (Join-Path $directory 'execution-plan.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    Assert-Session ($code -eq 0 -and $report.metadata.run_id -eq $runId -and $snapshot.metadata.run_id -eq $runId) 'Identite plan/rapport divergente.'
    Assert-Session ($events[0].type -eq 'session_started' -and $events[-1].type -eq 'session_completed') 'Evenements de session incomplets.'
    $schema = Get-Content (Join-Path $platform '.config/compliance-session.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach ($event in $events) {
        foreach ($field in $schema.'$defs'.event.required) { Assert-Session ($event.PSObject.Properties.Name -contains $field) "Champ evenement absent: $field" }
        Assert-Session ($schema.'$defs'.event.properties.type.enum -contains $event.type) 'Type evenement hors contrat.'
    }
    for ($index = 0; $index -lt $events.Count; $index++) { Assert-Session ($events[$index].sequence -eq $index + 1 -and $events[$index].run_id -eq $runId) 'Sequence ou run_id invalide.' }
    $starts = @($events | Where-Object type -eq 'control_started')
    $ends = @($events | Where-Object type -eq 'control_completed')
    Assert-Session ($starts.Count -gt 0 -and $ends.Count -eq $snapshot.execution_plan.controls.Count) 'Callbacks de controles absents.'
    Assert-Session (@($ends | Where-Object { $_.data.status -eq 'Skipped' -and $_.data.reason.code -eq 'permission_denied' }).Count -gt 0) 'Permissions refusees non explicites.'
    foreach ($event in $ends) { Assert-Session ((Test-Path $event.data.output_path) -and $event.data.result.duration_ms -ge 0) 'Sortie ou duree absente.' }
    Assert-Session (-not (Test-Path (Join-Path $target '.tools')) -and -not (Test-Path (Join-Path $target 'reports'))) 'Etat ecrit dans la Target.'
    $passed++
    $session = New-ComplianceSession -PlatformRoot $target -Repository $target -RunId ([guid]::NewGuid().ToString('N')) -Network $false -CodeExecution $false -CatalogHash $hash
    foreach ($case in @(
        @{ status = 'fail'; code = 'exit_nonzero'; expected = 'Failed' },
        @{ status = 'error'; code = 'timeout'; expected = 'Error' },
        @{ status = 'error'; code = 'dependency_failed'; expected = 'Blocked' },
        @{ status = 'skipped'; code = 'permission_denied'; expected = 'Skipped' },
        @{ status = 'skipped'; code = 'technology_absent'; expected = 'Not applicable' },
        @{ status = 'success'; code = 'output_truncated'; expected = 'Warning' }
    )) {
        $result = [pscustomobject]@{ status = $case.status; output_truncated = ($case.code -eq 'output_truncated'); diagnostics = @([pscustomobject]@{ code = $case.code; message = 'Fixture'; critical = $false }) }
        $presentation = Get-CompliancePresentation $result
        Assert-Session ($presentation.status -eq $case.expected -and $presentation.reason.code -eq $case.code) 'Statut ou motif incorrect.'
    }
    $passed++
    $tokens = $null; $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $platform 'scripts/quality-gate.ps1'), [ref]$tokens, [ref]$errors)
    foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Invoke-BoundedProcess', 'Get-ExecutionIntegrityError') }, $false)) { . ([scriptblock]::Create($definition.Extent.Text)) }
    $toolRoot = Join-Path $platform '.tools/bin'
    $script:ProgressSession = $session
    $cancelPath = Join-Path $session.directory 'cancel'
    $fixtureScript = Join-Path $target 'cancel.ps1'
    [IO.File]::WriteAllText($fixtureScript, "`$child = Start-Process -FilePath '$($hostPath.Replace("'", "''"))' -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 15' -PassThru; [Console]::Out.WriteLine(`$PID); [Console]::Out.WriteLine(`$child.Id); [IO.File]::WriteAllText('$($cancelPath.Replace("'", "''"))','cancel'); Start-Sleep -Seconds 15", [Text.UTF8Encoding]::new($false))
    $execution = Invoke-BoundedProcess -Executable $hostPath -Arguments @('-NoProfile', '-File', $fixtureScript) -WorkingDirectory $target -Timeout 10
    $processIds = @($execution.stdout.Trim() -split '\s+' | ForEach-Object { [int]$_ })
    Assert-Session ($execution.cancelled -and -not $execution.timed_out -and $processIds.Count -eq 2) 'Annulation du processus non restituee.'
    foreach ($processId in $processIds) { Assert-Session (-not (Get-Process -Id $processId -ErrorAction SilentlyContinue)) 'Processus ou enfant annule encore actif.' }
    $passed++
    $again = $false
    try { $null = New-ComplianceSession -PlatformRoot $target -Repository $target -RunId $session.run_id -Network $false -CodeExecution $false -CatalogHash $hash } catch { $again = $true }
    Assert-Session $again 'Une session ancienne a ete reutilisee.'
    $passed++
} finally {
    Remove-Item -LiteralPath $target -Recurse -Force
    if (Test-Path $directory) { Remove-Item -LiteralPath $directory -Recurse -Force }
}
Write-Information -InformationAction Continue "[SUMMARY] Compliance session integration PASS=$passed FAIL=0"
