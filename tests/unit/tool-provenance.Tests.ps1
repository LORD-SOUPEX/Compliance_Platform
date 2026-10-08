[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $repoRoot 'src/Tool.Provenance.psm1') -Force
$workspace = Join-Path $repoRoot ('.tools/test-workspaces/provenance-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $workspace '.tools/cache/wheels') -Force | Out-Null
try {
    $wheelName = 'example_pkg-1.0.0-py3-none-any.whl'
    $wheelPath = Join-Path (Join-Path $workspace '.tools/cache/wheels') $wheelName
    [IO.File]::WriteAllText($wheelPath, 'verified-wheel', [Text.UTF8Encoding]::new($false))
    $wheelHash = (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $timestamp = [DateTimeOffset]::UtcNow.ToString('o')
    $wheelRecord = [pscustomobject]@{
        name = 'example-pkg'
        version = '1.0.0'
        provenance = [pscustomobject]@{
            registry = 'PyPI'
            publisher = 'PyPI'
            project_author = 'Example Publisher'
            source_version = '1.0.0'
            source_url = 'https://files.pythonhosted.org/packages/example.whl'
            artifact_filename = $wheelName
            artifact_path = ".tools/cache/wheels/$wheelName"
            artifact_sha256 = $wheelHash
            acquired_at = $timestamp
            verified_at = $timestamp
            validation_method = 'pip_download_sha256_verified_against_official_index'
        }
    }
    if (Get-PythonWheelProvenanceError -Record $wheelRecord -RepositoryRoot $workspace) { throw 'Valid wheel provenance was rejected.' }
    $wheelRecord.provenance.artifact_sha256 = '0' * 64
    if ((Get-PythonWheelProvenanceError -Record $wheelRecord -RepositoryRoot $workspace) -notmatch 'SHA-256') { throw 'Altered wheel provenance was accepted.' }
    $wheelRecord.provenance.artifact_sha256 = $wheelHash
    $wheelRecord.provenance.artifact_path = '.tools/cache/wheels/../../../../outside.whl'
    if ((Get-PythonWheelProvenanceError -Record $wheelRecord -RepositoryRoot $workspace) -notmatch 'sortant') { throw 'Escaping wheel cache path was accepted.' }

    $bootstrapTokens = $null
    $bootstrapErrors = $null
    $bootstrapAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts/bootstrap.ps1'), [ref]$bootstrapTokens, [ref]$bootstrapErrors)
    $inventoryDefinition = $bootstrapAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-PythonWheelInventory' }, $false)
    . ([scriptblock]::Create($inventoryDefinition.Extent.Text))
    $lockPath = Join-Path $workspace 'requirements-dev.lock'
    [IO.File]::WriteAllText($lockPath, "example-pkg==1.0.0`n", [Text.UTF8Encoding]::new($false))
    $offlineRejected = $false
    try { $null = Get-PythonWheelInventory -VenvPython 'unused-python.exe' -RequirementsLockPath $lockPath -LockedPackages @{ 'example-pkg' = '1.0.0' } -InstalledVersions @{ 'example-pkg' = '1.0.0' } -RuntimeRoot (Join-Path $workspace '.tools/runtime') -Offline }
    catch { $offlineRejected = $_.Exception.Message -match 'Mode hors ligne' }
    if (-not $offlineRejected) { throw 'Offline mode attempted or accepted missing wheel provenance.' }

    $toolRecord = [pscustomobject]@{
        version = '1.2.3'
        sha256 = 'a' * 64
        provenance = [pscustomobject]@{
            status = 'official_checksum_verified'
            publisher = 'example.invalid/example/tool'
            source_version = '1.2.3'
            source_uri = 'https://example.invalid/tool/1.2.3.zip'
            checksum_uri = 'https://example.invalid/tool/checksums.txt'
            checksum_asset_sha256 = 'b' * 64
            published_artifact_sha256 = 'c' * 64
            runtime_artifact_sha256 = 'a' * 64
            acquired_at = $timestamp
            verified_at = $timestamp
            validation_method = 'official_checksum_manifest_and_runtime_copy_sha256'
        }
    }
    if (Get-ToolArtifactProvenanceError -Record $toolRecord) { throw 'Valid binary provenance was rejected.' }
    $toolRecord.provenance.status = 'local_copy_hash_verified'
    if ((Get-ToolArtifactProvenanceError -Record $toolRecord) -notmatch 'absente ou non vérifiée') { throw 'Unverified binary provenance was accepted.' }

    $gateTokens = $null
    $gateErrors = $null
    $gateAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $repoRoot 'scripts/quality-gate.ps1'), [ref]$gateTokens, [ref]$gateErrors)
    foreach ($functionName in @('Get-ExecutionIntegrityError', 'Invoke-BoundedProcess', 'Test-ResolvedCommandExecution')) {
        $definition = $gateAst.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName }, $false)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    $toolRoot = Join-Path $repoRoot '.tools/bin'
    $pythonPath = Join-Path $repoRoot '.venv/Scripts/python.exe'
    $pythonVersion = ((& $pythonPath --version) -join ' ').Split(' ')[1]
    $probe = Test-ResolvedCommandExecution -Executable $pythonPath -ExpectedVersion $pythonVersion -WorkingDirectory $workspace
    if ($probe.status -ne 'available' -or $probe.evidence.exit_code -ne 0 -or $probe.evidence.expected_version -ne $pythonVersion -or $probe.evidence.duration_ms -lt 0) { throw 'Native version probe did not record a successful execution.' }
    $failedProbe = Test-ResolvedCommandExecution -Executable $pythonPath -Arguments @('-c', 'import sys; sys.exit(7)') -WorkingDirectory $workspace
    if ($failedProbe.status -ne 'runtime_error' -or $failedProbe.evidence.exit_code -eq 0) { throw 'A non-zero command execution was accepted as available.' }
    $timeoutProbe = Test-ResolvedCommandExecution -Executable $pythonPath -Arguments @('-c', 'import time; time.sleep(2)') -WorkingDirectory $workspace -TimeoutSeconds 1
    if ($timeoutProbe.status -ne 'runtime_error' -or -not $timeoutProbe.evidence.timed_out) { throw 'A timed-out command was accepted as available.' }
    $batchProbePath = Join-Path $workspace 'version-probe.cmd'
    [IO.File]::WriteAllLines($batchProbePath, [string[]]@('@echo off', 'echo FixtureTool 3.4.5', 'exit /b 0'), [Text.Encoding]::ASCII)
    $batchProbe = Test-ResolvedCommandExecution -Executable $batchProbePath -ExpectedVersion '3.4.5' -WorkingDirectory $workspace
    if ($batchProbe.status -ne 'available' -or $batchProbe.evidence.exit_code -ne 0 -or $batchProbe.evidence.executable -ne $batchProbePath) { throw 'A Windows batch command was not qualified with evidence.' }
} finally {
    if (Test-Path -LiteralPath $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}

Write-Information -InformationAction Continue '[SUMMARY] Tool provenance unit PASS=10 FAIL=0'
