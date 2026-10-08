[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$lockScript = Join-Path $platformRoot 'scripts/update-lock.ps1'
$lockPath = Join-Path $platformRoot 'requirements-dev.lock'
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($lockScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -gt 0) { throw 'Lock script syntax is invalid.' }
foreach ($name in @('Get-NormalizedPackageName', 'Get-PackagePinMap', 'Get-PackageHashMap', 'Assert-PinMapsEqual', 'Assert-PackageHashMapsEqual', 'Write-HashedPackageLock')) {
    $function = $ast.Find({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name }, $false)
    if (-not $function) { throw "Lock validation function is missing: $name" }
    . ([scriptblock]::Create($function.Extent.Text))
}

$workspace = Join-Path $platformRoot ('.tools/test-workspaces/reproducibility-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
try {
    $validPath = Join-Path $workspace 'requirements.txt'
    [System.IO.File]::WriteAllText($validPath, "Ruff==0.16.10`nPIP_tools==7.6.2`n", [System.Text.UTF8Encoding]::new($false))
    $pins = Get-PackagePinMap -Path $validPath
    if ($pins['ruff'] -ne '0.16.10' -or $pins['pip-tools'] -ne '7.6.2') { throw 'Package names were not normalized to canonical pins.' }

    $wheelDirectory = Join-Path $workspace 'wheels'
    New-Item -ItemType Directory -Path $wheelDirectory -Force | Out-Null
    $wheelReport = New-Object System.Collections.Generic.List[object]
    foreach ($package in @(@{ name = 'ruff'; version = '0.16.10' }, @{ name = 'pip-tools'; version = '7.6.2' })) {
        $filename = "$($package.name)-$($package.version)-py3-none-any.whl"
        $wheelPath = Join-Path $wheelDirectory $filename
        [System.IO.File]::WriteAllText($wheelPath, "$($package.name)==$($package.version)", [System.Text.UTF8Encoding]::new($false))
        $wheelHash = (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $wheelReport.Add([pscustomobject]@{
            metadata = [pscustomobject]@{ name = $package.name; version = $package.version }
            download_info = [pscustomobject]@{ url = "https://files.pythonhosted.org/packages/$filename"; archive_info = [pscustomobject]@{ hashes = [pscustomobject]@{ sha256 = $wheelHash } } }
        })
    }
    $reportPath = Join-Path $workspace 'pip-report.json'
    [System.IO.File]::WriteAllText($reportPath, ([pscustomobject]@{ install = $wheelReport.ToArray() } | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
    $hashedLockPath = Join-Path $workspace 'requirements-hashed.txt'
    Write-HashedPackageLock -RequirementsPath $validPath -ReportPath $reportPath -WheelDirectory $wheelDirectory -OutputPath $hashedLockPath
    $hashedPins = Get-PackagePinMap -Path $hashedLockPath
    $hashMap = Get-PackageHashMap -Path $hashedLockPath
    Assert-PinMapsEqual -Expected $pins -Actual $hashedPins -Description 'Hashed fixture direct pins'
    if ($hashMap.Count -ne 2 -or $hashMap['ruff'].Count -ne 1 -or $hashMap['pip-tools'].Count -ne 1) { throw 'Hashed lock did not record one verified wheel per pin.' }
    $tamperedWheel = Join-Path $wheelDirectory 'ruff-0.16.10-py3-none-any.whl'
    [System.IO.File]::WriteAllText($tamperedWheel, 'tampered', [System.Text.UTF8Encoding]::new($false))
    $hashMismatchRejected = $false
    try { Write-HashedPackageLock -RequirementsPath $validPath -ReportPath $reportPath -WheelDirectory $wheelDirectory -OutputPath $hashedLockPath }
    catch { $hashMismatchRejected = $_.Exception.Message -match 'SHA-256' }
    if (-not $hashMismatchRejected) { throw 'Modified wheel was accepted while generating a hashed lock.' }

    $invalidPath = Join-Path $workspace 'unlocked.txt'
    [System.IO.File]::WriteAllText($invalidPath, "ruff>=0.16`n", [System.Text.UTF8Encoding]::new($false))
    $rejected = $false
    try { $null = Get-PackagePinMap -Path $invalidPath } catch { $rejected = $_.Exception.Message -match 'exact pin' }
    if (-not $rejected) { throw 'A floating requirement was accepted.' }

    $rejected = $false
    try { Assert-PinMapsEqual -Expected @{ ruff = '0.16.10' } -Actual @{ ruff = '0.16.9' } -Description 'Fixture' } catch { $rejected = $_.Exception.Message -match 'ruff' }
    if (-not $rejected) { throw 'A direct pin mismatch was accepted.' }

    $before = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash
    $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $lockScript -Check
    $exitCode = $LASTEXITCODE
    $after = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash
    if ($exitCode -ne 0 -or $before -ne $after -or -not (($output -join "`n") -match 'Lock consistent')) { throw "Lock check failed or modified the lock (exit=$exitCode)." }

    $bootstrapText = [System.IO.File]::ReadAllText((Join-Path $platformRoot 'scripts/bootstrap.ps1'), [System.Text.Encoding]::UTF8)
    $lockCheckPosition = $bootstrapText.IndexOf('scripts/update-lock.ps1', [StringComparison]::Ordinal)
    $qualifiedPosition = $bootstrapText.LastIndexOf("-Status 'qualified'", [StringComparison]::Ordinal)
    if ($lockCheckPosition -lt 0 -or $qualifiedPosition -lt 0 -or $lockCheckPosition -ge $qualifiedPosition) { throw 'Bootstrap qualifies the runtime before checking the lock.' }
} finally {
    if (Test-Path -LiteralPath $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}

Write-Information -InformationAction Continue '[SUMMARY] Reproducibility unit PASS=8 FAIL=0'
