[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    [Parameter(ParameterSetName = 'Check', Mandatory = $true)][switch]$Check,
    [Parameter(ParameterSetName = 'Update', Mandatory = $true)][switch]$Update,
    [Parameter(ParameterSetName = 'Update')][switch]$UpgradeAll
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$python = Join-Path $repoRoot '.venv\Scripts\python.exe'
$lockToolsPython = Join-Path $repoRoot '.tools\lock-venv\Scripts\python.exe'
$compiler = Join-Path $repoRoot '.tools\lock-venv\Scripts\pip-compile.exe'
$requirementsPath = Join-Path $repoRoot 'requirements-dev.txt'
$lockToolsRequirementsPath = Join-Path $repoRoot 'requirements-lock-tools.txt'
$lockPath = Join-Path $repoRoot 'requirements-dev.lock'
$manifestPath = Join-Path $repoRoot '.config\tool-versions.yml'

function Get-NormalizedPackageName {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [regex]::Replace($Name, '[-_.]+', '-').ToLowerInvariant()
}

function Get-PackagePinMap {
    param([Parameter(Mandatory = $true)][string]$Path)
    $pins = @{}
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $value = $line.Trim()
        if (-not $value -or $value.StartsWith('#')) { continue }
        if ($value -match '^--hash=sha256:[a-fA-F0-9]{64}$') { continue }
        $value = ($value -split ';', 2)[0].Trim()
        $value = $value.TrimEnd('\').Trim()
        $match = [regex]::Match($value, '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$')
        if (-not $match.Success) { throw "Requirement is not an exact pin in $Path : $line" }
        $name = Get-NormalizedPackageName -Name $match.Groups['name'].Value
        $version = $match.Groups['version'].Value
        if ($pins.ContainsKey($name) -and $pins[$name] -ne $version) { throw "Conflicting versions for $name in $Path." }
        $pins[$name] = $version
    }
    return $pins
}

function Get-PackageHashMap {
    param([Parameter(Mandatory = $true)][string]$Path)
    $hashes = @{}
    $currentPackage = $null
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $value = $line.Trim()
        $pinMatch = [regex]::Match($value, '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*\\?$')
        if ($pinMatch.Success) {
            $currentPackage = Get-NormalizedPackageName -Name $pinMatch.Groups['name'].Value
            if ($hashes.ContainsKey($currentPackage)) { throw "Duplicate package block in ${Path}: $currentPackage" }
            $hashes[$currentPackage] = New-Object System.Collections.Generic.List[string]
            continue
        }
        $hashMatch = [regex]::Match($value, '^--hash=sha256:(?<hash>[a-fA-F0-9]{64})$')
        if ($hashMatch.Success) {
            if (-not $currentPackage) { throw "Orphan hash entry in $Path." }
            $hashes[$currentPackage].Add($hashMatch.Groups['hash'].Value.ToLowerInvariant())
        } elseif ($value -and -not $value.StartsWith('#')) { $currentPackage = $null }
    }
    $missingHashes = @($hashes.Keys | Where-Object { $hashes[$_].Count -eq 0 })
    if ($missingHashes.Count -gt 0) { throw "Packages without hashes in ${Path}: $($missingHashes -join ', ')" }
    return $hashes
}

function Assert-PackageHashMapsEqual {
    param([hashtable]$Expected, [hashtable]$Actual, [string]$Description)
    $names = @($Expected.Keys + $Actual.Keys | Sort-Object -Unique)
    $differences = @($names | Where-Object {
        -not $Expected.ContainsKey($_) -or -not $Actual.ContainsKey($_) -or
        (@($Expected[$_] | Sort-Object) -join ',') -ne (@($Actual[$_] | Sort-Object) -join ',')
    })
    if ($differences.Count -gt 0) { throw "${Description}: $($differences -join ', ')" }
}

function Write-HashedPackageLock {
    param(
        [Parameter(Mandatory = $true)][string]$RequirementsPath,
        [Parameter(Mandatory = $true)][string]$ReportPath,
        [Parameter(Mandatory = $true)][string]$WheelDirectory,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )
    $pins = Get-PackagePinMap -Path $RequirementsPath
    $report = Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    $hashByName = @{}
    foreach ($item in @($report.install)) {
        $name = Get-NormalizedPackageName -Name ([string]$item.metadata.name)
        $version = [string]$item.metadata.version
        if (-not $pins.ContainsKey($name) -or $pins[$name] -ne $version -or $hashByName.ContainsKey($name)) { throw "PyPI report does not match the exact lock pin: $name $version" }
        $uri = [Uri]$item.download_info.url
        if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'files.pythonhosted.org') { throw "Wheel source is not official PyPI: $($item.download_info.url)" }
        $filename = [IO.Path]::GetFileName($uri.AbsolutePath)
        if ([IO.Path]::GetExtension($filename) -ne '.whl') { throw "Wheel artifact expected for $name; got $filename" }
        $expectedHash = [string]$item.download_info.archive_info.hashes.sha256
        if ($expectedHash -notmatch '^[a-fA-F0-9]{64}$') { throw "PyPI SHA-256 missing for $name" }
        $wheelPath = Join-Path $WheelDirectory $filename
        if (-not (Test-Path -LiteralPath $wheelPath -PathType Leaf)) { throw "Downloaded wheel missing: $filename" }
        $actualHash = (Get-FileHash -LiteralPath $wheelPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $expectedHash.ToLowerInvariant()) { throw "Downloaded wheel SHA-256 differs from PyPI report: $name" }
        $hashByName[$name] = $actualHash
    }
    if ($hashByName.Count -ne $pins.Count) { throw "Incomplete PyPI wheel report: $($hashByName.Count)/$($pins.Count) packages." }
    $outputLines = New-Object System.Collections.Generic.List[string]
    foreach ($line in Get-Content -LiteralPath $RequirementsPath -Encoding UTF8) {
        $pinMatch = [regex]::Match($line.Trim(), '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)\s*\\?$')
        if ($pinMatch.Success) {
            $name = Get-NormalizedPackageName -Name $pinMatch.Groups['name'].Value
            $outputLines.Add(($line.Trim().TrimEnd('\').Trim()) + ' \')
            $outputLines.Add("    --hash=sha256:$($hashByName[$name])")
        } else { $outputLines.Add($line) }
    }
    [System.IO.File]::WriteAllLines($OutputPath, [string[]]$outputLines, [System.Text.UTF8Encoding]::new($false))
    $null = Get-PackageHashMap -Path $OutputPath
}

function Get-ManifestPythonPinMap {
    param([Parameter(Mandatory = $true)][string]$Path)
    $manifest = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $blockMatch = [regex]::Match($manifest, '(?ms)^python_packages:\s*\r?\n(?<block>.*?)(?=^[A-Za-z][A-Za-z0-9_-]*:\s*$|\z)')
    if (-not $blockMatch.Success) { throw 'python_packages section is missing from tool-versions.yml.' }
    $pins = @{}
    $records = [regex]::Matches($blockMatch.Groups['block'].Value, '(?m)^  - name: (?<name>[A-Za-z0-9_.-]+)\r?\n    version: "(?<version>[^"]+)"')
    foreach ($record in $records) {
        $name = Get-NormalizedPackageName -Name $record.Groups['name'].Value
        if ($pins.ContainsKey($name)) { throw "Duplicate package in tool-versions.yml: $name" }
        $pins[$name] = $record.Groups['version'].Value
    }
    if ($pins.Count -eq 0) { throw 'No Python pins found in tool-versions.yml.' }
    return $pins
}

function Assert-PinMapsEqual {
    param([hashtable]$Expected, [hashtable]$Actual, [string]$Description)
    $names = @($Expected.Keys + $Actual.Keys | Sort-Object -Unique)
    $differences = @($names | Where-Object { $Expected[$_] -ne $Actual[$_] })
    if ($differences.Count -gt 0) {
        $details = @($differences | ForEach-Object { "$_ requirements=$($Expected[$_]) actual=$($Actual[$_])" }) -join '; '
        throw "${Description}: $details"
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'The requirements-dev lock is qualified for Windows x64 only.' }
if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $lockToolsPython -PathType Leaf) -or -not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Python and the pinned lock-tool venv must be installed by bootstrap.' }
if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) { throw 'requirements-dev.lock is missing.' }

$requirementsPins = Get-PackagePinMap -Path $requirementsPath
$lockToolPins = Get-PackagePinMap -Path $lockToolsRequirementsPath
$manifestPins = Get-ManifestPythonPinMap -Path $manifestPath
Assert-PinMapsEqual -Expected $requirementsPins -Actual $manifestPins -Description 'Pins directs divergents entre requirements-dev.txt et tool-versions.yml'
$compilerVersionOutput = (& $compiler --version 2>&1) -join ' '
if ($LASTEXITCODE -ne 0) { throw "Unable to run pip-compile: $compilerVersionOutput" }
$compilerVersionMatch = [regex]::Match($compilerVersionOutput, 'version\s+(?<version>[0-9][^\s]*)')
if (-not $compilerVersionMatch.Success -or $compilerVersionMatch.Groups['version'].Value -ne $lockToolPins['pip-tools']) {
    throw "Installed pip-tools differs from the pin: $compilerVersionOutput"
}
$lockPins = Get-PackagePinMap -Path $lockPath
if ($Check) {
    foreach ($name in $requirementsPins.Keys) {
        if (-not $lockPins.ContainsKey($name) -or $lockPins[$name] -ne $requirementsPins[$name]) { throw "Direct pin is missing or differs in lock: $name" }
    }
}

$cachePath = Join-Path $repoRoot '.tools\cache\locks'
New-Item -ItemType Directory -Path $cachePath -Force | Out-Null
$candidatePath = Join-Path $cachePath 'requirements-dev.lock.generated'
$hashCandidatePath = Join-Path $cachePath 'requirements-dev.lock.hashed'
$wheelReportPath = Join-Path $cachePath ("wheel-provenance.$([guid]::NewGuid().ToString('N')).json")
$wheelStagePath = Join-Path $cachePath ("wheel-stage.$([guid]::NewGuid().ToString('N'))")
$wheelCachePath = Join-Path $repoRoot '.tools/cache/wheels'
$constraintsPath = Join-Path $cachePath 'requirements-dev.lock.constraints'
$relativeCandidatePath = '.tools/cache/locks/requirements-dev.lock.generated'
$relativeConstraintsPath = '.tools/cache/locks/requirements-dev.lock.constraints'
$backupPath = Join-Path $cachePath ('requirements-dev.lock.' + [guid]::NewGuid().ToString('N') + '.bak')
try {
    $compileArguments = @('--quiet', '--resolver=backtracking', '--strip-extras', '--allow-unsafe', '--pip-args=--retries=0 --timeout=20', '--output-file', $relativeCandidatePath)
    if ($Check) { $compileArguments += @('--constraint', 'requirements-dev.lock') }
    elseif ($UpgradeAll) { $compileArguments += '--upgrade' }
    elseif ($Update) {
        $changedDirectPins = @($requirementsPins.Keys | Where-Object { -not $lockPins.ContainsKey($_) -or $lockPins[$_] -ne $requirementsPins[$_] })
        $constraintLines = @(Get-Content -LiteralPath $lockPath -Encoding UTF8 | Where-Object {
            $lineMatch = [regex]::Match($_, '^\s*(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==')
            -not $lineMatch.Success -or (Get-NormalizedPackageName -Name $lineMatch.Groups['name'].Value) -notin $changedDirectPins
        })
        [System.IO.File]::WriteAllLines($constraintsPath, [string[]]$constraintLines, [System.Text.UTF8Encoding]::new($false))
        $compileArguments += @('--constraint', $relativeConstraintsPath)
        foreach ($name in $changedDirectPins) { $compileArguments += @('--upgrade-package', $name) }
    }
    $compileArguments += 'requirements-dev.txt'
    Push-Location $repoRoot
    try {
        & $compiler @compileArguments | Out-Null
        $compileExitCode = $LASTEXITCODE
    } finally { Pop-Location }
    if ($compileExitCode -ne 0) { throw "pip-compile failed with exit code $compileExitCode." }

    $candidatePins = Get-PackagePinMap -Path $candidatePath
    foreach ($name in $requirementsPins.Keys) {
        if (-not $candidatePins.ContainsKey($name) -or $candidatePins[$name] -ne $requirementsPins[$name]) { throw "Generated lock does not preserve direct pin $name." }
    }
    New-Item -ItemType Directory -Path $wheelStagePath -Force | Out-Null
    $wheelReportArguments = @('-m', 'pip', 'install', '--quiet', '--dry-run', '--ignore-installed', '--no-deps', '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--report', $wheelReportPath, '-r', $candidatePath)
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $python @wheelReportArguments 2>&1 | Out-Null
        $wheelReportExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($wheelReportExitCode -ne 0) { throw "Unable to resolve official PyPI wheel provenance (exit=$wheelReportExitCode)." }
    $wheelDownloadArguments = @('-m', 'pip', 'download', '--quiet', '--no-deps', '--only-binary=:all:', '--index-url', 'https://pypi.org/simple', '--dest', $wheelStagePath, '-r', $candidatePath)
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $python @wheelDownloadArguments 2>&1 | Out-Null
        $wheelDownloadExitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $previousPreference }
    if ($wheelDownloadExitCode -ne 0) { throw "Unable to acquire official PyPI wheels (exit=$wheelDownloadExitCode)." }
    Write-HashedPackageLock -RequirementsPath $candidatePath -ReportPath $wheelReportPath -WheelDirectory $wheelStagePath -OutputPath $hashCandidatePath
    Assert-PinMapsEqual -Expected $candidatePins -Actual (Get-PackagePinMap -Path $hashCandidatePath) -Description 'Hashed lock changed package pins'
    $candidateHashes = Get-PackageHashMap -Path $hashCandidatePath
    if ($Check) {
        Assert-PinMapsEqual -Expected $lockPins -Actual $candidatePins -Description 'requirements-dev.lock is stale; run scripts/update-lock.ps1 -Update'
        Assert-PackageHashMapsEqual -Expected (Get-PackageHashMap -Path $lockPath) -Actual $candidateHashes -Description 'Artifact hashes are stale in requirements-dev.lock'
        $installedOutput = & $python -m pip list --format=json
        if ($LASTEXITCODE -ne 0) { throw 'Unable to read installed package versions in .venv.' }
        $installedPackages = ConvertFrom-Json -InputObject ($installedOutput -join "`n")
        $installedPins = @{}
        foreach ($package in $installedPackages) { $installedPins[(Get-NormalizedPackageName -Name $package.name)] = [string]$package.version }
        foreach ($name in $lockPins.Keys) {
            if (-not $installedPins.ContainsKey($name) -or $installedPins[$name] -ne $lockPins[$name]) { throw "Installed version differs from lock for $name; rebuild .venv." }
        }
        $lockToolOutput = & $lockToolsPython -m pip list --format=json
        if ($LASTEXITCODE -ne 0) { throw 'Unable to read lock-tool environment package versions.' }
        $lockToolPackages = ConvertFrom-Json -InputObject ($lockToolOutput -join "`n")
        $installedLockToolPins = @{}
        foreach ($package in $lockToolPackages) { $installedLockToolPins[(Get-NormalizedPackageName -Name $package.name)] = [string]$package.version }
        foreach ($name in $lockToolPins.Keys) {
            if (-not $installedLockToolPins.ContainsKey($name) -or $installedLockToolPins[$name] -ne $lockToolPins[$name]) { throw "Lock-tool version differs for $name; rebuild .tools/lock-venv." }
        }
        & $python -m pip check
        if ($LASTEXITCODE -ne 0) { throw 'pip check found incompatible dependencies in .venv.' }
        & $lockToolsPython -m pip check
        if ($LASTEXITCODE -ne 0) { throw 'pip check found incompatible dependencies in .tools/lock-venv.' }
        Write-Information -InformationAction Continue "[PASS] Lock consistent: $($lockPins.Count) project packages, $($requirementsPins.Count) project pins, $($lockToolPins.Count) lock-tool pins, pip-tools $($lockToolPins['pip-tools'])."
    } else {
        foreach ($item in (Get-Content -LiteralPath $wheelReportPath -Raw -Encoding UTF8 | ConvertFrom-Json).install) {
            $filename = [IO.Path]::GetFileName(([Uri]$item.download_info.url).AbsolutePath)
            $sourceWheel = Join-Path $wheelStagePath $filename
            $cachedWheel = Join-Path $wheelCachePath $filename
            if (Test-Path -LiteralPath $cachedWheel -PathType Leaf) {
                if ((Get-FileHash -LiteralPath $cachedWheel -Algorithm SHA256).Hash.ToLowerInvariant() -ne ([string]$item.download_info.archive_info.hashes.sha256).ToLowerInvariant()) { throw "Cached wheel hash mismatch: $filename" }
                Remove-Item -LiteralPath $sourceWheel -Force
            } else {
                New-Item -ItemType Directory -Path $wheelCachePath -Force | Out-Null
                Move-Item -LiteralPath $sourceWheel -Destination $cachedWheel
            }
        }
        [System.IO.File]::Replace($hashCandidatePath, $lockPath, $backupPath)
        Remove-Item -LiteralPath $backupPath -Force
        $finalLockHash = (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $runtimeReportPath = Join-Path (Join-Path $repoRoot '.tools/cache') "python-wheel-provenance-$finalLockHash.json"
        $temporaryRuntimeReport = "$runtimeReportPath.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            Copy-Item -LiteralPath $wheelReportPath -Destination $temporaryRuntimeReport
            Move-Item -LiteralPath $temporaryRuntimeReport -Destination $runtimeReportPath -Force
        } finally { if (Test-Path -LiteralPath $temporaryRuntimeReport -PathType Leaf) { Remove-Item -LiteralPath $temporaryRuntimeReport -Force } }
        Write-Information -InformationAction Continue "[PASS] Hashed lock regenerated with $($candidatePins.Count) packages and $($candidateHashes.Count) PyPI wheel hashes; run bootstrap then scripts/update-lock.ps1 -Check."
    }
} finally {
    if (Test-Path -LiteralPath $candidatePath -PathType Leaf) { Remove-Item -LiteralPath $candidatePath -Force }
    if (Test-Path -LiteralPath $hashCandidatePath -PathType Leaf) { Remove-Item -LiteralPath $hashCandidatePath -Force }
    if (Test-Path -LiteralPath $wheelReportPath -PathType Leaf) { Remove-Item -LiteralPath $wheelReportPath -Force }
    if (Test-Path -LiteralPath $wheelStagePath -PathType Container) { Remove-Item -LiteralPath $wheelStagePath -Recurse -Force }
    if (Test-Path -LiteralPath $constraintsPath -PathType Leaf) { Remove-Item -LiteralPath $constraintsPath -Force }
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) { Remove-Item -LiteralPath $backupPath -Force }
}
