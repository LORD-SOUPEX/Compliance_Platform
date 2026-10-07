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
        $value = ($value -split ';', 2)[0].Trim()
        $match = [regex]::Match($value, '^(?<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*(?<version>[A-Za-z0-9][A-Za-z0-9.!+_-]*)$')
        if (-not $match.Success) { throw "Requirement is not an exact pin in $Path : $line" }
        $name = Get-NormalizedPackageName -Name $match.Groups['name'].Value
        $version = $match.Groups['version'].Value
        if ($pins.ContainsKey($name) -and $pins[$name] -ne $version) { throw "Conflicting versions for $name in $Path." }
        $pins[$name] = $version
    }
    return $pins
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
$constraintsPath = Join-Path $cachePath 'requirements-dev.lock.constraints'
$relativeCandidatePath = '.tools/cache/locks/requirements-dev.lock.generated'
$relativeConstraintsPath = '.tools/cache/locks/requirements-dev.lock.constraints'
$backupPath = Join-Path $cachePath ('requirements-dev.lock.' + [guid]::NewGuid().ToString('N') + '.bak')
try {
    $compileArguments = @('--quiet', '--resolver=backtracking', '--strip-extras', '--allow-unsafe', '--output-file', $relativeCandidatePath)
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
    if ($Check) {
        Assert-PinMapsEqual -Expected $lockPins -Actual $candidatePins -Description 'requirements-dev.lock is stale; run scripts/update-lock.ps1 -Update'
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
        [System.IO.File]::Replace($candidatePath, $lockPath, $backupPath)
        Remove-Item -LiteralPath $backupPath -Force
        Write-Information -InformationAction Continue "[PASS] Lock regenerated with $($candidatePins.Count) packages; run bootstrap then scripts/update-lock.ps1 -Check."
    }
} finally {
    if (Test-Path -LiteralPath $candidatePath -PathType Leaf) { Remove-Item -LiteralPath $candidatePath -Force }
    if (Test-Path -LiteralPath $constraintsPath -PathType Leaf) { Remove-Item -LiteralPath $constraintsPath -Force }
    if (Test-Path -LiteralPath $backupPath -PathType Leaf) { Remove-Item -LiteralPath $backupPath -Force }
}
