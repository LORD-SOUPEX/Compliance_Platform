[CmdletBinding()]
param(
    [switch]$Force,
    [switch]$Offline,
    [switch]$SkipOptionalTools,
    [switch]$NoColor
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolsRoot = Join-Path $repoRoot '.tools'
$cacheRoot = Join-Path $toolsRoot 'cache'
$binRoot = Join-Path $toolsRoot 'bin'
$runtimeRoot = Join-Path $toolsRoot 'runtime'
$runtimeIndexPath = Join-Path $runtimeRoot 'index.json'
$script:RuntimePlatform = $null
$moduleRoot = Join-Path $toolsRoot 'powershell-modules'
$venvRoot = Join-Path $repoRoot '.venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'
$requirementsPath = Join-Path $repoRoot 'requirements-dev.txt'
$dependencyLock = Join-Path $repoRoot 'requirements-dev.lock'
$manifestPath = Join-Path $repoRoot '.config\tool-versions.yml'
if ($NoColor) { $env:NO_COLOR = '1' }

function Write-Status {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('INFO', 'PASS', 'WARN', 'ERROR')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Message
    )
    Write-Information -InformationAction Continue "[$Status] $Message"
}

function Get-ManifestBlock {
    param([string]$Text, [string]$Name, [int]$Indent = 0)
    $spaces = ' ' * $Indent
    $escapedName = [regex]::Escape($Name)
    $pattern = '(?ms)^' + $spaces + $escapedName + ':\s*\r?\n(?<body>.*?)(?=^' + $spaces + '[A-Za-z0-9_-]+:\s*$|\z)'
    $match = [regex]::Match($Text, $pattern)
    if (-not $match.Success) { throw "Section absente du manifeste : $Name" }
    return $match.Groups['body'].Value
}

function Get-ManifestValue {
    param([string]$Block, [string]$Name, [int]$Indent = 2)
    $spaces = ' ' * $Indent
    $escapedName = [regex]::Escape($Name)
    $pattern = '(?m)^' + $spaces + $escapedName + ':\s*(?<value>[^\r\n]+)\s*$'
    $match = [regex]::Match($Block, $pattern)
    if (-not $match.Success) { throw "Valeur absente du manifeste : $Name" }
    return $match.Groups['value'].Value.Trim().Trim([char[]]@('"', "'"))
}

function Get-ToolBlock {
    param([string]$Section, [string]$Name)
    return Get-ManifestBlock -Text $Section -Name $Name -Indent 2
}

function Invoke-CheckedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )
    & $FilePath @Arguments
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw "La commande '$Description' a échoué avec le code $exitCode." }
}

function Repair-PreCommitCache {
    param(
        [Parameter(Mandatory = $true)][string]$CacheRoot,
        [Parameter(Mandatory = $true)][string]$PythonPath,
        [switch]$Offline
    )
    $databasePath = Join-Path $CacheRoot 'db.db'
    if (-not (Test-Path -LiteralPath $databasePath -PathType Leaf)) { return }
    $probe = 'import json,pathlib,sqlite3,sys; connection=sqlite3.connect(pathlib.Path(sys.argv[1]).resolve().as_uri()+"?mode=ro",uri=True); print(json.dumps([row[0] for row in connection.execute("SELECT path FROM repos")])); connection.close()'
    $output = $probe | & $PythonPath - $databasePath
    if ($LASTEXITCODE -ne 0) { throw 'Impossible de verifier la base du cache pre-commit.' }
    $registeredPaths = $output | ConvertFrom-Json
    $cachePrefix = [IO.Path]::GetFullPath($CacheRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $stalePaths = @($registeredPaths | Where-Object {
        -not ([IO.Path]::GetFullPath($_).StartsWith($cachePrefix, [StringComparison]::OrdinalIgnoreCase)) -or
        -not (Test-Path -LiteralPath $_ -PathType Container)
    })
    if ($stalePaths.Count -eq 0) { return }
    if ($Offline) { throw 'Cache pre-commit deplace ou incomplet; reconstruction en ligne requise.' }
    $previousCache = $env:PRE_COMMIT_HOME
    try {
        $env:PRE_COMMIT_HOME = [IO.Path]::GetFullPath($CacheRoot)
        Invoke-CheckedCommand -FilePath $PythonPath -Arguments @('-m', 'pre_commit', 'clean') -Description 'reconstruction du cache pre-commit deplace'
    } finally { $env:PRE_COMMIT_HOME = $previousCache }
    Write-Status INFO 'Cache pre-commit deplace ou incomplet nettoye; les hooks seront reconstruits.'
}

function Get-CachePath {
    param([string]$Name)
    return Join-Path $cacheRoot $Name
}

function Initialize-WindowsCaBundle {
    $bundlePath = Join-Path $cacheRoot 'windows-root-ca.pem'
    if (Test-Path $bundlePath -PathType Leaf) { return $bundlePath }
    $certificates = @(Get-ChildItem -Path 'Cert:\CurrentUser\Root','Cert:\LocalMachine\Root' -ErrorAction SilentlyContinue)
    if ($certificates.Count -eq 0) { throw 'Aucun certificat racine de confiance ne peut être lu depuis Windows.' }
    $lines = New-Object System.Collections.Generic.List[string]
    foreach ($certificate in $certificates) {
        $base64 = [Convert]::ToBase64String($certificate.RawData)
        $lines.Add('-----BEGIN CERTIFICATE-----')
        for ($offset = 0; $offset -lt $base64.Length; $offset += 64) {
            $length = [Math]::Min(64, $base64.Length - $offset)
            $lines.Add($base64.Substring($offset, $length))
        }
        $lines.Add('-----END CERTIFICATE-----')
    }
    Set-Content -LiteralPath $bundlePath -Value $lines -Encoding ASCII
    Write-Status INFO 'Bundle temporaire préparé depuis les autorités racines Windows approuvées.'
    return $bundlePath
}

function Get-VerifiedDownload {
    param([string]$Uri, [string]$Path, [string]$Sha256, [string]$Description)
    if (-not (Test-Path $Path -PathType Leaf)) {
        if ($Offline) { throw "Mode hors ligne : archive absente du cache pour $Description ($Path)." }
        Write-Status INFO "Téléchargement depuis la source officielle : $Description"
        Invoke-WebRequest -Uri $Uri -OutFile $Path -UseBasicParsing -TimeoutSec 180
    }
    if ($Sha256) {
        $actualHash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -ne $Sha256.ToLowerInvariant()) { throw "SHA-256 invalide pour $Description : $actualHash" }
        Write-Status PASS "Empreinte SHA-256 vérifiée : $Description"
    }
    return $Path
}

function Test-PythonCandidate {
    param([string]$Executable, [string[]]$Prefix = @())
    if (-not (Test-Path $Executable -PathType Leaf) -and -not (Get-Command $Executable -ErrorAction SilentlyContinue)) { return $null }
    $probe = 'import sys; print(sys.version_info.major, sys.version_info.minor, sys.version.split()[0], sys.executable, sep=chr(124))'
    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Executable @Prefix -c $probe 2>&1
        $exitCode = $LASTEXITCODE
    } catch {
        $ErrorActionPreference = $previousErrorAction
        return $null
    }
    $ErrorActionPreference = $previousErrorAction
    if ($exitCode -ne 0) { return $null }
    try {
        $parts = (($output | Select-Object -Last 1) -split '\|', 4)
        if ($parts.Count -eq 4 -and $parts[0] -eq '3' -and $parts[1] -eq '11') {
            $details = [pscustomobject]@{ version = $parts[2]; executable = $parts[3]; major = 3; minor = 11 }
            return [pscustomobject]@{ Path = $Executable; Prefix = $Prefix; Details = $details }
        }
    } catch { return $null }
    return $null
}

function Register-ToolRuntimeEntry {
    param(
        [Parameter(Mandatory = $true)][string]$ToolName,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$SourcePath,
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$PlatformId
    )
    $runtimeIndexPath = Join-Path $RuntimeRoot 'index.json'
    if (-not (Test-Path -LiteralPath $SourcePath -PathType Leaf)) { throw "Binaire source absent pour le runtime : $SourcePath" }
    $toolDirectory = Join-Path (Join-Path $RuntimeRoot $PlatformId) (Join-Path $ToolName $Version)
    New-Item -ItemType Directory -Path $toolDirectory -Force | Out-Null
    $binaryName = Split-Path -Leaf $SourcePath
    $runtimeBinary = Join-Path $toolDirectory $binaryName
    Copy-Item -LiteralPath $SourcePath -Destination $runtimeBinary -Force
    $sourceHash = (Get-FileHash -LiteralPath $SourcePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $runtimeHash = (Get-FileHash -LiteralPath $runtimeBinary -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($sourceHash -ne $runtimeHash) { throw "L'intégrité du binaire copié dans le Tool Runtime est invalide : $ToolName $Version" }

    $index = if (Test-Path -LiteralPath $runtimeIndexPath -PathType Leaf) {
        try { Get-Content -LiteralPath $runtimeIndexPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "Index Tool Runtime invalide : $($_.Exception.Message)" }
    } else {
        [pscustomobject]@{ schema_version = 1; platforms = [pscustomobject]@{} }
    }
    if ($index.schema_version -ne 1 -or -not $index.platforms) { throw 'Schéma index Tool Runtime non supporté.' }
    $platformProperty = $index.platforms.PSObject.Properties[$PlatformId]
    if (-not $platformProperty) {
        $platformData = [pscustomobject]@{ status = 'experimental'; tools = @() }
        $index.platforms | Add-Member -MemberType NoteProperty -Name $PlatformId -Value $platformData
    } else {
        $platformData = $platformProperty.Value
        if ($platformData.status -notin @('qualified', 'experimental', 'targeted')) { throw "Statut plateforme Tool Runtime invalide : $PlatformId" }
    }
    $retainedTools = @($platformData.tools | Where-Object { $_.name -ne $ToolName -or $_.version -ne $Version })
    foreach ($installedTool in $retainedTools) {
        if ($installedTool.name -eq $ToolName) { $installedTool.active = $false }
    }
    $runtimePrefix = $RuntimeRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $relativeBinary = $runtimeBinary.Substring($runtimePrefix.Length).Replace('\', '/')
    $runtimeTool = [pscustomobject]@{
        name = $ToolName
        command = $ToolName
        version = $Version
        path = $relativeBinary
        sha256 = $runtimeHash
        status = 'qualified'
        active = $true
    }
    $platformData.tools = @($retainedTools + $runtimeTool)

    if (-not (Test-Path $RuntimeRoot -PathType Container)) { New-Item -ItemType Directory -Path $RuntimeRoot -Force | Out-Null }
    $temporaryIndex = Join-Path $RuntimeRoot ("runtime-index.$([guid]::NewGuid().ToString('N')).tmp")
    try {
        $index | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporaryIndex -Encoding UTF8
        Move-Item -LiteralPath $temporaryIndex -Destination $runtimeIndexPath -Force
    } finally {
        if (Test-Path -LiteralPath $temporaryIndex -PathType Leaf) { Remove-Item -LiteralPath $temporaryIndex -Force }
    }
    Write-Status PASS "$ToolName $Version enregistré et vérifié dans Tool Runtime ($PlatformId)."
}

function Update-ToolRuntimePlatformStatus {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeRoot,
        [Parameter(Mandatory = $true)][string]$PlatformId,
        [Parameter(Mandatory = $true)][ValidateSet('targeted', 'experimental', 'qualified')][string]$Status
    )
    $indexPath = Join-Path $RuntimeRoot 'index.json'
    $index = if (Test-Path -LiteralPath $indexPath -PathType Leaf) {
        Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    } else {
        [pscustomobject]@{ schema_version = 1; platforms = [pscustomobject]@{} }
    }
    if ($index.schema_version -ne 1 -or -not $index.platforms) { throw 'Schéma index Tool Runtime non supporté.' }
    $platformProperty = $index.platforms.PSObject.Properties[$PlatformId]
    if (-not $platformProperty) {
        if ($Status -eq 'qualified') { throw "Plateforme Tool Runtime absente de l'index : $PlatformId" }
        $platformProperty = [pscustomobject]@{ status = $Status; tools = @() }
        $index.platforms | Add-Member -MemberType NoteProperty -Name $PlatformId -Value $platformProperty
    }
    if ($Status -eq 'qualified' -and @($platformProperty.Value.tools | Where-Object { $_.active -and $_.status -eq 'qualified' }).Count -eq 0) {
        throw "Aucun outil qualifié dans le Tool Runtime pour $PlatformId."
    }
    if ($PSCmdlet.ShouldProcess($indexPath, "Qualifier la plateforme $PlatformId avec le statut $Status")) {
        $platformProperty.Value.status = $Status
        if ($Status -eq 'qualified') {
            $platformProperty.Value | Add-Member -MemberType NoteProperty -Name qualified_at -Value (Get-Date).ToString('o') -Force
        }
        $temporaryIndex = Join-Path $RuntimeRoot ("runtime-index.$([guid]::NewGuid().ToString('N')).tmp")
        try {
            $index | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporaryIndex -Encoding UTF8
            Move-Item -LiteralPath $temporaryIndex -Destination $indexPath -Force
        } finally {
            if (Test-Path -LiteralPath $temporaryIndex -PathType Leaf) { Remove-Item -LiteralPath $temporaryIndex -Force }
        }
    }
}

function Get-PythonRuntime {
    $localPython = Join-Path $toolsRoot 'python\python.exe'
    $candidate = Test-PythonCandidate -Executable $localPython
    if ($candidate) {
        Write-Status INFO 'Source Python : runtime local du dépôt.'
        return $candidate
    }

    $launcher = Get-Command py -ErrorAction SilentlyContinue
    if ($launcher) {
        $candidate = Test-PythonCandidate -Executable $launcher.Source -Prefix @('-3.11')
        if ($candidate) { Write-Status INFO 'Source Python : lanceur py -3.11.'; return $candidate }
    }

    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        $candidate = Test-PythonCandidate -Executable $pythonCommand.Source
        if ($candidate) { Write-Status INFO 'Source Python : commande python.'; return $candidate }
    }

    $knownPaths = New-Object System.Collections.Generic.List[string]
    foreach ($path in @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'),
        (Join-Path $env:USERPROFILE 'AppData\Local\Programs\Python\Python311\python.exe'),
        (Join-Path $env:ProgramFiles 'Python311\python.exe'),
        'C:\Program Files\Python\python.exe'
    )) { $knownPaths.Add($path) }
    foreach ($registryPath in @('HKCU:\Software\Python\PythonCore\3.11\InstallPath', 'HKLM:\Software\Python\PythonCore\3.11\InstallPath', 'HKLM:\Software\WOW6432Node\Python\PythonCore\3.11\InstallPath')) {
        if (Test-Path $registryPath) {
            $installPath = (Get-Item $registryPath).GetValue('')
            if ($installPath) { $knownPaths.Add((Join-Path $installPath 'python.exe')) }
        }
    }
    foreach ($path in ($knownPaths | Select-Object -Unique)) {
        $candidate = Test-PythonCandidate -Executable $path
        if ($candidate) { Write-Status INFO "Source Python : installation existante de l'utilisateur."; return $candidate }
    }

    $pythonBlock = Get-ManifestBlock -Text $script:Manifest -Name 'python'
    $pythonVersion = Get-ManifestValue -Block $pythonBlock -Name 'version'
    $pythonUri = Get-ManifestValue -Block $pythonBlock -Name 'source'
    $pythonHash = Get-ManifestValue -Block $pythonBlock -Name 'sha256'
    $archiveName = Split-Path -Leaf $pythonUri
    $archivePath = Get-VerifiedDownload -Uri $pythonUri -Path (Get-CachePath $archiveName) -Sha256 $pythonHash -Description "runtime Python $pythonVersion"
    $staging = Join-Path $cacheRoot 'python-runtime-staging'
    if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::ExtractToDirectory($archivePath, $staging)
    $stagedPython = Get-ChildItem -Path $staging -Filter 'python.exe' -File -Recurse | Select-Object -First 1
    if (-not $stagedPython) { throw "L’archive Python officielle ne contient pas python.exe : $archiveName" }
    $runtimeRoot = Join-Path $toolsRoot 'python'
    if (Test-Path $runtimeRoot) { Remove-Item -LiteralPath $runtimeRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
    Get-ChildItem -Path $staging -Force | Copy-Item -Destination $runtimeRoot -Recurse -Force
    Remove-Item -LiteralPath $staging -Recurse -Force
    $candidate = Test-PythonCandidate -Executable $localPython
    if (-not $candidate) { throw 'Le runtime Python local extrait ne démarre pas correctement.' }
    Write-Status INFO 'Source Python : runtime local du dépôt.'
    return $candidate
}

function Install-BinaryTool {
    param([string]$ToolName)
    $toolBlock = Get-ToolBlock -Section $script:BinaryTools -Name $ToolName
    $version = Get-ManifestValue -Block $toolBlock -Name 'version' -Indent 4
    $baseUri = Get-ManifestValue -Block $toolBlock -Name 'source' -Indent 4
    $asset = Get-ManifestValue -Block $toolBlock -Name 'asset' -Indent 4
    $checksumAsset = Get-ManifestValue -Block $toolBlock -Name 'checksum_asset' -Indent 4
    $checksumAssetHash = Get-ManifestValue -Block $toolBlock -Name 'checksum_asset_sha256' -Indent 4
    $localRelativePath = Get-ManifestValue -Block $toolBlock -Name 'local_path' -Indent 4
    $destination = Join-Path $repoRoot ($localRelativePath -replace '/', '\')
    $manifestCache = Get-CachePath "$ToolName-$version-$checksumAsset"
    $assetCache = Get-CachePath $asset

    if ((Test-Path $destination -PathType Leaf) -and -not $Force) {
        $versionArgs = Get-ManifestValue -Block $toolBlock -Name 'version_args' -Indent 4
        $versionOutput = & $destination @($versionArgs -split ' ') 2>&1
        if ($LASTEXITCODE -eq 0 -and ($versionOutput -join ' ') -match [regex]::Escape($version)) {
            Register-ToolRuntimeEntry -ToolName $ToolName -Version $version -SourcePath $destination -RuntimeRoot $runtimeRoot -PlatformId $script:RuntimePlatform
            Write-Status PASS "$ToolName $version déjà présent dans .tools/bin."
            return
        }
    }

    $null = Get-VerifiedDownload -Uri "$baseUri/$checksumAsset" -Path $manifestCache -Sha256 $checksumAssetHash -Description "manifeste SHA-256 de $ToolName $version"
    $manifestText = [System.IO.File]::ReadAllText($manifestCache, [System.Text.Encoding]::UTF8)
    $assetPattern = '(?m)^([A-Fa-f0-9]{64})\s+\*?' + [regex]::Escape($asset) + '\s*$'
    $assetMatch = [regex]::Match($manifestText, $assetPattern)
    if (-not $assetMatch.Success) { throw "Le manifeste officiel de $ToolName ne contient pas l’archive '$asset'." }
    $null = Get-VerifiedDownload -Uri "$baseUri/$asset" -Path $assetCache -Sha256 $assetMatch.Groups[1].Value -Description "$ToolName $version"

    $staging = Join-Path $cacheRoot "$ToolName-extract"
    if (Test-Path $staging) { Remove-Item -LiteralPath $staging -Recurse -Force }
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    if ([IO.Path]::GetExtension($asset) -eq '.zip') {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory($assetCache, $staging)
        $toolFileName = Split-Path -Leaf $destination
        $extracted = Get-ChildItem -Path $staging -Filter $toolFileName -File -Recurse | Select-Object -First 1
        if (-not $extracted) { throw "Binaire attendu absent de l’archive $asset : $toolFileName" }
        Copy-Item -LiteralPath $extracted.FullName -Destination $destination -Force
    } else {
        Copy-Item -LiteralPath $assetCache -Destination $destination -Force
    }
    Remove-Item -LiteralPath $staging -Recurse -Force
    $versionArgs = Get-ManifestValue -Block $toolBlock -Name 'version_args' -Indent 4
    $versionOutput = & $destination @($versionArgs -split ' ') 2>&1
    if ($LASTEXITCODE -ne 0 -or ($versionOutput -join ' ') -notmatch [regex]::Escape($version)) {
        throw "$ToolName n’a pas confirmé la version verrouillée $version."
    }
    Register-ToolRuntimeEntry -ToolName $ToolName -Version $version -SourcePath $destination -RuntimeRoot $runtimeRoot -PlatformId $script:RuntimePlatform
    Write-Status PASS "$ToolName $version installé et vérifié dans .tools/bin."
}

function Install-PSScriptAnalyzer {
    $powershellBlock = Get-ManifestBlock -Text $script:Manifest -Name 'powershell'
    $toolBlock = Get-ToolBlock -Section $powershellBlock -Name 'psscriptanalyzer'
    $version = Get-ManifestValue -Block $toolBlock -Name 'version' -Indent 4
    $modulePath = Join-Path $moduleRoot "PSScriptAnalyzer\$version"
    $moduleManifest = Join-Path $modulePath 'PSScriptAnalyzer.psd1'
    if ((Test-Path $moduleManifest -PathType Leaf) -and -not $Force) {
        $env:PSModulePath = "$moduleRoot;$env:PSModulePath"
        Import-Module $moduleManifest -Force -ErrorAction Stop
        Write-Status PASS "PSScriptAnalyzer $version disponible localement."
        return
    }

    if ($Offline) { throw "Mode hors ligne : installez d’abord PSScriptAnalyzer $version avec une connexion autorisée." }
    Save-Module -Name PSScriptAnalyzer -RequiredVersion $version -Repository PSGallery -Path $moduleRoot -Force -ErrorAction Stop
    $env:PSModulePath = "$moduleRoot;$env:PSModulePath"
    Import-Module $moduleManifest -Force -ErrorAction Stop
    if ((Get-Module PSScriptAnalyzer).Version.ToString() -ne $version) { throw 'Version PSScriptAnalyzer importée différente du verrou.' }
    Write-Status PASS "PSScriptAnalyzer $version enregistré dans .tools/powershell-modules."
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'Ce script cible Windows; utilisez scripts/bootstrap.sh sous Linux/macOS.' }
    $architectureValue = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    if ($architectureValue -notin @('AMD64', 'x86_64')) { throw "Le bootstrap actuel ne qualifie que Windows x64; architecture détectée : $architectureValue" }
    $script:RuntimePlatform = 'windows-x64'
    if (-not (Test-Path $manifestPath -PathType Leaf)) { throw 'Manifeste .config/tool-versions.yml absent.' }
    if (-not (Test-Path $requirementsPath -PathType Leaf)) { throw 'requirements-dev.txt absent.' }
    if (-not (Test-Path $dependencyLock -PathType Leaf)) { throw 'Verrou requirements-dev.lock absent.' }
    $script:Manifest = [System.IO.File]::ReadAllText($manifestPath, [System.Text.Encoding]::UTF8)
    $script:BinaryTools = Get-ManifestBlock -Text $script:Manifest -Name 'binary_tools'
    foreach ($directory in @($toolsRoot, $cacheRoot, $binRoot, $runtimeRoot, $moduleRoot, (Join-Path $toolsRoot 'pre-commit'), (Join-Path $toolsRoot 'test-workspaces'))) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }
    Update-ToolRuntimePlatformStatus -RuntimeRoot $runtimeRoot -PlatformId $script:RuntimePlatform -Status 'experimental'
    $env:PIP_CERT = Initialize-WindowsCaBundle
    $env:PRE_COMMIT_HOME = Join-Path $toolsRoot 'pre-commit'
    $env:PIP_CACHE_DIR = Join-Path $cacheRoot 'pip'
    $env:ANSIBLE_HOME = Join-Path $toolsRoot 'ansible'
    $env:ANSIBLE_LOCAL_TEMP = Join-Path $cacheRoot 'ansible-tmp'
    New-Item -ItemType Directory -Path $env:ANSIBLE_HOME,$env:ANSIBLE_LOCAL_TEMP -Force | Out-Null

    Write-Status INFO "Recherche d'un interpréteur Python 3.11 fonctionnel."
    $pythonRuntime = Get-PythonRuntime
    $pythonExe = $pythonRuntime.Path
    Write-Status INFO "Exécutable Python : $($pythonRuntime.Details.executable)"
    Write-Status PASS "Python $($pythonRuntime.Details.version) s’exécute réellement."
    if ((Test-Path $venvPython -PathType Leaf) -and $Force) { Remove-Item -LiteralPath $venvRoot -Recurse -Force }
    if (-not (Test-Path $venvPython -PathType Leaf)) {
        Invoke-CheckedCommand -FilePath $pythonExe -Arguments (@($pythonRuntime.Prefix) + @('-m', 'ensurepip', '--upgrade')) -Description 'amorçage pip du runtime'
        Invoke-CheckedCommand -FilePath $pythonExe -Arguments (@($pythonRuntime.Prefix) + @('-m', 'venv', $venvRoot)) -Description 'création de .venv'
    }
    if (-not (Test-PythonCandidate -Executable $venvPython)) { throw "Le Python de .venv ne démarre pas ou n'est pas Python 3.11." }

    $requirementsLines = @(Get-Content -Path $requirementsPath -Encoding UTF8)
    $pythonPackageBlock = Get-ManifestBlock -Text $script:Manifest -Name 'python_packages'
    $pins = [regex]::Matches($pythonPackageBlock, '(?m)^  - name: ([A-Za-z0-9_.-]+)\r?\n    version: "([^"]+)"')
    foreach ($pin in $pins) {
        $package = $pin.Groups[1].Value -replace '_', '-'
        if ($requirementsLines -notcontains "$package==$($pin.Groups[2].Value)") { throw "Pin de version incohérent pour $package." }
    }
    $pipVersion = Get-ManifestValue -Block $pythonPackageBlock -Name 'version' -Indent 4
    $pipArguments = @('-m', 'pip', 'install', '--upgrade', "pip==$pipVersion", '-c', $dependencyLock)
    if ($Offline) { $pipArguments += @('--no-index', '--find-links', (Join-Path $cacheRoot 'wheels')) }
    Invoke-CheckedCommand -FilePath $venvPython -Arguments $pipArguments -Description 'mise à niveau verrouillée de pip'
    $installArguments = @('-m', 'pip', 'install', '-r', $requirementsPath, '-c', $dependencyLock)
    if ($Force) { $installArguments += '--force-reinstall' }
    if ($Offline) {
        $wheelhouse = Join-Path $cacheRoot 'wheels'
        if (-not (Test-Path $wheelhouse -PathType Container)) { throw 'Mode hors ligne : .tools/cache/wheels absent; ajoutez-y les roues verrouillées.' }
        $installArguments += @('--no-index', '--find-links', $wheelhouse)
    }
    Invoke-CheckedCommand -FilePath $venvPython -Arguments $installArguments -Description 'installation des dépendances Python verrouillées'

    $lockToolsRequirementsPath = Join-Path $repoRoot 'requirements-lock-tools.txt'
    $lockVenvRoot = Join-Path $toolsRoot 'lock-venv'
    $lockVenvPython = Join-Path $lockVenvRoot 'Scripts\python.exe'
    if ($Force -and (Test-Path -LiteralPath $lockVenvRoot -PathType Container)) { Remove-Item -LiteralPath $lockVenvRoot -Recurse -Force }
    if (-not (Test-Path -LiteralPath $lockVenvPython -PathType Leaf)) {
        Invoke-CheckedCommand -FilePath $pythonExe -Arguments (@($pythonRuntime.Prefix) + @('-m', 'venv', $lockVenvRoot)) -Description 'création de .tools/lock-venv'
    }
    $lockToolsArguments = @('-m', 'pip', 'install', '-r', $lockToolsRequirementsPath)
    if ($Offline) { $lockToolsArguments += @('--no-index', '--find-links', (Join-Path $cacheRoot 'wheels')) }
    Invoke-CheckedCommand -FilePath $lockVenvPython -Arguments $lockToolsArguments -Description 'installation des outils verrouillés de génération du lock'
    Invoke-CheckedCommand -FilePath $lockVenvPython -Arguments @('-m', 'pip', 'check') -Description 'validation du venv de génération du lock'

    Install-PSScriptAnalyzer
    foreach ($toolName in @('gitleaks', 'tflint', 'terragrunt', 'hadolint', 'trivy')) {
        $toolBlock = Get-ToolBlock -Section $script:BinaryTools -Name $toolName
        $required = Get-ManifestValue -Block $toolBlock -Name 'required' -Indent 4
        if ($SkipOptionalTools -and $required -eq 'false') {
            Write-Status INFO "Outil facultatif ignoré à la demande : $toolName."
            continue
        }
        Install-BinaryTool -ToolName $toolName
    }

    $env:PSModulePath = "$moduleRoot;$env:PSModulePath"
    $env:PRE_COMMIT_HOME = Join-Path $toolsRoot 'pre-commit'
    $preCommit = Join-Path $venvRoot 'Scripts\pre-commit.exe'
    Repair-PreCommitCache -CacheRoot $env:PRE_COMMIT_HOME -PythonPath $venvPython -Offline:$Offline
    Invoke-CheckedCommand -FilePath $preCommit -Arguments @('install', '--install-hooks') -Description 'installation des hooks pre-commit locaux'
    $hookRelative = & git -C $repoRoot rev-parse --git-path hooks/pre-commit
    if ($LASTEXITCODE -ne 0) { throw 'Impossible de localiser le hook Git.' }
    $hookPath = if ([IO.Path]::IsPathRooted($hookRelative)) { $hookRelative } else { Join-Path $repoRoot $hookRelative }
    $hookContent = [IO.File]::ReadAllText($hookPath, [Text.Encoding]::UTF8)
    $hookEnvironment = 'export PRE_COMMIT_HOME="$(git rev-parse --show-toplevel)/.tools/pre-commit"' + "`n" + 'export PIP_CERT="$(git rev-parse --show-toplevel)/.tools/cache/windows-root-ca.pem"' + "`n"
    $hookContent = $hookContent.Replace('# start templated', $hookEnvironment + '# start templated')
    [IO.File]::WriteAllText($hookPath, $hookContent, [Text.UTF8Encoding]::new($false))

    foreach ($tool in @('pip', 'pre-commit', 'ruff', 'pylint', 'mypy', 'pytest', 'bandit', 'pip-audit', 'yamllint', 'ansible', 'ansible-lint', 'molecule', 'checkov')) {
        $extension = if ($tool -eq 'checkov') { '.cmd' } else { '.exe' }
        $executable = Join-Path $venvRoot "Scripts\$tool$extension"
        if ($tool -eq 'checkov') {
            $output = & $venvPython -x $executable --version 2>&1
            $code = $LASTEXITCODE
        } else {
            $previousErrorAction = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $output = & $executable --version 2>&1
                $code = $LASTEXITCODE
            } catch {
                $output = $_.Exception.Message
                $code = 1
            } finally {
                $ErrorActionPreference = $previousErrorAction
            }
        }
        if ($code -eq 0) { Write-Status INFO "$tool : $($output | Select-Object -First 1)" }
        elseif ($tool -in @('ansible', 'ansible-lint', 'molecule') -and [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            $distribution = if ($tool -eq 'ansible') { 'ansible-core' } else { $tool }
            $metadata = & $venvPython -c "import importlib.metadata as m; print(m.version('$distribution'))" 2>&1
            if ($LASTEXITCODE -ne 0) { throw "Le paquet $distribution n’est pas installé : $metadata" }
            Write-Status WARN "$tool $metadata installé; son exécution complète n’est pas prise en charge sur un contrôleur Windows."
        }
        else { throw "L’outil obligatoire $tool a échoué lors du contrôle --version (code $code)." }
    }
    if ($Offline) {
        Write-Status WARN 'Validation de résolution pip-compile ignorée en mode hors ligne; installation et pins locaux restent vérifiés.'
    } else {
        $lockCheck = Join-Path $repoRoot 'scripts/update-lock.ps1'
        Invoke-CheckedCommand -FilePath (Join-Path $PSHOME 'powershell.exe') -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $lockCheck, '-Check') -Description 'validation du lock Python'
    }
    Write-Status INFO "PSScriptAnalyzer : $((Get-Module PSScriptAnalyzer).Version)"
    Update-ToolRuntimePlatformStatus -RuntimeRoot $runtimeRoot -PlatformId $script:RuntimePlatform -Status 'qualified'
    Write-Status PASS 'Bootstrap local terminé; PATH système et installations globales inchangés.'
    exit 0
} catch {
    Write-Status ERROR "Échec du bootstrap : $($_.Exception.Message)"
    exit 1
}
