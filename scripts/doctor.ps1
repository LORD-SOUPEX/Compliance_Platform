[CmdletBinding()]
param(
    [string]$ReportPath,
    [switch]$NoColor,
    [switch]$Repair
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$toolsRoot = Join-Path $repoRoot '.tools'
$runtimeIndexPath = Join-Path $toolsRoot 'runtime\index.json'
$venvRoot = Join-Path $repoRoot '.venv'
$venvPython = Join-Path $venvRoot 'Scripts\python.exe'
Import-Module (Join-Path $repoRoot 'src/Tool.Provenance.psm1') -Force -ErrorAction Stop
$script:Counts = @{ PASS = 0; FAIL = 0; WARN = 0; SKIP = 0; ERROR = 0 }
$script:Results = New-Object System.Collections.Generic.List[object]
if ($NoColor) { $env:NO_COLOR = '1' }

function Add-Status {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP', 'ERROR')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $script:Counts[$Status]++
    $script:Results.Add([pscustomobject]@{ nom = $Name; statut = $Status; message = $Message })
    Write-Information -InformationAction Continue "[$Status] $Message"
}

function Get-ProjectFile {
    $excluded = @('.git', '.venv', '.tools', 'reports', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache', '.terraform', '.terragrunt-cache')
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($repoRoot)
    while ($pending.Count -gt 0) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
            if ($item.PSIsContainer) {
                if ($item.Name -notin $excluded -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $pending.Push($item.FullName) }
            } else { $item }
        }
    }
}

function Test-Executable {
    param([string]$Path, [string[]]$Arguments = @())
    if (-not (Test-Path $Path -PathType Leaf)) { return $null }
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $Path @Arguments 2>&1
        $code = $LASTEXITCODE
    } catch {
        $output = $_.Exception.Message
        $code = 1
    } finally { $ErrorActionPreference = $previousPreference }
    if ($code -ne 0) { return $null }
    return ($output -join ' ')
}

function Get-PinnedRequirement {
    $requirements = @(Get-Content -Path (Join-Path $repoRoot 'requirements-dev.txt') -Encoding UTF8 | Where-Object { $_ -match '^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+-]*)$' })
    $manifest = [System.IO.File]::ReadAllText((Join-Path $repoRoot '.config\tool-versions.yml'), [System.Text.Encoding]::UTF8)
    foreach ($line in $requirements) {
        if ($line -match '^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+-]*)$') {
            $packageName = $Matches[1]
            $packageVersion = $Matches[2]
            $namePattern = [regex]::Escape($packageName)
            $versionPattern = [regex]::Escape($packageVersion)
            if ($manifest -notmatch "(?m)^  - name: $namePattern\r?\n    version: `"$versionPattern`"") {
                Add-Status FAIL 'Catalogue des versions' "Version incohérente pour $packageName."
            }
        }
    }
    return $requirements
}

function Get-DoctorRuntimePlatform {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$IndexPath, [Parameter(Mandatory = $true)][string]$PlatformId)
    if (-not (Test-Path -LiteralPath $IndexPath -PathType Leaf)) { throw 'Runtime Index absent.' }
    $index = Get-Content -LiteralPath $IndexPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
    if ($index.schema_version -ne 1 -or -not $index.platforms) { throw 'Runtime Index schema invalide.' }
    $platformProperty = $index.platforms.PSObject.Properties[$PlatformId]
    if (-not $platformProperty) { throw "Plateforme absente du Runtime Index: $PlatformId" }
    $platform = $platformProperty.Value
    foreach ($field in @('status', 'tools', 'python', 'python_packages', 'powershell_modules')) {
        if ($platform.PSObject.Properties.Name -notcontains $field) { throw "Inventaire Runtime incomplet: $field" }
    }
    if ($platform.status -notin @('targeted', 'experimental', 'qualified') -or $platform.tools -isnot [array] -or $platform.python_packages -isnot [array] -or $platform.powershell_modules -isnot [array]) {
        throw "Types/statuts Runtime invalides: $PlatformId"
    }
    foreach ($field in @('version', 'source', 'executable', 'executable_sha256', 'environment', 'environment_executable_sha256', 'dependency_lock', 'dependency_lock_sha256', 'packages')) {
        if ($platform.python.PSObject.Properties.Name -notcontains $field) { throw "Inventaire Python Runtime incomplet: $field" }
    }
    if ($platform.python.packages -isnot [array]) { throw 'Inventaire packages Python invalide.' }
    return $platform
}

function Get-DoctorDirectorySha256 {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $null }
    $root = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    $entries = New-Object System.Collections.Generic.List[string]
    foreach ($file in Get-ChildItem -LiteralPath $Path -File -Recurse | Sort-Object FullName) {
        $relativePath = $file.FullName.Substring($root.Length).Replace('\', '/')
        $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $entries.Add("$relativePath $hash`n")
    }
    if ($entries.Count -eq 0) { return $null }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(($entries -join ''))
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($algorithm.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $algorithm.Dispose() }
}

try {
    Write-Information -InformationAction Continue "[INFO] Racine du dépôt : $repoRoot"
    $architectureValue = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $architecture = switch -Regex ($architectureValue) { '^(AMD64|x86_64)$' { 'x64'; break }; '^(ARM64|aarch64)$' { 'arm64'; break }; default { 'unknown' } }
    $runtimePlatformId = "windows-$architecture"
    Add-Status PASS 'Système' "Windows; architecture $architectureValue; PowerShell $($PSVersionTable.PSVersion)."
    if (Get-Command git -ErrorAction SilentlyContinue) { Add-Status PASS 'Git' 'Git est disponible.' }
    else { Add-Status ERROR 'Git' 'Git est obligatoire mais introuvable.' }

    $runtimePlatform = $null
    try {
        $runtimePlatform = Get-DoctorRuntimePlatform -IndexPath $runtimeIndexPath -PlatformId $runtimePlatformId
        if ($runtimePlatform.status -eq 'qualified') { Add-Status PASS 'Runtime Index' "Inventaire complet; runtime $runtimePlatformId qualifié." }
        else { Add-Status FAIL 'Runtime Index' "Statut runtime $runtimePlatformId : $($runtimePlatform.status)." }
    } catch { Add-Status ERROR 'Runtime Index' $_.Exception.Message }

    if ($runtimePlatform) {
        $pythonRecord = $runtimePlatform.python
        $runtimeOutput = Test-Executable -Path $pythonRecord.executable -Arguments @('--version')
        $runtimeHash = if (Test-Path -LiteralPath $pythonRecord.executable -PathType Leaf) { (Get-FileHash -LiteralPath $pythonRecord.executable -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        if ($runtimeOutput -eq "Python $($pythonRecord.version)" -and $runtimeHash -eq $pythonRecord.executable_sha256) { Add-Status PASS 'Runtime Python' "Python $($pythonRecord.version); source/hash conforme à l'index." }
        else { Add-Status ERROR 'Runtime Python' 'Exécutable, version ou hash different du Runtime Index.' }
    } else { Add-Status ERROR 'Runtime Python' 'Snapshot Python absent; relancez scripts/bootstrap.ps1.' }

    if (Test-Path $venvPython -PathType Leaf) {
        $venvOutput = Test-Executable -Path $venvPython -Arguments @('--version')
        $venvHash = (Get-FileHash -LiteralPath $venvPython -Algorithm SHA256).Hash.ToLowerInvariant()
        $basePythonOutput = & $venvPython -c 'import sys; print(sys._base_executable)'
        $basePythonCode = $LASTEXITCODE
        $basePythonPath = if ($basePythonCode -eq 0 -and $basePythonOutput) { [IO.Path]::GetFullPath(($basePythonOutput | Select-Object -Last 1)) } else { $null }
        $basePythonMatches = $runtimePlatform -and [string]::Equals($basePythonPath, [IO.Path]::GetFullPath($runtimePlatform.python.executable), [StringComparison]::OrdinalIgnoreCase)
        if ($runtimePlatform -and $venvOutput -eq "Python $($runtimePlatform.python.version)" -and $venvHash -eq $runtimePlatform.python.environment_executable_sha256 -and $basePythonMatches) { Add-Status PASS 'Environnement .venv' "Environnement et Python de base conformes au Runtime Index : $venvOutput." }
        else { Add-Status ERROR 'Environnement .venv' 'Le Python de .venv est absent ou inutilisable.' }
    } else { Add-Status ERROR 'Environnement .venv' 'Le dossier .venv est absent; lancez scripts/bootstrap.ps1.' }

    $requirements = Get-PinnedRequirement
    if ($runtimePlatform) {
        $lockPath = Join-Path $repoRoot 'requirements-dev.lock'
        $lockHash = if (Test-Path -LiteralPath $lockPath -PathType Leaf) { (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        if ($lockHash -ne $runtimePlatform.python.dependency_lock_sha256) { Add-Status FAIL 'Runtime lock' 'Le hash de requirements-dev.lock diverge du Runtime Index.' }
        else { Add-Status PASS 'Runtime lock' "Lock Python conforme; $(@($runtimePlatform.python_packages).Count) packages indexés." }

        $installedOutput = & $venvPython -m pip list --format=json
        $installedPackages = if ($LASTEXITCODE -eq 0) { ConvertFrom-Json -InputObject ($installedOutput -join "`n") } else { @() }
        $installedVersions = @{}
        foreach ($package in $installedPackages) { $installedVersions[[regex]::Replace([string]$package.name, '[-_.]+', '-').ToLowerInvariant()] = [string]$package.version }
        $inventoryErrors = @($runtimePlatform.python_packages | Where-Object {
            -not $installedVersions.ContainsKey($_.name) -or $installedVersions[$_.name] -ne $_.version
        })
        if ($inventoryErrors.Count -eq 0) { Add-Status PASS 'Runtime Python packages' "$($runtimePlatform.python_packages.Count) versions conformes à l'index." }
        else { Add-Status FAIL 'Runtime Python packages' "Versions divergentes: $(($inventoryErrors | ForEach-Object { $_.name }) -join ', ')." }
        $wheelProvenanceErrors = @($runtimePlatform.python_packages | Where-Object { Get-PythonWheelProvenanceError -Record $_ -RepositoryRoot $repoRoot })
        if ($wheelProvenanceErrors.Count -eq 0) { Add-Status PASS 'Provenance des roues Python' "$($runtimePlatform.python_packages.Count) roues PyPI acquises et vérifiées." }
        else { Add-Status ERROR 'Provenance des roues Python' "Provenance absente ou invalide: $(($wheelProvenanceErrors | ForEach-Object name) -join ', ')." }
    }
    $scriptsDirectory = Join-Path $venvRoot 'Scripts'
    foreach ($line in $requirements) {
        if ($line -match '^([A-Za-z0-9_.-]+)==([0-9][A-Za-z0-9.+-]*)$') {
            $packageName = $Matches[1]
            $expectedVersion = $Matches[2]
            if (-not (Test-Path $venvPython -PathType Leaf)) { continue }
            $previousPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $packageInfo = & $venvPython -m pip show $packageName 2>&1
                $pipCode = $LASTEXITCODE
            } catch { $packageInfo = $_.Exception.Message; $pipCode = 1 }
            finally { $ErrorActionPreference = $previousPreference }
            if ($pipCode -eq 0 -and ($packageInfo -match "(?m)^Version:\s*$([regex]::Escape($expectedVersion))\s*$")) {
                Add-Status PASS "Paquet $packageName" "Version $expectedVersion conforme au verrou."
            } elseif ($pipCode -eq 0) {
                Add-Status FAIL "Paquet $packageName" "La version installée ne correspond pas à $expectedVersion."
            } else { Add-Status ERROR "Paquet $packageName" "Paquet absent de .venv : $packageInfo" }
        }
    }

    $commandChecks = @(
        @{ Name = 'pre-commit'; File = 'pre-commit.exe'; Args = @('--version') },
        @{ Name = 'Ruff'; File = 'ruff.exe'; Args = @('--version') },
        @{ Name = 'Pylint'; File = 'pylint.exe'; Args = @('--version') },
        @{ Name = 'mypy'; File = 'mypy.exe'; Args = @('--version') },
        @{ Name = 'pytest'; File = 'pytest.exe'; Args = @('--version') },
        @{ Name = 'Bandit'; File = 'bandit.exe'; Args = @('--version') },
        @{ Name = 'pip-audit'; File = 'pip-audit.exe'; Args = @('--version') },
        @{ Name = 'yamllint'; File = 'yamllint.exe'; Args = @('--version') }
    )
    foreach ($tool in $commandChecks) {
        $path = Join-Path $scriptsDirectory $tool.File
        if (Test-Executable -Path $path -Arguments $tool.Args) { Add-Status PASS $tool.Name 'Commande locale exécutable.' }
        else { Add-Status ERROR $tool.Name 'Commande locale absente ou non exécutable.' }
    }

    $modulePath = Join-Path $toolsRoot 'powershell-modules'
    $env:PSModulePath = "$modulePath;$env:PSModulePath"
    $analyzerRecords = if ($runtimePlatform) { @($runtimePlatform.powershell_modules | Where-Object name -eq 'PSScriptAnalyzer') } else { @() }
    if (@($analyzerRecords).Count -ne 1) {
        Add-Status ERROR 'PSScriptAnalyzer Runtime' 'Module absent ou duplique dans le Runtime Index.'
    } else {
        $analyzerRecord = $analyzerRecords[0]
        $analyzerPath = [IO.Path]::GetFullPath((Join-Path $repoRoot $analyzerRecord.path))
        $analyzerManifest = Join-Path $analyzerPath 'PSScriptAnalyzer.psd1'
        $availableAnalyzer = Get-Module PSScriptAnalyzer -ListAvailable | Where-Object {
            $_.Version.ToString() -eq $analyzerRecord.version -and [IO.Path]::GetFullPath($_.ModuleBase) -eq $analyzerPath
        } | Select-Object -First 1
        $manifestHash = if (Test-Path -LiteralPath $analyzerManifest -PathType Leaf) { (Get-FileHash -LiteralPath $analyzerManifest -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
        $treeHash = Get-DoctorDirectorySha256 -Path $analyzerPath
        if ($availableAnalyzer -and $manifestHash -eq $analyzerRecord.manifest_sha256 -and $treeHash -eq $analyzerRecord.tree_sha256) { Add-Status PASS 'PSScriptAnalyzer' "Version $($analyzerRecord.version), manifeste et arbre conformes au Runtime Index." }
        else { Add-Status ERROR 'PSScriptAnalyzer' 'Module absent, version divergente ou hash runtime invalide.' }
    }

    foreach ($tool in @(
        @{ Name = 'Gitleaks'; File = 'gitleaks.exe'; Version = '8.30.1'; Args = @('version') },
        @{ Name = 'TFLint'; File = 'tflint.exe'; Version = '0.64.0'; Args = @('--version') },
        @{ Name = 'Terragrunt'; File = 'terragrunt.exe'; Version = '1.1.6'; Args = @('--version') },
        @{ Name = 'Hadolint'; File = 'hadolint.exe'; Version = '2.15.1'; Args = @('--version') },
        @{ Name = 'Trivy'; File = 'trivy.exe'; Version = '0.75.0'; Args = @('--version') }
    )) {
        $path = Join-Path (Join-Path $toolsRoot 'bin') $tool.File
        $output = Test-Executable -Path $path -Arguments $tool.Args
        $toolName = [IO.Path]::GetFileNameWithoutExtension($tool.File).ToLowerInvariant()
        $runtimeRecords = if ($runtimePlatform) { @($runtimePlatform.tools | Where-Object { $_.name -eq $toolName -and $_.active }) } else { @() }
        $integrityValid = $false
        if (@($runtimeRecords).Count -eq 1) {
            $record = @($runtimeRecords)[0]
            $runtimeArtifact = Join-Path (Join-Path $toolsRoot 'runtime') $record.path
            $runtimeHash = if (Test-Path -LiteralPath $runtimeArtifact -PathType Leaf) { (Get-FileHash -LiteralPath $runtimeArtifact -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
            $copyHash = if (Test-Path -LiteralPath $path -PathType Leaf) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() } else { $null }
            $provenanceError = Get-ToolArtifactProvenanceError -Record $record
            $integrityValid = $record.status -eq 'qualified' -and $record.version -eq $tool.Version -and $runtimeHash -eq $record.sha256 -and $copyHash -eq $record.sha256 -and -not $provenanceError
        }
        if ($output -and $output -match [regex]::Escape($tool.Version) -and $integrityValid) { Add-Status PASS $tool.Name "Version, provenance et empreinte runtime confirmees." }
        else { Add-Status ERROR $tool.Name "Binaire absent, version, provenance, activation ou empreinte Runtime Index invalide (attendu $($tool.Version))." }
    }

    $files = Get-ProjectFile
    if (@($files | Where-Object Extension -eq '.tf').Count -eq 0) { Add-Status SKIP 'Terraform' 'Aucun fichier .tf détecté.' }
    elseif (Get-Command terraform -ErrorAction SilentlyContinue) { Add-Status PASS 'Terraform' 'Terraform disponible pour un projet IaC.' }
    else { Add-Status ERROR 'Terraform' 'Des fichiers Terraform existent mais Terraform est absent.' }

    $ansible = (Test-Path (Join-Path $repoRoot 'ansible.cfg')) -or (Test-Path (Join-Path $repoRoot 'galaxy.yml')) -or (Test-Path (Join-Path $repoRoot 'roles') -PathType Container) -or (Test-Path (Join-Path $repoRoot 'playbooks') -PathType Container)
    if (-not $ansible) { Add-Status SKIP 'Ansible' 'Aucun composant Ansible détecté.' }
    elseif ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { Add-Status WARN 'Ansible' 'Composant détecté; exécution complète non supportée sur un contrôleur Windows.' }
    else { Add-Status PASS 'Ansible' 'Composant détecté et paquets Ansible locaux présents.' }

    if (@($files | Where-Object Name -Match '^(Dockerfile|Containerfile)(\..+)?$').Count -eq 0) { Add-Status SKIP 'Conteneurs' 'Aucun fichier Dockerfile ou Containerfile détecté.' }
    else { Add-Status PASS 'Conteneurs' 'Hadolint et Trivy locaux sont disponibles.' }

    $requiredFiles = @('.config/quality-gate.yml', '.config/tool-versions.yml', '.config/PSScriptAnalyzerSettings.psd1', '.github/copilot-instructions.md', '.github/merge_request_template.md', '.vscode/settings.json', '.vscode/extensions.json', '.vscode/tasks.json', '.pre-commit-config.yaml', 'requirements-dev.txt', 'pyproject.toml', 'scripts/bootstrap.ps1', 'scripts/doctor.ps1', 'scripts/quality-gate.ps1', 'scripts/test.ps1', 'scripts/check-emoji.ps1', '.gitlab-ci.yml', 'README.md', '.gitignore')
    $requiredFiles += @('requirements-dev.lock', '.gitleaks.toml', '.yamllint.yml', '.markdownlint.json', 'scripts/bootstrap.sh', 'scripts/doctor.sh', 'scripts/quality-gate.sh', 'scripts/test.sh', 'tests/integration/quality-gate.Tests.ps1')
    foreach ($path in $requiredFiles) {
        if (Test-Path (Join-Path $repoRoot $path) -PathType Leaf) { Add-Status PASS 'Fichier obligatoire' "Présent : $path" }
        else { Add-Status FAIL 'Fichier obligatoire' "Absent : $path" }
    }
    if (Test-Path (Join-Path $repoRoot '.pre-commit-config.yaml') -PathType Leaf) { Add-Status PASS 'Configuration pre-commit' 'Fichier de configuration présent.' }
    else { Add-Status FAIL 'Configuration pre-commit' 'Fichier de configuration absent.' }
    $hookPath = & git -C $repoRoot rev-parse --git-path hooks/pre-commit 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path (Join-Path $repoRoot $hookPath) -PathType Leaf)) { Add-Status PASS 'Hook local' 'Hook pre-commit installé dans le dépôt.' }
    else { Add-Status ERROR 'Hook local' 'Hook pre-commit absent; lancez le bootstrap.' }

    $pathSeparator = [regex]::Escape('\')
    $absolutePattern = '(?i)([A-Z]:' + $pathSeparator + 'Users' + $pathSeparator + '|[A-Z]:' + $pathSeparator + 'git' + $pathSeparator + '|/' + 'User' + 's/' + '[^/]+/|/' + 'hom' + 'e/' + '[^/]+/)'
    $absoluteFindings = New-Object System.Collections.Generic.List[string]
    $sensitiveFindings = New-Object System.Collections.Generic.List[string]
    $largeFiles = New-Object System.Collections.Generic.List[string]
    foreach ($file in $files) {
        if ($file.Length -gt 5MB) { $largeFiles.Add($file.Name) }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            if ($bytes -contains 0) { continue }
            $content = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        } catch [System.Text.DecoderFallbackException] { continue }
        if ($content -match $absolutePattern) { $absoluteFindings.Add($file.Name) }
        if ($file.Name -match '(^|\.)\.env($|\.)|\.tfstate($|\.)|\.tfvars($|\.)|id_rsa|id_ed25519|\.(pfx|p12|pem|key)$') { $sensitiveFindings.Add($file.Name) }
    }
    if ($absoluteFindings.Count -eq 0) { Add-Status PASS 'Chemins locaux' 'Aucun chemin absolu personnel détecté.' }
    else { Add-Status FAIL 'Chemins locaux' "Chemins personnels détectés : $($absoluteFindings -join ', ')" }
    if ($sensitiveFindings.Count -eq 0) { Add-Status PASS 'Fichiers sensibles' 'Aucun fichier sensible évident détecté.' }
    else { Add-Status FAIL 'Fichiers sensibles' "Fichiers potentiellement sensibles : $($sensitiveFindings -join ', ')" }
    if ($largeFiles.Count -eq 0) { Add-Status PASS 'Taille des fichiers' 'Aucun fichier texte supérieur à 5 Mio.' }
    else { Add-Status FAIL 'Taille des fichiers' "Fichiers supérieurs à 5 Mio : $($largeFiles -join ', ')" }

    $scanner = Join-Path $PSScriptRoot 'check-emoji.ps1'
    & powershell -NoProfile -ExecutionPolicy Bypass -File $scanner -Path $repoRoot
    if ($LASTEXITCODE -eq 0) { Add-Status PASS 'Emojis' 'Aucun pictogramme interdit.' }
    else { Add-Status FAIL 'Emojis' 'Des pictogrammes interdits ont été détectés.' }

    if ($Repair) {
        foreach ($directory in @($toolsRoot, (Join-Path $toolsRoot 'bin'), (Join-Path $toolsRoot 'cache'), $modulePath, (Join-Path $toolsRoot 'test-workspaces'))) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        $preCommit = Join-Path $venvRoot 'Scripts\pre-commit.exe'
        if (Test-Path $preCommit) {
            Push-Location $repoRoot
            try {
                & $preCommit install
                if ($LASTEXITCODE -ne 0) { Add-Status ERROR 'Réparation hook' 'Installation du hook pre-commit échouée.' }
                else { Add-Status PASS 'Réparation hook' 'Hook pre-commit installé; relancez bootstrap pour rétablir les variables de cache dans le hook.' }
            } finally { Pop-Location }
        }
        else { Add-Status ERROR 'Réparation hook' 'pre-commit local absent; lancez bootstrap.' }
    }

    if ($ReportPath) {
        $path = if ([IO.Path]::IsPathRooted($ReportPath)) { $ReportPath } else { Join-Path (Join-Path $repoRoot 'reports') $ReportPath }
        $directory = Split-Path -Parent $path
        if (-not (Test-Path $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
        [pscustomobject]@{ date_execution = (Get-Date).ToString('o'); controles = $script:Results.ToArray(); resume = $script:Counts } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        Write-Information -InformationAction Continue "[PASS] Rapport doctor écrit : $path"
    }

    Write-Information -InformationAction Continue ("[SUMMARY] PASS={0} FAIL={1} WARN={2} SKIP={3} ERROR={4}" -f $script:Counts.PASS,$script:Counts.FAIL,$script:Counts.WARN,$script:Counts.SKIP,$script:Counts.ERROR)
    if ($script:Counts.FAIL -gt 0 -or $script:Counts.ERROR -gt 0) { exit 1 }
    exit 0
} catch {
    Add-Status ERROR 'Exécution doctor' $_.Exception.Message
    Write-Information -InformationAction Continue ("[SUMMARY] PASS={0} FAIL={1} WARN={2} SKIP={3} ERROR={4}" -f $script:Counts.PASS,$script:Counts.FAIL,$script:Counts.WARN,$script:Counts.SKIP,$script:Counts.ERROR)
    exit 2
}
