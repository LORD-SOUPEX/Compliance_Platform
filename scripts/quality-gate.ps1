[CmdletBinding()]
param(
    [ValidateSet('Quick', 'Full', 'Ci', 'Fix')][string]$Mode = 'Quick',
    [ValidateSet('Generic', 'Documentation', 'Security', 'Python', 'PowerShell', 'Ansible', 'Terraform', 'Terragrunt', 'Container', 'Shell', 'Tests', 'All')][string]$Category = 'All',
    [string]$ReportPath,
    [string]$RepositoryPath,
    [switch]$DiscoveryOnly,
    [switch]$Compliance,
    [switch]$PlanOnly,
    [switch]$HumanSummary,
    [switch]$AllowNetwork,
    [switch]$AllowCodeExecution,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$ProgressRunId,
    [ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedCatalogSha256,
    [ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter = 'PowerShell',
    [ValidateRange(1, 86400)][int]$ComplianceTimeoutSeconds = 1800,
    [ValidateRange(1024, 10485760)][int]$ComplianceMaxOutputBytes = 1048576,
    [string[]]$ReportRedactionPattern = @(),
    [ValidateNotNullOrEmpty()][string]$ReportRedactionReplacement = '[REDACTED]',
    [ValidateRange(0, 3650)][int]$ReportRetentionDays = 0,
    [switch]$NoColor,
    [ValidateRange(1, 3600)][int]$TimeoutSeconds = 300
)

# [DEPRECATED / HÉRITÉ] Ce script PowerShell 5.1 est déprécié.
# Le moteur autonome Go (core/) et la CLI 'compliance' sont l'unique source de vérité.
# Utiliser la CLI Go 'compliance' (ex: compliance run / compliance selftest).

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Import-Module (Join-Path $platformRoot 'src/Control.Catalog.psm1') -Force -ErrorAction Stop
$script:ControlCatalog = Import-ControlCatalog -Path (Join-Path $platformRoot '.config/control-catalog.json')
Import-Module (Join-Path $platformRoot 'src/Platform.Support.psm1') -Force -ErrorAction Stop
$script:PlatformSupportMatrix = Import-PlatformSupportMatrix -Path (Join-Path $platformRoot '.config/platform-support.json')
Import-Module (Join-Path $platformRoot 'src/Tool.Provenance.psm1') -Force -ErrorAction Stop
if ([string]::IsNullOrWhiteSpace($RepositoryPath)) {
    $repoRoot = $platformRoot
} else {
    $repositoryItem = Get-Item -LiteralPath $RepositoryPath -ErrorAction Stop
    if (-not $repositoryItem.PSIsContainer) { throw "Le repository doit être un dossier : $RepositoryPath" }
    $repoRoot = $repositoryItem.FullName
}
$python = Join-Path $platformRoot '.venv\Scripts\python.exe'
$toolRoot = Join-Path $platformRoot '.tools\bin'
$script:RequestedMode = $Mode
$script:Category = $Category
$script:Counts = @{ PASS = 0; FAIL = 0; WARN = 0; SKIP = 0; ERROR = 0 }
$script:Results = New-Object System.Collections.Generic.List[object]
$script:RunFull = $Mode -in @('Full', 'Ci')
$script:StartedAt = Get-Date
$script:Files = @()
$script:ScanErrors = New-Object System.Collections.Generic.List[object]
$script:Technologies = $null
$script:ProcessTimeoutSeconds = $TimeoutSeconds
$script:ProbeCandidateTools = $true
$script:CommandProbeCache = @{}
$script:ProgressSession = $null
$script:ReportRedactionPatterns = @($ReportRedactionPattern | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
foreach ($pattern in $script:ReportRedactionPatterns) {
    try { $null = [regex]::new($pattern) }
    catch { throw "Motif de masquage regex invalide: $pattern" }
}
if ($NoColor) { $env:NO_COLOR = '1' }

function Protect-QualityGateReportValue {
    param([AllowNull()][object]$Value, [bool]$RedactText = $false)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if (-not $RedactText) { return $Value }
        $patternsVariable = Get-Variable -Name ReportRedactionPatterns -Scope Script -ErrorAction SilentlyContinue
        $replacementVariable = Get-Variable -Name ReportRedactionReplacement -Scope Script -ErrorAction SilentlyContinue
        $patterns = if ($patternsVariable) { @($patternsVariable.Value) } else { @() }
        $replacement = if ($replacementVariable) { [string]$replacementVariable.Value } else { '[REDACTED]' }
        $text = $Value
        foreach ($pattern in $patterns) { $text = [regex]::Replace($text, $pattern, $replacement) }
        return $text
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $copy = [ordered]@{}
        foreach ($key in $Value.Keys) {
            $sensitive = $RedactText -or ([string]$key -in @('repository', 'source', 'stdout', 'stderr', 'message', 'reason', 'path', 'files', 'arguments'))
            $copy[$key] = Protect-QualityGateReportValue -Value $Value[$key] -RedactText:$sensitive
        }
        return $copy
    }
    if ($Value -is [pscustomobject]) {
        $copy = [ordered]@{}
        foreach ($property in $Value.PSObject.Properties) {
            $sensitive = $RedactText -or ($property.Name -in @('repository', 'source', 'stdout', 'stderr', 'message', 'reason', 'path', 'files', 'arguments'))
            $copy[$property.Name] = Protect-QualityGateReportValue -Value $property.Value -RedactText:$sensitive
        }
        return [pscustomobject]$copy
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = New-Object System.Collections.Generic.List[object]
        foreach ($item in $Value) { $items.Add((Protect-QualityGateReportValue -Value $item -RedactText:$RedactText)) }
        return ,$items.ToArray()
    }
    return $Value
}

function Remove-ExpiredComplianceReport {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([Parameter(Mandatory = $true)][string]$ReportsDirectory, [ValidateRange(0, 3650)][int]$RetentionDays, [string]$CurrentReportPath)
    if ($RetentionDays -le 0 -or -not (Test-Path -LiteralPath $ReportsDirectory -PathType Container)) { return }
    $currentPath = if ($CurrentReportPath) { [IO.Path]::GetFullPath($CurrentReportPath) } else { $null }
    $cutoff = [DateTime]::UtcNow.AddDays(-$RetentionDays)
    foreach ($file in Get-ChildItem -LiteralPath $ReportsDirectory -Filter 'compliance-report*.json' -File) {
        if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        if ($currentPath -and [string]::Equals([IO.Path]::GetFullPath($file.FullName), $currentPath, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($file.LastWriteTimeUtc -ge $cutoff) { continue }
        if ($PSCmdlet.ShouldProcess($file.FullName, 'Supprimer un ancien rapport Compliance local')) {
            try { Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Stop }
            catch { [Console]::Error.WriteLine("Retention Compliance: suppression impossible pour $($file.Name): $($_.Exception.Message)") }
        }
    }
}

function Add-Check {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PASS', 'FAIL', 'WARN', 'SKIP', 'ERROR')][string]$Status,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Message,
        [long]$DurationMs = 0
    )
    $Message = Protect-QualityGateReportValue -Value $Message -RedactText:$true
    $script:Counts[$Status]++
    $script:Results.Add([pscustomobject]@{ nom = $Name; statut = $Status; message = $Message; duree_ms = $DurationMs })
    Write-Information -InformationAction Continue "[$Status] $Message"
}

function Test-Category {
    param([string]$Name)
    return ($script:Category -eq 'All' -or $script:Category -eq $Name)
}

function Add-ScanError {
    param([string]$Path, [string]$Operation, [Exception]$Exception)
    $relativePath = Get-RepositoryRelativePath -Path $Path -RepositoryRoot $repoRoot
    if (@($script:ScanErrors | Where-Object { $_.path -eq $relativePath -and $_.operation -eq $Operation }).Count -eq 0) {
        $script:ScanErrors.Add([pscustomobject]@{
            path = $relativePath
            operation = $Operation
            error_type = $Exception.GetType().Name
            message = $Exception.Message.Replace($repoRoot, '<repository>')
        })
    }
}

function Get-DiscoveryFileContent {
    param([System.IO.FileInfo]$File)
    try { return [IO.File]::ReadAllText($File.FullName, [Text.Encoding]::UTF8) }
    catch { Add-ScanError -Path $File.FullName -Operation 'read' -Exception $_.Exception }
}

function Get-ProjectFile {
    param([string]$Root = $repoRoot)
    $script:ScanErrors = New-Object System.Collections.Generic.List[object]
    $excluded = @('.git', '.venv', '.tools', '.extension-build', 'reports', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', '.cache', '.terraform', '.terragrunt-cache')
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        try { $items = @(Get-ChildItem -LiteralPath $directory -Force -ErrorAction Stop) }
        catch {
            Add-ScanError -Path $directory -Operation 'enumerate' -Exception $_.Exception
            continue
        }
        foreach ($item in $items) {
            if ($item.PSIsContainer) {
                if ($item.Name -notin $excluded -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $pending.Push($item.FullName) }
            } else { $item }
        }
    }
}

function Invoke-BoundedProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [ValidateRange(1, 3600)][int]$Timeout = 300,
        [int]$TimeoutMilliseconds = 0,
        [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
    )
    $waitMilliseconds = if ($TimeoutMilliseconds -gt 0) { $TimeoutMilliseconds } else { $Timeout * 1000 }
    if ($waitMilliseconds -lt 1 -or $waitMilliseconds -gt 86400000) { throw 'Timeout processus hors limites.' }
    $started = [DateTimeOffset]::UtcNow
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $result = [pscustomobject]@{ execution_start = $started.ToString('o'); execution_end = $null; duration_ms = 0; stdout = ''; stderr = ''; exit_code = $null; error = $null; timed_out = $false; output_truncated = $false; cancelled = $false }
    $process = New-Object Diagnostics.Process
    try {
        $resolved = if (Test-Path -LiteralPath $Executable -PathType Leaf) { [IO.Path]::GetFullPath($Executable) } else {
            $command = Get-Command $Executable -ErrorAction SilentlyContinue
            if ($command) { $command.Source } else { $null }
        }
        if (-not $resolved) { throw "Outil absent : $Executable" }
        $integrityError = Get-ExecutionIntegrityError -ArtifactPath $resolved
        if ($integrityError) { throw $integrityError }
        $process.StartInfo.FileName = $resolved
        $process.StartInfo.WorkingDirectory = $WorkingDirectory
        $process.StartInfo.UseShellExecute = $false
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.RedirectStandardError = $true
        $process.StartInfo.Arguments = ($Arguments | ForEach-Object {
            '"' + ([regex]::Replace([regex]::Replace($_, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1')) + '"'
        }) -join ' '
        $null = $process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        while (-not $process.WaitForExit([Math]::Min(200, $waitMilliseconds))) {
            $sessionVariable = Get-Variable -Name ProgressSession -Scope Script -ErrorAction SilentlyContinue
            $result.cancelled = $sessionVariable -and $sessionVariable.Value -and (Test-ComplianceCancellation -Session $sessionVariable.Value)
            if (-not $result.cancelled -and $timer.ElapsedMilliseconds -lt $waitMilliseconds) { continue }
            $result.timed_out = -not $result.cancelled
            $result.error = if ($result.cancelled) { 'Execution annulee.' } else { "Delai depasse : $Timeout secondes." }
            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { & taskkill /PID $process.Id /T /F | Out-Null }
            else { $process.Kill() }
            break
        }
        $process.WaitForExit()
        $result.stdout = $stdout.Result
        $result.stderr = $stderr.Result
        $result.exit_code = $process.ExitCode
        foreach ($streamName in @('stdout', 'stderr')) {
            $streamBytes = [Text.Encoding]::UTF8.GetBytes([string]$result.$streamName)
            if ($streamBytes.Length -gt $MaxOutputBytes) {
                $result.$streamName = [Text.Encoding]::UTF8.GetString($streamBytes, 0, $MaxOutputBytes)
                $result.output_truncated = $true
            }
        }
    } catch { $result.error = $_.Exception.Message }
    finally {
        $process.Dispose()
        $timer.Stop()
        $result.execution_end = [DateTimeOffset]::UtcNow.ToString('o')
        $result.duration_ms = $timer.ElapsedMilliseconds
    }
    return $result
}

function Test-ResolvedCommandExecution {
    param(
        [Parameter(Mandatory = $true)][string]$Executable,
        [string[]]$Arguments = @('--version'),
        [string]$ExpectedVersion,
        [string]$WorkingDirectory = $repoRoot,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 10
    )
    $evidenceArguments = @($Arguments)
    $probeExecutable = $Executable
    $probeArguments = @($Arguments)
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT -and [IO.Path]::GetExtension($Executable) -in @('.cmd', '.bat')) {
        $escapedExecutable = $Executable.Replace("'", "''")
        $quotedArguments = @($Arguments | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ' '
        $probeScript = "& '$escapedExecutable' $quotedArguments; exit `$LASTEXITCODE"
        $probeExecutable = Join-Path $PSHOME 'powershell.exe'
        $probeArguments = @('-NoProfile', '-NonInteractive', '-Command', $probeScript)
    }
    $execution = Invoke-BoundedProcess -Executable $probeExecutable -Arguments $probeArguments -WorkingDirectory $WorkingDirectory -Timeout $TimeoutSeconds -MaxOutputBytes 65536
    $output = @($execution.stdout, $execution.stderr) -join "`n"
    $failureReason = if ($execution.error) { $execution.error }
        elseif ($execution.exit_code -ne 0) { "La commande de qualification a retourné le code $($execution.exit_code)." }
        elseif ($ExpectedVersion -and $output -notmatch [regex]::Escape($ExpectedVersion)) { "La sortie ne confirme pas la version $ExpectedVersion." }
        else { $null }
    return [pscustomobject]@{
        status = if ($failureReason) { 'runtime_error' } else { 'available' }
        reason = $failureReason
        evidence = [pscustomobject]@{
            executable = $Executable
            arguments = $evidenceArguments
            expected_version = $ExpectedVersion
            exit_code = $execution.exit_code
            duration_ms = $execution.duration_ms
            timed_out = $execution.timed_out
            observed_at = $execution.execution_end
            version_output = ($output.Trim() -replace [regex]::Escape($repoRoot), '<platform>')
        }
    }
}

function Get-ResolverCommandProbe {
    param([string]$Executable, [string[]]$Arguments, [string]$ExpectedVersion, [switch]$SkipExecutionProbe)
    $probeSetting = Get-Variable -Name ProbeCandidateTools -Scope Script -ErrorAction SilentlyContinue
    if ($SkipExecutionProbe -or -not $probeSetting -or -not $probeSetting.Value) { return [pscustomobject]@{ status = 'available'; reason = $null; evidence = $null } }
    $cache = Get-Variable -Name CommandProbeCache -Scope Script -ErrorAction SilentlyContinue
    if (-not $cache) { $script:CommandProbeCache = @{}; $cache = Get-Variable -Name CommandProbeCache -Scope Script }
    $resolvedPath = if (Test-Path -LiteralPath $Executable -PathType Leaf) { [IO.Path]::GetFullPath($Executable) } else { $Executable }
    $cacheKey = "$resolvedPath|$($Arguments -join [char]31)|$ExpectedVersion"
    if ($cache.Value.ContainsKey($cacheKey)) { return $cache.Value[$cacheKey] }
    $result = Test-ResolvedCommandExecution -Executable $resolvedPath -Arguments $Arguments -ExpectedVersion $ExpectedVersion -WorkingDirectory $repoRoot
    $cache.Value[$cacheKey] = $result
    return $result
}

function Invoke-External {
    param(
        [string]$Name,
        [string]$Executable,
        [string[]]$Arguments = @(),
        [switch]$Required,
        [switch]$Optional,
        [ValidateRange(0, 3600)][int]$TimeoutSeconds = 0
    )
    $resolved = if (Test-Path $Executable -PathType Leaf) { $Executable } else {
        $command = Get-Command $Executable -ErrorAction SilentlyContinue
        if ($command) { $command.Source } else { $null }
    }
    if (-not $resolved) {
        $status = if ($Optional) { 'WARN' } elseif ($Required) { 'ERROR' } else { 'SKIP' }
        Add-Check $status $Name "Outil absent : $Executable"
        return $false
    }
    $processTimeout = if ($TimeoutSeconds -gt 0) { $TimeoutSeconds } else { $script:ProcessTimeoutSeconds }
    $execution = Invoke-BoundedProcess -Executable $resolved -Arguments $Arguments -WorkingDirectory $repoRoot -Timeout $processTimeout
    if ($execution.stdout) { Write-Information -InformationAction Continue $execution.stdout.TrimEnd() }
    if ($execution.stderr) { Write-Information -InformationAction Continue $execution.stderr.TrimEnd() }
    if ($execution.error) {
        Add-Check ERROR $Name $execution.error $execution.duration_ms
        return $false
    }
    if ($execution.exit_code -eq 0) {
        Add-Check PASS $Name "Contrôle réussi : $Name." $execution.duration_ms
        return $true
    }
    Add-Check FAIL $Name "Échec de $Name (code $($execution.exit_code))." $execution.duration_ms
    return $false
}

function Invoke-PythonTool {
    param([string]$Name, [string[]]$Arguments)
    if (-not (Test-Path $python -PathType Leaf)) {
        Add-Check ERROR $Name 'Python local absent; exécutez scripts/bootstrap.ps1.'
        return $false
    }
    return Invoke-External -Name $Name -Executable $python -Arguments (@('-m') + $Arguments) -Required
}

function Get-RepositoryRelativePath {
    param([string]$Path, [string]$RepositoryRoot)
    $rootPrefix = $RepositoryRoot.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if ($Path.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $Path.Substring($rootPrefix.Length).Replace('\', '/')
    }
    return '.'
}

function ConvertTo-TechnologyRecord {
    param([string]$Name)
    return [pscustomobject]@{
        technology = $Name
        status = 'absent'
        evidence = New-Object System.Collections.Generic.List[string]
        roots = New-Object System.Collections.Generic.List[string]
        ambiguities = New-Object System.Collections.Generic.List[string]
    }
}

function Add-TechnologyEvidence {
    param(
        [pscustomobject]$State,
        [System.IO.FileInfo]$File,
        [string]$RepositoryRoot,
        [string]$ProjectRoot,
        [ValidateSet('detected', 'ambiguous')][string]$Status = 'detected',
        [string]$Ambiguity
    )
    $relativeFile = Get-RepositoryRelativePath -Path $File.FullName -RepositoryRoot $RepositoryRoot
    $relativeRoot = if ($ProjectRoot -eq $RepositoryRoot) { '.' } else { Get-RepositoryRelativePath -Path $ProjectRoot -RepositoryRoot $RepositoryRoot }
    if (-not $State.evidence.Contains($relativeFile)) { $State.evidence.Add($relativeFile) }
    if (-not $State.roots.Contains($relativeRoot)) { $State.roots.Add($relativeRoot) }
    if ($Status -eq 'detected') { $State.status = 'detected' }
    elseif ($State.status -eq 'absent') { $State.status = 'ambiguous' }
    if ($Ambiguity -and -not $State.ambiguities.Contains($Ambiguity)) { $State.ambiguities.Add($Ambiguity) }
}

function Get-NearestProjectRoot {
    param([System.IO.FileInfo]$File, [string]$RepositoryRoot, [string[]]$Markers)
    $directory = Get-Item -LiteralPath $File.DirectoryName
    while ($directory -and $directory.FullName.StartsWith($RepositoryRoot, [StringComparison]::OrdinalIgnoreCase)) {
        foreach ($marker in $Markers) {
            if (Test-Path -LiteralPath (Join-Path $directory.FullName $marker) -PathType Leaf) { return $directory.FullName }
        }
        if ($directory.FullName -eq $RepositoryRoot) { break }
        $directory = $directory.Parent
    }
    return $File.DirectoryName
}

function Get-Technology {
    param([string]$RepositoryRoot = $repoRoot)
    $files = @($script:Files)
    $pythonFiles = @($files | Where-Object Extension -eq '.py')
    $sourcePython = @($pythonFiles | Where-Object FullName -NotMatch '[\\/]tests[\\/]')
    $testPython = @($pythonFiles | Where-Object FullName -Match '[\\/]tests[\\/]')
    $terraformFiles = @($files | Where-Object Extension -eq '.tf')
    $opentofuFiles = @($files | Where-Object Extension -eq '.tofu')
    $hclFiles = @($files | Where-Object { $_.Extension -eq '.hcl' -or $_.Name -match '^terragrunt\.hcl$' })
    $powerShellFiles = @($files | Where-Object Extension -In @('.ps1', '.psm1', '.psd1'))
    $shellFiles = @($files | Where-Object Extension -eq '.sh')
    $containerFiles = @($files | Where-Object Name -Match '^(Dockerfile|Containerfile)(\..+)?$|^(docker-compose|compose)\.(yml|yaml)$')
    $terragruntFiles = @($files | Where-Object Name -Match '^terragrunt(\.stack)?\.hcl$')
    $markdownFiles = @($files | Where-Object Extension -eq '.md')
    $javascriptFiles = @($files | Where-Object Extension -In @('.js', '.jsx', '.mjs', '.cjs'))
    $typescriptFiles = @($files | Where-Object Extension -In @('.ts', '.tsx', '.mts', '.cts'))
    $yamlFiles = @($files | Where-Object Extension -In @('.yml', '.yaml'))
    $states = @{}
    foreach ($name in @('terraform', 'opentofu', 'terragrunt', 'ansible', 'python', 'powershell', 'docker', 'kubernetes', 'helm', 'shell', 'javascript', 'typescript', 'markdown')) {
        $states[$name] = ConvertTo-TechnologyRecord -Name $name
    }

    foreach ($file in $pythonFiles) {
        $projectRoot = Get-NearestProjectRoot -File $file -RepositoryRoot $RepositoryRoot -Markers @('pyproject.toml', 'setup.py', 'setup.cfg', 'requirements.txt')
        Add-TechnologyEvidence -State $states.python -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot
    }
    foreach ($file in $powerShellFiles) { Add-TechnologyEvidence -State $states.powershell -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }
    foreach ($file in $shellFiles) { Add-TechnologyEvidence -State $states.shell -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }
    foreach ($file in $markdownFiles) { Add-TechnologyEvidence -State $states.markdown -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $RepositoryRoot }
    foreach ($file in $javascriptFiles) {
        $projectRoot = Get-NearestProjectRoot -File $file -RepositoryRoot $RepositoryRoot -Markers @('package.json')
        Add-TechnologyEvidence -State $states.javascript -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot
    }
    foreach ($file in $typescriptFiles) {
        $projectRoot = Get-NearestProjectRoot -File $file -RepositoryRoot $RepositoryRoot -Markers @('tsconfig.json', 'package.json')
        Add-TechnologyEvidence -State $states.typescript -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot
    }

    $terraformVersion = @($files | Where-Object Name -eq '.terraform-version')
    $opentofuMarkers = @($files | Where-Object Name -In @('.opentofu-version', '.tofurc'))
    foreach ($file in $opentofuFiles + $opentofuMarkers) { Add-TechnologyEvidence -State $states.opentofu -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }
    foreach ($file in $terraformFiles) {
        $projectRoot = Get-NearestProjectRoot -File $file -RepositoryRoot $RepositoryRoot -Markers @('.terraform-version', '.opentofu-version', '.tofurc')
        $hasTerraform = Test-Path -LiteralPath (Join-Path $projectRoot '.terraform-version') -PathType Leaf
        $hasOpenTofu = (Test-Path -LiteralPath (Join-Path $projectRoot '.opentofu-version') -PathType Leaf) -or (Test-Path -LiteralPath (Join-Path $projectRoot '.tofurc') -PathType Leaf)
        if ($hasTerraform -and -not $hasOpenTofu) {
            Add-TechnologyEvidence -State $states.terraform -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot
            foreach ($marker in @($terraformVersion | Where-Object DirectoryName -eq $projectRoot)) { Add-TechnologyEvidence -State $states.terraform -File $marker -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot }
        } elseif ($hasOpenTofu -and -not $hasTerraform) {
            Add-TechnologyEvidence -State $states.opentofu -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot
        } else {
            $ambiguity = if ($hasTerraform -and $hasOpenTofu) { 'Marqueurs Terraform et OpenTofu contradictoires dans la meme racine.' } else { 'Fichiers .tf sans marqueur de selection dans leur racine.' }
            Add-TechnologyEvidence -State $states.terraform -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot -Status ambiguous -Ambiguity $ambiguity
            Add-TechnologyEvidence -State $states.opentofu -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $projectRoot -Status ambiguous -Ambiguity $ambiguity
        }
    }

    foreach ($file in $terragruntFiles) { Add-TechnologyEvidence -State $states.terragrunt -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }
    foreach ($file in $containerFiles) { Add-TechnologyEvidence -State $states.docker -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }

    $helmCharts = @($files | Where-Object Name -eq 'Chart.yaml')
    foreach ($file in $helmCharts) { Add-TechnologyEvidence -State $states.helm -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }

    $ansibleEvidence = @($files | Where-Object {
        $relative = Get-RepositoryRelativePath -Path $_.FullName -RepositoryRoot $RepositoryRoot
        $relative -match '(^|/)(ansible\.cfg|galaxy\.yml)$|(^|/)meta/runtime\.yml$|(^|/)(roles|playbooks)/|(^|/)requirements\.yml$'
    })
    foreach ($file in $ansibleEvidence) {
        $relativeFile = Get-RepositoryRelativePath -Path $file.FullName -RepositoryRoot $RepositoryRoot
        $ansibleRoot = $file.DirectoryName
        if ($relativeFile -match '(^|/)(ansible\.cfg|galaxy\.yml)$') { $ansibleRoot = $file.DirectoryName }
        elseif ($relativeFile -match '^(?<root>.*?)(?:/)?(?:roles|playbooks)/') {
            $rootRelative = $Matches.root.TrimEnd('/')
            if ($rootRelative) { $ansibleRoot = Join-Path $RepositoryRoot $rootRelative.Replace('/', [IO.Path]::DirectorySeparatorChar) }
            elseif ($relativeFile -match '^roles/([^/]+)/') { $ansibleRoot = Join-Path (Join-Path $RepositoryRoot 'roles') $Matches[1] }
            else { $ansibleRoot = $RepositoryRoot }
        } elseif ($relativeFile -match '^(?<root>.*?)(?:/)?meta/runtime\.yml$') {
            $rootRelative = $Matches.root.TrimEnd('/')
            $ansibleRoot = if ($rootRelative) { Join-Path $RepositoryRoot $rootRelative.Replace('/', [IO.Path]::DirectorySeparatorChar) } else { $RepositoryRoot }
        }
        Add-TechnologyEvidence -State $states.ansible -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $ansibleRoot
    }
    if ($states.ansible.status -eq 'absent') {
        foreach ($file in $yamlFiles) {
            $content = Get-DiscoveryFileContent -File $file
            if ($content -match '(?m)^\s*(?:-\s*)?hosts\s*:') {
                $ambiguity = 'La clé hosts: dans un YAML est un signal faible; le fichier peut être un playbook Ansible ou un YAML générique.'
                Add-TechnologyEvidence -State $states.ansible -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName -Status ambiguous -Ambiguity $ambiguity
            }
        }
    }

    $kubernetesKinds = 'Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Service|ConfigMap|Secret|Ingress|PersistentVolume|PersistentVolumeClaim|Namespace|ServiceAccount|Role|RoleBinding|ClusterRole|ClusterRoleBinding|CustomResourceDefinition'
    foreach ($file in $yamlFiles) {
        $content = Get-DiscoveryFileContent -File $file
        if ($content -match '(?m)^\s*apiVersion\s*:\s*\S+' -and $content -match "(?m)^\s*kind\s*:\s*($kubernetesKinds)\s*(?:#.*)?$") {
            $status = if ($content -match '\{\{') { 'ambiguous' } else { 'detected' }
            $ambiguity = if ($status -eq 'ambiguous') { "Le YAML contient des marqueurs de template Helm; la ressource rendue n'est pas confirmée." } else { $null }
            Add-TechnologyEvidence -State $states.kubernetes -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName -Status $status -Ambiguity $ambiguity
        }
    }

    $packageFiles = @($files | Where-Object Name -eq 'package.json')
    foreach ($file in $packageFiles) { Add-TechnologyEvidence -State $states.javascript -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }
    $tsconfigFiles = @($files | Where-Object Name -Match '^tsconfig(\..+)?\.json$')
    foreach ($file in $tsconfigFiles) { Add-TechnologyEvidence -State $states.typescript -File $file -RepositoryRoot $RepositoryRoot -ProjectRoot $file.DirectoryName }

    $technologyResults = @($states.Values | ForEach-Object {
        [pscustomobject]@{
            technology = $_.technology
            status = if ($_.ambiguities.Count -gt 0) { 'ambiguous' } else { $_.status }
            evidence = @($_.evidence.ToArray())
            roots = @($_.roots.ToArray())
            ambiguities = @($_.ambiguities.ToArray())
        }
    } | Sort-Object technology)
    $projectRoots = @($technologyResults | ForEach-Object {
        $technology = $_.technology
        foreach ($root in $_.roots) { [pscustomobject]@{ technology = $technology; path = $root } }
    })
    $ambiguities = @($technologyResults | Where-Object { $_.ambiguities.Count -gt 0 } | ForEach-Object {
        [pscustomobject]@{ technology = $_.technology; evidence = $_.evidence; roots = $_.roots; reasons = $_.ambiguities }
    })
    $capabilityMatrix = Get-CapabilityMatrix -Discoveries $technologyResults
    $toolResolution = Resolve-CapabilityTool -CapabilityMatrix $capabilityMatrix

    [pscustomobject]@{
        repository_root = $RepositoryRoot
        python = ($pythonFiles.Count -gt 0)
        python_files = $pythonFiles
        python_source = $sourcePython
        python_tests = $testPython
        powershell = ($powerShellFiles.Count -gt 0)
        powershell_files = $powerShellFiles
        shell = ($shellFiles.Count -gt 0)
        shell_files = $shellFiles
        terraform = ($terraformFiles.Count -gt 0 -and $states.terraform.status -eq 'detected' -and $states.terraform.ambiguities.Count -eq 0)
        terraform_ambiguous = ($states.terraform.ambiguities.Count -gt 0)
        terraform_files = $terraformFiles
        terragrunt = ($terragruntFiles.Count -gt 0)
        hcl_files = $hclFiles
        ansible = ($states.ansible.status -in @('detected', 'ambiguous'))
        ansible_ambiguous = ($states.ansible.status -eq 'ambiguous')
        containers = ($containerFiles.Count -gt 0)
        container_files = $containerFiles
        markdown = ($markdownFiles.Count -gt 0)
        discoveries = $technologyResults
        project_roots = $projectRoots
        ambiguities = $ambiguities
        capability_matrix = $capabilityMatrix
        tool_resolution = $toolResolution
        scan_complete = ($script:ScanErrors.Count -eq 0)
        scan_errors = @($script:ScanErrors.ToArray())
    }
}

function Get-ExecutionPlatform {
    $operatingSystem = 'unknown'
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { $operatingSystem = 'windows' }
    elseif (Test-Path Env:OSTYPE) {
        if ($env:OSTYPE -like 'darwin*') { $operatingSystem = 'macos' }
        elseif ($env:OSTYPE -like 'linux*') { $operatingSystem = 'linux' }
    }
    $architectureValue = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $architecture = switch -Regex ($architectureValue) {
        '^(AMD64|x86_64)$' { 'x64'; break }
        '^(ARM64|aarch64)$' { 'arm64'; break }
        '^(x86|i386)$' { 'x86'; break }
        default { 'unknown' }
    }
    [pscustomobject]@{
        os = $operatingSystem
        architecture = $architecture
        id = "$operatingSystem-$architecture"
    }
}

function Get-PlatformQualificationStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$PlatformId)
    $platformEntries = @($script:PlatformSupportMatrix.platforms | Where-Object id -eq $PlatformId)
    if ($platformEntries.Count -ne 1) { return $null }
    return [string]$platformEntries[0].status
}

function Get-ToolRuntimeIndex {
    $runtimeRoot = Join-Path (Split-Path -Parent $toolRoot) 'runtime'
    $indexPath = Join-Path $runtimeRoot 'index.json'
    if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) { return $null }
    try {
        $index = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
        if ($index.schema_version -ne 1 -or -not $index.platforms) { throw 'Schema index Tool Runtime non supporte.' }
        return [pscustomobject]@{ root = $runtimeRoot; data = $index }
    } catch {
        return [pscustomobject]@{ root = $runtimeRoot; error = $_.Exception.Message; data = $null }
    }
}

function Get-ArtifactIntegrityError {
    param([string]$ArtifactPath, [pscustomobject]$Record)
    $hashProperty = $Record.PSObject.Properties['sha256']
    if (-not $hashProperty -or $hashProperty.Value -notmatch '^[a-fA-F0-9]{64}$') {
        return 'Empreinte SHA-256 absente ou invalide dans l index Tool Runtime.'
    }
    try {
        $actualHash = (Get-FileHash -LiteralPath $ArtifactPath -Algorithm SHA256 -ErrorAction Stop).Hash
        if ($actualHash -ne $hashProperty.Value) { return 'Integrite Tool Runtime invalide: SHA-256 different de l index.' }
    } catch { return "Verification d integrite impossible: $($_.Exception.Message)" }
}

function Get-IndexedPythonPackageName {
    param([Parameter(Mandatory = $true)][string]$Command)
    $distribution = if ($Command -eq 'ansible') { 'ansible-core' } else { $Command }
    return [regex]::Replace($distribution, '[-_.]+', '-').ToLowerInvariant()
}

function Get-IndexedModuleIntegrityError {
    param([string]$PlatformRoot, [pscustomobject]$Record)
    if ([string]::IsNullOrWhiteSpace($Record.path) -or [IO.Path]::IsPathRooted($Record.path)) { return 'Chemin du module PowerShell non relatif.' }
    $modulePath = [IO.Path]::GetFullPath((Join-Path $PlatformRoot $Record.path))
    $platformPrefix = [IO.Path]::GetFullPath($PlatformRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    if (-not $modulePath.StartsWith($platformPrefix, [StringComparison]::OrdinalIgnoreCase)) { return 'Chemin du module PowerShell sortant de la plateforme.' }
    $manifestPath = Join-Path $modulePath "$($Record.name).psd1"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { return 'Manifeste du module PowerShell absent.' }
    $manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($manifestHash -ne $Record.manifest_sha256) { return 'Manifeste du module PowerShell altere.' }
    $treeHash = Get-DirectoryTreeSha256 -Path $modulePath
    if (-not $treeHash -or $treeHash -ne $Record.tree_sha256) { return 'Arbre du module PowerShell altere.' }
}

function Get-ExecutionIntegrityError {
    param([string]$ArtifactPath)
    $artifactFullPath = [IO.Path]::GetFullPath($ArtifactPath)
    $runtimeRoot = Join-Path (Split-Path -Parent $toolRoot) 'runtime'
    $managed = $false
    foreach ($directory in @($toolRoot, $runtimeRoot)) {
        $prefix = [IO.Path]::GetFullPath($directory).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if ($artifactFullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { $managed = $true }
    }
    if (-not $managed) { return }
    $runtimeIndex = Get-ToolRuntimeIndex
    if (-not $runtimeIndex) { return 'Index Tool Runtime absent pour cet outil gere.' }
    if ($runtimeIndex.PSObject.Properties.Name -contains 'error') { return "Index Tool Runtime invalide: $($runtimeIndex.error)" }
    $platform = Get-ExecutionPlatform
    $platformRecord = $runtimeIndex.data.platforms.PSObject.Properties[$platform.id]
    if (-not $platformRecord -or $platformRecord.Value.status -ne 'qualified') { return 'Plateforme Tool Runtime non qualifiee.' }
    $runtimePrefix = [IO.Path]::GetFullPath($runtimeRoot).TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    foreach ($record in @($platformRecord.Value.tools | Where-Object active)) {
        if ([IO.Path]::IsPathRooted($record.path)) { return 'Chemin Tool Runtime non relatif.' }
        $indexedPath = [IO.Path]::GetFullPath((Join-Path $runtimeRoot $record.path))
        if (-not $indexedPath.StartsWith($runtimePrefix, [StringComparison]::OrdinalIgnoreCase)) { return 'Chemin sortant du Tool Runtime.' }
        $legacyPath = [IO.Path]::GetFullPath((Join-Path $toolRoot (Split-Path $record.path -Leaf)))
        if ($artifactFullPath -eq $indexedPath -or $artifactFullPath -eq $legacyPath) {
            if ($record.status -ne 'qualified') { return 'Outil Tool Runtime non qualifie.' }
            return Get-ArtifactIntegrityError -ArtifactPath $artifactFullPath -Record $record
        }
    }
    return 'Outil gere absent des versions actives de l index Tool Runtime.'
}

function Resolve-CandidateTool {
    param([string]$Name, [string]$Command, [switch]$SkipExecutionProbe)
    $runtimeRoot = Split-Path -Parent (Split-Path -Parent $toolRoot)
    $platform = Get-ExecutionPlatform
    $runtimeIndex = Get-ToolRuntimeIndex
    $platformRecord = $null
    if ($runtimeIndex -and $runtimeIndex.PSObject.Properties.Name -notcontains 'error') {
        $platformRecord = $runtimeIndex.data.platforms.PSObject.Properties[$platform.id]
    }
    if ($runtimeIndex -and $runtimeIndex.PSObject.Properties.Name -contains 'error') {
        return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $null; version = $null; runtime_managed = $true; platform = $platform.id; reason = "Index Tool Runtime invalide: $($runtimeIndex.error)" }
    }
    if ($platform.os -eq 'windows' -and $Command -in @('ansible', 'ansible-lint', 'molecule')) {
        return [pscustomobject]@{ name = $Name; command = $Command; status = 'incompatible'; source = $null; version = $null; runtime_managed = $false; platform = $platform.id; reason = 'Controleur Ansible/Molecule natif Windows non supporte; la presence du paquet ne prouve pas son execution.' }
    }
    if ($runtimeIndex) {
        $platformRecord = $runtimeIndex.data.platforms.PSObject.Properties[$platform.id]
        if ($platformRecord) {
            $platformData = $platformRecord.Value
            $toolRecord = @($platformData.tools | Where-Object { $_.name -eq $Name -or $_.command -eq $Command } | Where-Object active | Select-Object -First 1)
            if ($toolRecord.Count -gt 0) {
                $toolRecord = $toolRecord[0]
                if ($platformData.status -ne 'qualified' -or $toolRecord.status -ne 'qualified') {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'incompatible'; source = $null; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = "La plateforme ou l'outil n'est pas qualifie: $($platformData.status)/$($toolRecord.status)." }
                }
                $provenanceError = Get-ToolArtifactProvenanceError -Record $toolRecord
                if ($provenanceError) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'integrity_error'; source = $null; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = $provenanceError }
                }
                if ([string]::IsNullOrWhiteSpace($toolRecord.path) -or [IO.Path]::IsPathRooted($toolRecord.path)) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $null; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = "Le chemin de l'artefact runtime doit être relatif." }
                }
                $toolPath = [IO.Path]::GetFullPath((Join-Path $runtimeIndex.root $toolRecord.path))
                $runtimePrefix = $runtimeIndex.root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
                if (-not $toolPath.StartsWith($runtimePrefix, [StringComparison]::OrdinalIgnoreCase)) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $null; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = "Le chemin de l'artefact sort du Tool Runtime." }
                }
                if (-not (Test-Path -LiteralPath $toolPath -PathType Leaf)) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'not_installed'; source = $toolPath; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = "L'index annonce cet outil, mais son artefact est absent du cache." }
                }
                $integrityError = Get-ArtifactIntegrityError -ArtifactPath $toolPath -Record $toolRecord
                if ($integrityError) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'integrity_error'; source = $toolPath; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = $integrityError }
                }
                $versionArguments = @()
                if ($toolRecord.PSObject.Properties.Name -contains 'version_arguments') { $versionArguments = @($toolRecord.version_arguments) }
                if ($versionArguments.Count -eq 0) { $versionArguments = @('--version') }
                $probe = Get-ResolverCommandProbe -Executable $toolPath -Arguments $versionArguments -ExpectedVersion $toolRecord.version -SkipExecutionProbe:$SkipExecutionProbe
                if ($probe.status -ne 'available') { return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $toolPath; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = "Qualification d'execution impossible: $($probe.reason)"; execution_probe = $probe.evidence } }
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $toolPath; version = $toolRecord.version; runtime_managed = $true; platform = $platform.id; reason = 'Outil qualifié, provenance vérifiée et commande exécutée.'; execution_probe = $probe.evidence }
            }
        }
        $otherPlatformTool = $false
        foreach ($platformEntry in $runtimeIndex.data.platforms.PSObject.Properties) {
            if (@($platformEntry.Value.tools | Where-Object { $_.name -eq $Name -or $_.command -eq $Command }).Count -gt 0) { $otherPlatformTool = $true; break }
        }
        if ($otherPlatformTool -and -not $platformRecord) {
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'incompatible'; source = $null; version = $null; runtime_managed = $true; platform = $platform.id; reason = "L'outil est reference dans le runtime pour d'autres plateformes seulement." }
        }
    }
    $venvCandidates = @(
        (Join-Path $runtimeRoot ".venv\Scripts\$Command.exe"),
        (Join-Path $runtimeRoot ".venv\Scripts\$Command.cmd"),
        (Join-Path $runtimeRoot ".venv\Scripts\$Command")
    )
    foreach ($candidatePath in $venvCandidates) {
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            if ($platformRecord -and $platformRecord.Value.PSObject.Properties.Name -contains 'python_packages') {
                if ($platformRecord.Value.status -ne 'qualified') {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'incompatible'; source = $candidatePath; version = $null; runtime_managed = $true; platform = $platform.id; reason = 'Environnement Python present dans un runtime non qualifie.' }
                }
                $packageName = Get-IndexedPythonPackageName -Command $Command
                $inventoryError = Get-RuntimePythonInventoryError -Platform $platformRecord.Value
                if ($inventoryError) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $candidatePath; version = $null; runtime_managed = $true; platform = $platform.id; reason = $inventoryError }
                }
                $packageRecords = @($platformRecord.Value.python_packages | Where-Object name -eq $packageName)
                $pythonRecord = $platformRecord.Value.python
                if ($packageRecords.Count -ne 1 -or -not $pythonRecord) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $candidatePath; version = $null; runtime_managed = $true; platform = $platform.id; reason = "Package absent ou duplique dans l'inventaire Python: $packageName." }
                }
                $provenanceError = Get-PythonWheelProvenanceError -Record $packageRecords[0] -RepositoryRoot $runtimeRoot
                if ($provenanceError) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'integrity_error'; source = $candidatePath; version = $packageRecords[0].version; runtime_managed = $true; platform = $platform.id; reason = $provenanceError }
                }
                $lockPath = Join-Path $runtimeRoot 'requirements-dev.lock'
                if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf) -or (Get-FileHash -LiteralPath $lockPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonRecord.dependency_lock_sha256) {
                    return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $candidatePath; version = $packageRecords[0].version; runtime_managed = $true; platform = $platform.id; reason = 'Le lock Python ne correspond pas a l inventaire Runtime.' }
                }
                $probe = Get-ResolverCommandProbe -Executable $candidatePath -Arguments @('--version') -ExpectedVersion $packageRecords[0].version -SkipExecutionProbe:$SkipExecutionProbe
                if ($probe.status -ne 'available') { return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $candidatePath; version = $packageRecords[0].version; runtime_managed = $true; platform = $platform.id; reason = "Qualification d'execution impossible: $($probe.reason)"; execution_probe = $probe.evidence } }
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $candidatePath; version = $packageRecords[0].version; runtime_managed = $true; platform = $platform.id; reason = "Version $($packageRecords[0].version) du package $packageName indexee et commande executee."; execution_probe = $probe.evidence }
            }
            if ($platformRecord -and $platformRecord.Value.status -eq 'qualified') {
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $candidatePath; version = $null; runtime_managed = $true; platform = $platform.id; reason = 'Inventaire Python absent du Runtime Index.' }
            }
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $candidatePath; version = $null; runtime_managed = $true; platform = $platform.id; reason = "Outil trouve dans l'environnement Python gere par Compliance_Platform." }
        }
    }
    if ($Command -eq 'Invoke-ScriptAnalyzer') {
        if ($platformRecord -and $platformRecord.Value.PSObject.Properties.Name -contains 'powershell_modules') {
            if ($platformRecord.Value.status -ne 'qualified') {
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'incompatible'; source = $null; version = $null; runtime_managed = $true; platform = $platform.id; reason = 'Modules PowerShell presents dans un runtime non qualifie.' }
            }
            $moduleRecords = @($platformRecord.Value.powershell_modules | Where-Object name -eq 'PSScriptAnalyzer')
            if ($moduleRecords.Count -ne 1) {
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $null; version = $null; runtime_managed = $true; platform = $platform.id; reason = 'PSScriptAnalyzer absent ou duplique dans le Runtime Index.' }
            }
            $moduleRecord = $moduleRecords[0]
            $moduleIntegrityError = Get-IndexedModuleIntegrityError -PlatformRoot $runtimeRoot -Record $moduleRecord
            if ($moduleIntegrityError) {
                return [pscustomobject]@{ name = $Name; command = $Command; status = 'integrity_error'; source = (Join-Path $runtimeRoot $moduleRecord.path); version = $moduleRecord.version; runtime_managed = $true; platform = $platform.id; reason = $moduleIntegrityError }
            }
            $modulePath = [IO.Path]::GetFullPath((Join-Path $runtimeRoot $moduleRecord.path))
            $moduleManifest = Join-Path $modulePath 'PSScriptAnalyzer.psd1'
            $escapedModuleManifest = $moduleManifest.Replace("'", "''")
            $probeScript = "Import-Module -Name '$escapedModuleManifest' -Force -ErrorAction Stop; Invoke-ScriptAnalyzer -ScriptDefinition 'Write-Output 1' -Severity Error | Out-Null; (Get-Module PSScriptAnalyzer).Version.ToString()"
            $probe = Get-ResolverCommandProbe -Executable (Join-Path $PSHOME 'powershell.exe') -Arguments @('-NoProfile', '-NonInteractive', '-Command', $probeScript) -ExpectedVersion $moduleRecord.version -SkipExecutionProbe:$SkipExecutionProbe
            if ($probe.status -ne 'available') { return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = (Join-Path $runtimeRoot $moduleRecord.path); version = $moduleRecord.version; runtime_managed = $true; platform = $platform.id; reason = "Qualification d'execution impossible: $($probe.reason)"; execution_probe = $probe.evidence } }
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = (Join-Path (Join-Path $runtimeRoot $moduleRecord.path) 'PSScriptAnalyzer.psd1'); version = $moduleRecord.version; runtime_managed = $true; platform = $platform.id; reason = 'Module PSScriptAnalyzer indexe, integre et execute.'; execution_probe = $probe.evidence }
        }
        if ($platformRecord -and $platformRecord.Value.status -eq 'qualified') {
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $null; version = $null; runtime_managed = $true; platform = $platform.id; reason = 'Inventaire des modules PowerShell absent du Runtime Index.' }
        }
        $moduleRoot = Join-Path $runtimeRoot '.tools\powershell-modules\PSScriptAnalyzer'
        $moduleManifest = Get-ChildItem -LiteralPath $moduleRoot -Filter 'PSScriptAnalyzer.psd1' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($moduleManifest) {
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $moduleManifest.FullName; version = $moduleManifest.Directory.Name; runtime_managed = $true; platform = $platform.id; reason = 'Module trouvé dans les modules PowerShell gérés par Compliance_Platform.' }
        }
    }
    $commandInfo = Get-Command -Name $Command -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($commandInfo) {
        $source = if ($commandInfo.Source) { $commandInfo.Source } else { $commandInfo.Name }
        $probeArguments = if ($Command -in @('terraform', 'tofu', 'opentofu')) { @('version') } else { @('--version') }
        $probe = Get-ResolverCommandProbe -Executable $source -Arguments $probeArguments -ExpectedVersion $null -SkipExecutionProbe:$SkipExecutionProbe
        if ($probe.status -ne 'available') { return [pscustomobject]@{ name = $Name; command = $Command; status = 'runtime_error'; source = $source; version = $null; runtime_managed = $false; platform = $platform.id; reason = "Qualification d'execution impossible: $($probe.reason)"; execution_probe = $probe.evidence } }
        return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $source; version = $null; runtime_managed = $false; platform = $platform.id; reason = 'Commande du PATH résolue et exécutée.'; execution_probe = $probe.evidence }
    }
    $relativeCandidates = @(
        ".tools\bin\$Command.exe",
        ".tools\bin\$Command",
        ".venv\Scripts\$Command.exe",
        ".venv\Scripts\$Command.cmd",
        ".venv\Scripts\$Command"
    )
    foreach ($relativePath in $relativeCandidates) {
        $candidatePath = Join-Path $runtimeRoot $relativePath
        if (Test-Path -LiteralPath $candidatePath -PathType Leaf) {
            return [pscustomobject]@{ name = $Name; command = $Command; status = 'available'; source = $candidatePath; version = $null; runtime_managed = $false; platform = $platform.id; reason = 'Binaire présent dans les outils locaux de Compliance_Platform hors index runtime.' }
        }
    }
    [pscustomobject]@{ name = $Name; command = $Command; status = 'not_installed'; source = $null; version = $null; runtime_managed = $false; platform = $platform.id; reason = "Aucune commande ou aucun binaire local trouvé pour '$Command'." }
}

function Get-CapabilityProfile {
    param([string]$Technology)
    return @(Get-CatalogCapabilityProfile -Catalog $script:ControlCatalog -Technology $Technology)
}

function Get-CapabilityMatrix {
    param([object[]]$Discoveries)
    $platform = Get-ExecutionPlatform
    $entries = foreach ($discovery in $Discoveries) {
            $capabilityProfile = @(Get-CapabilityProfile -Technology $discovery.technology)
            $capabilities = foreach ($capability in $capabilityProfile) {
                $selectionPolicy = if ($capability.PSObject.Properties.Name -contains 'selection_policy') { $capability.selection_policy } else { 'all' }
                if ($selectionPolicy -notin @('all', 'alternative')) { throw 'Politique de selection de capacite invalide.' }
                $toolStateList = New-Object System.Collections.Generic.List[object]
                $alternativeSatisfied = $false
                foreach ($toolDefinition in $capability.tools) {
                    $skipProbe = $discovery.status -ne 'detected' -or ($selectionPolicy -eq 'alternative' -and $alternativeSatisfied)
                    $tool = Resolve-CandidateTool -Name $toolDefinition.name -Command $toolDefinition.command -SkipExecutionProbe:$skipProbe
                    foreach ($property in @('catalog_id', 'severity', 'side_effect_level', 'permissions', 'timeout_seconds', 'cost', 'parameters', 'dependencies', 'limitations', 'platform_support')) {
                        if ($toolDefinition.PSObject.Properties.Name -contains $property) { $tool | Add-Member -MemberType NoteProperty -Name $property -Value $toolDefinition.$property -Force }
                    }
                    $toolStateList.Add($tool)
                    if ($selectionPolicy -eq 'alternative' -and $tool.status -eq 'available') { $alternativeSatisfied = $true }
                }
                $toolStates = @($toolStateList.ToArray())
            $availableTools = @($toolStates | Where-Object status -eq 'available')
            $availability = if ($discovery.status -eq 'ambiguous') { 'ambiguous' }
                elseif ($discovery.status -eq 'absent') { 'not_applicable' }
                elseif ($toolStates.Count -eq 0) { 'unconfigured' }
                elseif ($selectionPolicy -eq 'alternative' -and $availableTools.Count -gt 0) { 'available' }
                elseif ($availableTools.Count -eq $toolStates.Count) { 'available' }
                elseif ($availableTools.Count -gt 0) { 'partially_available' }
                else { 'unavailable' }
            $reasons = New-Object System.Collections.Generic.List[string]
            if ($discovery.status -eq 'ambiguous') { $reasons.Add("La technologie est ambiguë; aucune capacité n’est considérée comme résolue.") }
            elseif ($discovery.status -eq 'absent') { $reasons.Add("La technologie est absente; la capacité n’est pas applicable.") }
            elseif ($toolStates.Count -eq 0) { $reasons.Add("Aucun outil candidat n'est configure pour cette capacite.") }
            elseif ($availableTools.Count -eq 0) { $reasons.Add("Aucun outil candidat n'est disponible sur cette plateforme.") }
            elseif ($selectionPolicy -eq 'alternative' -and $availableTools.Count -gt 0) { $reasons.Add('Une alternative est disponible; le premier candidat disponible sera retenu selon l ordre du profil.') }
            elseif ($availableTools.Count -lt $toolStates.Count) { $reasons.Add("Certains outils candidats sont disponibles; d'autres restent indisponibles sur cette plateforme.") }
            else { $reasons.Add('Au moins un outil candidat est disponible; la sélection finale appartient au Tool Resolver.') }
            [pscustomobject]@{
                name = $capability.name
                selection_policy = $selectionPolicy
                catalog_controls = @($capability.controls)
                    required = ($discovery.status -eq 'detected')
                availability = $availability
                candidate_tools = @($toolStates)
                available_tools = @($availableTools | ForEach-Object name)
                reasons = @($reasons.ToArray())
            }
        }
        $allTools = @($capabilities | ForEach-Object { $_.candidate_tools })
        [pscustomobject]@{
            technology = $discovery.technology
            technology_status = $discovery.status
            required_capabilities = @($capabilities | Where-Object required | ForEach-Object name)
            capabilities = @($capabilities)
            candidate_tools = @($allTools | Sort-Object name, command -Unique)
            platform = $platform
            reasons = @($discovery.ambiguities)
        }
    }
    @($entries)
}

function Resolve-CapabilityTool {
    param([object[]]$CapabilityMatrix)
    foreach ($technology in $CapabilityMatrix) {
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $selectedAssignments = 0
        $selectedByCommand = @{}
        $unresolved = New-Object System.Collections.Generic.List[object]
        if ($technology.technology_status -eq 'detected') {
            foreach ($capability in $technology.capabilities) {
                if (-not $capability.required) { continue }
                $selectionPolicy = if ($capability.PSObject.Properties.Name -contains 'selection_policy') { $capability.selection_policy } else { 'all' }
                if ($selectionPolicy -notin @('all', 'alternative')) { throw 'Politique de selection de capacite invalide.' }
                $availableCandidates = @($capability.candidate_tools | Where-Object status -eq 'available')
                if ($availableCandidates.Count -eq 0) {
                    $unresolved.Add([pscustomobject]@{
                        capability = $capability.name
                        status = $capability.availability
                        reasons = @($capability.reasons)
                    })
                    continue
                }
                if ($selectionPolicy -eq 'alternative') { $availableCandidates = @($availableCandidates | Select-Object -First 1) }
                foreach ($candidate in $availableCandidates) {
                    $selectedAssignments++
                    if (-not $selectedByCommand.ContainsKey($candidate.command)) {
                        $candidateVersion = if ($candidate.PSObject.Properties.Name -contains 'version') { $candidate.version } else { $null }
                        $candidateRuntimeManaged = if ($candidate.PSObject.Properties.Name -contains 'runtime_managed') { [bool]$candidate.runtime_managed } else { $false }
                        $candidatePlatform = if ($candidate.PSObject.Properties.Name -contains 'platform') { $candidate.platform } else { $technology.platform }
                        $selectedByCommand[$candidate.command] = [pscustomobject]@{
                            name = $candidate.name
                            command = $candidate.command
                            source = $candidate.source
                            version = $candidateVersion
                            runtime_managed = $candidateRuntimeManaged
                            platform = $candidatePlatform
                            execution_probe = if ($candidate.PSObject.Properties.Name -contains 'execution_probe') { $candidate.execution_probe } else { $null }
                            capabilities = New-Object System.Collections.Generic.List[string]
                        }
                    }
                    $selected = $selectedByCommand[$candidate.command]
                    if (-not $selected.capabilities.Contains($capability.name)) { $selected.capabilities.Add($capability.name) }
                }
                if ($selectionPolicy -eq 'all' -and $capability.availability -eq 'partially_available') {
                    $unresolved.Add([pscustomobject]@{
                        capability = $capability.name
                        status = 'partially_available'
                        reasons = @($capability.reasons)
                    })
                }
            }
        }
        $selectedTools = @($selectedByCommand.Values | Sort-Object command | ForEach-Object {
            [pscustomobject]@{
                name = $_.name
                command = $_.command
                source = $_.source
                version = $_.version
                runtime_managed = $_.runtime_managed
                platform = $_.platform
                execution_probe = $_.execution_probe
                capabilities = @($_.capabilities.ToArray())
            }
        })
        $resolutionStatus = if ($technology.technology_status -ne 'detected') { $technology.technology_status }
            elseif ($unresolved.Count -gt 0 -and $selectedTools.Count -gt 0) { 'partial' }
            elseif ($unresolved.Count -gt 0) { 'unavailable' }
            else { 'ready' }
        $timer.Stop()
        [pscustomobject]@{
            technology = $technology.technology
            technology_status = $technology.technology_status
            platform = $technology.platform
            status = $resolutionStatus
            selected_tools = $selectedTools
            unresolved_capabilities = @($unresolved.ToArray())
            metrics = [pscustomobject]@{
                required_capabilities = @($technology.capabilities | Where-Object required).Count
                candidate_occurrences = @($technology.capabilities | ForEach-Object { $_.candidate_tools }).Count
                selected_commands = $selectedTools.Count
                reused_assignments = $selectedAssignments - $selectedTools.Count
                unresolved_capabilities = $unresolved.Count
                duration_ms = $timer.ElapsedMilliseconds
            }
            reasons = if ($technology.technology_status -eq 'ambiguous') { @($technology.reasons) }
                elseif ($technology.technology_status -eq 'absent') { @('Technologie absente; aucun outil sélectionné.') }
                else { @() }
        }
    }
}

function Invoke-EmojiCheck {
    if (-not (Test-Category 'Security') -and -not (Test-Category 'Generic') -and -not (Test-Category 'All')) { return }
    $emojiScript = Join-Path $PSScriptRoot 'check-emoji.ps1'
    Invoke-External -Name 'Contrôle pictogrammes' -Executable 'powershell' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $emojiScript, '-Path', '.') -Required | Out-Null
}

function Invoke-GenericCheck {
    if (-not (Test-Category 'Generic') -and -not (Test-Category 'All')) { return }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) { Add-Check ERROR 'Dépôt Git' 'Git est obligatoire mais introuvable.' }
    else {
        $unmerged = & $git.Source -C $repoRoot diff --name-only --diff-filter=U
        $code = $LASTEXITCODE
        if ($code -ne 0) { Add-Check ERROR 'Conflits Git' "Impossible de lire l'état des conflits Git." }
        elseif (@($unmerged).Count -eq 0) { Add-Check PASS 'Conflits Git' 'Aucun conflit Git non résolu.' }
        else { Add-Check FAIL 'Conflits Git' "Conflits non résolus : $($unmerged -join ', ')" }
    }

    $issues = New-Object System.Collections.Generic.List[string]
    foreach ($file in $script:Files) {
        if ($file.Length -gt 5MB) { $issues.Add("Fichier supérieur à 5 Mio : $($file.Name)") }
        if ($file.Extension -in @('.pem', '.key', '.p12', '.pfx')) { $issues.Add("Fichier de clé privée potentiel : $($file.Name)") }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)
            if ($bytes -contains 0) { continue }
            $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        } catch [System.Text.DecoderFallbackException] { continue }
        if ($text -match '(?m)[ \t]+$') { $issues.Add("Espaces en fin de ligne : $($file.Name)") }
        if ($text.Length -gt 0 -and -not $text.EndsWith("`n")) { $issues.Add("Fin de fichier manquante : $($file.Name)") }
    }
    if ($issues.Count -eq 0) { Add-Check PASS 'Hygiène des fichiers' 'Tailles, espaces, fins de fichier et extensions sensibles vérifiés.' }
    else { Add-Check FAIL 'Hygiène des fichiers' ($issues -join '; ') }

    $yaml = @($script:Files | Where-Object Extension -In @('.yml', '.yaml'))
    if ($yaml.Count -eq 0) { Add-Check SKIP 'YAML' 'Aucun fichier YAML détecté.' }
    else {
        $yamllint = Join-Path $repoRoot '.venv\Scripts\yamllint.exe'
        $yamlArguments = @('-c', (Join-Path $repoRoot '.yamllint.yml')) + @($yaml.FullName)
        Invoke-External -Name 'Validation YAML' -Executable $yamllint -Arguments $yamlArguments -Required | Out-Null
    }

    $jsonFiles = @($script:Files | Where-Object Extension -eq '.json')
    $jsonErrors = New-Object System.Collections.Generic.List[string]
    Add-Type -AssemblyName System.Web.Extensions
    $jsonParser = New-Object System.Web.Script.Serialization.JavaScriptSerializer
    $jsonParser.MaxJsonLength = 10485760
    $jsonParser.RecursionLimit = 100
    foreach ($file in $jsonFiles) {
        try { $null = $jsonParser.DeserializeObject([IO.File]::ReadAllText($file.FullName, [Text.Encoding]::UTF8)) }
        catch { $jsonErrors.Add("$($file.Name) : $($_.Exception.Message)") }
    }
    if ($jsonFiles.Count -eq 0) { Add-Check SKIP 'Validation JSON' 'Aucun fichier JSON détecté.' }
    elseif ($jsonErrors.Count -eq 0) { Add-Check PASS 'Validation JSON' 'Tous les fichiers JSON sont valides.' }
    else { Add-Check FAIL 'Validation JSON' ($jsonErrors -join '; ') }

    $tomlFiles = @($script:Files | Where-Object Extension -eq '.toml')
    if ($tomlFiles.Count -eq 0) { Add-Check SKIP 'Validation TOML' 'Aucun fichier TOML détecté.' }
    elseif (-not (Test-Path $python -PathType Leaf)) { Add-Check ERROR 'Validation TOML' 'Le Python local est requis pour lire TOML.' }
    else {
        $tomlValid = $true
        foreach ($file in $tomlFiles) {
            'import sys,tomllib; tomllib.load(open(sys.argv[1], "rb"))' | & $python - $file.FullName
            if ($LASTEXITCODE -ne 0) { $tomlValid = $false }
        }
        if ($tomlValid) { Add-Check PASS 'Validation TOML' 'Tous les fichiers TOML sont valides.' }
        else { Add-Check FAIL 'Validation TOML' 'Au moins un fichier TOML est invalide.' }
    }

    $xmlFiles = @($script:Files | Where-Object Extension -eq '.xml')
    $xmlErrors = New-Object System.Collections.Generic.List[string]
    foreach ($file in $xmlFiles) {
        try { [xml](Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8) | Out-Null }
        catch { $xmlErrors.Add("$($file.Name) : $($_.Exception.Message)") }
    }
    if ($xmlFiles.Count -eq 0) { Add-Check SKIP 'Validation XML' 'Aucun fichier XML détecté.' }
    elseif ($xmlErrors.Count -eq 0) { Add-Check PASS 'Validation XML' 'Tous les fichiers XML sont valides.' }
    else { Add-Check FAIL 'Validation XML' ($xmlErrors -join '; ') }
}

function Invoke-SecretCheck {
    if (-not (Test-Category 'Security') -and -not (Test-Category 'Generic') -and -not (Test-Category 'All')) { return }
    $gitleaks = Join-Path $toolRoot 'gitleaks.exe'
    if (-not (Test-Path $gitleaks -PathType Leaf)) { Add-Check ERROR 'Gitleaks' 'Gitleaks requis absent de .tools/bin.'; return }
    Invoke-External -Name 'Analyse des secrets Gitleaks' -Executable $gitleaks -Arguments @('dir', '--redact', '--no-banner', '--config', (Join-Path $repoRoot '.gitleaks.toml'), $repoRoot) -Required | Out-Null
}

function Invoke-MarkdownCheck {
    if (-not (Test-Category 'Documentation') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.markdown) { Add-Check SKIP 'Markdownlint' 'Aucun fichier Markdown détecté.'; return }
    $preCommit = Join-Path $repoRoot '.venv\Scripts\pre-commit.exe'
    $env:PRE_COMMIT_HOME = Join-Path $repoRoot '.tools\pre-commit'
    $env:PIP_CERT = Join-Path $repoRoot '.tools\cache\windows-root-ca.pem'
    if (-not (Test-Path $preCommit -PathType Leaf)) { Add-Check ERROR 'Markdownlint' 'pre-commit local absent après bootstrap.'; return }
    $markdownFiles = @($script:Files | Where-Object Extension -eq '.md')
    Invoke-External -Name 'Markdownlint' -Executable $preCommit -Arguments (@('run', 'markdownlint', '--files') + @($markdownFiles.FullName)) -Required | Out-Null
}

function Invoke-PythonCheck {
    if (-not (Test-Category 'Python') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.python) {
        Add-Check SKIP 'Python' 'Aucun code Python détecté.'
        if ($script:RunFull) { Invoke-PythonTool -Name 'Audit des dépendances Python' -Arguments @('pip_audit', '--local', '--strict') | Out-Null }
        return
    }
    Invoke-PythonTool -Name 'Ruff format' -Arguments (@('ruff', 'format', '--check') + @($script:Technologies.python_files.FullName)) | Out-Null
    Invoke-PythonTool -Name 'Ruff lint' -Arguments (@('ruff', 'check') + @($script:Technologies.python_files.FullName)) | Out-Null
    if (-not $script:RunFull) { return }
    if ($script:Technologies.python_source.Count -gt 0) {
        Invoke-PythonTool -Name 'Pylint' -Arguments (@('pylint') + @($script:Technologies.python_source.FullName)) | Out-Null
        Invoke-PythonTool -Name 'mypy' -Arguments (@('mypy', '--config-file', (Join-Path $repoRoot 'pyproject.toml')) + @($script:Technologies.python_source.FullName)) | Out-Null
        Invoke-PythonTool -Name 'Bandit' -Arguments (@('bandit') + @($script:Technologies.python_source.FullName)) | Out-Null
    } else {
        Add-Check SKIP 'Pylint' 'Aucun code Python applicatif détecté.'
        Add-Check SKIP 'mypy' 'Aucun code Python applicatif détecté.'
        Add-Check SKIP 'Bandit' 'Aucun code Python applicatif détecté.'
    }
    Invoke-PythonTool -Name 'Audit des dépendances Python' -Arguments @('pip_audit', '--local', '--strict') | Out-Null
}

function Invoke-PowerShellCheck {
    if (-not (Test-Category 'PowerShell') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.powershell) { Add-Check SKIP 'PowerShell' 'Aucun fichier PowerShell détecté.'; return }
    $parseErrors = New-Object System.Collections.Generic.List[string]
    foreach ($file in $script:Technologies.powershell_files) {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        foreach ($parseError in $errors) { $parseErrors.Add("$($file.Name) : $($parseError.Message)") }
    }
    if ($parseErrors.Count -eq 0) { Add-Check PASS 'Syntaxe PowerShell' 'Tous les scripts PowerShell sont syntaxiquement valides.' }
    else { Add-Check FAIL 'Syntaxe PowerShell' ($parseErrors -join '; ') }

    $moduleRoot = Join-Path $repoRoot '.tools\powershell-modules'
    $env:PSModulePath = "$moduleRoot;$env:PSModulePath"
    $settings = Join-Path $repoRoot '.config\PSScriptAnalyzerSettings.psd1'
    $analyzer = Get-Command Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue
    if (-not $analyzer) { Add-Check ERROR 'PSScriptAnalyzer' 'PSScriptAnalyzer local requis absent; relancez bootstrap.'; return }
    $results = @(Invoke-ScriptAnalyzer -Path (Join-Path $repoRoot 'scripts') -Recurse -Settings $settings)
    $errors = @($results | Where-Object Severity -eq 'Error')
    $warnings = @($results | Where-Object Severity -eq 'Warning')
    if ($errors.Count -gt 0) { Add-Check FAIL 'PSScriptAnalyzer' (($errors | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.Message)" }) -join '; ') }
    elseif ($warnings.Count -gt 0) { Add-Check FAIL 'PSScriptAnalyzer' (($warnings | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.Message)" }) -join '; ') }
    else { Add-Check PASS 'PSScriptAnalyzer' 'Aucune erreur ni aucun avertissement PowerShell.' }
}

function Invoke-AnsibleCheck {
    if (-not (Test-Category 'Ansible') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.ansible) { Add-Check SKIP 'Ansible' 'Ansible non détecté.'; return }
    if ($script:Technologies.ansible_ambiguous) { Add-Check WARN 'Ansible' 'Signal Ansible ambigu; aucun contrôle Ansible n''est lancé.'; return }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { Add-Check WARN 'Ansible' "Contenu Ansible détecté; ansible-core n'est pas pris en charge comme contrôleur natif Windows."; return }
    $ansibleLint = Join-Path $repoRoot '.venv\Scripts\ansible-lint.exe'
    Invoke-External -Name 'ansible-lint profil production' -Executable $ansibleLint -Arguments @('--profile', 'production', '--strict') -Required | Out-Null
    if ($script:RunFull) {
        $scenarios = @($script:Files | Where-Object FullName -Match '[\\/]molecule[\\/][^\\/]+[\\/]molecule\.yml$')
        foreach ($scenario in $scenarios) {
            Invoke-External -Name "Molecule $($scenario.Directory.Name)" -Executable (Join-Path $repoRoot '.venv\Scripts\molecule.exe') -Arguments @('test', '-s', $scenario.Directory.Name) -Required | Out-Null
        }
        if ($scenarios.Count -eq 0) { Add-Check SKIP 'Molecule' 'Aucun scénario Molecule détecté.' }
    }
}

function Invoke-TerraformCheck {
    if (-not (Test-Category 'Terraform') -and -not (Test-Category 'All')) { return }
    if ($script:Technologies.terraform_ambiguous) { Add-Check WARN 'Terraform/OpenTofu' 'Les fichiers HCL ne permettent pas de résoudre Terraform ou OpenTofu; aucun outil IaC n''est lancé.'; return }
    if (-not $script:Technologies.terraform) { Add-Check SKIP 'Terraform' 'Terraform non détecté.'; return }
    $terraformCommand = Get-Command terraform -ErrorAction SilentlyContinue
    if (-not $terraformCommand) { Add-Check ERROR 'Terraform' "Terraform est applicable mais absent du PATH; aucun téléchargement automatique n'est configuré."; return }
    $env:TF_DATA_DIR = Join-Path $repoRoot '.tools\terraform-data'
    $env:TF_PLUGIN_CACHE_DIR = Join-Path $repoRoot '.tools\cache\terraform-plugins'
    New-Item -ItemType Directory -Path $env:TF_DATA_DIR,$env:TF_PLUGIN_CACHE_DIR -Force | Out-Null
    Invoke-External -Name 'terraform fmt' -Executable $terraformCommand.Source -Arguments @('fmt', '-check', '-diff', '-recursive') -Required | Out-Null
    Invoke-External -Name 'terraform init sans backend' -Executable $terraformCommand.Source -Arguments @('init', '-backend=false', '-input=false', '-no-color') -Required | Out-Null
    Invoke-External -Name 'terraform validate' -Executable $terraformCommand.Source -Arguments @('validate', '-no-color') -Required | Out-Null
    Invoke-External -Name 'TFLint' -Executable (Join-Path $toolRoot 'tflint.exe') -Arguments @('--recursive', '--no-color') -Required | Out-Null
    if ($script:RunFull) {
        Invoke-External -Name 'Checkov' -Executable $python -Arguments @('-x', (Join-Path $repoRoot '.venv\Scripts\checkov.cmd'), '-d', $repoRoot, '--framework', 'terraform', '--quiet') -Required | Out-Null
    }
}

function Invoke-TerragruntCheck {
    if (-not (Test-Category 'Terragrunt') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.terragrunt) { Add-Check SKIP 'Terragrunt' 'Terragrunt non détecté.'; return }
    Invoke-External -Name 'Format Terragrunt HCL' -Executable (Join-Path $toolRoot 'terragrunt.exe') -Arguments @('hcl', 'fmt', '--check') -Required | Out-Null
    Add-Check WARN 'Validation Terragrunt' "Aucune initialisation ni commande de backend réel n'est exécutée automatiquement."
}

function Invoke-ContainerCheck {
    if (-not (Test-Category 'Container') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.containers) { Add-Check SKIP 'Conteneurs' 'Aucun Dockerfile ou Containerfile détecté.'; return }
    $dockerIgnore = Join-Path $repoRoot '.dockerignore'
    if (Test-Path $dockerIgnore -PathType Leaf) { Add-Check PASS '.dockerignore' 'Le fichier .dockerignore est présent.' }
    else { Add-Check FAIL '.dockerignore' 'Un Dockerfile/Containerfile est présent sans .dockerignore.' }
    $containerIssues = New-Object System.Collections.Generic.List[string]
    foreach ($file in $script:Technologies.container_files) {
        $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
        if ($content -match '(?im)^\s*FROM\s+[^\s:]+(?::latest)?\s*$') { $containerIssues.Add("Image de base non verrouillée : $($file.Name)") }
        if ($content -match '(?im)^\s*(?:ARG|ENV)\s+[^\r\n]*(?:password|secret|token|api[_-]?key)\s*=\s*\S+') { $containerIssues.Add("Valeur sensible dans ARG/ENV : $($file.Name)") }
        if ($content -notmatch '(?im)^\s*USER\s+(?!root\b|0\b)\S+') { $containerIssues.Add("Aucun utilisateur non privilégié explicite : $($file.Name)") }
    }
    if ($containerIssues.Count -eq 0) { Add-Check PASS 'Règles conteneurs' 'Images verrouillées, utilisateur et variables vérifiés.' }
    else { Add-Check FAIL 'Règles conteneurs' ($containerIssues -join '; ') }
    Invoke-External -Name 'Hadolint' -Executable (Join-Path $toolRoot 'hadolint.exe') -Arguments @($script:Technologies.container_files.FullName) -Required | Out-Null
    if ($script:RunFull) { Invoke-External -Name 'Trivy filesystem' -Executable (Join-Path $toolRoot 'trivy.exe') -Arguments (@('fs', '--scanners', 'vuln,misconfig,secret', '--exit-code', '1', '--no-progress', '--skip-dirs', '.git', '--skip-dirs', '.venv', '--skip-dirs', '.tools', '--skip-dirs', 'reports') + @($repoRoot)) -Required | Out-Null }
}

function Invoke-ShellCheck {
    if (-not (Test-Category 'Shell') -and -not (Test-Category 'All')) { return }
    if (-not $script:Technologies.shell) { Add-Check SKIP 'ShellCheck' 'Aucun script Bash détecté.'; return }
    $shellcheck = Join-Path $toolRoot 'shellcheck.exe'
    if (-not (Test-Path $shellcheck -PathType Leaf)) { Add-Check WARN 'ShellCheck' "Des scripts Bash existent; ShellCheck n'est pas fourni pour Windows."; return }
    Invoke-External -Name 'ShellCheck' -Executable $shellcheck -Arguments @($script:Technologies.shell_files.FullName) -Required | Out-Null
}

function Invoke-FixMode {
    if ($script:Technologies.python) {
        Invoke-PythonTool -Name 'Ruff format' -Arguments (@('ruff', 'format') + @($script:Technologies.python_files.FullName)) | Out-Null
        Invoke-PythonTool -Name 'Ruff corrections sûres' -Arguments (@('ruff', 'check', '--fix') + @($script:Technologies.python_files.FullName)) | Out-Null
    }
    if ($script:Technologies.terraform) {
        $terraformCommand = Get-Command terraform -ErrorAction SilentlyContinue
        if ($terraformCommand) { Invoke-External -Name 'terraform fmt' -Executable $terraformCommand.Source -Arguments @('fmt', '-recursive') -Required | Out-Null }
        else { Add-Check ERROR 'terraform fmt' 'Terraform applicable mais absent du PATH.' }
    }
    $extensions = @('.ps1', '.psm1', '.psd1', '.py', '.md', '.yml', '.yaml', '.json', '.toml', '.xml', '.txt')
    foreach ($file in $script:Files) {
        if ($file.Extension -notin $extensions -and $file.Name -notin @('.gitignore', '.gitattributes', '.editorconfig')) { continue }
        try { $content = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8) }
        catch { continue }
        $newline = if ($file.Extension -in @('.ps1', '.psm1', '.psd1')) { "`r`n" } else { "`n" }
        $lines = [regex]::Split($content, "\r?\n")
        $normalized = (($lines | ForEach-Object { $_ -replace '[ \t]+$', '' }) -join $newline).TrimEnd("`r", "`n") + $newline
        if ($normalized -cne $content) {
            [System.IO.File]::WriteAllText($file.FullName, $normalized, (New-Object System.Text.UTF8Encoding($file.Extension -in @('.ps1', '.psm1', '.psd1'))))
        }
    }
    Add-Check PASS 'Corrections sûres' 'Normalisation des espaces et fins de fichiers terminée.'
}

try {
    if ($ProgressRunId) {
        if (-not $Compliance -or $PlanOnly -or $DiscoveryOnly -or $Mode -eq 'Fix') { throw 'La progression exige un audit Compliance global.' }
        Import-Module (Join-Path $platformRoot 'src/Compliance.Session.psm1') -Force
        [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
        $script:ProgressSession = New-ComplianceSession -PlatformRoot $platformRoot -Repository $repoRoot -RunId $ProgressRunId -Network ([bool]$AllowNetwork) -CodeExecution ([bool]$AllowCodeExecution) -CatalogHash $script:ControlCatalog.content_sha256
        Write-ComplianceEvent -Session $script:ProgressSession -Type 'session_started' -Data $script:ProgressSession
        if ($ExpectedCatalogSha256 -and $ExpectedCatalogSha256 -ne $script:ControlCatalog.content_sha256) { throw 'Catalogue modifie depuis le consentement ; nouvelle preparation requise.' }
        $runtime = Get-ToolRuntimeIndex
        if (-not $runtime -or $runtime.PSObject.Properties.Name -contains 'error' -or $runtime.data.platforms.'windows-x64'.status -ne 'qualified') { throw 'Runtime source invalide.' }
        $inventoryError = Get-RuntimePythonInventoryError -Platform $runtime.data.platforms.'windows-x64'
        if ($inventoryError) { throw $inventoryError }
        Write-ComplianceEvent -Session $script:ProgressSession -Type 'preparation_started'
    }
    if ($PlanOnly -and -not $Compliance) { throw 'PlanOnly exige le mode Compliance.' }
    if ($Compliance -and ($DiscoveryOnly -or $Mode -eq 'Fix' -or $Category -ne 'All')) { throw 'Compliance ne se combine pas avec DiscoveryOnly, Fix ou Category.' }
    Push-Location $repoRoot
    $discoveryTimer = [Diagnostics.Stopwatch]::StartNew()
    $script:Files = @(Get-ProjectFile -Root $repoRoot)
    $script:Technologies = Get-Technology -RepositoryRoot $repoRoot
    $discoveryTimer.Stop()
    $resolverDurationMs = [long](@($script:Technologies.tool_resolution | ForEach-Object { $_.metrics.duration_ms } | Measure-Object -Sum).Sum)
    $script:StageMetrics = [pscustomobject]@{
        discovery_ms = [Math]::Max(0, $discoveryTimer.ElapsedMilliseconds - $resolverDurationMs)
        resolver_ms = $resolverDurationMs
        compliance_ms = 0
        reporting_ms = 0
    }
    if ($DiscoveryOnly -or $Compliance) {
        $discoveryResult = [pscustomobject]@{
            schema_version = 1
            repository = $repoRoot
            technologies = $script:Technologies.discoveries
            project_roots = $script:Technologies.project_roots
            ambiguities = $script:Technologies.ambiguities
            capability_matrix = $script:Technologies.capability_matrix
            tool_resolution = $script:Technologies.tool_resolution
            scan_complete = $script:Technologies.scan_complete
            scan_errors = $script:Technologies.scan_errors
            metrics = [pscustomobject]@{
                discovery_ms = $script:StageMetrics.discovery_ms
                resolver_ms = $script:StageMetrics.resolver_ms
            }
        }
        if ($Compliance) {
            Import-Module (Join-Path $platformRoot 'src/Compliance.Engine.psm1') -Force -ErrorAction Stop
            $executionPlan = [pscustomobject]@{ schema_version = 1; repository = $repoRoot; controls = @() }
            $executionResults = @()
            $preparationFailed = $false
            $complianceTimer = [Diagnostics.Stopwatch]::StartNew()
            try {
                $executionPlan = New-CompliancePlan -Discovery $discoveryResult.technologies -CapabilityMatrix $discoveryResult.capability_matrix -Resolver $discoveryResult.tool_resolution -RepositoryRoot $repoRoot -Timeout $TimeoutSeconds -GlobalTimeout $ComplianceTimeoutSeconds -MaxOutputBytes $ComplianceMaxOutputBytes -AllowNetwork:$AllowNetwork -AllowCodeExecution:$AllowCodeExecution
                if ($script:ProgressSession) {
                    Write-ComplianceEvent -Session $script:ProgressSession -Type 'preparation_completed' -Data ([pscustomobject]@{ scan_complete = $discoveryResult.scan_complete })
                    $snapshot = New-ComplianceReport -Discovery $discoveryResult -Matrix $discoveryResult.capability_matrix -Resolver $discoveryResult.tool_resolution -Plan $executionPlan -Results @() -PlanOnly -RunId $ProgressRunId -SourceAdapter $Adapter -CatalogSha256 $script:ControlCatalog.content_sha256 -RedactionPatterns $script:ReportRedactionPatterns -RedactionReplacement $ReportRedactionReplacement
                    Write-ComplianceSessionJson -Path (Join-Path $script:ProgressSession.directory 'execution-plan.json') -Value $snapshot
                    Write-ComplianceEvent -Session $script:ProgressSession -Type 'plan_available' -Data $snapshot
                }
                if (-not $PlanOnly -and $discoveryResult.scan_complete) {
                    $runner = {
                        param($executable, $arguments, $root, $timeout, $maximumOutputBytes)
                        Invoke-BoundedProcess -Executable $executable -Arguments $arguments -WorkingDirectory $root -Timeout ([int][Math]::Ceiling($timeout)) -TimeoutMilliseconds ([int][Math]::Ceiling($timeout * 1000)) -MaxOutputBytes $maximumOutputBytes
                    }
                    $env:PRE_COMMIT_HOME = Join-Path $platformRoot '.tools/pre-commit'
                    $env:PIP_CERT = Join-Path $platformRoot '.tools/cache/windows-root-ca.pem'
                    $progressOptions = @{}
                    if ($script:ProgressSession) {
                        $progressOptions.IsCancelled = { Test-ComplianceCancellation -Session $script:ProgressSession }
                        $progressOptions.OnControlStarted = {
                            param($control, $started)
                            Write-ComplianceEvent -Session $script:ProgressSession -Type 'control_started' -Control $control -Data ([pscustomobject]@{ status = 'Running'; execution_start = $started })
                        }
                        $progressOptions.OnControlCompleted = {
                            param($control, $result)
                            $safeResult = Protect-QualityGateReportValue -Value $result
                            $hash = [Security.Cryptography.SHA256]::Create()
                            try { $key = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($control.id))).Replace('-', '').ToLowerInvariant() }
                            finally { $hash.Dispose() }
                            $outputPath = Join-Path $script:ProgressSession.directory "logs/$key.json"
                            Write-ComplianceSessionJson -Path $outputPath -Value $safeResult
                            $presentation = Get-CompliancePresentation -Result $safeResult
                            Write-ComplianceEvent -Session $script:ProgressSession -Type 'control_completed' -Control $control -Data ([pscustomobject]@{ status = $presentation.status; reason = $presentation.reason; result = $safeResult; output_path = $outputPath })
                        }
                    }
                    $executionResults = @(Invoke-CompliancePlan -Plan $executionPlan -ProcessRunner $runner -PlatformRoot $platformRoot -GlobalTimeout $ComplianceTimeoutSeconds @progressOptions)
                }
            } catch {
                $preparationFailed = $true
                $now = [DateTimeOffset]::UtcNow.ToString('o')
                $executionResults = @([pscustomobject]@{ control_id = 'engine/preparation'; technology = 'engine'; capability = 'preparation'; root = '.'; status = 'error'; execution_start = $now; execution_end = $now; duration_ms = 0; tool_version = $null; stdout = ''; stderr = ''; exit_code = $null; critical = $true; diagnostics = @([pscustomobject]@{ code = 'preparation_error'; message = $_.Exception.Message; critical = $true }) })
            } finally {
                $complianceTimer.Stop()
                $script:StageMetrics.compliance_ms = $complianceTimer.ElapsedMilliseconds
            }
            $platformQualificationStatus = Get-PlatformQualificationStatus -PlatformId (Get-ExecutionPlatform).id
            $sessionOptions = @{}
            $cancelled = $false
            if ($script:ProgressSession) { $cancelled = Test-ComplianceCancellation -Session $script:ProgressSession; $sessionOptions.RunId = $ProgressRunId; $sessionOptions.Interrupted = $cancelled }
            $complianceReport = New-ComplianceReport -Discovery $discoveryResult -Matrix $discoveryResult.capability_matrix -Resolver $discoveryResult.tool_resolution -Plan $executionPlan -Results $executionResults -PlanOnly:($PlanOnly -and -not $preparationFailed) -SourceAdapter $Adapter -CatalogSha256 $script:ControlCatalog.content_sha256 -PlatformQualificationStatus $platformQualificationStatus -StageMetrics $script:StageMetrics -RedactionPatterns $script:ReportRedactionPatterns -RedactionReplacement $ReportRedactionReplacement @sessionOptions
            if ($preparationFailed) { $complianceReport.execution_status = 'error' }
            $complianceJson = $complianceReport | ConvertTo-Json -Depth 20
            $reportName = if ($script:ProgressSession) { $script:ProgressSession.report_path } elseif ($ReportPath) { $ReportPath } else { 'compliance-report.json' }
            $compliancePath = if ([IO.Path]::IsPathRooted($reportName)) { $reportName } else { Join-Path (Join-Path $platformRoot 'reports') $reportName }
            $reportDirectory = Split-Path -Parent $compliancePath
            if (-not (Test-Path -LiteralPath $reportDirectory -PathType Container)) { New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null }
            if ($script:ProgressSession) { Write-ComplianceSessionJson -Path $compliancePath -Value $complianceReport }
            else { [IO.File]::WriteAllText($compliancePath, $complianceJson, [Text.UTF8Encoding]::new($false)) }
            Remove-ExpiredComplianceReport -ReportsDirectory (Join-Path $platformRoot 'reports') -RetentionDays $ReportRetentionDays -CurrentReportPath $compliancePath
            if ($HumanSummary) {
                $displayVerdict = if ($PlanOnly) { 'PLAN' } else { $complianceReport.verdict }
                [Console]::Error.WriteLine("Compliance ${displayVerdict}: $($complianceReport.summary.success) success, $($complianceReport.summary.fail) fail, $($complianceReport.summary.error) error, $($complianceReport.summary.skipped) skipped. Rapport: $compliancePath")
            }
            if ($script:ProgressSession) {
                Write-ComplianceEvent -Session $script:ProgressSession -Type 'report_available' -Data ([pscustomobject]@{ report_path = $compliancePath })
                $state = if ($cancelled) { 'cancelled' } elseif ($preparationFailed -or -not $discoveryResult.scan_complete) { 'failed' } else { 'completed' }
                Complete-ComplianceSession -Session $script:ProgressSession -State $state
                Write-ComplianceEvent -Session $script:ProgressSession -Type "session_$state" -Data ([pscustomobject]@{ verdict = $complianceReport.verdict; coverage = $complianceReport.coverage; reason = if ($cancelled) { [pscustomobject]@{ code = 'session_interrupted'; message = 'Audit annule ; couverture incomplete.' } } else { $null } })
            } else { Write-Output $complianceJson }
            if ($cancelled) { exit 2 }
            if ($preparationFailed -or -not $discoveryResult.scan_complete) { exit 2 }
            if ($PlanOnly) { exit 0 }
            if ($complianceReport.verdict -eq 'FAIL') { exit 1 }
            exit 0
        }
        $discoveryOutput = if ($script:ReportRedactionPatterns.Count -gt 0) { Protect-QualityGateReportValue -Value $discoveryResult } else { $discoveryResult }
        $discoveryJson = $discoveryOutput | ConvertTo-Json -Depth 12
        if ($ReportPath) {
            $discoveryReportPath = if ([System.IO.Path]::IsPathRooted($ReportPath)) { $ReportPath } else { Join-Path (Join-Path $platformRoot 'reports') $ReportPath }
            $discoveryReportDirectory = Split-Path -Parent $discoveryReportPath
            if (-not (Test-Path $discoveryReportDirectory -PathType Container)) { New-Item -ItemType Directory -Path $discoveryReportDirectory -Force | Out-Null }
            Set-Content -LiteralPath $discoveryReportPath -Value $discoveryJson -Encoding UTF8
        }
        Write-Output $discoveryJson
        if (-not $script:Technologies.scan_complete) { exit 2 }
        exit 0
    }
    Write-Information -InformationAction Continue '[INFO] Détection des technologies du dépôt.'
    if (-not $script:Technologies.scan_complete) { Add-Check ERROR 'Discovery' 'Scan incomplet; consulter scan_errors dans le rapport.' }
    foreach ($detection in $script:Technologies.discoveries) {
        if ($detection.status -eq 'detected') { Write-Information -InformationAction Continue "[INFO] Technologie détectée : $($detection.technology)." }
        elseif ($detection.status -eq 'ambiguous') { Write-Information -InformationAction Continue "[WARN] Technologie ambiguë : $($detection.technology)." }
        else { Write-Information -InformationAction Continue "[INFO] Technologie absente : $($detection.technology)." }
    }
    if ($Mode -eq 'Fix') {
        Invoke-FixMode
        $script:RunFull = $false
        $script:RequestedMode = 'Quick après Fix'
    }
    Invoke-GenericCheck
    Invoke-EmojiCheck
    Invoke-SecretCheck
    Invoke-MarkdownCheck
    Invoke-PythonCheck
    Invoke-PowerShellCheck
    Invoke-AnsibleCheck
    Invoke-TerraformCheck
    Invoke-TerragruntCheck
    Invoke-ContainerCheck
    Invoke-ShellCheck
    if ((Test-Category 'Tests') -and ($script:RunFull -or $Category -eq 'Tests')) {
        Invoke-External -Name 'Tests du socle et Python' -Executable 'powershell' -Arguments @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $PSScriptRoot 'test.ps1'), '-NoColor') -Required -TimeoutSeconds ([Math]::Max(420, $script:ProcessTimeoutSeconds)) | Out-Null
    }

    $summary = [pscustomobject]@{ PASS = $script:Counts.PASS; FAIL = $script:Counts.FAIL; WARN = $script:Counts.WARN; SKIP = $script:Counts.SKIP; ERROR = $script:Counts.ERROR }
    $exitCode = if ($script:Counts.FAIL -gt 0 -or $script:Counts.ERROR -gt 0) { 1 } else { 0 }
    Import-Module (Join-Path $platformRoot 'src/Compliance.Engine.psm1') -Force -ErrorAction Stop
    $legacyDiscovery = [pscustomobject]@{
        schema_version = 1
        repository = $repoRoot
        technologies = $script:Technologies.discoveries
        project_roots = $script:Technologies.project_roots
        ambiguities = $script:Technologies.ambiguities
        capability_matrix = $script:Technologies.capability_matrix
        tool_resolution = $script:Technologies.tool_resolution
        scan_complete = $script:Technologies.scan_complete
        scan_errors = $script:Technologies.scan_errors
    }
    $platformQualificationStatus = Get-PlatformQualificationStatus -PlatformId (Get-ExecutionPlatform).id
    $referenceReport = ConvertTo-ComplianceReportFromChecks -Checks $script:Results.ToArray() -RepositoryRoot $repoRoot -Discovery $legacyDiscovery -Matrix $script:Technologies.capability_matrix -Resolver $script:Technologies.tool_resolution -Mode $script:RequestedMode -CatalogSha256 $script:ControlCatalog.content_sha256 -PlatformQualificationStatus $platformQualificationStatus -StageMetrics $script:StageMetrics -RedactionPatterns $script:ReportRedactionPatterns -RedactionReplacement $ReportRedactionReplacement
    $referencePath = Join-Path (Join-Path $platformRoot 'reports') 'compliance-report.json'
    if (-not (Test-Path (Split-Path -Parent $referencePath) -PathType Container)) { New-Item -ItemType Directory -Path (Split-Path -Parent $referencePath) -Force | Out-Null }
    [IO.File]::WriteAllText($referencePath, ($referenceReport | ConvertTo-Json -Depth 20), [Text.UTF8Encoding]::new($false))
    Remove-ExpiredComplianceReport -ReportsDirectory (Join-Path $platformRoot 'reports') -RetentionDays $ReportRetentionDays -CurrentReportPath $referencePath
    if ($ReportPath -or $Mode -eq 'Ci') {
        $relativeReport = if ($ReportPath) { $ReportPath } else { 'quality-report.json' }
        $reportPathResolved = if ([System.IO.Path]::IsPathRooted($relativeReport)) { $relativeReport } else { Join-Path (Join-Path $repoRoot 'reports') $relativeReport }
        $reportDirectory = Split-Path -Parent $reportPathResolved
        if (-not (Test-Path $reportDirectory -PathType Container)) { New-Item -ItemType Directory -Path $reportDirectory -Force | Out-Null }
        $technologyReport = [ordered]@{}
        foreach ($property in $script:Technologies.PSObject.Properties) {
            if ($property.Name -in @('python_files', 'python_source', 'python_tests', 'powershell_files', 'shell_files', 'terraform_files', 'hcl_files', 'container_files')) {
                $technologyReport[$property.Name] = @($property.Value | ForEach-Object { $_.FullName.Substring($repoRoot.Length + 1).Replace('\', '/') })
            } else { $technologyReport[$property.Name] = $property.Value }
        }
        $report = [pscustomobject]@{
            date_execution = (Get-Date).ToString('o')
            mode = $script:RequestedMode
            categorie = $script:Category
            technologies = $technologyReport
            controles = $script:Results.ToArray()
            resume = $summary
            code_sortie = $exitCode
        }
        if ($script:ReportRedactionPatterns.Count -gt 0) { $report = Protect-QualityGateReportValue -Value $report }
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $reportPathResolved -Encoding UTF8
        Write-Information -InformationAction Continue "[PASS] Rapport JSON créé : $reportPathResolved"
    }
    Write-Information -InformationAction Continue ("[SUMMARY] PASS={0} FAIL={1} WARN={2} SKIP={3} ERROR={4}" -f $summary.PASS,$summary.FAIL,$summary.WARN,$summary.SKIP,$summary.ERROR)
    if ($exitCode -ne 0) { Write-Information -InformationAction Continue '[BLOCKED] Quality Gate bloqué.'; exit $exitCode }
    Write-Information -InformationAction Continue '[PASS] Quality Gate terminé avec succès.'
    exit 0
} catch {
    if ($script:ProgressSession) {
        Complete-ComplianceSession -Session $script:ProgressSession -State 'failed'
        Write-ComplianceEvent -Session $script:ProgressSession -Type 'session_failed' -Data ([pscustomobject]@{ reason = [pscustomobject]@{ code = 'preparation_error'; message = Protect-QualityGateReportValue -Value $_.Exception.Message -RedactText:$true } })
        exit 2
    }
    Add-Check ERROR 'Exécution Quality Gate' $_.Exception.Message
    Write-Information -InformationAction Continue ("[SUMMARY] PASS={0} FAIL={1} WARN={2} SKIP={3} ERROR={4}" -f $script:Counts.PASS,$script:Counts.FAIL,$script:Counts.WARN,$script:Counts.SKIP,$script:Counts.ERROR)
    exit 2
} finally {
    if ((Get-Location).Path -eq $repoRoot) { Pop-Location }
}
