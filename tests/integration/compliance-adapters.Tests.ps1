[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$adapterScript = Join-Path $platformRoot 'scripts/compliance-adapter.ps1'
$bashScript = Join-Path $platformRoot 'scripts/compliance.sh'
$processHost = Join-Path $PSHOME 'powershell.exe'
$bashHost = 'C:\Program Files\Git\bin\bash.exe'
$workspace = Join-Path $platformRoot ('.tools/test-workspaces/adapters-' + [guid]::NewGuid().ToString('N'))
$repoRoot = Join-Path $workspace 'consumer'
$reportRoot = Join-Path $workspace 'reports'
$script:Passed = 0
$script:Failed = 0

function Assert-AdapterIntegration {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-AdapterFixture {
    param([string]$Name, [string]$Content)
    $path = Join-Path $repoRoot $Name
    New-Item -ItemType Directory -Path (Split-Path -Parent $path) -Force | Out-Null
    [IO.File]::WriteAllText($path, $Content, [Text.UTF8Encoding]::new($false))
}

function Invoke-AdapterCase {
    param([string]$Name, [scriptblock]$Body)
    if (Test-Path $repoRoot) { Remove-Item -LiteralPath $repoRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $repoRoot,$reportRoot -Force | Out-Null
    try {
        & $Body
        $script:Passed++
        Write-Information -InformationAction Continue "[PASS] Adapter integration : $Name"
    } catch {
        $script:Failed++
        Write-Information -InformationAction Continue "[FAIL] Adapter integration : $Name : $($_.Exception.Message)"
    }
}

function Invoke-PowerShellAdapter {
    param([string]$Name, [string]$ReportPath, [switch]$PlanOnly, [switch]$HumanSummary, [switch]$AllowCodeExecution)
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $adapterScript, '-Adapter', $Name, '-RepositoryPath', $repoRoot, '-ReportPath', $ReportPath)
    if ($PlanOnly) { $arguments += '-PlanOnly' }
    if ($HumanSummary) { $arguments += '-HumanSummary' }
    if ($AllowCodeExecution) { $arguments += '-AllowCodeExecution' }
    $output = & $processHost @arguments
    $code = $LASTEXITCODE
    $report = if (Test-Path -LiteralPath $ReportPath -PathType Leaf) { Get-Content -LiteralPath $ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
    [pscustomobject]@{ code = $code; output = @($output); report = $report; report_path = $ReportPath }
}

try {
    Invoke-AdapterCase 'PowerShell adapter plan only' {
        Write-AdapterFixture 'main.ps1' "Write-Output 'ok'`n"
        $result = Invoke-PowerShellAdapter -Name PowerShell -ReportPath (Join-Path $reportRoot 'powershell.json') -PlanOnly -HumanSummary
        $properties = if ($result.report) { @($result.report.PSObject.Properties.Name) -join ',' } else { 'missing-report' }
        $status = if ($result.report -and $result.report.PSObject.Properties.Name -contains 'execution_status') { $result.report.execution_status } else { 'missing-status' }
        Assert-AdapterIntegration ($result.code -eq 0 -and $status -eq 'planned' -and $null -eq $result.report.verdict) "PowerShell plan-only code=$($result.code); status=$status; keys=$properties"
        Assert-AdapterIntegration ($result.report.metadata.source_adapter -eq 'PowerShell') 'Identite adaptateur perdue.'
        Assert-AdapterIntegration (@($result.output | ConvertFrom-Json).Count -gt 0) 'stdout n est pas du JSON.'
    }
    Invoke-AdapterCase 'VS Code adapter reports valid consumer' {
        Write-AdapterFixture 'main.ps1' "Write-Output 'ok'`n"
        $result = Invoke-PowerShellAdapter -Name VSCode -ReportPath (Join-Path $reportRoot 'vscode.json') -PlanOnly -HumanSummary
        $adapterName = if ($result.report -and $result.report.PSObject.Properties.Name -contains 'metadata') { $result.report.metadata.source_adapter } else { 'missing-metadata' }
        Assert-AdapterIntegration ($result.code -eq 0 -and $adapterName -eq 'VSCode') "Adaptateur VS Code code=$($result.code); adapter=$adapterName"
    }
    Invoke-AdapterCase 'GitLab adapter keeps FAIL advisory' {
        Write-AdapterFixture 'broken.ps1' "function Broken {`n"
        $result = Invoke-PowerShellAdapter -Name GitLab -ReportPath (Join-Path $reportRoot 'gitlab.json') -AllowCodeExecution
        $verdict = if ($result.report -and $result.report.PSObject.Properties.Name -contains 'verdict') { $result.report.verdict } else { 'missing-verdict' }
        Assert-AdapterIntegration ($result.code -eq 0 -and $verdict -eq 'FAIL' -and $result.report.advisory) "FAIL GitLab code=$($result.code); verdict=$verdict"
        Assert-AdapterIntegration ($result.report.metadata.source_adapter -eq 'GitLab') 'Provenance GitLab absente.'
    }
    if (Test-Path $bashHost -PathType Leaf) {
        Invoke-AdapterCase 'Bash Git for Windows relays plan only' {
            Write-AdapterFixture 'main.ps1' "Write-Output 'ok'`n"
            $output = & $bashHost $bashScript -RepositoryPath $repoRoot -ReportPath (Join-Path $reportRoot 'bash.json') -PlanOnly -HumanSummary
            $code = $LASTEXITCODE
            $reportPath = Join-Path $reportRoot 'bash.json'
            $report = if (Test-Path $reportPath) { Get-Content -LiteralPath $reportPath -Raw -Encoding UTF8 | ConvertFrom-Json } else { $null }
            Assert-AdapterIntegration ($code -eq 0 -and $report -and $report.execution_status -eq 'planned' -and $report.metadata.source_adapter -eq 'Bash') "Relais Bash incorrect ($code): $($output -join ' ')"
        }
    } else { Write-Information -InformationAction Continue '[SKIP] Git Bash indisponible; relais Bash non execute.' }
    Write-Information -InformationAction Continue "[SUMMARY] Adapter integration PASS=$script:Passed FAIL=$script:Failed"
    if ($script:Failed) { exit 1 }
    exit 0
} finally {
    if (Test-Path $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
