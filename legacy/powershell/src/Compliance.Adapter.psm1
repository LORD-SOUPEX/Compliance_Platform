<#
.SYNOPSIS
    [DEPRECATED / HÉRITÉ] Ce module PowerShell est un composant hérité.
    Le moteur autonome Go (core/) et la CLI 'compliance' sont l'unique source de vérité.
#>

Set-StrictMode -Version Latest

function New-ComplianceAdapterRequest {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter,
        [Parameter(Mandatory = $true)][string]$RepositoryPath,
        [string]$ReportPath,
        [switch]$PlanOnly,
        [switch]$HumanSummary,
        [switch]$AllowNetwork,
        [switch]$AllowCodeExecution
    )
    $repositoryItem = Get-Item -LiteralPath $RepositoryPath -ErrorAction Stop
    if (-not $repositoryItem.PSIsContainer) { throw 'Le chemin adaptateur doit désigner un dépôt local.' }
    if ($ReportPath -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { throw 'Les rapports distants ne sont pas pris en charge par le contrat local.' }
    return [pscustomobject]@{
        schema_version = 1
        adapter = $Adapter
        repository = $repositoryItem.FullName
        report_path = $ReportPath
        mode = 'Compliance'
        plan_only = [bool]$PlanOnly
        presentation = [pscustomobject]@{ human_summary = [bool]$HumanSummary }
        permissions = [pscustomobject]@{ network = [bool]$AllowNetwork; code_execution = [bool]$AllowCodeExecution }
        source_transmitted = $false
        secrets_transmitted = $false
    }
}

function Get-ComplianceAdapterMetadata {
    param([ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter)
    return [pscustomobject]@{
        name = $Adapter
        contract_version = 1
        platforms = @('windows-x64')
        limitations = if ($Adapter -eq 'Bash') { @('Bash est un relais du moteur PowerShell; le runtime moteur Linux/macOS n est pas qualifie.') } else { @('Le verdict est consultatif; le processus appelant peut choisir sa propre politique de code de sortie.') }
    }
}

function ConvertTo-ComplianceAdapterExitCode {
    param([ValidateSet('PowerShell', 'Bash', 'VSCode', 'GitLab')][string]$Adapter, [int]$EngineCode, [string]$Verdict)
    if ($Adapter -eq 'GitLab' -and $EngineCode -in @(0, 1) -and $Verdict -in @('PASS', 'FAIL')) { return 0 }
    return $EngineCode
}

Export-ModuleMember -Function New-ComplianceAdapterRequest, Get-ComplianceAdapterMetadata, ConvertTo-ComplianceAdapterExitCode
