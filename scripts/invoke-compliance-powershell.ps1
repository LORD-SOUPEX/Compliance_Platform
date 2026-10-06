[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ModulePath,
    [Parameter(Mandatory = $true)][string]$SettingsPath,
    [Parameter(Mandatory = $true)][string]$FilesJson
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module -Name $ModulePath -Force -ErrorAction Stop
$findings = @()
foreach ($file in ($FilesJson | ConvertFrom-Json)) {
    $tokens = $null
    $parseErrors = $null
    [Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$parseErrors) | Out-Null
    if ($parseErrors.Count -gt 0) {
        foreach ($parseError in $parseErrors) {
            $findings += [pscustomobject]@{ ScriptName = [IO.Path]::GetFileName($file); Line = $parseError.Extent.StartLineNumber; RuleName = 'PowerShellSyntax'; Severity = 'Error'; Message = $parseError.Message }
        }
    } else { $findings += @(Invoke-ScriptAnalyzer -Path $file -Settings $SettingsPath -ErrorAction Stop) }
}
foreach ($finding in $findings) {
    [pscustomobject]@{ file = $finding.ScriptName; line = $finding.Line; rule = $finding.RuleName; severity = [string]$finding.Severity; message = $finding.Message } | ConvertTo-Json -Compress
}
if (@($findings | Where-Object { $_.Severity -in @('Error', 'Warning') }).Count -gt 0) { exit 1 }
exit 0
