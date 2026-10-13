param(
    [string]$ReportPath = "M:\Git\Compliance_Platform\core\testdata\go_report.json"
)

Import-Module "M:\Git\Compliance_Platform\src\Compliance.Engine.psm1" -Force

$json = Get-Content $ReportPath -Raw -Encoding UTF8
$report = $json | ConvertFrom-Json

Write-Host "findings is null:" ($null -eq $report.findings)
Write-Host "findings count:" (@($report.findings).Count)
$expectedFindings = @($report.execution_results | Where-Object status -in @('fail', 'error')).Count
if ($report.discovery.PSObject.Properties.Name -contains 'scan_complete' -and -not $report.discovery.scan_complete) {
    $expectedFindings += if ($report.discovery.PSObject.Properties.Name -contains 'scan_errors') { @($report.discovery.scan_errors).Count } else { 0 }
}
Write-Host "expectedFindings:" $expectedFindings

try {
    $valid = Test-ComplianceReport -Report $report
    Write-Host "VALIDATION SUCCESS: Test-ComplianceReport returned $valid"
    exit 0
} catch {
    Write-Error "VALIDATION FAILED: $_"
    exit 1
}
