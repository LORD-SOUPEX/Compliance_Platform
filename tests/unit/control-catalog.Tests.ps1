[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$platformRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
Import-Module (Join-Path $platformRoot 'src/Control.Catalog.psm1') -Force
$passed = 0

function Assert-Catalog {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$schema = Get-Content -LiteralPath (Join-Path $platformRoot '.config/control-catalog.schema.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$catalogPath = Join-Path $platformRoot '.config/control-catalog.json'
$catalog = Import-ControlCatalog -Path $catalogPath
Assert-Catalog ($schema.properties.schema_version.const -eq $catalog.schema_version -and $schema.'$defs'.control.properties.severity.enum.Count -eq 4) 'Schema JSON incompatible avec le catalogue.'
Assert-Catalog ($catalog.content_sha256 -eq (Get-FileHash -LiteralPath $catalogPath -Algorithm SHA256).Hash.ToLowerInvariant()) 'Empreinte du catalogue absente ou incoherente.'
Assert-Catalog ($schema.'$defs'.control.required -contains 'objective' -and $schema.'$defs'.control.required -contains 'limitations' -and @($catalog.controls | Where-Object { [string]::IsNullOrWhiteSpace($_.objective) -or $null -eq $_.limitations }).Count -eq 0) 'Objectif ou limites explicites absents d un controle.'
Assert-Catalog (@($catalog.controls.id | Select-Object -Unique).Count -eq $catalog.controls.Count) 'IDs de controle dupliques.'
$python = @(Get-CatalogCapabilityProfile -Catalog $catalog -Technology python)
Assert-Catalog (($python | Where-Object name -eq linting).tools.Count -eq 2) 'Les controles Pylint/Ruff ne sont pas dans le catalogue.'
$kubernetes = @(Get-CatalogCapabilityProfile -Catalog $catalog -Technology kubernetes)
Assert-Catalog (($kubernetes | Where-Object name -eq security).selection_policy -eq 'alternative') 'Politique alternative absente du catalogue.'
$javascript = @(Get-CatalogCapabilityProfile -Catalog $catalog -Technology javascript)
Assert-Catalog ($javascript[0].tools.Count -eq 0 -and $javascript[0].controls[0].tool -eq $null) 'Capacite non configuree perdue du catalogue.'
$passed++

$temporary = Join-Path $platformRoot ('.tools/test-workspaces/catalog-' + [guid]::NewGuid().ToString('N') + '.json')
try {
    $duplicate = $catalog | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $duplicate.controls += $duplicate.controls[0]
    $duplicate | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $temporary -Encoding UTF8
    $rejected = $false
    try { $null = Import-ControlCatalog -Path $temporary } catch { $rejected = $_.Exception.Message -match 'duplique' }
    Assert-Catalog $rejected 'ID duplique accepte.'

    $invalidPermission = $catalog | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $invalidPermission.controls[0].permissions = @('network')
    $invalidPermission | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $temporary -Encoding UTF8
    $rejected = $false
    try { $null = Import-ControlCatalog -Path $temporary } catch { $rejected = $_.Exception.Message -match 'Permissions incoherentes' }
    Assert-Catalog $rejected 'Permission contradictoire acceptee.'

    $unknownField = $catalog | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $unknownField.controls[0] | Add-Member -MemberType NoteProperty -Name arbitrary_override -Value $true
    $unknownField | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $temporary -Encoding UTF8
    $rejected = $false
    try { $null = Import-ControlCatalog -Path $temporary } catch { $rejected = $_.Exception.Message -match 'non autorise' }
    Assert-Catalog $rejected 'Propriete non declaree acceptee.'

    $missingDependency = $catalog | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $missingDependency.controls[0].dependencies = @('catalog-control-absent')
    $missingDependency | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $temporary -Encoding UTF8
    $rejected = $false
    try { $null = Import-ControlCatalog -Path $temporary } catch { $rejected = $_.Exception.Message -match 'Dependance Control Catalog absente' }
    Assert-Catalog $rejected 'Dependance catalogue absente acceptee.'

    $cycle = $catalog | ConvertTo-Json -Depth 16 | ConvertFrom-Json
    $cycle.controls[0].dependencies = @($cycle.controls[1].id)
    $cycle.controls[1].dependencies = @($cycle.controls[0].id)
    $cycle | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $temporary -Encoding UTF8
    $rejected = $false
    try { $null = Import-ControlCatalog -Path $temporary } catch { $rejected = $_.Exception.Message -match 'Cycle' }
    Assert-Catalog $rejected 'Cycle de catalogue accepte.'
    $passed += 5
} finally {
    if (Test-Path $temporary) { Remove-Item -LiteralPath $temporary -Force }
}

Write-Information -InformationAction Continue "[SUMMARY] Control Catalog unit PASS=$passed FAIL=0"
