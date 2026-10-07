[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$originalRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$catalogModule = Join-Path $originalRoot 'src/Control.Catalog.psm1'
Import-Module $catalogModule -Force
Import-Module (Join-Path $originalRoot 'src/Compliance.Engine.psm1') -Force
$script:ControlCatalog = Import-ControlCatalog -Path (Join-Path $originalRoot '.config/control-catalog.json')
$gatePath = Join-Path $originalRoot 'scripts/quality-gate.ps1'
$tokens = $null
$parseErrors = $null
$gateAst = [Management.Automation.Language.Parser]::ParseFile($gatePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw 'Le Quality Gate ne peut pas être analysé.' }
foreach ($definition in $gateAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}

$workspace = Join-Path $originalRoot ('.tools/test-workspaces/' + [guid]::NewGuid().ToString('N'))
$repoRoot = Join-Path $workspace 'fixture'
$python = Join-Path $originalRoot '.venv/Scripts/python.exe'
$processHost = Join-Path $PSHOME 'powershell.exe'
$toolRoot = Join-Path $repoRoot '.tools/bin'
$script:Category = 'All'
$script:ProcessTimeoutSeconds = 10
$script:Passed = 0
$script:Failed = 0

function Assert-Condition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Write-Fixture {
    param([string]$RelativePath, [string]$Content)
    $destination = Join-Path $repoRoot $RelativePath
    New-Item -ItemType Directory -Path (Split-Path $destination -Parent) -Force | Out-Null
    [IO.File]::WriteAllText($destination, $Content, [Text.UTF8Encoding]::new($false))
}

function Copy-GateFixture {
    New-Item -ItemType Directory -Path (Join-Path $repoRoot 'scripts'), (Join-Path $repoRoot 'src'), (Join-Path $repoRoot '.config') -Force | Out-Null
    Copy-Item $gatePath (Join-Path $repoRoot 'scripts/quality-gate.ps1')
    Copy-Item (Join-Path $originalRoot 'src/Control.Catalog.psm1') (Join-Path $repoRoot 'src/Control.Catalog.psm1')
    Copy-Item (Join-Path $originalRoot 'src/Platform.Support.psm1') (Join-Path $repoRoot 'src/Platform.Support.psm1')
    Copy-Item (Join-Path $originalRoot 'src/Compliance.Engine.psm1') (Join-Path $repoRoot 'src/Compliance.Engine.psm1')
    Copy-Item (Join-Path $originalRoot '.config/control-catalog.json') (Join-Path $repoRoot '.config/control-catalog.json')
    Copy-Item (Join-Path $originalRoot '.config/platform-support.json') (Join-Path $repoRoot '.config/platform-support.json')
    Copy-Item (Join-Path $originalRoot 'scripts/check-emoji.ps1') (Join-Path $repoRoot 'scripts/check-emoji.ps1')
}

function Update-Detection {
    $script:Files = @(Get-ProjectFile)
    $script:Technologies = Get-Technology
}

function Invoke-TestCase {
    param([string]$Name, [scriptblock]$Body)
    if (Test-Path $repoRoot) { Remove-Item -LiteralPath $repoRoot -Recurse -Force }
    New-Item -ItemType Directory -Path $repoRoot -Force | Out-Null
    $script:Counts = @{ PASS = 0; FAIL = 0; WARN = 0; SKIP = 0; ERROR = 0 }
    $script:Results = New-Object System.Collections.Generic.List[object]
    try {
        & $Body
        $script:Passed++
        Write-Information -InformationAction Continue "[PASS] Test : $Name"
    } catch {
        $script:Failed++
        Write-Information -InformationAction Continue "[FAIL] Test : $Name : $($_.Exception.Message)"
    }
}

function Invoke-Scanner {
    New-Item -ItemType Directory -Path (Join-Path $repoRoot 'scripts') -Force | Out-Null
    $scanner = Join-Path $repoRoot 'scripts/check-emoji.ps1'
    Copy-Item (Join-Path $originalRoot 'scripts/check-emoji.ps1') $scanner
    & powershell -NoProfile -ExecutionPolicy Bypass -File $scanner -Path $repoRoot | Out-Null
    return $LASTEXITCODE
}

try {
    Invoke-TestCase 'Dépôt vide sans technologie' {
        Update-Detection
        Assert-Condition (-not ($script:Technologies.python -or $script:Technologies.terraform -or $script:Technologies.ansible)) 'Détection indue.'
    }
    Invoke-TestCase 'Python applicatif' {
        Write-Fixture 'src/value.py' "value = 1`n"
        Update-Detection
        Assert-Condition ($script:Technologies.python_source.Count -eq 1) 'Source non détectée.'
    }
    Invoke-TestCase 'Tests Python distincts des sources' {
        Write-Fixture 'tests/test_value.py' "def test_value(): pass`n"
        Update-Detection
        Assert-Condition ($script:Technologies.python_tests.Count -eq 1 -and $script:Technologies.python_source.Count -eq 0) 'Classement erroné.'
    }
    Invoke-TestCase 'PowerShell' {
        Write-Fixture 'module.psm1' "function Get-Value { return 1 }`n"
        Update-Detection
        Assert-Condition $script:Technologies.powershell 'PowerShell non détecté.'
    }
    Invoke-TestCase 'Terraform HCL ambigu avec OpenTofu' {
        Write-Fixture 'main.tf' "terraform {}`n"
        Update-Detection
        $terraform = $script:Technologies.discoveries | Where-Object technology -eq 'terraform'
        $opentofu = $script:Technologies.discoveries | Where-Object technology -eq 'opentofu'
        Assert-Condition ($script:Technologies.terraform_ambiguous -and $terraform.status -eq 'ambiguous' -and $opentofu.status -eq 'ambiguous') 'Le format HCL partagé n''est pas signalé comme ambigu.'
        Invoke-TerraformCheck
        Assert-Condition ($script:Counts.WARN -eq 1 -and $script:Results[0].nom -eq 'Terraform/OpenTofu') 'Un outil Terraform a été lancé malgré l''ambiguïté.'
    }
    Invoke-TestCase 'Monorepo Terraform et OpenTofu resolus par racine' {
        Write-Fixture 'terraform/.terraform-version' "1.15.8`n"
        Write-Fixture 'terraform/modules/app/main.tf' "terraform {}`n"
        Write-Fixture 'tofu/.opentofu-version' "1.10.0`n"
        Write-Fixture 'tofu/main.tf' "terraform {}`n"
        Update-Detection
        $terraform = $script:Technologies.discoveries | Where-Object technology -eq 'terraform'
        $opentofu = $script:Technologies.discoveries | Where-Object technology -eq 'opentofu'
        Assert-Condition ($terraform.status -eq 'detected' -and $terraform.roots -contains 'terraform' -and $terraform.evidence -contains 'terraform/modules/app/main.tf') 'Racine Terraform non resolue.'
        Assert-Condition ($opentofu.status -eq 'detected' -and $opentofu.roots -contains 'tofu' -and $opentofu.evidence -contains 'tofu/main.tf') 'Les marqueurs OpenTofu contaminent un autre projet.'
        Write-Fixture 'unselected/main.tf' "terraform {}`n"
        Update-Detection
        Assert-Condition ($script:Technologies.terraform_ambiguous -and -not $script:Technologies.terraform) 'Une racine non resolue autorise les controles sur tout le depot.'
        Assert-Condition (($script:Technologies.discoveries | Where-Object technology -eq 'terraform').status -eq 'ambiguous') 'Ambiguite partielle masquee par une autre racine detectee.'
    }
    Invoke-TestCase 'Discovery conserve un rapport de lecture incomplete' {
        Write-Fixture 'deployment.yaml' "apiVersion: v1`nkind: Pod`n"
        $reportPath = Join-Path $repoRoot 'reports/discovery.json'
        $lockedFile = [IO.File]::Open((Join-Path $repoRoot 'deployment.yaml'), [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try {
            $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gatePath -RepositoryPath $repoRoot -DiscoveryOnly -ReportPath $reportPath -NoColor
            $exitCode = $LASTEXITCODE
            $result = ($output -join "`n") | ConvertFrom-Json
            Assert-Condition ($exitCode -eq 2 -and -not $result.scan_complete -and $result.scan_errors.Count -eq 1) 'Erreur de lecture masquee ou dupliquee.'
            Assert-Condition ($result.metrics.discovery_ms -ge 0 -and $result.metrics.resolver_ms -ge 0) 'Métriques Discovery/Resolver absentes du rapport DiscoveryOnly.'
            Assert-Condition ($result.scan_errors[0].path -eq 'deployment.yaml' -and $result.scan_errors[0].operation -eq 'read') 'Diagnostic de lecture non localise.'
            Assert-Condition ((Test-Path $reportPath) -and $result.technologies.Count -gt 0) 'Rapport diagnostique non conserve.'
        } finally { $lockedFile.Dispose() }
        Update-Detection
        Assert-Condition $script:Technologies.scan_complete 'Une erreur ancienne persiste dans un nouveau scan.'
    }
    Invoke-TestCase 'Discovery restitue les erreurs de parcours' {
        $files = @(Get-ProjectFile -Root (Join-Path $repoRoot 'missing-directory'))
        Assert-Condition ($files.Count -eq 0 -and $script:ScanErrors.Count -eq 1 -and $script:ScanErrors[0].operation -eq 'enumerate') 'Erreur de parcours non restituee.'
    }
    Invoke-TestCase 'Terragrunt sans Terraform' {
        Write-Fixture 'terragrunt.hcl' "locals {}`n"
        Update-Detection
        Assert-Condition ($script:Technologies.terragrunt -and -not $script:Technologies.terraform) 'Détection HCL erronée.'
    }
    Invoke-TestCase 'Ansible par rôles' {
        Write-Fixture 'roles/example/tasks/main.yml' "---`n[]`n"
        Update-Detection
        $ansible = $script:Technologies.discoveries | Where-Object technology -eq 'ansible'
        Assert-Condition ($script:Technologies.ansible -and $ansible.roots -contains 'roles/example') 'Rôle ou racine non détecté.'
    }
    Invoke-TestCase 'Ansible dans un projet imbriqué' {
        Write-Fixture 'services/infra/ansible.cfg' '[defaults]'
        Write-Fixture 'services/infra/roles/web/tasks/main.yml' "---`n[]`n"
        Update-Detection
        $ansible = $script:Technologies.discoveries | Where-Object technology -eq 'ansible'
        Assert-Condition ($ansible.status -eq 'detected' -and $ansible.roots -contains 'services/infra') 'Racine Ansible imbriquée absente.'
    }
    Invoke-TestCase 'Ansible par hosts' {
        Write-Fixture 'deployment.yml' "---`n- hosts: localhost`n  tasks: []`n"
        Update-Detection
        Assert-Condition $script:Technologies.ansible 'Playbook non détecté.'
    }
    Invoke-TestCase 'Containerfile avec suffixe' {
        Write-Fixture 'Containerfile.test' "FROM scratch`n"
        Update-Detection
        Assert-Condition $script:Technologies.containers 'Conteneur non détecté.'
    }
    Invoke-TestCase 'Markdown' {
        Write-Fixture 'notes.md' "# Notes`n"
        Update-Detection
        Assert-Condition $script:Technologies.markdown 'Markdown non détecté.'
    }
    Invoke-TestCase 'Bash' {
        Write-Fixture 'run.sh' "#!/usr/bin/env bash`nexit 0`n"
        Update-Detection
        Assert-Condition $script:Technologies.shell 'Bash non détecté.'
    }
    Invoke-TestCase 'Racines imbriquées et preuves structurées' {
        Write-Fixture 'services/api/pyproject.toml' "[project]`nname = 'api'`n"
        Write-Fixture 'services/api/src/main.py' "value = 1`n"
        Write-Fixture 'services/web/package.json' "{}`n"
        Write-Fixture 'services/web/src/index.ts' "export const value = 1`n"
        Write-Fixture 'clusters/dev/deployment.yaml' "apiVersion: apps/v1`nkind: Deployment`nmetadata:`n  name: app`n"
        Write-Fixture 'charts/app/Chart.yaml' "apiVersion: v2`nname: app`nversion: 1.0.0`n"
        Update-Detection
        $python = $script:Technologies.discoveries | Where-Object technology -eq 'python'
        $javascript = $script:Technologies.discoveries | Where-Object technology -eq 'javascript'
        $typescript = $script:Technologies.discoveries | Where-Object technology -eq 'typescript'
        $kubernetes = $script:Technologies.discoveries | Where-Object technology -eq 'kubernetes'
        $helm = $script:Technologies.discoveries | Where-Object technology -eq 'helm'
        Assert-Condition ($python.status -eq 'detected' -and $python.roots -contains 'services/api') 'Racine Python imbriquée absente.'
        Assert-Condition ($javascript.status -eq 'detected' -and $typescript.status -eq 'detected' -and $javascript.roots -contains 'services/web' -and $typescript.roots -contains 'services/web') 'Détection ou racine JavaScript/TypeScript incorrecte.'
        Assert-Condition ($kubernetes.status -eq 'detected' -and $kubernetes.evidence -contains 'clusters/dev/deployment.yaml') 'Preuve Kubernetes manquante.'
        Assert-Condition ($helm.status -eq 'detected' -and $helm.roots -contains 'charts/app') 'Racine Helm absente.'
    }
    Invoke-TestCase 'Corpus consommateurs synthétique et métriques étiquetées' {
        $corpus = @(
            [pscustomobject]@{ id = 'powershell'; cohort = 'positive'; expected = @('powershell'); ambiguous = @(); files = @{ 'module.psm1' = 'function Get-Value { return 1 }' } },
            [pscustomobject]@{ id = 'terraform'; cohort = 'positive'; expected = @('terraform'); ambiguous = @(); files = @{ '.terraform-version' = '1.15.8'; 'main.tf' = 'terraform {}' } },
            [pscustomobject]@{ id = 'opentofu'; cohort = 'positive'; expected = @('opentofu'); ambiguous = @(); files = @{ '.opentofu-version' = '1.10.0'; 'main.tf' = 'terraform {}' } },
            [pscustomobject]@{ id = 'terragrunt'; cohort = 'positive'; expected = @('terragrunt'); ambiguous = @(); files = @{ 'terragrunt.hcl' = 'locals {}' } },
            [pscustomobject]@{ id = 'ansible'; cohort = 'positive'; expected = @('ansible'); ambiguous = @(); files = @{ 'ansible.cfg' = '[defaults]'; 'roles/web/tasks/main.yml' = '---' } },
            [pscustomobject]@{ id = 'docker'; cohort = 'positive'; expected = @('docker'); ambiguous = @(); files = @{ 'Dockerfile' = 'FROM scratch' } },
            [pscustomobject]@{ id = 'kubernetes'; cohort = 'positive'; expected = @('kubernetes'); ambiguous = @(); files = @{ 'deployment.yaml' = "apiVersion: apps/v1`nkind: Deployment`nmetadata:`n  name: app" } },
            [pscustomobject]@{ id = 'helm'; cohort = 'positive'; expected = @('helm'); ambiguous = @(); files = @{ 'Chart.yaml' = "apiVersion: v2`nname: app`nversion: 1.0.0" } },
            [pscustomobject]@{ id = 'javascript'; cohort = 'positive'; expected = @('javascript'); ambiguous = @(); files = @{ 'package.json' = '{}'; 'index.js' = 'export const value = 1' } },
            [pscustomobject]@{ id = 'typescript'; cohort = 'positive'; expected = @('javascript', 'typescript'); ambiguous = @(); files = @{ 'package.json' = '{}'; 'tsconfig.json' = '{}'; 'index.ts' = 'export const value: number = 1' } },
            [pscustomobject]@{ id = 'empty'; cohort = 'negative'; expected = @(); ambiguous = @(); files = @{} },
            [pscustomobject]@{ id = 'generic-yaml'; cohort = 'negative'; expected = @(); ambiguous = @(); files = @{ 'config.yml' = "service:`n  name: app" } },
            [pscustomobject]@{ id = 'unmarked-hcl'; cohort = 'ambiguity'; expected = @(); ambiguous = @('terraform', 'opentofu'); files = @{ 'main.tf' = 'terraform {}' } },
            [pscustomobject]@{ id = 'weak-ansible-signal'; cohort = 'ambiguity'; expected = @(); ambiguous = @('ansible'); files = @{ 'config.yml' = "- hosts: localhost`n  tasks: []" } }
        )
        $falsePositives = 0
        $falseNegatives = 0
        $unexpectedAmbiguities = 0
        $missedExpectedAmbiguities = 0
        $positiveSamples = 0
        $negativeSamples = 0
        $expectedAmbiguitySamples = 0
        foreach ($case in $corpus) {
            if (Test-Path $repoRoot) { Remove-Item -LiteralPath $repoRoot -Recurse -Force }
            New-Item -ItemType Directory -Path $repoRoot -Force | Out-Null
            foreach ($relativePath in $case.files.Keys) { Write-Fixture $relativePath $case.files[$relativePath] }
            Update-Detection
            $detected = @($script:Technologies.discoveries | Where-Object status -eq 'detected' | Select-Object -ExpandProperty technology)
            $ambiguous = @($script:Technologies.discoveries | Where-Object status -eq 'ambiguous' | Select-Object -ExpandProperty technology)
            foreach ($technology in $case.expected) { if ($technology -notin $detected) { $falseNegatives++ } }
            foreach ($technology in $detected) { if ($technology -notin $case.expected) { $falsePositives++ } }
            foreach ($technology in $case.ambiguous) {
                $expectedAmbiguitySamples++
                if ($technology -notin $ambiguous) { $missedExpectedAmbiguities++ }
            }
            foreach ($technology in $ambiguous) { if ($technology -notin $case.ambiguous) { $unexpectedAmbiguities++ } }
            if ($case.cohort -eq 'positive') { $positiveSamples++ }
            elseif ($case.cohort -eq 'negative') { $negativeSamples++ }
        }
        Assert-Condition ($positiveSamples -eq 10 -and $negativeSamples -eq 2) 'Taille du corpus positif/négatif incohérente.'
        Assert-Condition ($falsePositives -eq 0 -and $falseNegatives -eq 0) "Métriques corpus en échec: FP=$falsePositives FN=$falseNegatives."
        Assert-Condition ($expectedAmbiguitySamples -eq 3 -and $missedExpectedAmbiguities -eq 0 -and $unexpectedAmbiguities -eq 0) "Ambiguïtés corpus incohérentes: attendues=$expectedAmbiguitySamples manquées=$missedExpectedAmbiguities inattendues=$unexpectedAmbiguities."
        Write-Information -InformationAction Continue "[METRICS] Corpus synthétique Windows x64: positifs=$positiveSamples négatifs=$negativeSamples faux_positifs=$falsePositives faux_negatifs=$falseNegatives ambiguïtés_attendues=$expectedAmbiguitySamples ambiguïtés_manquées=$missedExpectedAmbiguities ambiguïtés_inattendues=$unexpectedAmbiguities"
    }
    Invoke-TestCase 'Hosts YAML seul reste ambigu Ansible' {
        Write-Fixture 'config/deployment.yml' "- hosts: localhost`n  tasks: []`n"
        Update-Detection
        $ansible = $script:Technologies.discoveries | Where-Object technology -eq 'ansible'
        Assert-Condition ($ansible.status -eq 'ambiguous' -and $script:Technologies.ambiguities.Count -gt 0) 'Un signal YAML faible a été déclaré certain.'
        Invoke-AnsibleCheck
        Assert-Condition ($script:Counts.WARN -eq 1 -and $script:Results[0].message -match 'ambigu') 'Un contrôle Ansible a été lancé malgré un signal faible.'
    }
    Invoke-TestCase 'Tool Resolver sélectionne les capacités disponibles seulement' {
        $matrix = @([pscustomobject]@{
            technology = 'python'
            technology_status = 'detected'
            platform = [pscustomobject]@{ os = 'windows'; architecture = 'x64'; id = 'windows-x64' }
            capabilities = @(
                [pscustomobject]@{ name = 'formatting'; required = $true; availability = 'available'; candidate_tools = @([pscustomobject]@{ name = 'ruff'; command = 'ruff'; status = 'available'; source = 'fixture/ruff.exe' }); reasons = @() },
                [pscustomobject]@{ name = 'linting'; required = $true; availability = 'partially_available'; candidate_tools = @([pscustomobject]@{ name = 'ruff'; command = 'ruff'; status = 'available'; source = 'fixture/ruff.exe' }, [pscustomobject]@{ name = 'pylint'; command = 'pylint'; status = 'not_installed'; source = $null }); reasons = @('pylint absent') },
                [pscustomobject]@{ name = 'testing'; required = $true; availability = 'unavailable'; candidate_tools = @([pscustomobject]@{ name = 'pytest'; command = 'pytest'; status = 'not_installed'; source = $null }); reasons = @('pytest absent') }
            )
        })
        $resolution = @(Resolve-CapabilityTool -CapabilityMatrix $matrix)[0]
        Assert-Condition ($resolution.status -eq 'partial' -and $resolution.selected_tools.Count -eq 1) 'Le plan ne sélectionne pas seulement les outils disponibles.'
        Assert-Condition ($resolution.selected_tools[0].command -eq 'ruff' -and $resolution.selected_tools[0].capabilities.Count -eq 2) 'L''outil partagé n''est pas dédupliqué avec ses capacités.'
        Assert-Condition ($resolution.unresolved_capabilities.Count -eq 2) 'Les capacités partielles/indisponibles ne sont pas restituées.'
        Assert-Condition ($resolution.metrics.selected_commands -eq 1 -and $resolution.metrics.reused_assignments -eq 1 -and $resolution.metrics.required_capabilities -eq 3) 'Compteurs de resolution incoherents.'
        Assert-Condition ($resolution.metrics.duration_ms -ge 0) 'Duree de resolution invalide.'
    }
    Invoke-TestCase 'Control Catalog alimente Matrix et Execution Plan' {
        Write-Fixture 'app.py' "value = 1`n"
        Update-Detection
        $technology = $script:Technologies.discoveries | Where-Object technology -eq 'python'
        $matrix = Get-CapabilityMatrix -Discoveries @($technology)
        $resolution = Resolve-CapabilityTool -CapabilityMatrix $matrix
        $pythonMatrix = $matrix | Where-Object technology -eq 'python'
        $lint = $pythonMatrix.capabilities | Where-Object name -eq 'linting'
        $ruff = $lint.candidate_tools | Where-Object command -eq 'ruff'
        Assert-Condition ($ruff.catalog_id -eq 'python.lint.ruff' -and $ruff.severity -eq 'medium' -and $lint.catalog_controls.Count -eq 2) 'Metadonnees catalogue absentes de la Matrix.'
        $plan = New-CompliancePlan -Discovery @($technology) -CapabilityMatrix $matrix -Resolver $resolution -RepositoryRoot $repoRoot -AllowCodeExecution
        $planControls = @($plan.controls | Where-Object technology -eq 'python')
        Assert-Condition (@($planControls | Where-Object { $_.control_catalog_id -eq 'python.lint.ruff' -and $_.severity -eq 'medium' -and $_.side_effect_level -eq 'read_only' }).Count -eq 1) 'Metadonnees catalogue non propagees au plan.'
        Assert-Condition (@($planControls | Where-Object { $_.control_catalog_id -eq 'python.lint.pylint' -and $_.side_effect_level -eq 'code_execution' -and $_.permissions -contains 'code_execution' }).Count -eq 1) 'Permissions outil non propagees au plan.'
    }
    Invoke-TestCase 'Resolver alternatives explicites et priorite du profil' {
        $primary = [pscustomobject]@{ name = 'primary'; command = 'primary'; status = 'not_installed'; source = $null }
        $fallback = [pscustomobject]@{ name = 'fallback'; command = 'fallback'; status = 'available'; source = 'fixture/fallback.exe' }
        $capability = [pscustomobject]@{ name = 'security'; required = $true; selection_policy = 'alternative'; availability = 'partially_available'; candidate_tools = @($primary, $fallback); reasons = @('Alternative disponible') }
        $matrix = @([pscustomobject]@{ technology = 'fixture'; technology_status = 'detected'; platform = Get-ExecutionPlatform; capabilities = @($capability); reasons = @() })
        $resolution = @(Resolve-CapabilityTool -CapabilityMatrix $matrix)[0]
        Assert-Condition ($resolution.status -eq 'ready' -and $resolution.selected_tools.Count -eq 1 -and $resolution.selected_tools[0].command -eq 'fallback' -and $resolution.unresolved_capabilities.Count -eq 0) 'Alternative disponible non resolue.'
        $primary.status = 'available'
        $primary.source = 'fixture/primary.exe'
        $resolution = @(Resolve-CapabilityTool -CapabilityMatrix $matrix)[0]
        Assert-Condition ($resolution.selected_tools.Count -eq 1 -and $resolution.selected_tools[0].command -eq 'primary') 'Priorite du profil ignoree.'
        Write-Fixture '.tools/bin/trivy.exe' 'fixture-presence'
        $discoveries = @([pscustomobject]@{ technology = 'kubernetes'; status = 'detected'; ambiguities = @() })
        $computed = @(Get-CapabilityMatrix -Discoveries $discoveries)[0]
        $security = $computed.capabilities | Where-Object name -eq 'security'
        Assert-Condition ($security.selection_policy -eq 'alternative' -and $security.availability -eq 'available') 'Une alternative disponible est encore declaree partielle dans la matrice.'
    }
    Invoke-TestCase 'Presence Ansible ne signifie pas execution native Windows' {
        Write-Fixture '.venv/Scripts/ansible-lint.exe' 'fixture-presence'
        $tool = Resolve-CandidateTool -Name 'ansible-lint' -Command 'ansible-lint'
        Assert-Condition ($tool.status -eq 'incompatible' -and $tool.reason -match 'Windows') 'Un lanceur present a qualifie a tort un controleur Windows.'
    }
    Invoke-TestCase 'Tool Resolver ne sélectionne pas une technologie ambiguë' {
        $matrix = @([pscustomobject]@{
            technology = 'terraform'
            technology_status = 'ambiguous'
            platform = [pscustomobject]@{ os = 'windows'; architecture = 'x64'; id = 'windows-x64' }
            capabilities = @([pscustomobject]@{ name = 'formatting'; required = $false; availability = 'ambiguous'; candidate_tools = @([pscustomobject]@{ name = 'terraform'; command = 'terraform'; status = 'available'; source = 'fixture/terraform.exe' }); reasons = @('HCL ambigu') })
            reasons = @('Terraform/OpenTofu ambigu')
        })
        $resolution = @(Resolve-CapabilityTool -CapabilityMatrix $matrix)[0]
        Assert-Condition ($resolution.status -eq 'ambiguous' -and $resolution.selected_tools.Count -eq 0) 'Un outil a été sélectionné malgré l''ambiguïté.'
    }
    Invoke-TestCase 'Tool Runtime résout la version active qualifiée' {
        $platform = Get-ExecutionPlatform
        $artifactRelativePath = "$($platform.id)/ruff/1.2.3/ruff.exe"
        $artifactFixturePath = ".tools/runtime/$artifactRelativePath"
        Write-Fixture $artifactFixturePath 'runtime-fixture'
        $manifest = [pscustomobject]@{
            schema_version = 1
            platforms = [pscustomobject]@{
                $platform.id = [pscustomobject]@{
                    status = 'qualified'
                    tools = @(
                        [pscustomobject]@{ name = 'ruff'; command = 'ruff'; version = '1.1.0'; path = ".tools/runtime/$($platform.id)/ruff/1.1.0/ruff.exe"; status = 'qualified'; active = $false },
                        [pscustomobject]@{ name = 'ruff'; command = 'ruff'; version = '1.2.3'; path = $artifactRelativePath; sha256 = (Get-FileHash (Join-Path $repoRoot $artifactFixturePath) -Algorithm SHA256).Hash; status = 'qualified'; active = $true }
                    )
                }
            }
        }
        Write-Fixture '.tools/runtime/index.json' ($manifest | ConvertTo-Json -Depth 8)
        $tool = Resolve-CandidateTool -Name 'ruff' -Command 'ruff'
        Assert-Condition ($tool.status -eq 'available' -and $tool.runtime_managed -and $tool.version -eq '1.2.3' -and $tool.platform -eq $platform.id) ("Version active du runtime non résolue: $($tool | ConvertTo-Json -Compress -Depth 5)")
        Assert-Condition ($tool.source -eq (Join-Path $repoRoot $artifactFixturePath)) 'Chemin artefact runtime incorrect.'
    }
    Invoke-TestCase 'Integrite runtime et copie historique verifiee avant usage' {
        $platform = Get-ExecutionPlatform
        $artifactRelativePath = "$($platform.id)/ruff/1.2.3/ruff.exe"
        Write-Fixture ".tools/runtime/$artifactRelativePath" 'runtime-original'
        $record = [pscustomobject]@{ name = 'ruff'; command = 'ruff'; version = '1.2.3'; path = $artifactRelativePath; sha256 = (Get-FileHash (Join-Path $repoRoot ".tools/runtime/$artifactRelativePath") -Algorithm SHA256).Hash; status = 'qualified'; active = $true }
        $manifest = [pscustomobject]@{ schema_version = 1; platforms = [pscustomobject]@{ $platform.id = [pscustomobject]@{ status = 'qualified'; tools = @($record) } } }
        Write-Fixture '.tools/runtime/index.json' ($manifest | ConvertTo-Json -Depth 8)
        Assert-Condition ((Resolve-CandidateTool -Name 'ruff' -Command 'ruff').status -eq 'available') 'Artefact intact refuse.'
        Write-Fixture ".tools/runtime/$artifactRelativePath" 'runtime-altere'
        Assert-Condition ((Resolve-CandidateTool -Name 'ruff' -Command 'ruff').status -eq 'integrity_error') 'Artefact altere accepte.'
        Write-Fixture '.tools/bin/ruff.exe' 'copie-alteree'
        $executed = Invoke-External -Name 'Copie alteree' -Executable (Join-Path $toolRoot 'ruff.exe') -Required
        Assert-Condition (-not $executed -and $script:Counts.ERROR -eq 1 -and $script:Results[0].message -match 'SHA-256') 'Copie historique non bloquee avant execution.'
        Write-Fixture ".tools/runtime/$artifactRelativePath" 'runtime-original'
        $record.PSObject.Properties.Remove('sha256')
        Write-Fixture '.tools/runtime/index.json' ($manifest | ConvertTo-Json -Depth 8)
        Assert-Condition ((Resolve-CandidateTool -Name 'ruff' -Command 'ruff').status -eq 'integrity_error') 'Empreinte absente acceptee.'
        $manifest.schema_version = 99
        Write-Fixture '.tools/runtime/index.json' ($manifest | ConvertTo-Json -Depth 8)
        Assert-Condition ((Resolve-CandidateTool -Name 'ruff' -Command 'ruff').status -eq 'runtime_error') 'Schema invalide contourne via un outil historique.'
    }
    Invoke-TestCase 'Tool Bootstrap versionne et indexe le runtime' {
        $bootstrapPath = Join-Path $originalRoot 'scripts/bootstrap.ps1'
        $bootstrapTokens = $null
        $bootstrapErrors = $null
        $bootstrapAst = [Management.Automation.Language.Parser]::ParseFile($bootstrapPath, [ref]$bootstrapTokens, [ref]$bootstrapErrors)
        $runtimeFunctions = @($bootstrapAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Register-ToolRuntimeEntry', 'Update-ToolRuntimePlatformStatus', 'Get-VerifiedDownload', 'Write-Status') }, $false))
        foreach ($definition in $runtimeFunctions) { . ([scriptblock]::Create($definition.Extent.Text)) }
        Write-Fixture 'source-ruff-1.1.exe' 'locked-binary-old'
        Write-Fixture 'source-ruff-1.2.exe' 'locked-binary-new'
        Write-Fixture 'verified/release.zip' 'published-archive'
        $expectedArchiveHash = (Get-FileHash (Join-Path $repoRoot 'verified/release.zip') -Algorithm SHA256).Hash
        Assert-Condition ((Get-VerifiedDownload -Uri 'https://example.invalid/release.zip' -Path (Join-Path $repoRoot 'verified/release.zip') -Sha256 $expectedArchiveHash -Description 'fixture release') -eq (Join-Path $repoRoot 'verified/release.zip')) 'Archive correspondant au hash officiel refuse.'
        $wrongChecksumRejected = $false
        try { $null = Get-VerifiedDownload -Uri 'https://example.invalid/release.zip' -Path (Join-Path $repoRoot 'verified/release.zip') -Sha256 ('0' * 64) -Description 'fixture release' }
        catch { $wrongChecksumRejected = $_.Exception.Message -match 'SHA-256 invalide' }
        Assert-Condition $wrongChecksumRejected 'Archive avec somme officielle divergente acceptee.'
        $runtimeRoot = Join-Path $repoRoot '.tools/runtime'
        Register-ToolRuntimeEntry -ToolName 'ruff' -Version '1.1.0' -SourcePath (Join-Path $repoRoot 'source-ruff-1.1.exe') -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64'
        Register-ToolRuntimeEntry -ToolName 'ruff' -Version '1.2.0' -SourcePath (Join-Path $repoRoot 'source-ruff-1.2.exe') -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64'
        $index = Get-Content (Join-Path $runtimeRoot 'index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $versions = @($index.platforms.'windows-x64'.tools | Where-Object name -eq 'ruff')
        $active = @($versions | Where-Object active)
        Assert-Condition ($versions.Count -eq 2 -and $active.Count -eq 1 -and $active[0].version -eq '1.2.0') 'Les versions runtime ou leur pointeur actif sont incohérents.'
        Assert-Condition ($active[0].sha256 -eq (Get-FileHash (Join-Path $runtimeRoot $active[0].path) -Algorithm SHA256).Hash.ToLowerInvariant()) 'L''empreinte de l''artefact runtime diffère.'
        Register-ToolRuntimeEntry -ToolName 'ruff' -Version '1.2.0' -SourcePath (Join-Path $repoRoot 'source-ruff-1.2.exe') -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64'
        $index = Get-Content (Join-Path $runtimeRoot 'index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        $versions = @($index.platforms.'windows-x64'.tools | Where-Object name -eq 'ruff')
        $active = @($versions | Where-Object active)
        Assert-Condition ($versions.Count -eq 2 -and $active.Count -eq 1) 'La réinscription d''une version a créé un doublon.'
        Assert-Condition ($index.platforms.'windows-x64'.status -eq 'experimental') 'La plateforme a été déclarée qualifiée avant le bootstrap complet.'
        Update-ToolRuntimePlatformStatus -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64' -Status 'qualified'
        Register-ToolRuntimeEntry -ToolName 'ruff' -Version '1.1.0' -SourcePath (Join-Path $repoRoot 'source-ruff-1.1.exe') -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64'
        $rollback = Resolve-CandidateTool -Name 'ruff' -Command 'ruff'
        Assert-Condition ($rollback.status -eq 'available' -and $rollback.version -eq '1.1.0') 'Rollback vers une version runtime conservee impossible.'
        Register-ToolRuntimeEntry -ToolName 'ruff' -Version '1.2.0' -SourcePath (Join-Path $repoRoot 'source-ruff-1.2.exe') -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64'
        $resolved = Resolve-CandidateTool -Name 'ruff' -Command 'ruff'
        Assert-Condition ($resolved.status -eq 'available' -and $resolved.version -eq '1.2.0') 'Reactivation de la version runtime courante impossible.'
        Update-ToolRuntimePlatformStatus -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64' -Status 'experimental'
        $index = Get-Content (Join-Path $runtimeRoot 'index.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Condition ($index.platforms.'windows-x64'.status -eq 'experimental') 'Une mise à jour n''a pas invalidé la qualification précédente.'
        Update-ToolRuntimePlatformStatus -RuntimeRoot $runtimeRoot -PlatformId 'windows-x64' -Status 'qualified'
        $resolved = Resolve-CandidateTool -Name 'ruff' -Command 'ruff'
        Assert-Condition ($resolved.runtime_managed -and $resolved.version -eq '1.2.0' -and $resolved.status -eq 'available') 'Le Resolver n''utilise pas la version runtime active.'
    }
    Invoke-TestCase 'Cache pre-commit deplace reconstruit sans toucher aux outils' {
        $bootstrapTokens = $null
        $bootstrapErrors = $null
        $bootstrapAst = [Management.Automation.Language.Parser]::ParseFile((Join-Path $originalRoot 'scripts/bootstrap.ps1'), [ref]$bootstrapTokens, [ref]$bootstrapErrors)
        foreach ($definition in $bootstrapAst.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -in @('Repair-PreCommitCache', 'Invoke-CheckedCommand', 'Write-Status') }, $false)) {
            . ([scriptblock]::Create($definition.Extent.Text))
        }
        Write-Fixture '.tools/pre-commit/repo-current/marker' 'cache valide'
        Write-Fixture '.tools/pre-commit/repo-second/marker' 'second cache valide'
        Write-Fixture '.tools/bin/marker' 'outil conserve'
        $cacheRoot = Join-Path $repoRoot '.tools/pre-commit'
        $databasePath = Join-Path $cacheRoot 'db.db'
        $seed = 'import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); connection.execute("CREATE TABLE repos (path TEXT)"); connection.executemany("INSERT INTO repos VALUES (?)", [(path,) for path in sys.argv[2:]]); connection.commit(); connection.close()'
        $seed | & $python - $databasePath (Join-Path $cacheRoot 'repo-current') (Join-Path $cacheRoot 'repo-second')
        Assert-Condition ($LASTEXITCODE -eq 0) 'Base de fixture non creee.'
        Repair-PreCommitCache -CacheRoot $cacheRoot -PythonPath $python
        Assert-Condition (Test-Path $databasePath) 'Un cache valide a ete supprime.'
        $move = 'import sqlite3,sys; connection=sqlite3.connect(sys.argv[1]); connection.execute("UPDATE repos SET path = ?", (sys.argv[2],)); connection.commit(); connection.close()'
        $move | & $python - $databasePath (Join-Path $workspace 'ancien-cache/repo-old')
        Assert-Condition ($LASTEXITCODE -eq 0) 'Fixture deplacee non configuree.'
        $offlineBlocked = $false
        try { Repair-PreCommitCache -CacheRoot $cacheRoot -PythonPath $python -Offline }
        catch { $offlineBlocked = $_.Exception.Message -match 'reconstruction en ligne' }
        Assert-Condition ($offlineBlocked -and (Test-Path $databasePath)) 'Le mode hors ligne a masque le blocage ou supprime le cache.'
        $previousCache = $env:PRE_COMMIT_HOME
        Repair-PreCommitCache -CacheRoot $cacheRoot -PythonPath $python
        Assert-Condition (-not (Test-Path $databasePath)) 'Le cache deplace est conserve.'
        Assert-Condition ((Test-Path (Join-Path $repoRoot '.tools/bin/marker')) -and $env:PRE_COMMIT_HOME -eq $previousCache) 'Les outils ou l environnement ont ete modifies.'
    }
    Invoke-TestCase 'Tool Runtime refuse une plateforme non qualifiée' {
        $platform = Get-ExecutionPlatform
        $manifest = [pscustomobject]@{
            schema_version = 1
            platforms = [pscustomobject]@{
                $platform.id = [pscustomobject]@{
                    status = 'experimental'
                    tools = @([pscustomobject]@{ name = 'ruff'; command = 'ruff'; version = '1.2.3'; path = "$($platform.id)/ruff/1.2.3/ruff.exe"; status = 'qualified'; active = $true })
                }
            }
        }
        Write-Fixture '.tools/runtime/index.json' ($manifest | ConvertTo-Json -Depth 8)
        $tool = Resolve-CandidateTool -Name 'ruff' -Command 'ruff'
        Assert-Condition ($tool.status -eq 'incompatible' -and $tool.runtime_managed) 'Un runtime expérimental a été utilisé.'
    }
    Invoke-TestCase 'CLI Discovery analyse un repository externe' {
        Write-Fixture 'nested/project/main.ps1' "Write-Output 'ok'`n"
        $output = & powershell -NoProfile -ExecutionPolicy Bypass -File $gatePath -RepositoryPath $repoRoot -DiscoveryOnly -NoColor
        $exitCode = $LASTEXITCODE
        $result = ($output -join "`n") | ConvertFrom-Json
        Assert-Condition ($exitCode -eq 0 -and $result.repository -eq $repoRoot) 'Le chemin externe ne figure pas dans le résultat.'
        Assert-Condition ($null -ne $result.capability_matrix -and $null -ne $result.tool_resolution) 'La Capability Matrix ou le Tool Resolver manque du JSON.'
        $powerShell = $result.technologies | Where-Object technology -eq 'powershell'
        Assert-Condition ($powerShell.status -eq 'detected' -and $powerShell.evidence -contains 'nested/project/main.ps1' -and $powerShell.roots -contains 'nested/project') 'Preuve ou racine externe manquante.'
        $powerShellMatrix = $result.capability_matrix | Where-Object technology -eq 'powershell'
        $linting = $powerShellMatrix.capabilities | Where-Object name -eq 'linting'
        Assert-Condition ($powerShellMatrix.technology_status -eq 'detected' -and $powerShellMatrix.required_capabilities -contains 'linting') 'Capacité PowerShell requise absente de la matrice.'
        Assert-Condition ($linting.candidate_tools[0].name -eq 'PSScriptAnalyzer' -and $linting.candidate_tools[0].status -in @('available', 'not_installed') -and $linting.reasons.Count -gt 0) 'Candidat, disponibilité ou motif manquant.'
        Assert-Condition ($powerShellMatrix.platform.os -eq 'windows' -and $powerShellMatrix.platform.architecture -ne 'unknown') 'Plateforme OS + architecture absente.'
        $absentAnsible = $result.capability_matrix | Where-Object technology -eq 'ansible'
        Assert-Condition ($absentAnsible.technology_status -eq 'absent' -and $absentAnsible.required_capabilities.Count -eq 0 -and $absentAnsible.capabilities[0].availability -eq 'not_applicable') 'Une technologie absente est déclarée requise ou disponible.'
    }
    Invoke-TestCase 'Exclusions générées avant parcours' {
        Write-Fixture '.tools/cache/hidden.py' "invalid`n"
        Write-Fixture '.venv/hidden.tf' "invalid`n"
        Write-Fixture 'reports/hidden.sh' "invalid`n"
        Update-Detection
        Assert-Condition ($script:Files.Count -eq 0) 'Contenu généré parcouru.'
    }
    Invoke-TestCase 'Accents français acceptés' {
        Write-Fixture 'notes.txt' "Vérification réussie, été.`n"
        Assert-Condition ((Invoke-Scanner) -eq 0) 'Accents refusés.'
    }
    Invoke-TestCase 'Pictogramme BMP refusé' {
        Write-Fixture 'notes.txt' ([char]0x2600 + "`n")
        Assert-Condition ((Invoke-Scanner) -ne 0) 'Pictogramme accepté.'
    }
    Invoke-TestCase 'Emoji hors BMP refusé' {
        Write-Fixture 'notes.txt' ([char]::ConvertFromUtf32(0x1F600) + "`n")
        Assert-Condition ((Invoke-Scanner) -ne 0) 'Emoji accepté.'
    }
    Invoke-TestCase 'Binaire ignoré par le scanner texte' {
        [IO.File]::WriteAllBytes((Join-Path $repoRoot 'data.bin'), [byte[]]@(0, 240, 159, 152, 128))
        Assert-Condition ((Invoke-Scanner) -eq 0) 'Binaire traité comme texte.'
    }
    Invoke-TestCase 'Pictogrammes générés exclus' {
        Write-Fixture '.tools/cache/notes.txt' ([char]::ConvertFromUtf32(0x1F600) + "`n")
        Assert-Condition ((Invoke-Scanner) -eq 0) 'Cache analysé.'
    }
    Invoke-TestCase 'Outil requis absent bloque' {
        $result = Invoke-External -Name 'Absent' -Executable (Join-Path $repoRoot 'missing.exe') -Required
        Assert-Condition (-not $result -and $script:Counts.ERROR -eq 1) 'Absence non bloquante.'
    }
    Invoke-TestCase 'Outil facultatif absent avertit' {
        $result = Invoke-External -Name 'Absent' -Executable (Join-Path $repoRoot 'missing.exe') -Optional
        Assert-Condition (-not $result -and $script:Counts.WARN -eq 1 -and $script:Counts.ERROR -eq 0) 'Statut facultatif incorrect.'
    }
    Invoke-TestCase 'Code externe non nul bloque' {
        Write-Fixture 'scripts/exit-seven.ps1' 'exit 7'
        $result = Invoke-External -Name 'Code 7' -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'scripts/exit-seven.ps1')) -Required
        Assert-Condition (-not $result -and $script:Counts.FAIL -eq 1 -and $script:Results[0].message -match 'code 7') 'Le code de sortie externe attendu n''a pas été observé.'
    }
    Invoke-TestCase 'Arguments avec espaces et guillemets' {
        Write-Fixture 'scripts/assert-argument.ps1' 'if ($args[0] -cne ''a "b" c'') { exit 1 }'
        $result = Invoke-External -Name 'Arguments' -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'scripts/assert-argument.ps1'), 'a "b" c') -Required
        Assert-Condition ($result -and $script:Counts.PASS -eq 1) 'Argument altéré.'
    }
    Invoke-TestCase 'Délai externe bloque' {
        Write-Fixture 'scripts/sleep.ps1' 'Start-Sleep -Seconds 5'
        $script:ProcessTimeoutSeconds = 1
        try {
            $result = Invoke-External -Name 'Délai' -Executable $processHost -Arguments @('-NoProfile', '-File', (Join-Path $repoRoot 'scripts/sleep.ps1')) -Required
            Assert-Condition (-not $result -and $script:Counts.ERROR -eq 1) 'Délai non appliqué.'
        } finally { $script:ProcessTimeoutSeconds = 10 }
    }
    Invoke-TestCase 'Rapport Ci et code cohérents' {
        Write-Fixture 'run.sh' "#!/usr/bin/env bash`nexit 0`n"
        Copy-GateFixture
        $fixtureGate = Join-Path $repoRoot 'scripts/quality-gate.ps1'
        $childOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $fixtureGate -Mode Ci -Category Shell -ReportPath result.json -NoColor
        $exitCode = $LASTEXITCODE
        Assert-Condition ($exitCode -eq 0) "Gate enfant en echec ($exitCode): $($childOutput -join ' ')"
        $report = Get-Content (Join-Path $repoRoot 'reports/result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Condition ($exitCode -eq 0 -and $report.code_sortie -eq 0 -and $report.mode -eq 'Ci' -and $report.resume.WARN -eq 1) 'Rapport incohérent.'
        Assert-Condition ($report.technologies.shell_files.Count -eq 1 -and $report.technologies.shell_files[0] -eq 'run.sh') 'Objets fichiers non normalisés.'
        $reference = Get-Content (Join-Path $repoRoot 'reports/compliance-report.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Condition ($reference.schema_version -eq 1 -and $reference.metadata.source_mode -eq 'Ci' -and $reference.verdict -eq 'PASS' -and $reference.execution_results.Count -eq 1) 'Rapport de référence absent ou divergent du mode historique.'
        $expectedCatalogHash = (Get-FileHash -LiteralPath (Join-Path $repoRoot '.config/control-catalog.json') -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-Condition ($reference.metadata.catalog_sha256 -eq $expectedCatalogHash) 'Empreinte du catalogue absente du rapport historique.'
        Assert-Condition ($reference.metadata.platform_qualification_status -eq 'experimental') 'Statut de qualification plateforme absent du rapport.'
        Assert-Condition (@('discovery_ms', 'resolver_ms', 'compliance_ms', 'reporting_ms' | Where-Object { $reference.metrics.PSObject.Properties.Name -notcontains $_ }).Count -eq 0) 'Métriques de durée absentes du rapport historique.'
        Assert-Condition (@($reference.metrics.PSObject.Properties | Where-Object { $_.Value -isnot [long] -and $_.Value -isnot [int] -or $_.Value -lt 0 }).Count -eq 0) 'Métriques historiques non entières ou négatives.'
    }
    Invoke-TestCase 'Fix normalise sans infrastructure' {
        Write-Fixture 'notes.txt' 'texte  '
        Copy-GateFixture
        $fixtureGate = Join-Path $repoRoot 'scripts/quality-gate.ps1'
        $childOutput = & powershell -NoProfile -ExecutionPolicy Bypass -File $fixtureGate -Mode Fix -Category Shell -NoColor
        $exitCode = $LASTEXITCODE
        Assert-Condition ($exitCode -eq 0 -and [IO.File]::ReadAllText((Join-Path $repoRoot 'notes.txt')) -ceq "texte`n") "Fix incorrect ($exitCode): $($childOutput -join ' ')"
    }
    Invoke-TestCase 'Formats JSON TOML XML valides' {
        & git -C $repoRoot init --quiet | Out-Null
        Write-Fixture 'data.json' "{`"value`": 1}`n"
        Write-Fixture 'data.toml' "value = 1`n"
        Write-Fixture 'data.xml' "<value>1</value>`n"
        Update-Detection
        Invoke-GenericCheck
        Assert-Condition ($script:Counts.FAIL -eq 0 -and $script:Counts.ERROR -eq 0) 'Format valide refusé.'
    }
    Invoke-TestCase 'Formats JSON TOML XML invalides bloquent' {
        & git -C $repoRoot init --quiet | Out-Null
        Write-Fixture 'data.json' "{invalid`n"
        Write-Fixture 'data.toml' "value = [`n"
        Write-Fixture 'data.xml' "<value>`n"
        Update-Detection
        Invoke-GenericCheck
        Assert-Condition ($script:Counts.FAIL -eq 3) 'Format invalide accepté.'
    }
    Invoke-TestCase 'Clé binaire détectée avant filtre texte' {
        & git -C $repoRoot init --quiet | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $repoRoot 'example.pfx'), [byte[]]@(0, 1, 2))
        Update-Detection
        Invoke-GenericCheck
        Assert-Condition ($script:Counts.FAIL -eq 1) 'Extension sensible binaire ignorée.'
    }
    Invoke-TestCase 'Rapport ERROR reste bloquant' {
        Write-Fixture 'notes.md' "# Notes`n"
        Copy-GateFixture
        $fixtureGate = Join-Path $repoRoot 'scripts/quality-gate.ps1'
        & powershell -NoProfile -ExecutionPolicy Bypass -File $fixtureGate -Mode Ci -Category Documentation -ReportPath result.json -NoColor | Out-Null
        $exitCode = $LASTEXITCODE
        $report = Get-Content (Join-Path $repoRoot 'reports/result.json') -Raw -Encoding UTF8 | ConvertFrom-Json
        Assert-Condition ($exitCode -ne 0 -and $report.code_sortie -ne 0 -and $report.resume.ERROR -eq 1) 'ERROR masquée.'
    }
    Write-Information -InformationAction Continue "[SUMMARY] Tests PASS=$script:Passed FAIL=$script:Failed"
    if ($script:Failed) { exit 1 }
    exit 0
} finally {
    if (Test-Path $workspace) { Remove-Item -LiteralPath $workspace -Recurse -Force }
}
