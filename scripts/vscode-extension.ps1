[CmdletBinding()]
param([ValidateSet('Install', 'Build', 'Test', 'TestHost', 'Package')][string]$Action = 'Test')

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$extension = Join-Path $root 'vscode-extension'
$toolRoot = Join-Path $root '.tools/vscode-extension'
$node = Get-ChildItem -LiteralPath (Join-Path $root '.tools/pre-commit') -Filter 'node.exe' -File -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match 'node_env-26\.10\.0[\\/]' } | Select-Object -First 1
if (-not $node) { throw 'Node 26.10.0 local absent; preparer le hook Markdown avec Bootstrap.' }
$version = & $node.FullName --version
if ($LASTEXITCODE -ne 0 -or $version -ne 'v26.10.0') { throw 'Le Node local ne correspond pas au pin 26.10.0.' }
$compiler = Join-Path $toolRoot 'node_modules/typescript/bin/tsc'
if ($Action -eq 'Install') {
    $npm = Join-Path $node.DirectoryName 'node_modules/npm/bin/npm-cli.js'
    $npmVersion = & $node.FullName $npm --version
    if ($LASTEXITCODE -ne 0 -or $npmVersion -ne '11.19.1') { throw 'npm local doit correspondre au pin 11.19.1.' }
    New-Item -ItemType Directory -Path $toolRoot -Force | Out-Null
    Copy-Item (Join-Path $extension 'package.json'), (Join-Path $extension 'package-lock.json') $toolRoot -Force
    & $node.FullName $npm ci --prefix $toolRoot --ignore-scripts --cache (Join-Path $root '.tools/cache/npm') --no-audit --no-fund
    if ($LASTEXITCODE -ne 0) { throw 'Installation des dependances locales de l extension impossible.' }
    exit 0
}
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) { throw 'Outils de l extension absents; lancer scripts/vscode-extension.ps1 -Action Install.' }
& $node.FullName $compiler -p (Join-Path $extension 'tsconfig.json')
if ($LASTEXITCODE -ne 0) { throw 'Compilation de l extension en echec.' }
if ($Action -eq 'Test') {
    & $node.FullName --test --test-concurrency=1 (Join-Path $extension '.extension-build/tests/*.test.js')
    if ($LASTEXITCODE -ne 0) { throw 'Tests de l extension en echec.' }
}
if ($Action -eq 'TestHost') {
    $launcher = Get-Command code -ErrorAction Stop
    $executable = Join-Path (Split-Path (Split-Path $launcher.Source -Parent) -Parent) 'Code.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Executable VS Code local introuvable.' }
    $previousNodePath = $env:NODE_PATH
    $previousExecutable = $env:COMPLIANCE_VSCODE_EXECUTABLE
    try {
        $env:NODE_PATH = Join-Path $toolRoot 'node_modules'
        $env:COMPLIANCE_VSCODE_EXECUTABLE = $executable
        & $node.FullName (Join-Path $extension '.extension-build/tests/run-host.js')
        if ($LASTEXITCODE -ne 0) { throw 'Tests Extension Host en echec.' }
    } finally {
        $env:NODE_PATH = $previousNodePath
        $env:COMPLIANCE_VSCODE_EXECUTABLE = $previousExecutable
    }
}
if ($Action -eq 'Package') {
    $python = Join-Path $root '.tools/python/python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        $python = 'python'
    }
    $packager = Join-Path $root 'scripts/package_vsix.py'
    & $python $packager
    if ($LASTEXITCODE -ne 0) { throw 'Packaging VSIX en echec.' }
}
