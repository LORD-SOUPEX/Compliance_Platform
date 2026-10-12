[CmdletBinding()]
param(
    [string[]]$Path = @('.')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$ignoredDirectoryPattern = '(^|[\\/])(?:\.git|\.venv|\.tools|\.extension-build|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache|\.cache|reports|\.terraform|\.terragrunt-cache)([\\/]|$)'
$forbiddenRanges = @(
    @(0x2300, 0x23FF),
    @(0x2600, 0x27BF),
    @(0x2B00, 0x2BFF),
    @(0x1F000, 0x1FAFF),
    @(0x200D, 0x200D),
    @(0xFE0F, 0xFE0F),
    @(0x20E3, 0x20E3),
    @(0xE0020, 0xE007F)
)
$findings = New-Object System.Collections.Generic.List[string]
$utf8Strict = New-Object System.Text.UTF8Encoding($false, $true)

function Get-TextCandidate {
    param([string]$Directory)
    $pending = New-Object System.Collections.Generic.Stack[string]
    $pending.Push($Directory)
    while ($pending.Count -gt 0) {
        foreach ($item in Get-ChildItem -LiteralPath $pending.Pop() -Force) {
            $relativeItem = $item.FullName.Substring($repoRoot.Length)
            if ($relativeItem -match $ignoredDirectoryPattern) { continue }
            if ($item.PSIsContainer) {
                if (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $pending.Push($item.FullName) }
            } else { $item }
        }
    }
}

foreach ($inputPath in $Path) {
    $resolvedPath = if ([System.IO.Path]::IsPathRooted($inputPath)) { $inputPath } else { Join-Path (Get-Location) $inputPath }
    if (-not (Test-Path -LiteralPath $resolvedPath)) {
        $findings.Add("Chemin introuvable : $inputPath")
        continue
    }
    $items = if (Test-Path -LiteralPath $resolvedPath -PathType Container) {
        Get-TextCandidate -Directory $resolvedPath
    } else {
        Get-Item -LiteralPath $resolvedPath -Force
    }

    foreach ($item in $items) {
        $fullPath = (Resolve-Path -LiteralPath $item.FullName).Path
        if ($fullPath -notlike "$repoRoot*") { continue }
        $relativePath = $fullPath.Substring($repoRoot.Length).TrimStart([char[]]@('\', '/'))
        if ($relativePath -match $ignoredDirectoryPattern) { continue }
        try {
            $bytes = [System.IO.File]::ReadAllBytes($fullPath)
            if ($bytes -contains 0) { continue }
            $text = $utf8Strict.GetString($bytes)
        } catch [System.Text.DecoderFallbackException] {
            continue
        }

        for ($index = 0; $index -lt $text.Length; $index++) {
            $codePoint = [char]::ConvertToUtf32($text, $index)
            if ([char]::IsHighSurrogate($text[$index])) { $index++ }
            $category = [char]::GetUnicodeCategory([char]::ConvertFromUtf32($codePoint), 0)
            $isForbidden = $category -eq [Globalization.UnicodeCategory]::OtherSymbol
            foreach ($range in $forbiddenRanges) {
                if ($codePoint -ge $range[0] -and $codePoint -le $range[1]) { $isForbidden = $true; break }
            }
            if ($isForbidden) {
                $findings.Add("Pictogramme interdit U+$('{0:X4}' -f $codePoint) dans $relativePath")
                break
            }
        }
    }
}

if ($findings.Count -gt 0) {
    foreach ($finding in $findings) { Write-Information -InformationAction Continue "[FAIL] $finding" }
    exit 1
}
Write-Information -InformationAction Continue '[PASS] Aucun emoji ni pictogramme interdit détecté.'
exit 0
