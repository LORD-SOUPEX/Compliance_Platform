#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if command -v powershell.exe >/dev/null 2>&1; then
    exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script_dir/compliance-adapter.ps1" -Adapter Bash "$@"
fi
if command -v pwsh >/dev/null 2>&1; then
    exec pwsh -NoProfile -File "$script_dir/compliance-adapter.ps1" -Adapter Bash "$@"
fi
printf '%s\n' '[ERROR] Compliance nécessite powershell.exe (Windows) ou pwsh.' >&2
exit 2
