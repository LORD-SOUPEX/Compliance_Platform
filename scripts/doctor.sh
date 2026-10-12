#!/usr/bin/env bash
set -euo pipefail
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if ! command -v powershell.exe >/dev/null 2>&1; then
    printf '%s\n' '[ERROR] Relais Git Bash Windows; Linux/macOS non pris en charge.' >&2
    exit 2
fi
exec powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script_dir/doctor.ps1" "$@"
