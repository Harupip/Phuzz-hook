#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
code_root="$(cd "$script_dir/../.." && pwd)"
output_dir="$code_root/fuzzer/output"
ps_script="$script_dir/run-wordpress-phuzz.ps1"
fuzzer_service="fuzzer-wordpress-plugin"

to_windows_path() {
  local input_path="$1"

  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$input_path"
    return
  fi

  if [[ "$input_path" =~ ^/mnt/([a-zA-Z])/(.*)$ ]]; then
    local drive_letter="${BASH_REMATCH[1]^^}"
    local remainder="${BASH_REMATCH[2]//\//\\}"
    printf '%s\n' "${drive_letter}:\\${remainder}"
    return
  fi

  printf '%s\n' "$input_path"
}

if [[ ! -d "$output_dir" ]]; then
  echo "Missing output directory: $output_dir" >&2
  exit 1
fi

if [[ ! -f "$ps_script" ]]; then
  echo "Missing PowerShell runner: $ps_script" >&2
  exit 1
fi

windows_ps_script="$(to_windows_path "$ps_script")"
cd "$code_root"

if command -v pwsh >/dev/null 2>&1; then
  ps_runner=(pwsh -NoProfile -ExecutionPolicy Bypass -File "$windows_ps_script")
elif command -v powershell.exe >/dev/null 2>&1; then
  ps_runner=(powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$windows_ps_script")
else
  echo "Could not find pwsh or powershell.exe in PATH." >&2
  exit 1
fi

echo "Stopping $fuzzer_service before clearing old output"
docker compose stop "$fuzzer_service" >/dev/null 2>&1 || true

echo "Clearing $output_dir/*"
windows_output_dir="$(to_windows_path "$output_dir")"
"${ps_runner[@]::${#ps_runner[@]}-2}" -Command \
  "Get-ChildItem -LiteralPath '$windows_output_dir' -Force | Where-Object { \$_.Name -ne '.gitkeep' } | Remove-Item -Recurse -Force"

exec "${ps_runner[@]}" "$@"

# bash ./run-wordpress-phuzz.sh -NoFollowLogs
