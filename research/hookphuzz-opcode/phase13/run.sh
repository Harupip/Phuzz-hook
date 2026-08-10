#!/usr/bin/env bash
set -euo pipefail
phase_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
plugin_zip_dir="$phase_dir/../../../phuzz-main/code/web/applications/wordpress/_plugins"
plugins=()
matrix_path=""
select_plugin=0
usage() {
  cat >&2 <<'EOF'
usage: run.sh [--plugin <slug> ...] [--matrix <path>] [--select-plugin]

No arguments run the canonical Phase 13 matrix. --plugin, --matrix, and
--select-plugin run the exploratory gate set for local plugin ZIPs.
EOF
}

discover_plugin_slugs() {
  [[ -d "$plugin_zip_dir" ]] || return 0
  find "$plugin_zip_dir" -maxdepth 1 -type f -name '*.zip' -printf '%f\n' |
    sed 's/\.zip$//' |
    sort -u
}

read_plugin_menu() {
  local slugs=() index choice
  mapfile -t slugs < <(discover_plugin_slugs)
  [[ ${#slugs[@]} -gt 0 ]] || { echo "No local plugin ZIPs found in $plugin_zip_dir" >&2; return 2; }

  echo "" >&2
  echo "Choose local WordPress plugin:" >&2
  for index in "${!slugs[@]}"; do
    printf '  %d) %s\n' "$((index + 1))" "${slugs[$index]}" >&2
  done

  printf 'Select [1-%d]: ' "${#slugs[@]}" >&2
  read -r choice
  [[ "$choice" =~ ^[0-9]+$ ]] || { echo "Invalid plugin selection '$choice'. Choose a number." >&2; return 2; }
  (( choice >= 1 && choice <= ${#slugs[@]} )) || { echo "Invalid plugin selection '$choice'. Choose 1-${#slugs[@]}." >&2; return 2; }
  printf '%s\n' "${slugs[$((choice - 1))]}"
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --plugin)
        [[ $# -ge 2 ]] || { usage; return 2; }
        plugins+=("$2")
        shift 2
        ;;
      --matrix)
        [[ $# -ge 2 ]] || { usage; return 2; }
        matrix_path="$2"
        shift 2
        ;;
      --select-plugin)
        select_plugin=1
        shift
        ;;
      -h|--help)
        usage
        return 64
        ;;
      *)
        usage
        return 2
        ;;
    esac
  done
}

normalize_selection() {
  local selected matrix_dir modes=0
  [[ ${#plugins[@]} -gt 0 ]] && ((modes+=1))
  [[ -n "$matrix_path" ]] && ((modes+=1))
  [[ "$select_plugin" -eq 1 ]] && ((modes+=1))
  [[ "$modes" -le 1 ]] || { echo "--plugin, --matrix, and --select-plugin are mutually exclusive" >&2; return 2; }

  if [[ "$select_plugin" -eq 1 ]]; then
    selected=$(read_plugin_menu)
    plugins=("$selected")
  fi
  if [[ -n "$matrix_path" ]]; then
    [[ -f "$matrix_path" ]] || { echo "missing matrix: $matrix_path" >&2; return 2; }
    matrix_dir=$(cd "$(dirname "$matrix_path")" && pwd)
    matrix_path="$matrix_dir/$(basename "$matrix_path")"
  fi
}

phase13_env_args() {
  local run_id="$1" selected
  printf '%s\n' "PHASE13_RUN_ID=$run_id"
  if [[ ${#plugins[@]} -gt 0 ]]; then
    selected=$(IFS=,; echo "${plugins[*]}")
    printf '%s\n' "PHASE13_RUN_MODE=exploratory" "PHASE13_SELECTED_PLUGINS=$selected"
  elif [[ -n "$matrix_path" ]]; then
    printf '%s\n' "PHASE13_RUN_MODE=exploratory" "PHASE13_MATRIX_PATH=$matrix_path"
  fi
}

main() {
  local parse_status run_id phase12_run env_args=()
  parse_args "$@" || { parse_status=$?; [[ "$parse_status" -eq 64 ]] && return 0; return "$parse_status"; }
  normalize_selection

  run_id="phase13-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mkdir -p "$phase_dir/results/$run_id"
  timeout 1800s bash "$phase_dir/../phase12/run.sh"
  phase12_run=$(python3 -c "import json; print(json.load(open('$phase_dir/../phase12/results/latest-run.json'))['run_id'])")
  cp "$phase_dir/../phase12/results/$phase12_run/final-gate-status.json" "$phase_dir/results/$run_id/current-machine-phase12-baseline.json"
  mapfile -t env_args < <(phase13_env_args "$run_id")
  env "${env_args[@]}" timeout 1800s python3 "$phase_dir/scripts/phase13.py"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
