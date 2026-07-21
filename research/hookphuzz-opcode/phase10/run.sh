#!/usr/bin/env bash
set -u -o pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
run_id="phase10-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
python_bin="${PYTHON_BIN:-python3}"
mkdir -p "$results_dir"

run() { "$@"; }
{
  printf 'Phase 10 run: %s\n' "$run_id"
  run timeout 60s "$python_bin" -m unittest discover -s "$phase_dir/tests" -v
  unit_status=$?
  if [[ $unit_status -ne 0 ]]; then
    mkdir -p "$results_dir/input"
    printf '{"gates":{}}\n' > "$results_dir/input/manifest.json"
  else
    run timeout 900s bash "$phase_dir/scripts/live_harness.sh" "$results_dir" "$run_id"
    live_status=$?
    if [[ $live_status -ne 0 && ! -f "$results_dir/input/manifest.json" ]]; then
      mkdir -p "$results_dir/input"
      printf '{"gates":{}}\n' > "$results_dir/input/manifest.json"
    fi
  fi
  run "$python_bin" "$phase_dir/scripts/validate.py" --results "$results_dir" --run-id "$run_id"
  status=$?
  printf '%s\n' "$status" > "$results_dir/run.exitcode.txt"
  exit "$status"
} 2>&1 | tee "$results_dir/run.stdout.log"
exit "${PIPESTATUS[0]}"
