#!/usr/bin/env bash
set -euo pipefail
phase_dir=$(cd "$(dirname "$0")" && pwd)
run_id="phase13-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir -p "$phase_dir/results/$run_id"
timeout 1800s bash "$phase_dir/../phase12/run.sh"
phase12_run=$(python3 -c "import json; print(json.load(open('$phase_dir/../phase12/results/latest-run.json'))['run_id'])")
cp "$phase_dir/../phase12/results/$phase12_run/final-gate-status.json" "$phase_dir/results/$run_id/current-machine-phase12-baseline.json"
PHASE13_RUN_ID="$run_id" timeout 1800s python3 "$phase_dir/scripts/phase13.py"
