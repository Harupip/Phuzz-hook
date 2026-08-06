#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$phase_dir/../../.." && pwd)"
generic_dir="$repo_root/research/hookphuzz-opcode/phase-demo-generic-ajax"
run_id="weekly-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
project="hpweekly-$(date -u +%Y%m%d%H%M%S)-$$"
run_dir="$phase_dir/results/$run_id"
compose=(docker compose -p "$project" -f "$generic_dir/docker-compose.yml" -f "$phase_dir/docker-compose.yml")

mkdir -p "$run_dir"
export HOOKPHUZZ_DEMO_RUN_ID="$run_id"
export HOOKPHUZZ_WEEKLY_RUN_ID="$run_id"
export HOOKPHUZZ_WEEKLY_PROJECT="$project"
export HOOKPHUZZ_WEEKLY_RESULTS_DIR="$run_dir"
export HOOKPHUZZ_REPO_ROOT="$repo_root"
export HOOKPHUZZ_FUZZER_DIR="$repo_root/phuzz-main/code/fuzzer"

cleanup() {
  timeout 120s "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

run() {
  docker image inspect hookphuzz-opcode-demo-generic-ajax-wordpress:latest >/dev/null
  docker image inspect code-fuzzer-wordpress-plugin:latest >/dev/null
  docker run --rm -v "$generic_dir:/workspace:ro" --entrypoint php hookphuzz-opcode-demo-generic-ajax-wordpress:latest /workspace/tests/recursive-discovery.php
  export HOOKPHUZZ_WEEKLY_REGRESSION_PASS=true
  timeout 240s "${compose[@]}" up -d --no-build --wait --wait-timeout 180 db wordpress
  timeout 90s "${compose[@]}" run --rm --no-deps -T phuzz-loader
}

set +e
run > >(tee "$run_dir/run.stdout.log") 2> >(tee "$run_dir/run.stderr.log" >&2)
status=$?
set -e
exit "$status"
