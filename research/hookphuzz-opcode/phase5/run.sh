#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase5 -f "$phase_dir/docker-compose.yml")
mkdir -p "$results_dir"

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -f "$results_dir"/*.txt "$results_dir"/*.json "$results_dir"/*.log

if ! timeout 600s "${compose[@]}" build > "$results_dir/docker-build.log" 2>&1; then
  printf 'Status: PHASE_5_FAIL\nFailing test: Docker build\nExpected: successful image build\nActual: build failed or timed out\nLog path: %s/docker-build.log\nHypothesis: extension compilation or Docker dependency failure\n' "$results_dir" > "$results_dir/final-verdict.txt"
  printf 'PHASE_5_FAIL\n'
  cat "$results_dir/final-verdict.txt"
  exit 1
fi
if ! timeout 90s "${compose[@]}" up -d enabled disabled > "$results_dir/docker-up.log" 2>&1; then
  printf 'Status: PHASE_5_FAIL\nFailing test: Apache startup\nExpected: healthy enabled and disabled services\nActual: startup failed or timed out\nLog path: %s/docker-up.log\nHypothesis: Apache configuration or extension load failure\n' "$results_dir" > "$results_dir/final-verdict.txt"
  printf 'PHASE_5_FAIL\n'
  cat "$results_dir/final-verdict.txt"
  exit 1
fi
if ! timeout 600s "${compose[@]}" run --rm verifier > "$results_dir/verifier.log" 2>&1; then
  printf 'PHASE_5_FAIL\n'
  if [[ -f "$results_dir/final-verdict.txt" ]]; then cat "$results_dir/final-verdict.txt"; else
    printf 'Failing test: verifier startup\nExpected: verifier creates final-verdict.txt\nActual: verifier exited before producing a verdict\nLog path: %s/verifier.log\nHypothesis: verifier container or shell startup failure\n' "$results_dir"
  fi
  exit 1
fi
printf 'PHASE_5_PASS\n'
