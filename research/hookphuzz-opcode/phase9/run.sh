#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
history_dir="$phase_dir/results-history"
compose=(docker compose -p hookphuzz-opcode-phase9 -f "$phase_dir/docker-compose.yml")
export PHASE9_RUN_ID="phase9-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"

cleanup() {
  timeout 120s "${compose[@]}" down --volumes --remove-orphans > /dev/null 2>&1 || true
}
cleanup
if [[ -d "$results_dir" ]] && [[ -n "$(find "$results_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  mkdir -p "$history_dir"
  mkdir -p "$history_dir/$PHASE9_RUN_ID-pre-run"
  cp -a "$results_dir/." "$history_dir/$PHASE9_RUN_ID-pre-run/"
  rm -rf "$results_dir"
fi
mkdir -p "$results_dir"
printf '%s\n' "$PHASE9_RUN_ID" > "$results_dir/run-id.txt"

if ! timeout 900s "${compose[@]}" build > "$results_dir/build.log" 2>&1; then
  printf 'PHASE_9_FAIL\nDocker build failed or timed out. See %s/build.log\n' "$results_dir"
  exit 1
fi
if ! timeout 300s "${compose[@]}" up -d --wait --wait-timeout 280 enabled disabled enabled-static > "$results_dir/docker-up.log" 2>&1; then
  printf 'PHASE_9_FAIL\nWordPress Apache startup failed or timed out. See %s/docker-up.log\n' "$results_dir"
  exit 1
fi

printf 'Runtime extension proof is recorded by current-run opcode artifacts under results/artifacts/.\n' > "$results_dir/extension-enabled.txt"
printf 'Disabled-service semantic evidence is retained in the verifier log.\n' > "$results_dir/extension-disabled.txt"
cat > "$results_dir/environment.txt" <<EOF
Image: php:8.2.10-apache
Runtime: Apache + mod_php in Docker
WordPress: 6.5.5
Database: MariaDB 10.11.8
JIT: disabled
OPcache: disabled
Extension source: isolated Phase 9 extension based on proven Phase 6 direct-read source
Artifact directory: /shared/opcode-events
Run ID: $PHASE9_RUN_ID
EOF

timeout 1200s "${compose[@]}" run --rm -T verifier > "$results_dir/verifier.log" 2>&1 &
verifier_pid=$!
verifier_passed=false
for _ in $(seq 1 12000); do
  if grep -qx 'PHASE_9_PASS' "$results_dir/verifier.log" 2>/dev/null && grep -Fq "\"run_id\": \"$PHASE9_RUN_ID\"" "$results_dir/phase9-validation-summary.json" 2>/dev/null && grep -Fq '"overall_pass": true' "$results_dir/phase9-validation-summary.json" 2>/dev/null; then
    verifier_passed=true
    kill "$verifier_pid" > /dev/null 2>&1 || true
    wait "$verifier_pid" > /dev/null 2>&1 || true
    break
  fi
  if ! kill -0 "$verifier_pid" > /dev/null 2>&1; then
    wait "$verifier_pid" || true
    break
  fi
  sleep .1
done
if [[ "$verifier_passed" != true ]]; then
  kill "$verifier_pid" > /dev/null 2>&1 || true
  wait "$verifier_pid" > /dev/null 2>&1 || true
  printf 'PHASE_9_FAIL\n'
  [[ -f "$results_dir/final-verdict.txt" ]] && cat "$results_dir/final-verdict.txt" || cat "$results_dir/verifier.log"
  exit 1
fi
printf 'PHASE_9_PASS\n'
