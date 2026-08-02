#!/usr/bin/env bash
set -euo pipefail

phase_dir=$(cd "$(dirname "$0")" && pwd)
phase11_dir=$(cd "$phase_dir/../phase11-rest-method-generalization/phase11b-cf7" && pwd)
run_id="phase12-final-$(date -u +%Y%m%dT%H%M%SZ)-$$"
run_started_epoch=$(date +%s)
results_dir="$phase_dir/results/$run_id"
mkdir -p "$results_dir"
export PHASE12_RESULTS_DIR="$(cd "$results_dir" && pwd)"
export PHASE11B_RUN_ID="$run_id" PHASE11B_LOCAL_USERNAME=phase12final PHASE11B_LOCAL_PASSWORD="local-$run_id" PHASE11B_DENIED_USERNAME=phase12finaldenied PHASE11B_DENIED_PASSWORD="denied-$run_id"
cf7_lifecycle=(python3 "$phase11_dir/scripts/cf7_lifecycle.py")
cf7_project=$("${cf7_lifecycle[@]}" project-name --run-id "$run_id" --owner phase12)
fixture_project=$("${cf7_lifecycle[@]}" project-name --run-id "$run_id" --owner phase12-fixture)
fixture_compose=(docker compose --project-name "$fixture_project" --file "$phase_dir/docker-compose.yml")
python3 "$phase_dir/scripts/write_run_start.py" "$results_dir" "$run_id" "$run_started_epoch" "$cf7_project"

cleanup() {
  local fixture_code=0 cf7_code=0
  timeout 120s "${fixture_compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || fixture_code=$?
  timeout 180s "${cf7_lifecycle[@]}" stop --phase-dir "$phase11_dir" --run-id "$run_id" --results-dir "$results_dir" --owner phase12 --project-name "$cf7_project" >/dev/null 2>&1 || cf7_code=$?
  if [[ $fixture_code -ne 0 || $cf7_code -ne 0 ]]; then
    printf 'Phase 12 cleanup failed: fixture=%s cf7=%s\n' "$fixture_code" "$cf7_code" >&2
    return 1
  fi
}

on_exit() {
  local status=$? cleanup_code=0
  set +e
  cleanup
  cleanup_code=$?
  set -e
  if [[ $status -eq 0 && $cleanup_code -ne 0 ]]; then return "$cleanup_code"; fi
  return "$status"
}

trap on_exit EXIT
printf 'Phase 12 run ID: %s\n' "$run_id"

fixture_step() {
  local name=$1
  shift
  if ! "$@" >"$results_dir/$name.log" 2>&1; then
    printf 'Phase 12 fixture step failed: %s (see %s/%s.log)\n' "$name" "$results_dir" "$name" >&2
    return 1
  fi
}

timeout 600s "${cf7_lifecycle[@]}" start --phase-dir "$phase11_dir" --run-id "$run_id" --results-dir "$results_dir" --owner phase12 --project-name "$cf7_project"
fixture_step fixture-up timeout 300s "${fixture_compose[@]}" up -d --no-build
for _ in $(seq 1 60); do
  if "${fixture_compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null 2>&1; then break; fi
  sleep 1
done
fixture_step fixture-http timeout 60s "${fixture_compose[@]}" exec -T web curl -fsS -o /dev/null http://localhost/wp-login.php
fixture_step fixture-setup timeout 120s "${fixture_compose[@]}" exec -T web bash /phase12/scripts/setup.sh
fixture_step fixture-proof timeout 180s "${fixture_compose[@]}" exec -T web python3 /phase12/scripts/run_fixture.py
fixture_step fixture-schema timeout 60s python3 "$phase_dir/tests/test_phase12_schema.py"
fixture_step fixture-lint timeout 60s "${fixture_compose[@]}" exec -T web php -l /var/www/html/wp-content/plugins/hookphuzz-phase12-fixture/hookphuzz-phase12.php

cf7_container_id=$(python3 - "$results_dir/cf7-bootstrap.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1], encoding='utf-8'))
container_id = value.get('web_container_id')
if not isinstance(container_id, str) or not container_id:
    raise SystemExit('CF7 bootstrap did not provide a container ID')
print(container_id)
PY
)
timeout 30s docker cp "$phase_dir/scripts/run_cf7_current.py" "$cf7_container_id:/tmp/run_cf7_current.py"
timeout 180s docker compose --project-name "$cf7_project" --file "$phase11_dir/docker-compose.yml" exec -T -e "PHASE12_RUN_ID=$run_id" -e "PHASE12_COMPOSE_PROJECT=$cf7_project" web python3 /tmp/run_cf7_current.py
for name in cf7-route-argument-capture.json cf7-parameter-resolution.json cf7-replay-result.json cf7-replay-evidence.json; do
  timeout 30s docker cp "$cf7_container_id:/tmp/phase12-cf7/$name" "$results_dir/$name"
done
timeout 30s python3 "$phase_dir/scripts/write_regression_results.py" "$results_dir" "$run_id"
timeout 60s python3 "$phase_dir/scripts/check_gates.py" "$results_dir" "$run_id" "$run_started_epoch" "$cf7_project"
cleanup
trap - EXIT
timeout 60s python3 "$phase_dir/scripts/finalize.py" "$results_dir" "$phase_dir/results/latest-run.json"
printf 'PHASE_12_REST_ARGUMENT_SCHEMA_EXTRACTION_PASS\n'
