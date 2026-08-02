#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$phase_dir/../../../.." && pwd)"
phase11_dir="$phase_dir/.."
results="$phase_dir/results"
run_id="phase11b-cf7-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
helper=(python3 "$phase_dir/scripts/cf7_lifecycle.py")
project=$("${helper[@]}" project-name --run-id "$run_id" --owner phase11b)
compose=(docker compose --project-name "$project" --file "$phase_dir/docker-compose.yml")
export PHASE11B_RUN_ID="$run_id"
export PHASE11B_LOCAL_USERNAME="phase11bcf7"
export PHASE11B_DENIED_USERNAME="phase11bcf7denied"
export PHASE11B_LOCAL_PASSWORD="local-${run_id}-${RANDOM}"
export PHASE11B_DENIED_PASSWORD="local-denied-${run_id}-${RANDOM}"

cleanup() { timeout 180s "${helper[@]}" stop --phase-dir "$phase_dir" --results-dir "$results" --run-id "$run_id" --owner phase11b --project-name "$project" >/dev/null 2>&1 || true; }

archive_current_run() {
  mkdir -p "$results/history" "$phase_dir/configs" "$phase_dir/artifacts"
  for item in "$results"/*; do
    [[ -e "$item" && "$(basename "$item")" != history ]] || continue
    mv "$item" "$results/history/$run_id-$(basename "$item")"
  done
  for item in "$phase_dir/configs"/*; do
    [[ -e "$item" ]] || continue
    mv "$item" "$results/history/$run_id-config-$(basename "$item")"
  done
  mkdir -p "$results/callbacks"
}

main() {
  trap cleanup EXIT
  cleanup
  timeout 600s "${helper[@]}" start --phase-dir "$phase_dir" --run-id "$run_id" --results-dir "$results" --owner phase11b --project-name "$project"
  {
    "${compose[@]}" exec -T web php -v
    "${compose[@]}" exec -T web php -r 'echo "Zend=" . zend_version() . PHP_EOL; echo "UOPZ=" . phpversion("uopz") . PHP_EOL;'
    "${compose[@]}" exec -T web wp --allow-root --path=/var/www/html core version
    "${compose[@]}" exec -T web wp --allow-root --path=/var/www/html plugin get contact-form-7 --field=version
    printf 'host=local Docker\ncompose_project=%s\nrun_id=%s\n' "$project" "$run_id"
  } > "$results/environment.txt"
  timeout 180s "${compose[@]}" exec -T web python3 /phase11b/scripts/run_phase11b.py
}

run_check() {
  local name="$1" limit="$2"
  shift 2
  set +e
  timeout "$limit" "$@" > "$results/regression-$name.log" 2>&1
  local code=$?
  set -e
  if [[ $code -eq 0 ]]; then
    regression_checks["$name"]='PASS'
  else
    regression_checks["$name"]="FAIL (exit $code)"
  fi
}

archive_current_run
set +e
main > "$results/run.stdout.log" 2> "$results/run.stderr.log"
proof_code=$?
set -e
cleanup
if [[ $proof_code -ne 0 ]]; then
  python3 - "$results/regression-summary.json" <<'PY'
import json,sys
json.dump({'checks': {'proof': 'FAIL'}}, open(sys.argv[1], 'w'), indent=2)
PY
  printf '# Regression results\n\n- proof: FAIL; regressions were not run after a failed local proof.\n' > "$results/regression-results.md"
  python3 "$phase_dir/scripts/finalize.py" "$results" || true
  printf 'PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_FAIL\n'
  exit 1
fi
declare -A regression_checks=()
run_check phase11a_complete 1800s bash "$phase11_dir/run.sh"
run_check http_method_hardening 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_rest_method_generalization.py" "$repo_root/phuzz-main/code/fuzzer/tests/test_seed_method_inference.py" -v
run_check route_capture 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_bootstrap_entry_discovery.py" -v
run_check route_materialization 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_rest_method_generalization.py" -v
run_check config_exporter 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py" -v
run_check request_runner 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_seed_method_inference.py" -v
run_check authentication_login 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_entrypoints.py" -v
run_check request_id_correlation 300s python3 -m unittest "$repo_root/phuzz-main/code/fuzzer/tests/test_rest_method_generalization.py" -v
run_check phase9 1200s bash "$repo_root/research/hookphuzz-opcode/phase9/run.sh"
run_check phase10 300s python3 -m unittest discover -s "$repo_root/research/hookphuzz-opcode/phase10/tests" -v
python3 - "$results/regression-summary.json" "${regression_checks[phase11a_complete]}" "${regression_checks[http_method_hardening]}" "${regression_checks[route_capture]}" "${regression_checks[route_materialization]}" "${regression_checks[config_exporter]}" "${regression_checks[request_runner]}" "${regression_checks[authentication_login]}" "${regression_checks[request_id_correlation]}" "${regression_checks[phase9]}" "${regression_checks[phase10]}" <<'PY'
import json,sys
keys=['phase11a_complete','http_method_hardening','route_capture','route_materialization','config_exporter','request_runner','authentication_login','request_id_correlation','phase9','phase10']
json.dump({'checks':dict(zip(keys,sys.argv[2:]))},open(sys.argv[1],'w'),indent=2)
PY
{
  printf '# Regression results\n\n'
  for name in phase11a_complete http_method_hardening route_capture route_materialization config_exporter request_runner authentication_login request_id_correlation phase9 phase10; do
    printf -- '- %s: %s\n' "$name" "${regression_checks[$name]}"
  done
} > "$results/regression-results.md"
set +e
python3 "$phase_dir/scripts/finalize.py" "$results"
final_code=$?
set -e
if [[ $proof_code -ne 0 || $final_code -ne 0 ]]; then
  printf 'PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_FAIL\n'
  exit 1
fi
printf 'PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_PASS\n'
