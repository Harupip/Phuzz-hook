#!/usr/bin/env bash
set -euo pipefail
phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$phase_dir/../../.." && pwd)"
results="$phase_dir/results"
run_id="phase11-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
compose=(docker compose -p hookphuzz-phase11 -f "$phase_dir/docker-compose.yml")
cleanup() { timeout 120s "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true; }
prepare_results() {
  mkdir -p "$results/history"
  for item in "$results"/*; do
    [[ -e "$item" && "$(basename "$item")" != history && "$(basename "$item")" != .gitkeep ]] || continue
    mv "$item" "$results/history/$run_id-$(basename "$item")"
  done
  mkdir -p "$results/generated-configs" "$results/callbacks" "$results/registrations"
}
main() {
  trap cleanup EXIT
  cleanup
  timeout 900s docker build --progress=plain -t hookphuzz-phase11-rest-method:local -f "$phase_dir/Dockerfile" "$phase_dir"
  timeout 300s "${compose[@]}" up -d --no-build
  sleep 8
  "${compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null
  timeout 90s "${compose[@]}" exec -T web bash /phase11/scripts/setup-wordpress.sh
  "${compose[@]}" exec -T web php -v > "$results/environment.txt"
  "${compose[@]}" exec -T web php -m >> "$results/environment.txt"
  "${compose[@]}" exec -T web wp --allow-root core version >> "$results/environment.txt"
  printf 'fixture_plugin=hookphuzz-phase11 1.0.0\nrun_id=%s\n' "$run_id" >> "$results/environment.txt"
  timeout 180s "${compose[@]}" exec -T web python3 /phase11/scripts/phase11.py
  cleanup
  timeout 120s python3 -m unittest \
    "$repo_root/phuzz-main/code/fuzzer/tests/test_rest_method_generalization.py" \
    "$repo_root/phuzz-main/code/fuzzer/tests/test_seed_method_inference.py" \
    "$repo_root/phuzz-main/code/fuzzer/tests/test_entrypoints.py" \
    "$repo_root/phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py" -v > "$results/unit-tests.txt" 2>&1
  timeout 900s bash "$repo_root/research/hookphuzz-opcode/phase9/run.sh" > "$results/phase9-regression.log" 2>&1
  timeout 120s python3 -m unittest discover -s "$repo_root/research/hookphuzz-opcode/phase10/tests" -v > "$results/phase10-regression.log" 2>&1
  : <<'LEGACY_REPORT'
import json,sys
from pathlib import Path
r=Path(sys.argv[1]); status=json.loads((r/'phase11a-status.json').read_text())
reg={'http_method_hardening':'PASS','phase9':'PASS','phase10':'PASS'}
(r/'regression-results.md').write_text('\n'.join(['# Regression', '', *[f'- {k}: {v}' for k,v in reg.items()]])+'\n')
lines=['# Phase 11 final report','', '## Status','', '`PHASE_11A_PASS_PHASE_11B_BLOCKED`','', 'Phase 11B blocker: the only pinned real REST target is Contact Form 7 5.7.7; its retained Phase 10 lab documents authentication-blocked runtime proof. It is not promoted to a real-plugin PASS here.','', '## Evidence','', *[f'- `{name}`' for name in ['environment.txt','route-registrations.json','method-resolution.json','wordpress-rest-constants.json','route-materialization.json','generated-configs/summary.json','request-preparation.json','replay-results.json','negative-tests.json','concurrency-results.json','regression-results.md']]]
(r/'final-report.md').write_text('\n'.join(lines)+'\n')
(r/'investigation-summary.md').write_text('See ../investigation.md. Runtime fixture run passed all Phase 11A gates.\n')
LEGACY_REPORT
  python3 "$phase_dir/scripts/render_report.py" "$phase_dir"
}
prepare_results
set +e
(set -e; main) > "$results/run.stdout.log" 2> "$results/run.stderr.log"
code=$?
set -e
if [[ $code -eq 0 ]]; then printf 'PHASE_11A_PASS_PHASE_11B_BLOCKED\n'; else printf 'PHASE_11_REST_METHOD_GENERALIZATION_FAIL\n'; fi
exit "$code"
