#!/usr/bin/env bash
set -euo pipefail
phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results="$phase_dir/results"
run_id="phase10-cf7-rest-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
compose=(docker compose -p hookphuzz-phase10-cf7-rest -f "$phase_dir/docker-compose.yml")
image='hookphuzz-phase10-cf7-rest-web:local'
cleanup() { timeout 120s "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true; }
wait_runtime() { local id="$1"; for _ in $(seq 1 50); do [[ -f "$results/runtime/$id.rest.json" ]] && return 0; sleep .1; done; return 1; }
request_status() { python3 - "$1" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))['http_status'])
PY
}
main() {
 trap cleanup EXIT
 cleanup
 mkdir -p "$results/runtime" "$results/opcode-events" "$results/requests"
 python3 "$phase_dir/collector/source_analysis.py" --zip "$phase_dir/targets/contact-form-7.5.7.7.zip" --out "$results/source-analysis.json" --md "$results/source-analysis.md"
 timeout 60s python3 -m unittest discover -s "$phase_dir/tests" -v > "$results/unit-tests.txt" 2>&1
 python3 "$phase_dir/tests/scan-insecure-tls.py" "$phase_dir" > "$results/tls-scan.txt"
 build=(docker build --no-cache --progress=plain -t "$image" -f "$phase_dir/Dockerfile" "$phase_dir")
 if [[ -n "${HOOKPHUZZ_BUILD_CA_FILE:-}" ]]; then [[ -f "$HOOKPHUZZ_BUILD_CA_FILE" ]] || { echo 'HOOKPHUZZ_BUILD_CA_FILE missing' >&2; return 2; }; openssl x509 -in "$HOOKPHUZZ_BUILD_CA_FILE" -noout >/dev/null; build+=(--secret "id=environment_ca,src=$HOOKPHUZZ_BUILD_CA_FILE"); fi
 timeout 900s "${build[@]}"
 timeout 300s "${compose[@]}" up -d --no-build
 for _ in $(seq 1 90); do "${compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null && break; sleep 1; done
 "${compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null
 "${compose[@]}" exec -T web bash /workspace/wordpress/setup-wordpress.sh > "$results/plugin-output.txt"
 python3 - "$results/plugin-output.txt" "$results/plugin-state.json" <<'PY'
import json,sys
s=open(sys.argv[1]).read();json.dump({'installed':True,'active':'contact-form-7' in s,'plugin':'contact-form-7','version':'5.7.7'},open(sys.argv[2],'w'),indent=2)
PY
 "${compose[@]}" exec -T web bash /workspace/wordpress/login-session.sh > "$results/auth-session.json"
 "${compose[@]}" exec -T web php -v > "$results/environment.txt"
 "${compose[@]}" exec -T web apache2ctl -v >> "$results/environment.txt"
 "${compose[@]}" exec -T web mariadb --version >> "$results/environment.txt"
 printf 'wordpress=6.5.5\ncontact_form_7=5.7.7\narchive_sha256=%s\nrun_id=%s\n' "$(sha256sum "$phase_dir/targets/contact-form-7.5.7.7.zip" | awk '{print $1}')" "$run_id" >> "$results/environment.txt"
 canonical_id="$run_id-route-canonical"; canonical_marker="HOOKPHUZZ_CF7_ROUTE_${run_id//[^A-Za-z0-9]/_}"
 "${compose[@]}" exec -T web bash /workspace/wordpress/rest-request.sh route "$canonical_id" "$canonical_marker" canonical search "$canonical_marker"
 if [[ "$(request_status "$results/requests/$canonical_id.json")" == 200 ]]; then effective=canonical; effective_id="$canonical_id"; wait_runtime "$effective_id"; else effective=fallback; effective_id="$run_id-route-fallback"; "${compose[@]}" exec -T web bash /workspace/wordpress/rest-request.sh route "$effective_id" "$canonical_marker" fallback search "$canonical_marker"; wait_runtime "$effective_id"; fi
 python3 "$phase_dir/collector/route_artifact.py" --runtime "$results/runtime/$effective_id.rest.json" --request "$results/requests/$effective_id.json" --canonical-request "$results/requests/$canonical_id.json" --registration "$results/rest-route-registration.json" --resolution "$results/rest-route-resolution.json"
 keys=(per_page offset order orderby search); values=(7 3 asc id '')
 for i in "${!keys[@]}"; do key="${keys[$i]}"; marker="HOOKPHUZZ_CF7_${key^^}_${run_id//[^A-Za-z0-9]/_}"; value="${values[$i]}"; [[ "$key" != search ]] || value="$marker"; id="$run_id-probe-$key"; "${compose[@]}" exec -T web bash /workspace/wordpress/rest-request.sh discovery "$id" "$marker" "$effective" "$key" "$value"; wait_runtime "$id"; done
 python3 "$phase_dir/collector/normalize_events.py" --runtime "$results/runtime" --source "$results/source-analysis.json" --out "$results/normalized-params.json" --raw-helper "$results/raw-rest-helper-events.json" --raw-opcode "$results/raw-opcode-events.json" --callback "$results/callback-evidence.json"
 python3 "$phase_dir/collector/generate_config.py" --normalized "$results/normalized-params.json" --resolution "$results/rest-route-resolution.json" --out "$results/generated-config.json"
 for i in "${!keys[@]}"; do key="${keys[$i]}"; marker="HOOKPHUZZ_CF7_REPLAY_${key^^}_${run_id//[^A-Za-z0-9]/_}"; value="${values[$i]}"; [[ "$key" != search ]] || value="$marker"; id="$run_id-replay-$key"; "${compose[@]}" exec -T web bash /workspace/wordpress/rest-request.sh replay "$id" "$marker" "$effective" "$key" "$value"; wait_runtime "$id"; done
 python3 "$phase_dir/collector/validate_replay.py" --runtime-dir "$results/runtime" --request-dir "$results/requests" --out "$results/replay-validation.json"
 "${compose[@]}" exec -T web python3 /workspace/tests/integration.py "$effective"
 python3 "$phase_dir/collector/finalize.py" --results "$results" --run-id "$run_id"
}
mkdir -p "$results"
mkdir -p "$results/history"
for item in "$results"/*; do [[ -e "$item" && "$(basename "$item")" != history && "$(basename "$item")" != .gitkeep ]] || continue; mv "$item" "$results/history/$run_id-$(basename "$item")"; done
set +e
( set -e; main ) > "$results/run.stdout.log" 2>&1
code=$?
set -e
if [[ $code -eq 0 ]]; then printf 'PHASE_10_CF7_REST_PASS\n'; else status='PHASE_10_CF7_REST_FAIL'; printf '# Phase 10 CF7 REST final report\n\n## Status\n\n`%s`\n\nBlocker: inspect `run.stdout.log`.\n' "$status" > "$results/final-report.md"; printf '%s\n' "$status"; exit "$code"; fi
