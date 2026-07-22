#!/usr/bin/env bash
set -euo pipefail
phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; results="$phase_dir/results"; run_id="phase10-crm-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"; python_bin="${PYTHON_BIN:-python3}"; image='hookphuzz-phase10-crm-web:local'; compose=(docker compose -p hookphuzz-phase10-crm -f "$phase_dir/docker-compose.yml")
rm -rf "$results"; mkdir -p "$results"
exec > >(tee "$results/run.stdout.log") 2>&1
fail(){ code=$?; printf 'PHASE_10_CRM_FAIL\nroot_cause=%s\n' "${BASH_COMMAND:-unknown}" > "$results/final-status.txt"; exit "$code"; }
trap fail ERR
"$python_bin" "$phase_dir/collector/source_analysis.py" --plugin "$phase_dir/../../../phuzz-main/code/web/applications/wordpress/_plugins/crm-perks-forms/crm-perks-forms" --out "$results/plugin-source-analysis.md" --nonce-out "$results/nonce-source-analysis.md" --ajax-out "$results/ajax-client-analysis.md" --admin-out "$results/admin-page-analysis.json" --contract-out "$results/nonce-contract.json"
timeout 60s "$python_bin" -m unittest discover -s "$phase_dir/tests" -v > "$results/unit-tests.txt" 2>&1
{
  echo 'Dockerfile stage: runtime'; echo 'Download line: GitHub WP-CLI URL in runtime RUN layer'; echo 'Base image: php:8.2.10-apache';
  docker run --rm -v "$phase_dir/tests/tls-probe.sh:/probe.sh:ro" php:8.2.10-apache bash /probe.sh
} > "$results/tls-diagnosis.txt" 2>&1
cp "$results/tls-diagnosis.txt" "$results/tls-certificate-chain.txt"
"$python_bin" "$phase_dir/tests/scan-insecure-tls.py" "$phase_dir" > "$results/insecure-tls-scan.txt"
"${compose[@]}" down --volumes --remove-orphans
build=(docker build --no-cache --progress=plain -t "$image" -f "$phase_dir/Dockerfile" "$phase_dir/..")
if [[ -n "${HOOKPHUZZ_BUILD_CA_FILE:-}" ]]; then
  [[ -f "$HOOKPHUZZ_BUILD_CA_FILE" ]] || { echo 'HOOKPHUZZ_BUILD_CA_FILE missing' >&2; exit 2; }
  openssl x509 -in "$HOOKPHUZZ_BUILD_CA_FILE" -noout >/dev/null
  build+=(--secret "id=environment_ca,src=$HOOKPHUZZ_BUILD_CA_FILE")
fi
timeout 900s "${build[@]}"
docker run --rm -v "$phase_dir/tests/tls-preflight.sh:/tls-preflight.sh:ro" "$image" bash /tls-preflight.sh > "$results/tls-preflight.txt" 2>&1
grep -qx 'TLS_PREFLIGHT_PASS' "$results/tls-preflight.txt"
"${compose[@]}" up -d --no-build
for _ in $(seq 1 90); do if "${compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null; then break; fi; sleep 1; done
"${compose[@]}" exec -T web curl -fsS http://localhost/wp-login.php >/dev/null
"${compose[@]}" exec -T web bash /workspace/wordpress/setup-wordpress.sh > "$results/plugin-status.txt"
"${compose[@]}" exec -T web bash /workspace/wordpress/install-plugin.sh >> "$results/plugin-status.txt"
"${compose[@]}" exec -T web bash /workspace/wordpress/login-session.sh > "$results/auth-session-summary.json"
"${compose[@]}" exec -T web php /workspace/wordpress/validate-nonce.php
"${compose[@]}" exec -T web php -v > "$results/environment.txt"
"${compose[@]}" exec -T web apache2ctl -v >> "$results/environment.txt"
"${compose[@]}" exec -T web mariadb --version >> "$results/environment.txt"
live_id="$run_id-live"; live_marker="PHASE10_CRM_${run_id//[^A-Za-z0-9]/}_LIVE"
printf 'request_id=%s\nmarker=<redacted>\n' "$live_id" > "$results/live-request.txt"
"${compose[@]}" exec -T web bash /workspace/wordpress/crm-request.sh live "$live_id" "$live_marker"
cp "$results/live-opcode-events.json" "$results/raw-opcode-events.json"; cp "$results/live-helper-events.json" "$results/raw-helper-events.json"; cp "$results/live-callback-evidence.json" "$results/callback-evidence.json"
printf 'POST /wp-admin/admin-ajax.php\nrequest_id=%s\naction=vx_form_save_api_settings\nnonce=<redacted>\ncookie=<redacted>\nmarker=<redacted>\n' "$live_id" > "$results/live-request-redacted.txt"
"$python_bin" -c 'import json,sys; c=json.load(open(sys.argv[1])); n=json.load(open(sys.argv[2])); json.dump({"authenticated":True,"nonce_required":True,"nonce_valid":n["valid"],"action_dispatched":c.get("callback_reached") is True,"callback_reached":c.get("callback_reached") is True,"marker_observed":c.get("marker_observed") is True},open(sys.argv[3],"w"),indent=2)' "$results/callback-evidence.json" "$results/nonce-validation.json" "$results/live-callback-validation.json"
"$python_bin" "$phase_dir/collector/normalize_events.py" --opcode "$results/raw-opcode-events.json" --helper "$results/raw-helper-events.json" --callback "$results/callback-evidence.json" --plugin crm-perks-forms --version 1.0.7 --action vx_form_save_api_settings --callback-id cfx_form_admin_pages::save_api_settings --out "$results/normalized-params.json" --classification "$results/event-classification.json"
"$python_bin" "$phase_dir/collector/generate_config.py" "$results/normalized-params.json" --out "$results/generated-config.json" --summary "$results/generated-config-summary.json"
"${compose[@]}" exec -T web python3 /workspace/replay/replay_generated_config.py --config /results/generated-config.json --out /results/replay-request.json
cp "$results/replay-opcode-events.json" "$results/replay-events.json"
"$python_bin" "$phase_dir/collector/validate_replay.py" --config "$results/generated-config.json" --events "$results/replay-events.json" --callback "$results/replay-callback-evidence.json" --response "$results/replay-response.txt" --out "$results/replay-validation.json"
"${compose[@]}" exec -T web python3 /workspace/tests/integration.py
"$python_bin" "$phase_dir/collector/finalize.py" --results "$results" --run-id "$run_id" | tee "$results/final-status.txt"
"${compose[@]}" down --volumes --remove-orphans
trap - ERR
