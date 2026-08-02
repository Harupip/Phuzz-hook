#!/usr/bin/env bash
set -euo pipefail
phase_dir=$(cd "$(dirname "$0")" && pwd)
run_id="phase12-final-$(date -u +%Y%m%dT%H%M%SZ)-$$"
echo "Phase 12 run ID: $run_id"
export PHASE11B_RUN_ID="$run_id" PHASE11B_LOCAL_USERNAME=phase12final PHASE11B_LOCAL_PASSWORD="local-$run_id" PHASE11B_DENIED_USERNAME=phase12finaldenied PHASE11B_DENIED_PASSWORD="denied-$run_id"
compose=(docker compose -p hookphuzz-phase12 -f "$phase_dir/docker-compose.yml")
cleanup(){ "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
"${compose[@]}" up -d
for _ in $(seq 1 30); do "${compose[@]}" exec -T web test -f /var/www/html/wp-settings.php && break; sleep 1; done
"${compose[@]}" exec -T web bash /phase12/scripts/setup.sh
"${compose[@]}" exec -T web python3 /phase12/scripts/run_fixture.py
python3 "$phase_dir/tests/test_phase12_schema.py"
"${compose[@]}" exec -T web php -l /var/www/html/wp-content/plugins/hookphuzz-phase12-fixture/hookphuzz-phase12.php
docker cp "$phase_dir/scripts/run_cf7_current.py" phase11b-cf7-web-1:/tmp/run_cf7_current.py
docker exec -e PHASE12_RUN_ID="$run_id" phase11b-cf7-web-1 python3 /tmp/run_cf7_current.py
for name in cf7-route-argument-capture.json cf7-parameter-resolution.json cf7-replay-result.json; do docker cp "phase11b-cf7-web-1:/tmp/phase12-cf7/$name" "$phase_dir/results/$name"; done
python3 "$phase_dir/scripts/check_gates.py" "$phase_dir/results" "$run_id"
