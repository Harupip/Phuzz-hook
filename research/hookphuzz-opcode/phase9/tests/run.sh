#!/usr/bin/env bash
set -euo pipefail
root=/workspace results=$root/results artifacts=/shared/opcode-events registry=/shared/phase9-callback-registry.json
run_id=${PHASE9_RUN_ID:?PHASE9_RUN_ID is required}
mkdir -p "$results/artifacts" "$results/raw"
printf '%s\n' "$run_id" > "$results/run-id.txt"
fail(){ echo "PHASE_9_FAIL: $*" >&2; exit 1; }
wait_file(){ local p=$1; for _ in $(seq 1 200); do [[ -f $p ]] && { echo "$p"; return; }; sleep .1; done; fail "artifact_missing:$p"; }
send(){ local id=$1 action=$2 auth=${3:-0}; local jar=${4:-}; local args=(-sS --max-time 20 -D "$results/raw/$id.headers" -o "$results/raw/$id.body" -w '%{http_code}' -X POST -H "X-Fuzzer-Covid: $id" -H "X-Phase9-Run-ID: $run_id" -b 'fixture_cookie=phase9-cookie'); [[ $auth == 1 ]] && args+=(-b "$jar"); curl "${args[@]}" --data-urlencode 'literal_post=discovery' --data-urlencode 'shared_name=discovery' --data-urlencode 'runtime_selector=runtime_key' --data-urlencode 'runtime_key=discovery' --data-urlencode 'profile[email]=discovery@example.test' --data-urlencode 'empty_key=not-empty' --data-urlencode 'optional_key=optional' --data-urlencode 'helper_level_1=one' --data-urlencode 'helper_level_2[value]=two' --data-urlencode 'method_direct=method' --data-urlencode 'class_a=a' --data-urlencode 'class_b=b' --data-urlencode 'auth_value=auth' --data-urlencode 'duplicate_key=PHASE9_DISCOVERY_DUPLICATE' "http://enabled/wp-admin/admin-ajax.php?action=$action&literal_get=discovery&shared_name=discovery&isset_key=1" > "$results/raw/$id.status"; [[ $(<"$results/raw/$id.status") == 200 ]] || fail "http:$id"; }
rm -f "$registry"
send "$run_id-registry-bootstrap" hookphuzz_phase9_function
wait_file "$registry" >/dev/null
cp "$registry" "$results/discovered-callback-registry.json"
jar=$(mktemp)
curl -sS --max-time 20 -c "$jar" -d 'log=phase9admin&pwd=phase9admin&wp-submit=Log+In&redirect_to=/wp-admin/' http://enabled/wp-login.php >/dev/null
for pair in 'function:hookphuzz_phase9_function:0' 'method:hookphuzz_phase9_method:0' 'class-a:hookphuzz_phase9_class_a:0' 'class-b:hookphuzz_phase9_class_b:0' 'authenticated:hookphuzz_phase9_authenticated:1' 'duplicate:hookphuzz_phase9_duplicate_probe:0'; do
  IFS=: read -r label action auth <<<"$pair"
  id="$run_id-discovery-$label"
  send "$id" "$action" "$auth" "$jar"
  cp "$(wait_file "$artifacts/$id.json")" "$results/artifacts/discovery-$label.json"
done
bash "$root/tests/source-resolution.sh" "$results" "$artifacts" "$run_id" || fail source_resolution
php "$root/tests/bootstrap-noise.php" "$artifacts/$run_id-direct-get.json" "$results/bootstrap-noise-isolation.json" "$run_id" || fail bootstrap_noise
php "$root/generator/generate_configs.php" --callback-registry "$results/discovered-callback-registry.json" --discovery-artifact "$results/artifacts/discovery-function.json" --discovery-artifact "$results/artifacts/discovery-method.json" --discovery-artifact "$results/artifacts/discovery-class-a.json" --discovery-artifact "$results/artifacts/discovery-class-b.json" --discovery-artifact "$results/artifacts/discovery-authenticated.json" --discovery-artifact "$results/artifacts/discovery-duplicate.json" --source-resolution "$results/source-resolution.json" --output "$results/generated-configs.json" --phuzz-output "$results/generated-phuzz-configs.json" > "$results/discovery-artifacts-summary.json" || fail generator
php "$root/tests/duplicate-helper.php" "$results/artifacts/discovery-duplicate.json" "$results/generated-configs.json" "$results/duplicate-helper-summary.json" "$run_id" || fail duplicate_helper
php "$root/replay/replay.php" --configs "$results/generated-configs.json" --artifact-dir "$artifacts" --base http://enabled --cookie-jar "$jar" --run-id "$run_id" --output "$results/replay-validation-summary.json" || fail replay
bash "$root/tests/load-suite.sh" concurrency "$results" "$artifacts" 20 "$run_id" || fail concurrency
bash "$root/tests/load-suite.sh" stability "$results" "$artifacts" 300 "$run_id" || fail stability
rm -f "$jar"
if ! php "$root/tests/aggregate.php" "$results" "$run_id"; then
  cat "$results/phase9-validation-summary.json" >&2 || true
  fail aggregate_validation
fi
printf 'PHASE_9_PASS\n' > "$results/final-verdict.txt"
printf 'PHASE_9_PASS\n'
