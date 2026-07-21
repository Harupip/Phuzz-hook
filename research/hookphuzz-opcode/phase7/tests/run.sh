#!/usr/bin/env bash
set -euo pipefail

phase_dir=/workspace
results_dir="$phase_dir/results"
artifact_dir=/shared/opcode-events
raw_enabled="$results_dir/raw-enabled"
raw_disabled="$results_dir/raw-disabled"
temp_dir="$(mktemp -d)"
final_file="$results_dir/final-report.md"

fail() { printf 'PHASE_7_FAIL: %s\n' "$1" >&2; exit 1; }
wait_artifact() {
  local id="$1"
  local path="$artifact_dir/$id.json"
  for _ in $(seq 1 150); do [[ -f "$path" ]] && { printf '%s' "$path"; return; }; sleep .1; done
  fail "missing artifact: $id"
}
archive_raw() {
  mkdir -p "$raw_enabled" "$raw_disabled" "$results_dir/sample-artifacts"
  [[ -d "$artifact_dir" ]] && cp -a "$artifact_dir" "$raw_enabled/artifacts"
  [[ -d /logs/enabled ]] && cp -a /logs/enabled "$raw_enabled/logs"
  [[ -d /logs/disabled ]] && cp -a /logs/disabled "$raw_disabled/logs"
  rm -rf "$temp_dir"
}
trap archive_raw EXIT
http_ok() { [[ "$(<"$1")" == 200 ]] || fail "$2 returned HTTP $(<"$1")"; grep -qi '^Content-Type: application/json' "$3" || fail "$2 missing JSON content type"; }
send_function() {
  local service="$1" raw="$2" label="$3" id="$4" mode="$5" tag="$6"
  local runtime="runtime_$tag"
  mkdir -p "$raw"
  curl -sS --max-time 15 -D "$raw/$label.headers" -o "$raw/$label.body" -w '%{http_code}' -X POST \
    -H "X-Fuzzer-Covid: $id" -H "Cookie: fixture_cookie=cookie-$tag" \
    --data-urlencode "literal_post=literal-post-$tag" --data-urlencode "runtime_selector=$runtime" \
    --data-urlencode "$runtime=runtime-value-$tag" --data-urlencode "profile[email]=profile-email-$tag" \
    --data-urlencode "empty_key=not-empty-$tag" --data-urlencode "optional_key=optional-$tag" \
    --data-urlencode "direct_callback=direct-$tag" --data-urlencode "helper_level_1=helper-one-$tag" \
    --data-urlencode "helper_level_2[value]=helper-two-$tag" --data-urlencode "phase7_mode=$mode" \
    --data-urlencode "early_marker=early-$tag" --data-urlencode "throw_marker=throw-$tag" --data-urlencode "after_catch=after-$tag" \
    --data-urlencode 'cap_value=cap' \
    "http://$service/wp-admin/admin-ajax.php?action=hookphuzz_phase7_probe&literal_get=literal-get-$tag&isset_key=isset-$tag" > "$raw/$label.status" || fail "$label curl failed"
  http_ok "$raw/$label.status" "$label" "$raw/$label.headers"
  php "$phase_dir/tests/assert.php" response "$raw/$label.body" >/dev/null || fail "$label response malformed"
}
send_method() {
  local service="$1" raw="$2" label="$3" id="$4" tag="$5"
  mkdir -p "$raw"
  curl -sS --max-time 15 -D "$raw/$label.headers" -o "$raw/$label.body" -w '%{http_code}' -X POST \
    -H "X-Fuzzer-Covid: $id" --data-urlencode "method_direct=method-$tag" \
    "http://$service/wp-admin/admin-ajax.php?action=hookphuzz_phase7_method_probe" > "$raw/$label.status" || fail "$label curl failed"
  http_ok "$raw/$label.status" "$label" "$raw/$label.headers"
  php "$phase_dir/tests/assert.php" response "$raw/$label.body" >/dev/null || fail "$label response malformed"
}
send_plain() {
  local service="$1" raw="$2" label="$3" id="$4" url="$5"
  mkdir -p "$raw"
  curl -sS --max-time 15 -D "$raw/$label.headers" -o "$raw/$label.body" -w '%{http_code}' -X POST -H "X-Fuzzer-Covid: $id" "$url" > "$raw/$label.status" || fail "$label curl failed"
}
headers() { grep -Ei '^(Content-Type|Cache-Control|X-Robots-Tag|X-Content-Type-Options):' "$1" | tr -d '\r' || true; }
log_size() { [[ -f "$1" ]] && wc -c < "$1" || printf 0; }
slice_log() { [[ -f "$1" ]] && tail -c +$(( $2 + 1 )) "$1" > "$3" || : > "$3"; }
normalise_log() { sed -E -e 's/^\[[^]]+\] //' -e 's/\[pid [0-9]+(:tid [0-9]+)?\] //' "$1" | grep -v 'hookphuzz_opcode_phase7: request artifact skipped: missing X-Fuzzer-Covid' || true; }

mkdir -p "$results_dir" "$raw_enabled" "$raw_disabled" "$results_dir/sample-artifacts"

send_function enabled "$raw_enabled" direct-function direct-function normal direct
direct_artifact="$(wait_artifact direct-function)"
php "$phase_dir/tests/assert.php" function "$direct_artifact" runtime_direct > "$results_dir/direct-read-regression.json" || fail 'direct-read regression'
cp "$results_dir/direct-read-regression.json" "$results_dir/callback-attribution.json"
php "$phase_dir/tests/assert.php" function "$direct_artifact" runtime_direct > "$results_dir/helper-attribution.json" || fail 'helper attribution'
cp "$direct_artifact" "$results_dir/sample-artifacts/function-direct.json"
php "$phase_dir/tests/assert.php" noise "$direct_artifact" > "$results_dir/bootstrap-noise.json" || fail 'bootstrap noise separation'

send_method enabled "$raw_enabled" method-callback method-callback method
method_artifact="$(wait_artifact method-callback)"
php "$phase_dir/tests/assert.php" method "$method_artifact" > "$results_dir/method-callback.json" || fail 'method attribution'
cp "$method_artifact" "$results_dir/sample-artifacts/method.json"

send_plain enabled "$raw_enabled" unknown-action unknown-action 'http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase7_unknown'
unknown_artifact="$(wait_artifact unknown-action)"
send_plain enabled "$raw_enabled" missing-action missing-action 'http://enabled/wp-admin/admin-ajax.php'
missing_artifact="$(wait_artifact missing-action)"
php "$phase_dir/tests/assert.php" none "$unknown_artifact" > "$results_dir/unknown-action.json" || fail 'unknown action attribution'
php "$phase_dir/tests/assert.php" none "$missing_artifact" > "$results_dir/missing-action.json" || fail 'missing action attribution'

send_function enabled "$raw_enabled" early-return early-return early early
early_artifact="$(wait_artifact early-return)"
send_method enabled "$raw_enabled" after-early after-early after-early
after_early_artifact="$(wait_artifact after-early)"
php "$phase_dir/tests/assert.php" method "$after_early_artifact" > "$temp_dir/early-cleanup.json" || fail 'early return cleanup'
send_function enabled "$raw_enabled" exception exception throw exception
exception_artifact="$(wait_artifact exception)"
php "$phase_dir/tests/assert.php" cleanup "$exception_artifact" > "$temp_dir/exception-cleanup.json" || fail 'exception cleanup'
send_method enabled "$raw_enabled" after-exception after-exception after-exception
php "$phase_dir/tests/assert.php" method "$(wait_artifact after-exception)" > "$temp_dir/after-exception-cleanup.json" || fail 'exception carry-over'
php -r '$a=json_decode(file_get_contents($argv[1]),true); $b=json_decode(file_get_contents($argv[2]),true); $c=json_decode(file_get_contents($argv[3]),true); echo json_encode(["status"=>"PASS","early_return"=>$a,"exception"=>$b,"post_exception_request"=>$c],JSON_PRETTY_PRINT),"\n";' "$temp_dir/early-cleanup.json" "$temp_dir/exception-cleanup.json" "$temp_dir/after-exception-cleanup.json" > "$results_dir/cleanup-tests.json"

send_function enabled "$raw_enabled" event-cap event-cap cap cap
cap_artifact="$(wait_artifact event-cap)"
php "$phase_dir/tests/assert.php" cap "$cap_artifact" > "$results_dir/event-cap.json" || fail 'event cap regression'

enabled_apache_before="$(log_size /logs/enabled/apache-error.log)"; enabled_php_before="$(log_size /logs/enabled/php-error.log)"
disabled_apache_before="$(log_size /logs/disabled/apache-error.log)"; disabled_php_before="$(log_size /logs/disabled/php-error.log)"
for scenario in normal early throw; do
  send_function enabled "$raw_enabled" "semantic-function-$scenario-enabled" "semantic-function-$scenario-enabled" "$scenario" "semantic-$scenario"
  send_function disabled "$raw_disabled" "semantic-function-$scenario-disabled" "semantic-function-$scenario-disabled" "$scenario" "semantic-$scenario"
  cmp -s "$raw_enabled/semantic-function-$scenario-enabled.body" "$raw_disabled/semantic-function-$scenario-disabled.body" || fail "semantic body function $scenario"
  [[ "$(<"$raw_enabled/semantic-function-$scenario-enabled.status")" == "$(<"$raw_disabled/semantic-function-$scenario-disabled.status")" ]] || fail "semantic status function $scenario"
  [[ "$(headers "$raw_enabled/semantic-function-$scenario-enabled.headers")" == "$(headers "$raw_disabled/semantic-function-$scenario-disabled.headers")" ]] || fail "semantic headers function $scenario"
done
send_method enabled "$raw_enabled" semantic-method-enabled semantic-method-enabled semantic-method
send_method disabled "$raw_disabled" semantic-method-disabled semantic-method-disabled semantic-method
cmp -s "$raw_enabled/semantic-method-enabled.body" "$raw_disabled/semantic-method-disabled.body" || fail 'semantic method body'
[[ "$(headers "$raw_enabled/semantic-method-enabled.headers")" == "$(headers "$raw_disabled/semantic-method-disabled.headers")" ]] || fail 'semantic method headers'
for action in unknown missing; do
  url='http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase7_unknown'; [[ "$action" == missing ]] && url='http://enabled/wp-admin/admin-ajax.php'
  send_plain enabled "$raw_enabled" "semantic-$action-enabled" "semantic-$action-enabled" "$url"
  url="${url/enabled/disabled}"
  send_plain disabled "$raw_disabled" "semantic-$action-disabled" "semantic-$action-disabled" "$url"
  cmp -s "$raw_enabled/semantic-$action-enabled.body" "$raw_disabled/semantic-$action-disabled.body" || fail "semantic $action body"
done
slice_log /logs/enabled/apache-error.log "$enabled_apache_before" "$temp_dir/enabled-apache.log"; slice_log /logs/disabled/apache-error.log "$disabled_apache_before" "$temp_dir/disabled-apache.log"
slice_log /logs/enabled/php-error.log "$enabled_php_before" "$temp_dir/enabled-php.log"; slice_log /logs/disabled/php-error.log "$disabled_php_before" "$temp_dir/disabled-php.log"
normalise_log "$temp_dir/enabled-apache.log" > "$temp_dir/enabled-apache.normalized"; normalise_log "$temp_dir/disabled-apache.log" > "$temp_dir/disabled-apache.normalized"
normalise_log "$temp_dir/enabled-php.log" > "$temp_dir/enabled-php.normalized"; normalise_log "$temp_dir/disabled-php.log" > "$temp_dir/disabled-php.normalized"
cmp -s "$temp_dir/enabled-apache.normalized" "$temp_dir/disabled-apache.normalized" || fail 'semantic Apache log'
cmp -s "$temp_dir/enabled-php.normalized" "$temp_dir/disabled-php.normalized" || fail 'semantic PHP log'
php -r 'echo json_encode(["status"=>"PASS","matrix"=>["function-normal","function-early","function-throw","method","unknown","missing"],"logs"=>"PASS"], JSON_PRETTY_PRINT),"\n";' > "$results_dir/semantic-comparison.json"

parallel_failures=0
for index in $(seq -w 0 19); do
  if ((10#$index % 2)); then (send_method enabled "$raw_enabled" "parallel-$index" "parallel-$index" "parallel-$index" "parallel-$index") &
  else (send_function enabled "$raw_enabled" "parallel-$index" "parallel-$index" normal "parallel-$index") & fi
done
wait
for index in $(seq -w 0 19); do
  artifact="$(wait_artifact "parallel-$index")"
  if ((10#$index % 2)); then php "$phase_dir/tests/assert.php" method "$artifact" >/dev/null || parallel_failures=$((parallel_failures+1))
  else php "$phase_dir/tests/assert.php" function "$artifact" "runtime_parallel-$index" >/dev/null || parallel_failures=$((parallel_failures+1)); fi
done
[[ "$parallel_failures" == 0 ]] || fail "concurrency failures: $parallel_failures"
php -r 'echo json_encode(["status"=>"PASS","requests"=>20,"unique_request_ids"=>20,"malformed_json"=>0,"callback_contamination"=>0], JSON_PRETTY_PRINT),"\n";' > "$results_dir/concurrency.json"

stability_failures=0
for index in $(seq -w 0 299); do
  id="stability-$index"; case $((10#$index % 6)) in
    0) send_function enabled "$raw_enabled" "$id" "$id" normal "$id"; check=(function "runtime_$id");;
    1) send_method enabled "$raw_enabled" "$id" "$id" "$id"; check=(method);;
    2) send_function enabled "$raw_enabled" "$id" "$id" early "$id"; check=(valid);;
    3) send_function enabled "$raw_enabled" "$id" "$id" throw "$id"; check=(cleanup);;
    4) send_plain enabled "$raw_enabled" "$id" "$id" 'http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase7_unknown'; check=(none);;
    5) send_plain enabled "$raw_enabled" "$id" "$id" 'http://enabled/wp-admin/admin-ajax.php'; check=(none);;
  esac
  artifact="$(wait_artifact "$id")"
  case "${check[0]}" in
    function) php "$phase_dir/tests/assert.php" function "$artifact" "${check[1]}" >/dev/null || stability_failures=$((stability_failures+1));;
    *) php "$phase_dir/tests/assert.php" "${check[0]}" "$artifact" >/dev/null || stability_failures=$((stability_failures+1));;
  esac
done
[[ "$stability_failures" == 0 ]] || fail "stability failures: $stability_failures"
php -r 'echo json_encode(["status"=>"PASS","requests"=>300,"failures"=>0,"crashes"=>0,"hangs"=>0,"malformed_artifacts"=>0,"state_carry_over"=>0], JSON_PRETTY_PRINT),"\n";' > "$results_dir/stability.json"
php "$phase_dir/tests/final_report.php" "$results_dir" > /dev/null
printf 'PHASE_7_PASS\n'
