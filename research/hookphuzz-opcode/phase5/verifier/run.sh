#!/usr/bin/env bash
set -euo pipefail

phase_dir=/workspace
results_dir="$phase_dir/results"
artifact_dir=/shared/opcode-events
temp_dir="$(mktemp -d)"
trap 'rm -rf "$temp_dir"' EXIT

required_results=(environment.txt http-test-summary.txt concurrency-summary.txt stability-loop.txt event-cap-summary.txt semantic-diff.txt sample-events.json final-verdict.txt)
mkdir -p "$results_dir"
for result in "${required_results[@]}"; do rm -f "$results_dir/$result"; done

write_final() {
  local status="$1" detail="$2"
  cat > "$results_dir/final-verdict.txt" <<EOF
Status: $status

1. Status
$detail

2. Environment
See environment.txt.

3. Files created
environment.txt, http-test-summary.txt, concurrency-summary.txt, stability-loop.txt, event-cap-summary.txt, semantic-diff.txt, sample-events.json, final-verdict.txt.

4. Artifact schema
schema_version 1 with request_id, pid, method, redacted uri, event_count, dropped_event_count, and mapped event metadata only.

5. HTTP test table
See http-test-summary.txt.

6. Concurrency result
See concurrency-summary.txt.

7. Semantic comparison
See semantic-diff.txt.

8. Stability result
See stability-loop.txt.

9. Exact command executed
bash research/hookphuzz-opcode/phase5/run.sh

10. Known limitations
Only direct GET/POST/REQUEST/COOKIE opcode-slot provenance is covered. Invalid, missing, or duplicate request IDs intentionally create no artifact.

11. Deferred scope
Assignment/reference/argument/return/property/ArrayAccess provenance, WordPress, UOPZ, HookPhuzz integration, config generation, and replay remain deferred. This is not complete dynamic parameter discovery.
EOF
}

fail() {
  local test="$1" expected="$2" actual="$3" log_path="$4" hypothesis="$5"
  write_final PHASE_5_FAIL "Failing test: $test
Expected: $expected
Actual: $actual
Log path: $log_path
Hypothesis: $hypothesis"
  exit 1
}

http_request() {
  local service="$1" label="$2" request_id="$3" method="$4" path="$5" data="$6" cookie="$7"
  local header_file="$temp_dir/$label-$service.headers"
  local body_file="$temp_dir/$label-$service.body"
  local status_file="$temp_dir/$label-$service.status"
  local args=(-sS --max-time 10 -D "$header_file" -o "$body_file" -w '%{http_code}')
  if [[ "$request_id" != '-' ]]; then args+=(-H "X-Fuzzer-Covid: $request_id"); fi
  if [[ -n "$cookie" ]]; then args+=(-H "Cookie: $cookie"); fi
  if [[ "$method" != GET ]]; then args+=(-X "$method"); fi
  if [[ -n "$data" ]]; then args+=(--data "$data"); fi
  if ! curl "${args[@]}" "http://$service$path" > "$status_file"; then
    fail "$label HTTP" 'curl request succeeds' 'curl failed or timed out' "$temp_dir" 'Apache/PHP process crash or hang'
  fi
  HTTP_STATUS="$(<"$status_file")"
  HTTP_BODY="$body_file"
  HTTP_HEADERS="$header_file"
}

assert_response() {
  local label="$1" fixture="$2"
  [[ "$HTTP_STATUS" == 200 ]] || fail "$label status" 'HTTP 200' "HTTP $HTTP_STATUS" "$HTTP_HEADERS" 'fixture semantic regression'
  grep -qi '^Content-Type: application/json' "$HTTP_HEADERS" \
    || fail "$label Content-Type" 'application/json' 'header missing or changed' "$HTTP_HEADERS" 'unexpected response header change'
  grep -qi "^X-Phase5-Fixture: $fixture" "$HTTP_HEADERS" \
    || fail "$label fixture header" "$fixture" 'header missing or changed' "$HTTP_HEADERS" 'unexpected response header change'
}

wait_artifact() {
  local request_id="$1"
  local path="$artifact_dir/$request_id.json"
  local attempt
  for attempt in $(seq 1 50); do
    [[ -f "$path" ]] && { printf '%s' "$path"; return 0; }
    sleep 0.1
  done
  fail "$request_id artifact" 'artifact created' 'artifact missing' "/logs/enabled/apache-error.log" 'RSHUTDOWN flush, permissions, or request-ID capture failed'
}

check_artifact() {
  local artifact="$1" request_id="$2" method="$3" expected_events="$4" expected_dropped="$5"
  if ! php "$phase_dir/verifier/validate.php" "$artifact" "$request_id" "$method" "$expected_events" "$expected_dropped"; then
    fail "$request_id artifact validation" 'schema and expected mapped events' 'JSON/schema/event mismatch' "$artifact" 'opcode mapping, request lifecycle, or artifact serialization failed'
  fi
}

record_http() {
  printf '| %s | %s | PASS |\n' "$1" "$2" >> "$results_dir/http-test-summary.txt"
}

run_enabled() {
  local label="$1" request_id="$2" method="$3" path="$4" data="$5" cookie="$6" fixture="$7" expected_events="$8" expected_dropped="$9"
  http_request enabled "$label" "$request_id" "$method" "$path" "$data" "$cookie"
  assert_response "$label" "$fixture"
  local artifact
  artifact="$(wait_artifact "$request_id")"
  check_artifact "$artifact" "$request_id" "$method" "$expected_events" "$expected_dropped"
  record_http "$label" "${expected_events}"
}

log_size() { [[ -f "$1" ]] && wc -c < "$1" || printf '0'; }

slice_log() {
  local source="$1" offset="$2" target="$3"
  if [[ -f "$source" ]]; then tail -c +$((offset + 1)) "$source" > "$target"; else : > "$target"; fi
}

normalise_log() {
  sed -E -e 's/^\[[^]]+\] //' -e 's/\[pid [0-9]+(:tid [0-9]+)?\] //' "$1" \
    | grep -v 'hookphuzz_opcode_phase5: request artifact skipped: missing X-Fuzzer-Covid' || true
}

semantic_pair() {
  local label="$1" method="$2" path="$3" data="$4" cookie="$5" fixture="$6"
  http_request enabled "semantic-$label" "semantic-enabled-$label" "$method" "$path" "$data" "$cookie"
  assert_response "semantic enabled $label" "$fixture"
  local enabled_status="$HTTP_STATUS" enabled_body="$HTTP_BODY" enabled_headers="$HTTP_HEADERS"
  http_request disabled "semantic-$label" "semantic-disabled-$label" "$method" "$path" "$data" "$cookie"
  assert_response "semantic disabled $label" "$fixture"
  {
    printf '## %s\n' "$label"
    printf 'enabled status: %s\ndisabled status: %s\n' "$enabled_status" "$HTTP_STATUS"
  } >> "$results_dir/semantic-diff.txt"
  [[ "$enabled_status" == "$HTTP_STATUS" ]] || fail "semantic $label status" "$enabled_status" "$HTTP_STATUS" "$results_dir/semantic-diff.txt" 'extension changed HTTP status'
  cmp -s "$enabled_body" "$HTTP_BODY" || fail "semantic $label body" 'enabled and disabled bodies match' 'response body differs' "$results_dir/semantic-diff.txt" 'extension changed PHP semantics'
  for header in Content-Type X-Phase5-Fixture X-Powered-By; do
    local enabled_value disabled_value
    enabled_value="$(grep -i "^$header:" "$enabled_headers" | tr -d '\r')"
    disabled_value="$(grep -i "^$header:" "$HTTP_HEADERS" | tr -d '\r')"
    [[ "$enabled_value" == "$disabled_value" ]] || fail "semantic $label $header" "$enabled_value" "$disabled_value" "$results_dir/semantic-diff.txt" 'extension changed response headers'
  done
  printf 'response and important headers: PASS\n\n' >> "$results_dir/semantic-diff.txt"
}

extension_status="$(curl -fsS --max-time 10 http://enabled/extension.php)"
[[ "$extension_status" == *'"hookphuzz_opcode_phase5":true'* ]] \
  || fail 'Apache extension load' 'enabled extension under Apache/PHP 8.2.10' "$extension_status" "$results_dir/environment.txt" 'extension ini or build output is unavailable to mod_php'
disabled_status="$(curl -fsS --max-time 10 http://disabled/extension.php)"
[[ "$disabled_status" == *'"hookphuzz_opcode_phase5":false'* ]] \
  || fail 'disabled baseline' 'extension disabled baseline' "$disabled_status" "$results_dir/environment.txt" 'disabled image accidentally loads the extension'
cat > "$results_dir/environment.txt" <<EOF
Image: php:8.2.10-apache
Runtime: Apache + mod_php in Docker
JIT: disabled (opcache.jit=0)
OPcache: disabled (opcache.enable=0)
Enabled Apache extension endpoint: $extension_status
Disabled baseline endpoint: $disabled_status
Artifact directory: /shared/opcode-events
EOF
printf '| Test | Expected events | Status |\n| --- | --- | --- |\n' > "$results_dir/http-test-summary.txt"

run_enabled 'GET literal' 'get-literal' GET '/get-literal.php?get_literal=visible' '' '' 'get-literal' '[["GET",["get_literal"],"read","phase5_get_literal"]]' 0
run_enabled 'GET runtime key' 'get-runtime' GET '/get-runtime.php?get_runtime=visible' '' '' 'get-runtime' '[["GET",["get_runtime"],"read","phase5_get_runtime"]]' 0
run_enabled 'POST literal' 'post-literal' POST '/post-literal.php' 'post_literal=visible' '' 'post-literal' '[["POST",["post_literal"],"read","phase5_post_literal"]]' 0
run_enabled 'POST runtime key' 'post-runtime' POST '/post-runtime.php' 'post_runtime=visible' '' 'post-runtime' '[["POST",["post_runtime"],"read","phase5_post_runtime"]]' 0
run_enabled 'REQUEST attribution' 'request' POST '/request.php' 'request_key=visible' '' 'request' '[["REQUEST",["request_key"],"read","phase5_request"]]' 0
run_enabled 'COOKIE attribution' 'cookie' GET '/cookie.php' '' 'cookie_key=visible' 'cookie' '[["COOKIE",["cookie_key"],"read","phase5_cookie"]]' 0
run_enabled 'nested POST' 'nested' POST '/nested.php' 'user[email]=visible' '' 'nested' '[["POST",["user"],"read","phase5_nested"],["POST",["user","email"],"read","phase5_nested"]]' 0
run_enabled 'isset' 'isset' GET '/isset.php?isset_key=visible' '' '' 'isset' '[["GET",["isset_key"],"isset","phase5_isset"]]' 0
run_enabled 'empty' 'empty' POST '/empty.php' 'empty_key=visible' '' 'empty' '[["POST",["empty_key"],"empty","phase5_empty"]]' 0
run_enabled 'null coalescing' 'coalesce' POST '/coalesce.php' 'coalesce_key=visible' '' 'coalesce' '[["REQUEST",["coalesce_key"],"silent_read","phase5_coalesce"]]' 0
run_enabled 'missing keys' 'missing' POST '/missing.php' '' '' 'missing' '[["GET",["missing_get"],"read","phase5_missing"],["POST",["missing_post"],"read","phase5_missing"]]' 0
run_enabled 'integer key' 'integer' GET '/integer.php?7=visible' '' '' 'integer' '[["GET",[7],"read","phase5_integer"]]' 0
run_enabled 'object-key' 'object-key' GET '/object-key.php' '' '' 'object-key' '[]' 0
grep -Fq '"to_string_calls":0' "$temp_dir/object-key-enabled.body" \
  || fail 'object key semantics' '__toString called zero times' 'object-key response differs' "$temp_dir/object-key-enabled.body" 'extension coerced an object key'
run_enabled 'negative controls' 'negative' GET '/negative.php' '' '' 'negative' '[]' 0

http_request enabled 'missing-header' '-' GET '/get-literal.php?get_literal=visible' '' ''
assert_response 'missing header' 'get-literal'
sleep 0.2
[[ ! -f "$artifact_dir/.json" ]] || fail 'missing request ID' 'no artifact' 'unexpected artifact' "$artifact_dir" 'request ID fallback was enabled'
record_http 'missing request ID' 'no artifact'

http_request enabled 'invalid-header' 'bad/id' GET '/get-literal.php?get_literal=visible' '' ''
assert_response 'invalid header' 'get-literal'
sleep 0.2
[[ ! -f "$artifact_dir/bad/id.json" ]] || fail 'invalid request ID' 'no artifact' 'unsafe artifact path exists' "$artifact_dir" 'request ID validation failed'
record_http 'invalid request ID' 'no artifact'

run_enabled 'duplicate first request' 'duplicate' GET '/get-literal.php?get_literal=visible' '' '' 'get-literal' '[["GET",["get_literal"],"read","phase5_get_literal"]]' 0
http_request enabled 'duplicate-second' 'duplicate' GET '/get-runtime.php?get_runtime=visible' '' ''
assert_response 'duplicate second request' 'get-runtime'
sleep 0.2
check_artifact "$artifact_dir/duplicate.json" duplicate GET '[["GET",["get_literal"],"read","phase5_get_literal"]]' 0
record_http 'duplicate request ID' 'original artifact preserved'

for index in $(seq -w 0 19); do
  key="parallel_key_$index"
  id="parallel-$index"
  curl -sS --max-time 10 -H "X-Fuzzer-Covid: $id" "http://enabled/parallel.php/$key?$key=visible" > "$temp_dir/$id.body" &
done
wait
parallel_count="$(find "$artifact_dir" -maxdepth 1 -name 'parallel-*.json' -type f | wc -l)"
[[ "$parallel_count" == 20 ]] || fail 'parallel artifact count' '20 artifacts' "$parallel_count artifacts" "$artifact_dir" 'concurrency lost or overwrote an artifact'
for index in $(seq -w 0 19); do
  key="parallel_key_$index"
  id="parallel-$index"
  artifact="$(wait_artifact "$id")"
  check_artifact "$artifact" "$id" GET "[[\"GET\",[\"$key\"],\"read\",\"phase5_parallel\"]]" 0
done
cat > "$results_dir/concurrency-summary.txt" <<EOF
Requests: 20
Unique request IDs: parallel-00 through parallel-19
Artifacts found: $parallel_count
Cross-request events: 0
Malformed JSON: 0
Overwrite detected: 0
Status: PASS
EOF

stability_failures=0
for index in $(seq -w 0 399); do
  id="stability-$index"
  http_request enabled "stability-$index" "$id" GET '/get-literal.php?get_literal=visible' '' ''
  if [[ "$HTTP_STATUS" != 200 ]]; then stability_failures=$((stability_failures + 1)); continue; fi
  artifact="$(wait_artifact "$id")"
  if ! php "$phase_dir/verifier/validate.php" "$artifact" "$id" GET '[["GET",["get_literal"],"read","phase5_get_literal"]]' 0; then
    stability_failures=$((stability_failures + 1))
  fi
done
cat > "$results_dir/stability-loop.txt" <<EOF
Sequential requests: 400
Failures: $stability_failures
Apache/PHP crashes observed: 0
Hangs observed: 0
Malformed artifacts: 0
State carry-over observed: 0
Status: $([[ "$stability_failures" == 0 ]] && echo PASS || echo FAIL)
EOF
[[ "$stability_failures" == 0 ]] || fail '400 sequential requests' '400 valid independent artifacts' "$stability_failures failures" "$results_dir/stability-loop.txt" 'request cleanup or Apache worker stability failed'

http_request enabled 'event-cap' 'event-cap' GET '/event-cap.php?event_cap=visible' '' ''
assert_response 'event cap' 'event-cap'
cap_artifact="$(wait_artifact event-cap)"
php "$phase_dir/verifier/validate-cap.php" "$cap_artifact" \
  || fail 'event cap' '4096 stored events and 1 dropped event' 'cap artifact mismatch' "$cap_artifact" 'event cap or drop accounting failed'
run_enabled 'post-cap reset' 'post-cap-reset' GET '/get-literal.php?get_literal=visible' '' '' 'get-literal' '[["GET",["get_literal"],"read","phase5_get_literal"]]' 0
cat > "$results_dir/event-cap-summary.txt" <<EOF
Request: event-cap
Stored events: 4096
Dropped events: 1
Follow-up request event_count: 1
Follow-up request dropped_event_count: 0
Apache/PHP continued serving: PASS
Status: PASS
EOF

enabled_apache_before="$(log_size /logs/enabled/apache-error.log)"
disabled_apache_before="$(log_size /logs/disabled/apache-error.log)"
enabled_php_before="$(log_size /logs/enabled/php-error.log)"
disabled_php_before="$(log_size /logs/disabled/php-error.log)"
: > "$results_dir/semantic-diff.txt"
semantic_pair 'get-literal' GET '/get-literal.php?get_literal=visible' '' '' 'get-literal'
semantic_pair 'get-runtime' GET '/get-runtime.php?get_runtime=visible' '' '' 'get-runtime'
semantic_pair 'post-literal' POST '/post-literal.php' 'post_literal=visible' '' 'post-literal'
semantic_pair 'post-runtime' POST '/post-runtime.php' 'post_runtime=visible' '' 'post-runtime'
semantic_pair 'request' POST '/request.php' 'request_key=visible' '' 'request'
semantic_pair 'cookie' GET '/cookie.php' '' 'cookie_key=visible' 'cookie'
semantic_pair 'nested' POST '/nested.php' 'user[email]=visible' '' 'nested'
semantic_pair 'isset' GET '/isset.php?isset_key=visible' '' '' 'isset'
semantic_pair 'empty' POST '/empty.php' 'empty_key=visible' '' 'empty'
semantic_pair 'coalesce' POST '/coalesce.php' 'coalesce_key=visible' '' 'coalesce'
semantic_pair 'missing' POST '/missing.php' '' '' 'missing'
semantic_pair 'integer' GET '/integer.php?7=visible' '' '' 'integer'
semantic_pair 'object-key' GET '/object-key.php' '' '' 'object-key'
semantic_pair 'negative' GET '/negative.php' '' '' 'negative'

slice_log /logs/enabled/apache-error.log "$enabled_apache_before" "$temp_dir/enabled-apache.log"
slice_log /logs/disabled/apache-error.log "$disabled_apache_before" "$temp_dir/disabled-apache.log"
slice_log /logs/enabled/php-error.log "$enabled_php_before" "$temp_dir/enabled-php.log"
slice_log /logs/disabled/php-error.log "$disabled_php_before" "$temp_dir/disabled-php.log"
normalise_log "$temp_dir/enabled-apache.log" > "$temp_dir/enabled-apache.normalized"
normalise_log "$temp_dir/disabled-apache.log" > "$temp_dir/disabled-apache.normalized"
normalise_log "$temp_dir/enabled-php.log" > "$temp_dir/enabled-php.normalized"
normalise_log "$temp_dir/disabled-php.log" > "$temp_dir/disabled-php.normalized"
{
  printf '## Apache error log\n\n'
  diff -u "$temp_dir/disabled-apache.normalized" "$temp_dir/enabled-apache.normalized" || true
  printf '\n## PHP error log\n\n'
  diff -u "$temp_dir/disabled-php.normalized" "$temp_dir/enabled-php.normalized" || true
} >> "$results_dir/semantic-diff.txt"
cmp -s "$temp_dir/enabled-apache.normalized" "$temp_dir/disabled-apache.normalized" \
  || fail 'semantic Apache error log' 'normalized logs match' 'normalized logs differ' "$results_dir/semantic-diff.txt" 'extension changed warning/error behavior'
cmp -s "$temp_dir/enabled-php.normalized" "$temp_dir/disabled-php.normalized" \
  || fail 'semantic PHP error log' 'normalized logs match' 'normalized logs differ' "$results_dir/semantic-diff.txt" 'extension changed PHP stderr behavior'
printf '\nOverall semantic result: PASS\n' >> "$results_dir/semantic-diff.txt"

cp "$artifact_dir/nested.json" "$results_dir/sample-events.json"
write_final PHASE_5_PASS 'All HTTP attribution, artifact isolation, concurrency, event-cap, semantic, and stability gates passed.'
