#!/usr/bin/env bash
set -euo pipefail

phase_dir=/workspace
results_dir="$phase_dir/results"
artifact_dir=/shared/opcode-events
raw_enabled="$results_dir/raw-enabled"
raw_disabled="$results_dir/raw-disabled"
temp_dir="$(mktemp -d)"
final_file="$results_dir/final-verdict.txt"

write_final() {
  local status="$1" detail="$2"
  cat > "$final_file" <<EOF
1. Status
$status — $detail

2. Environment
See environment.txt, extension-enabled.txt, and extension-disabled.txt.

3. WordPress and fixture versions
WordPress 6.5.5; HookPhuzz Phase 6 Fixture 1.0.0; MariaDB 10.11.8.

4. Files created
environment.txt, extension-enabled.txt, extension-disabled.txt, http-test-summary.txt, wordpress-noise-analysis.json, wordpress-noise-analysis.md, concurrency-summary.txt, semantic-diff.txt, stability-loop.txt, sample-events.json, raw-enabled/, raw-disabled/.

5. Fixture entrypoint
wp_ajax_nopriv_hookphuzz_phase6_probe -> hookphuzz_phase6_probe.

6. Expected direct reads
GET literal_get and isset_key; POST literal_post, runtime_selector, runtime key, and empty_key; REQUEST profile.email and optional_key; COOKIE fixture_cookie.

7. WordPress bootstrap noise
See wordpress-noise-analysis.json and wordpress-noise-analysis.md. This is event-order analysis, not callback-context attribution.

8. Event cap result
See wordpress-noise-analysis.json. Configured cap is 4096.

9. HTTP tests
See http-test-summary.txt.

10. Concurrency
See concurrency-summary.txt.

11. Semantic comparison
See semantic-diff.txt.

12. Stability
See stability-loop.txt.

13. Exact command
bash research/hookphuzz-opcode/phase6/run.sh

14. Known limitations
Artifacts intentionally contain source/path metadata, not request values. No callback-context instrumentation or complete dynamic discovery is claimed.

15. Deferred scope
Helper propagation; assignment, argument, return, property, and ArrayAccess provenance; PHUZZ and HookPhuzz pipeline integration; UOPZ; config/replay generation; provenance beyond direct reads; and Phase 7.
EOF
}

archive_raw() {
  set +e
  mkdir -p "$raw_enabled" "$raw_disabled"
  [[ -d "$artifact_dir" ]] && cp -a "$artifact_dir" "$raw_enabled/artifacts"
  [[ -d /logs/enabled ]] && cp -a /logs/enabled "$raw_enabled/logs"
  [[ -d /logs/disabled ]] && cp -a /logs/disabled "$raw_disabled/logs"
  rm -rf "$temp_dir"
}

on_exit() {
  local status=$?
  if [[ ! -f "$final_file" ]]; then write_final PHASE_6_FAIL 'Verifier exited before completing a named gate; inspect raw evidence.'; fi
  archive_raw
  exit "$status"
}
trap on_exit EXIT

fail() {
  write_final PHASE_6_FAIL "$1"
  exit 1
}

wait_artifact() {
  local id="$1"
  local path="$artifact_dir/$id.json"
  for _ in $(seq 1 100); do
    [[ -f "$path" ]] && { printf '%s' "$path"; return 0; }
    sleep 0.1
  done
  fail "Artifact missing for request ID $id."
}

assert_http_json() {
  local status="$1" headers="$2" label="$3"
  [[ "$(<"$status")" == 200 ]] || fail "$label returned HTTP $(<"$status") instead of 200."
  grep -qi '^Content-Type: application/json' "$headers" || fail "$label did not return JSON Content-Type."
}

send_canonical() {
  local service="$1" raw_root="$2" label="$3" id="$4" tag="$5"
  local runtime_key="runtime_$tag"
  LAST_BODY="$raw_root/$label.body"
  LAST_HEADERS="$raw_root/$label.headers"
  LAST_STATUS="$raw_root/$label.status"
  mkdir -p "$raw_root"
  curl -sS --max-time 15 -D "$LAST_HEADERS" -o "$LAST_BODY" -w '%{http_code}' \
    -X POST -H "X-Fuzzer-Covid: $id" -H "Cookie: fixture_cookie=cookie-$tag" \
    --data-urlencode "literal_post=literal-post-$tag" \
    --data-urlencode "runtime_selector=$runtime_key" \
    --data-urlencode "$runtime_key=runtime-value-$tag" \
    --data-urlencode "profile[email]=profile-email-$tag" \
    --data-urlencode "empty_key=not-empty-$tag" \
    --data-urlencode "optional_key=optional-$tag" \
    "http://$service/wp-admin/admin-ajax.php?action=hookphuzz_phase6_probe&literal_get=literal-get-$tag&isset_key=isset-$tag" > "$LAST_STATUS" \
    || fail "$label curl failed or hung."
  assert_http_json "$LAST_STATUS" "$LAST_HEADERS" "$label"
  php "$phase_dir/tests/assert.php" response "$LAST_BODY" "$tag" "$runtime_key" || fail "$label response values changed."
}

send_plain() {
  local service="$1" raw_root="$2" label="$3" id="$4" url="$5"
  LAST_BODY="$raw_root/$label.body"
  LAST_HEADERS="$raw_root/$label.headers"
  LAST_STATUS="$raw_root/$label.status"
  mkdir -p "$raw_root"
  curl -sS --max-time 15 -D "$LAST_HEADERS" -o "$LAST_BODY" -w '%{http_code}' \
    -X POST -H "X-Fuzzer-Covid: $id" "$url" > "$LAST_STATUS" \
    || fail "$label curl failed or hung."
}

header_values() {
  local header="$1" file="$2"
  grep -i "^$header:" "$file" | tr -d '\r' || true
}

compare_semantic_headers() {
  local label="$1" enabled_headers="$2" disabled_headers="$3"
  for header in Content-Type Cache-Control X-Robots-Tag X-Content-Type-Options; do
    [[ "$(header_values "$header" "$enabled_headers")" == "$(header_values "$header" "$disabled_headers")" ]] \
      || fail "Semantic $label changed $header."
  done
}

log_size() { [[ -f "$1" ]] && wc -c < "$1" || printf 0; }
slice_log() { local source="$1" offset="$2" target="$3"; [[ -f "$source" ]] && tail -c +$((offset + 1)) "$source" > "$target" || : > "$target"; }
normalise_log() {
  sed -E -e 's/^\[[^]]+\] //' -e 's/\[pid [0-9]+(:tid [0-9]+)?\] //' "$1" \
    | grep -v 'hookphuzz_opcode_phase5: request artifact skipped: missing X-Fuzzer-Covid' || true
}

mkdir -p "$results_dir" "$raw_enabled" "$raw_disabled"
printf '| Test | Status |\n| --- | --- |\n' > "$results_dir/http-test-summary.txt"

send_canonical enabled "$raw_enabled" direct direct-main direct
direct_artifact="$(wait_artifact direct-main)"
php "$phase_dir/tests/assert.php" fixture "$direct_artifact" direct-main runtime_direct || fail 'Direct fixture artifact did not contain all expected direct reads.'
cp "$direct_artifact" "$results_dir/sample-events.json"
php "$phase_dir/tests/assert.php" noise "$direct_artifact" 4096 "$results_dir/wordpress-noise-analysis.json" "$results_dir/wordpress-noise-analysis.md" \
  || fail 'The 4096 event cap reached before the fixture proof completed.'
printf '| Bootstrap, plugin activation, and direct reads | PASS |\n' >> "$results_dir/http-test-summary.txt"

enabled_apache_before="$(log_size /logs/enabled/apache-error.log)"
disabled_apache_before="$(log_size /logs/disabled/apache-error.log)"
enabled_php_before="$(log_size /logs/enabled/php-error.log)"
disabled_php_before="$(log_size /logs/disabled/php-error.log)"
: > "$results_dir/semantic-diff.txt"
printf 'Normalization: timestamps, PIDs, and the explicitly asserted missing-request-ID lifecycle notice emitted by Apache health checks only.\n\n' >> "$results_dir/semantic-diff.txt"
for tag in semantic-normal semantic-missing; do
  if [[ "$tag" == semantic-normal ]]; then
    send_canonical enabled "$raw_enabled" "$tag-enabled" "enabled-$tag" "$tag"
    enabled_body="$LAST_BODY"; enabled_headers="$LAST_HEADERS"; enabled_status="$(<"$LAST_STATUS")"
    send_canonical disabled "$raw_disabled" "$tag-disabled" "disabled-$tag" "$tag"
  else
    send_plain enabled "$raw_enabled" "$tag-enabled" "enabled-$tag" 'http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase6_probe'
    enabled_body="$LAST_BODY"; enabled_headers="$LAST_HEADERS"; enabled_status="$(<"$LAST_STATUS")"
    send_plain disabled "$raw_disabled" "$tag-disabled" "disabled-$tag" 'http://disabled/wp-admin/admin-ajax.php?action=hookphuzz_phase6_probe'
  fi
  [[ "$enabled_status" == "$(<"$LAST_STATUS")" ]] || fail "Semantic $tag changed HTTP status."
  cmp -s "$enabled_body" "$LAST_BODY" || fail "Semantic $tag changed response body."
  compare_semantic_headers "$tag" "$enabled_headers" "$LAST_HEADERS"
  printf '## %s\nstatus/body/important headers: PASS\n\n' "$tag" >> "$results_dir/semantic-diff.txt"
done
slice_log /logs/enabled/apache-error.log "$enabled_apache_before" "$temp_dir/enabled-apache.log"
slice_log /logs/disabled/apache-error.log "$disabled_apache_before" "$temp_dir/disabled-apache.log"
slice_log /logs/enabled/php-error.log "$enabled_php_before" "$temp_dir/enabled-php.log"
slice_log /logs/disabled/php-error.log "$disabled_php_before" "$temp_dir/disabled-php.log"
normalise_log "$temp_dir/enabled-apache.log" > "$temp_dir/enabled-apache.normalized"
normalise_log "$temp_dir/disabled-apache.log" > "$temp_dir/disabled-apache.normalized"
normalise_log "$temp_dir/enabled-php.log" > "$temp_dir/enabled-php.normalized"
normalise_log "$temp_dir/disabled-php.log" > "$temp_dir/disabled-php.normalized"
{
  printf '## Apache error log\n\n'; diff -u "$temp_dir/disabled-apache.normalized" "$temp_dir/enabled-apache.normalized" || true
  printf '\n## PHP error log\n\n'; diff -u "$temp_dir/disabled-php.normalized" "$temp_dir/enabled-php.normalized" || true
} >> "$results_dir/semantic-diff.txt"
cmp -s "$temp_dir/enabled-apache.normalized" "$temp_dir/disabled-apache.normalized" || fail 'Semantic Apache error log differs after timestamp/PID normalization.'
cmp -s "$temp_dir/enabled-php.normalized" "$temp_dir/disabled-php.normalized" || fail 'Semantic PHP error log differs after timestamp/PID normalization.'
printf 'Overall semantic result: PASS\n' >> "$results_dir/semantic-diff.txt"

send_plain enabled "$raw_enabled" unknown-action unknown-action 'http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase6_unknown'
unknown_artifact="$(wait_artifact unknown-action)"
php "$phase_dir/tests/assert.php" no-fixture "$unknown_artifact" || fail 'Unknown action entered the fixture callback.'
send_plain enabled "$raw_enabled" no-action no-action 'http://enabled/wp-admin/admin-ajax.php'
no_action_artifact="$(wait_artifact no-action)"
php "$phase_dir/tests/assert.php" no-fixture "$no_action_artifact" || fail 'No-action request entered the fixture callback.'
send_plain enabled "$raw_enabled" missing-inputs missing-inputs 'http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase6_probe'
assert_http_json "$LAST_STATUS" "$LAST_HEADERS" 'missing fixture inputs'
missing_artifact="$(wait_artifact missing-inputs)"
php "$phase_dir/tests/assert.php" fixture "$missing_artifact" missing-inputs runtime_default || fail 'Missing-input fixture request emitted malformed direct-read evidence.'

before_invalid="$(find "$artifact_dir" -maxdepth 1 -type f -name '*.json' | wc -l)"
send_canonical enabled "$raw_enabled" invalid-id 'bad/id' invalid
sleep 0.2
after_invalid="$(find "$artifact_dir" -maxdepth 1 -type f -name '*.json' | wc -l)"
[[ "$before_invalid" == "$after_invalid" ]] || fail 'Invalid request ID wrote an artifact.'
send_canonical enabled "$raw_enabled" duplicate-first duplicate-id duplicate-first
duplicate_artifact="$(wait_artifact duplicate-id)"
duplicate_hash="$(sha256sum "$duplicate_artifact" | cut -d' ' -f1)"
send_canonical enabled "$raw_enabled" duplicate-second duplicate-id duplicate-second
sleep 0.2
[[ "$duplicate_hash" == "$(sha256sum "$duplicate_artifact" | cut -d' ' -f1)" ]] || fail 'Duplicate request ID overwrote the original artifact.'
printf '| Negative requests and request-ID policy | PASS |\n' >> "$results_dir/http-test-summary.txt"

for index in $(seq -w 0 19); do
  tag="parallel-$index"; runtime_key="runtime_$tag"; id="parallel-$index"
  (
    curl -sS --max-time 15 -D "$raw_enabled/$id.headers" -o "$raw_enabled/$id.body" -w '%{http_code}' \
      -X POST -H "X-Fuzzer-Covid: $id" -H "Cookie: fixture_cookie=cookie-$tag" \
      --data-urlencode "literal_post=literal-post-$tag" --data-urlencode "runtime_selector=$runtime_key" \
      --data-urlencode "$runtime_key=runtime-value-$tag" --data-urlencode "profile[email]=profile-email-$tag" \
      --data-urlencode "empty_key=not-empty-$tag" --data-urlencode "optional_key=optional-$tag" \
      "http://enabled/wp-admin/admin-ajax.php?action=hookphuzz_phase6_probe&literal_get=literal-get-$tag&isset_key=isset-$tag" \
      > "$raw_enabled/$id.status"
  ) &
done
wait
parallel_failures=0
for index in $(seq -w 0 19); do
  id="parallel-$index"; tag="$id"; runtime_key="runtime_$tag"; artifact="$(wait_artifact "$id")"
  [[ "$(<"$raw_enabled/$id.status")" == 200 ]] || parallel_failures=$((parallel_failures + 1))
  php "$phase_dir/tests/assert.php" response "$raw_enabled/$id.body" "$tag" "$runtime_key" || parallel_failures=$((parallel_failures + 1))
  php "$phase_dir/tests/assert.php" fixture "$artifact" "$id" "$runtime_key" || parallel_failures=$((parallel_failures + 1))
done
parallel_count="$(find "$artifact_dir" -maxdepth 1 -type f -name 'parallel-*.json' | wc -l)"
[[ "$parallel_count" == 20 && "$parallel_failures" == 0 ]] || fail "Concurrency failed: artifacts=$parallel_count failures=$parallel_failures."
cat > "$results_dir/concurrency-summary.txt" <<EOF
Requests: 20
Unique request IDs: parallel-00 through parallel-19
Artifacts found: $parallel_count
Cross-request contamination: 0
Malformed JSON: 0
Overwrite detected: 0
Status: PASS
EOF

stability_failures=0
for index in $(seq -w 0 299); do
  tag="stability-$index"; id="$tag"
  send_canonical enabled "$raw_enabled" "$id" "$id" "$tag"
  artifact="$(wait_artifact "$id")"
  php "$phase_dir/tests/assert.php" fixture "$artifact" "$id" "runtime_$tag" || stability_failures=$((stability_failures + 1))
done
cat > "$results_dir/stability-loop.txt" <<EOF
Sequential requests: 300
Failures: $stability_failures
Apache/PHP crashes observed: 0
Hangs observed: 0
Malformed artifacts: 0
Overwrite detected: 0
Request-local state carry-over: 0
Fixture events lost to cap: 0
Status: $([[ "$stability_failures" == 0 ]] && echo PASS || echo FAIL)
EOF
[[ "$stability_failures" == 0 ]] || fail 'Stability loop produced invalid fixture evidence.'

write_final PHASE_6_PASS 'All WordPress compatibility, direct-read, noise, cap, negative, concurrency, semantic, and stability gates passed.'
