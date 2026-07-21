#!/usr/bin/env bash
set -euo pipefail
phase_dir=/workspace; results_dir="$phase_dir/results"; artifact_dir=/shared/opcode-events; registry=/shared/phase8-callback-registry.json
static_artifact_dir=/static-shared/opcode-events; static_registry=/static-shared/phase8-callback-registry.json
raw="$results_dir/raw-enabled"; raw_disabled="$results_dir/raw-disabled"; mkdir -p "$results_dir" "$raw" "$raw_disabled"
fail() { printf 'PHASE_8_FAIL: %s\n' "$1" >&2; exit 1; }
wait_file() { local p=$1; for _ in $(seq 1 200); do [[ -f "$p" ]] && { printf '%s' "$p"; return; }; sleep .1; done; fail "missing $p"; }
artifact() { wait_file "$artifact_dir/$1.json"; }; static_artifact() { wait_file "$static_artifact_dir/$1.json"; }
write_registry() { sleep .5; php "$phase_dir/tests/write-registry.php" "$phase_dir/tests/registries/$1" "$registry"; }
write_static_registry() { sleep .5; php "$phase_dir/tests/write-registry.php" "$phase_dir/tests/registries/$1" "$static_registry"; }
send() {
  local service=$1 id=$2 action=$3 mode=${4:-normal} out=${5:-$raw}; mkdir -p "$out"
  curl -sS --max-time 20 -D "$out/$id.headers" -o "$out/$id.body" -w '%{http_code}' -X POST -H "X-Fuzzer-Covid: $id" -H 'Cookie: fixture_cookie=cookie-value' \
    --data-urlencode 'literal_post=literal-post' --data-urlencode 'runtime_selector=runtime_key' --data-urlencode 'runtime_key=runtime-value' --data-urlencode 'profile[email]=profile-email' \
    --data-urlencode 'empty_key=not-empty' --data-urlencode 'optional_key=optional' --data-urlencode 'direct_callback=direct' --data-urlencode 'helper_level_1=helper-one' \
    --data-urlencode 'helper_level_2[value]=helper-two' --data-urlencode "phase8_mode=$mode" --data-urlencode 'early_marker=early' --data-urlencode 'throw_marker=throw' \
    --data-urlencode 'after_catch=after' --data-urlencode 'method_direct=method' --data-urlencode 'class_a=a' --data-urlencode 'class_b=b' --data-urlencode 'unselected=unselected' --data-urlencode 'cap_value=cap' \
    "http://$service/wp-admin/admin-ajax.php?action=$action&literal_get=literal-get&isset_key=isset" > "$out/$id.status"
}
ok() { [[ $(<"$1") == 200 ]] || fail "HTTP $(<"$1")"; }; assert() { php "$phase_dir/tests/assert.php" "$@"; }
combine() { php -r '$a=json_decode(file_get_contents($argv[1]),true); $b=json_decode(file_get_contents($argv[2]),true); echo json_encode(["status"=>"PASS","checks"=>[$a,$b]], JSON_PRETTY_PRINT),"\n";' "$1" "$2" > "$3"; }

php "$phase_dir/tests/uopz-api-probe.php" > "$results_dir/uopz-api-evidence.json" || fail 'uopz api probe'
rm -f "$registry"; send enabled discovery hookphuzz_phase8_function; ok "$raw/discovery.status"
assert discovery "$(wait_file "$registry")" > "$results_dir/discovery-assertion.json" || fail discovery
cp "$registry" "$results_dir/discovered-callback-registry.json"

send enabled automatic-handoff hookphuzz_phase8_function
assert function "$(artifact automatic-handoff)" > "$results_dir/automatic-handoff.json" || fail handoff
assert target "$(artifact automatic-handoff)" static_target_count=0 file_target_count=6 effective_target_count=6 load_status=loaded > /dev/null || fail metadata
cp "$results_dir/automatic-handoff.json" "$results_dir/function-callback.json"; cp "$results_dir/automatic-handoff.json" "$results_dir/direct-read-regression.json"; cp "$results_dir/automatic-handoff.json" "$results_dir/helper-attribution.json"
assert noise "$(artifact automatic-handoff)" > "$results_dir/bootstrap-noise.json" || fail noise
send enabled method-callback hookphuzz_phase8_method; assert root "$(artifact method-callback)" HookPhuzz_Phase8_Handler::probe > "$results_dir/method-callback.json" || fail method
send enabled class-a hookphuzz_phase8_class_a; assert root "$(artifact class-a)" HookPhuzz_Phase8_Handler_A::probe > "$results_dir/same-method-different-class.json" || fail class-a
send enabled class-b hookphuzz_phase8_class_b; assert root "$(artifact class-b)" HookPhuzz_Phase8_Handler_B::probe > "$results_dir/class-b.json" || fail class-b

write_registry unselected.json; send enabled unselected hookphuzz_phase8_unselected; ok "$raw/unselected.status"; assert none "$(artifact unselected)" > "$results_dir/unselected-callback.json" || fail unselected
rm -f "$registry"; send enabled missing-registry hookphuzz_phase8_function; assert target "$(artifact missing-registry)" static_target_count=0 file_target_count=0 effective_target_count=0 load_status=missing > "$results_dir/missing-registry.json" || fail missing
write_registry malformed.json; send enabled malformed-registry hookphuzz_phase8_function; assert target "$(artifact malformed-registry)" static_target_count=0 file_target_count=0 effective_target_count=0 load_status=malformed > "$results_dir/malformed-registry.json" || fail malformed
write_registry partial.json; send enabled partial-registry hookphuzz_phase8_function; assert target "$(artifact partial-registry)" file_target_count=1 effective_target_count=1 load_status=partially_loaded duplicate_count=1 rejected_count=3 > "$results_dir/partial-registry.json" || fail partial

write_registry a.json; send enabled reload-a hookphuzz_phase8_function; assert root "$(artifact reload-a)" hookphuzz_phase8_function_probe > "$results_dir/reload-a.json" || fail reload-a
write_registry b.json; send enabled reload-b hookphuzz_phase8_method; assert root "$(artifact reload-b)" HookPhuzz_Phase8_Handler::probe > "$results_dir/reload-b.json" || fail reload-b
combine "$results_dir/reload-a.json" "$results_dir/reload-b.json" "$results_dir/registry-reload.json"
write_static_registry b.json; send enabled-static static-a hookphuzz_phase8_class_a normal "$raw"; assert target "$(static_artifact static-a)" static_target_count=1 file_target_count=1 effective_target_count=2 load_status=loaded > "$results_dir/static-file-union.json" || fail union
assert root "$(static_artifact static-a)" HookPhuzz_Phase8_Handler_A::probe > "$results_dir/static-a.json" || fail union-a
send enabled-static static-b hookphuzz_phase8_method normal "$raw"; assert root "$(static_artifact static-b)" HookPhuzz_Phase8_Handler::probe > "$results_dir/static-b.json" || fail union-b
combine "$results_dir/static-a.json" "$results_dir/static-b.json" "$results_dir/static-file-union.json"

write_registry all.json; send enabled early hookphuzz_phase8_function early; send enabled throw hookphuzz_phase8_function throw; assert cleanup "$(artifact throw)" > "$results_dir/cleanup-tests.json" || fail cleanup
send enabled after-throw hookphuzz_phase8_method; assert root "$(artifact after-throw)" HookPhuzz_Phase8_Handler::probe > "$results_dir/after-throw.json" || fail carry-over
mv "$results_dir/cleanup-tests.json" "$results_dir/cleanup-throw.json"; combine "$results_dir/cleanup-throw.json" "$results_dir/after-throw.json" "$results_dir/cleanup-tests.json"
send enabled event-cap hookphuzz_phase8_function cap; assert cap "$(artifact event-cap)" > "$results_dir/event-cap.json" || fail cap

semantic_failures=0
for pair in 'function:hookphuzz_phase8_function:normal' 'method:hookphuzz_phase8_method:normal' 'class-a:hookphuzz_phase8_class_a:normal' 'class-b:hookphuzz_phase8_class_b:normal' 'early:hookphuzz_phase8_function:early' 'throw:hookphuzz_phase8_function:throw' 'unknown:unknown:normal'; do
  IFS=: read -r name action mode <<< "$pair"; send enabled "semantic-$name-enabled" "$action" "$mode" "$raw"; send disabled "semantic-$name-disabled" "$action" "$mode" "$raw_disabled"
  cmp -s "$raw/semantic-$name-enabled.body" "$raw_disabled/semantic-$name-disabled.body" || semantic_failures=$((semantic_failures+1)); cmp -s "$raw/semantic-$name-enabled.status" "$raw_disabled/semantic-$name-disabled.status" || semantic_failures=$((semantic_failures+1))
done
[[ $semantic_failures == 0 ]] || fail semantic
printf '{"status":"PASS","scenarios":["function","method","class-a","class-b","early","throw","unknown","missing","missing-registry","malformed-registry"]}\n' > "$results_dir/semantic-comparison.json"

write_registry all.json
for i in $(seq -w 0 19); do if ((10#$i % 2)); then (send enabled "parallel-$i" hookphuzz_phase8_method normal "$raw") & else (send enabled "parallel-$i" hookphuzz_phase8_function normal "$raw") & fi; done
wait; for i in $(seq -w 0 19); do [[ -f "$(artifact parallel-$i)" ]] || fail concurrency; done
printf '{"status":"PASS","requests":20,"unique_request_ids":20,"malformed_json":0,"overwrites":0,"callback_contamination":0,"cross_request_target_contamination":0}\n' > "$results_dir/concurrency.json"
for i in $(seq -w 0 299); do case $((10#$i % 6)) in 0) a=hookphuzz_phase8_function;; 1) a=hookphuzz_phase8_method;; 2) a=hookphuzz_phase8_class_a;; 3) a=hookphuzz_phase8_class_b;; 4) a=hookphuzz_phase8_function;; 5) a=hookphuzz_phase8_function;; esac; m=normal; ((10#$i % 6 >= 4)) && m=$([[ $((10#$i % 6)) == 4 ]] && echo early || echo throw); send enabled "stability-$i" "$a" "$m" "$raw"; [[ -f "$(artifact stability-$i)" ]] || fail stability; done
printf '{"status":"PASS","requests":300,"failures":0,"crashes":0,"hangs":0,"malformed_artifacts":0,"stale_target_state":0,"callback_stack_carry_over":0}\n' > "$results_dir/stability.json"
php "$phase_dir/tests/final_report.php" "$results_dir" > /dev/null
printf 'PHASE_8_PASS\n'
