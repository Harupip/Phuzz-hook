#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase3 -f "$phase_dir/docker-compose.yml")
evidence_files=(
  environment.txt build.log module-info.txt php-lint.txt raw-opcodes.txt opcode-analysis.md
  direct-get-events.json direct-post-events.json runtime-key-events.json cookie-events.json integer-key-events.json
  nested-events.json nested-runtime-events.json missing-key-events.json control-events.json unsupported-key-events.json
  missing-key-semantics-diff.txt unsupported-key-semantics-diff.txt request-reset.txt event-limit.txt stability-loop.txt
  opcode-scope.txt opcache-smoke.txt phase3-summary.md
)

clear_evidence() {
  mkdir -p "$results_dir"
  local item
  for item in "${evidence_files[@]}"; do rm -f "$results_dir/$item"; done
}

write_summary() {
  local status="$1"
  local detail="${2:-}"
  cat > "$results_dir/phase3-summary.md" <<EOF
# HookPhuzz opcode Phase 3 summary

## Status

$status

## Result

$detail
EOF
}

fail() { write_summary PHASE_3_FAIL "$1"; exit 1; }
blocked() { write_summary PHASE_3_BLOCKED_OPCODE_SHAPE "$1"; exit 0; }

capture() {
  local out="$1" err="$2" code="$3"
  shift 3
  set +e
  "$@" >"$out" 2>"$err"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$code"
}

validate_events() {
  local event_file="$1" expected="$2"
  php -n -r '
    $events = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
    $expected = json_decode($argv[2], true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($events) || count($events) !== count($expected)) exit(1);
    foreach ($expected as $index => $want) {
      $event = $events[$index];
      foreach (["source", "key_type", "key", "depth", "parameter_candidate", "mapped"] as $field) {
        if (($event[$field] ?? null) !== $want[$field]) exit(1);
      }
      if (($event["reason"] ?? null) !== ($want["reason"] ?? null)) exit(1);
      if (count($event["path"] ?? []) !== count($want["path"])) exit(1);
      foreach ($want["path"] as $path_index => $value) {
        if (($event["path"][$path_index]["value"] ?? null) !== $value) exit(1);
      }
      if (($event["event_type"] ?? null) !== "superglobal_dim_read" || !is_string($event["filename"] ?? null) || ($event["line"] ?? 0) < 1) exit(1);
    }
  ' "$event_file" "$expected"
}

run_event_fixture() {
  local fixture="$1" result="$2" expected="$3" expected_output="$4"
  local prefix="${fixture%.php}"
  capture "$temp_dir/$prefix.out" "$temp_dir/$prefix.err" "$temp_dir/$prefix.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
  [[ "$(<"$temp_dir/$prefix.code")" == 0 ]] || fail "$fixture failed"
  if [[ "$expected_output" != __ANY__ ]]; then
    [[ "$(head -n 1 "$temp_dir/$prefix.out")" == "$expected_output" ]] || fail "$fixture stdout mismatch"
  fi
  tail -n 1 "$temp_dir/$prefix.out" > "$results_dir/$result"
  validate_events "$results_dir/$result" "$expected" || fail "$fixture event validation failed"
}

compare_semantics() {
  local fixture="$1" result="$2"
  local ok=1
  capture "$temp_dir/base.out" "$temp_dir/base.err" "$temp_dir/base.code" \
    php -n -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
  capture "$temp_dir/instrumented.out" "$temp_dir/instrumented.err" "$temp_dir/instrumented.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
  {
    printf 'Baseline exit code: %s\nInstrumented exit code: %s\n\n' "$(<"$temp_dir/base.code")" "$(<"$temp_dir/instrumented.code")"
    if diff -u "$temp_dir/base.out" "$temp_dir/instrumented.out"; then echo 'stdout: PASS'; else echo 'stdout: FAIL'; ok=0; fi
    if diff -u "$temp_dir/base.err" "$temp_dir/instrumented.err"; then echo 'stderr: PASS'; else echo 'stderr: FAIL'; ok=0; fi
    if [[ "$(<"$temp_dir/base.code")" == "$(<"$temp_dir/instrumented.code")" ]]; then echo 'exit status: PASS'; else echo 'exit status: FAIL'; ok=0; fi
  } > "$results_dir/$result"
  [[ $ok == 1 ]] || fail "$fixture changed PHP semantics"
}

check_opcode_shape() {
  php -d opcache.enable_cli=1 -d opcache.jit=0 -d opcache.opt_debug_level=0x10000 \
    "$phase_dir/tests/opcode_shape.php" > "$results_dir/raw-opcodes.txt" 2>&1
  local required
  for required in \
    'FETCH_R (global) string("_GET")' \
    'FETCH_R (global) string("_POST")' \
    'FETCH_R (global) string("_REQUEST")' \
    'FETCH_R (global) string("_COOKIE")' \
    'FETCH_DIM_R T0 string("id")' \
    'FETCH_DIM_R T0 string("username")' \
    'FETCH_DIM_R T1 CV0($runtimeKey)' \
    'FETCH_DIM_R T1 string("name")'; do
    grep -Fq "$required" "$results_dir/raw-opcodes.txt" || blocked "Required PHP 8.2.10 opcode shape was absent: $required. See raw-opcodes.txt."
  done
  cat > "$results_dir/opcode-analysis.md" <<'EOF'
# Phase 3 opcode analysis

PHP 8.2.10 OPcache debug output proves direct reads use `ZEND_FETCH_R (global)`.
`op1` is the constant global name (`_GET`, `_POST`, `_REQUEST`, `_COOKIE`), `result` is a temporary slot, and `ZEND_FETCH_DIM_R` consumes that slot as `op1`.

For nested POST the observed chain is `T0 = FETCH_R _POST`, `T1 = FETCH_DIM_R T0 "user"`, then `T2 = FETCH_DIM_R T1 "name"`. The `(global)` fetch type is the evidence required before accepting `FETCH_R`; the extension additionally checks `ZEND_FETCH_GLOBAL` and exact constant names at runtime.
EOF
}

run_inside() {
  mkdir -p "$results_dir"
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT
  check_opcode_shape
  {
    echo 'Docker image: php:8.2.10-cli with built OPcache'
    php -v
    php -r 'echo zend_version(), PHP_EOL;'
    php -d opcache.enable_cli=0 -d opcache.jit=0 -r 'printf("opcache.enable_cli: %s\nopcache.jit: %s\n", ini_get("opcache.enable_cli"), ini_get("opcache.jit"));'
  } > "$results_dir/environment.txt" 2>&1
  php --ri hookphuzz_opcode > "$results_dir/module-info.txt" 2>&1
  grep -Fq 'configured user opcodes => ZEND_FETCH_R, ZEND_FETCH_DIM_R' "$results_dir/module-info.txt" || fail 'module handler scope mismatch'
  if [[ "$(grep -o 'zend_set_user_opcode_handler(ZEND_[A-Z_]*' "$phase_dir/extension/hookphuzz_opcode.c" | sort -u | tr '\n' ' ')" != 'zend_set_user_opcode_handler(ZEND_FETCH_DIM_R zend_set_user_opcode_handler(ZEND_FETCH_R ' ]]; then fail 'source registers an unexpected opcode'; fi
  printf 'Registered handlers: ZEND_FETCH_R, ZEND_FETCH_DIM_R\nStatus: PASS\n' > "$results_dir/opcode-scope.txt"
  for file in "$phase_dir"/tests/*.php; do php -l "$file"; done > "$results_dir/php-lint.txt" 2>&1

  run_event_fixture direct_get_events.php direct-get-events.json '[{"source":"GET","key_type":"string","key":"id","path":["id"],"depth":1,"parameter_candidate":true,"mapped":true}]' get-id
  run_event_fixture direct_post_events.php direct-post-events.json '[{"source":"POST","key_type":"string","key":"username","path":["username"],"depth":1,"parameter_candidate":true,"mapped":true}]' alice
  run_event_fixture runtime_key_events.php runtime-key-events.json '[{"source":"REQUEST","key_type":"string","key":"email","path":["email"],"depth":1,"parameter_candidate":true,"mapped":true}]' alice@example.test
  run_event_fixture cookie_events.php cookie-events.json '[{"source":"COOKIE","key_type":"string","key":"session_id","path":["session_id"],"depth":1,"parameter_candidate":true,"mapped":true}]' cookie-session
  run_event_fixture integer_key_events.php integer-key-events.json '[{"source":"POST","key_type":"int","key":10,"path":[10],"depth":1,"parameter_candidate":false,"mapped":true}]' ten
  run_event_fixture nested_events.php nested-events.json '[{"source":"POST","key_type":"string","key":"user","path":["user"],"depth":1,"parameter_candidate":true,"mapped":true},{"source":"POST","key_type":"string","key":"name","path":["user","name"],"depth":2,"parameter_candidate":true,"mapped":true}]' alice
  run_event_fixture nested_runtime_events.php nested-runtime-events.json '[{"source":"POST","key_type":"string","key":"user","path":["user"],"depth":1,"parameter_candidate":true,"mapped":true},{"source":"POST","key_type":"string","key":"email","path":["user","email"],"depth":2,"parameter_candidate":true,"mapped":true}]' alice@example.test
  run_event_fixture missing_key_events.php missing-key-events.json '[{"source":"GET","key_type":"string","key":"missing","path":["missing"],"depth":1,"parameter_candidate":true,"mapped":true}]' __ANY__
  run_event_fixture control_events.php control-events.json '[]' '1|2|3'
  run_event_fixture unsupported_key_events.php unsupported-key-events.json '[{"source":"POST","key_type":"object","key":null,"path":[],"depth":0,"parameter_candidate":false,"mapped":false,"reason":"unsupported_key_type"}]' caught:TypeError
  if grep -q TOSTRING_CALLED "$temp_dir/unsupported_key_events.out" "$temp_dir/unsupported_key_events.err"; then fail 'object key invoked __toString'; fi

  compare_semantics missing_key.php missing-key-semantics-diff.txt
  if ! grep -q 'Undefined array key "missing"' "$temp_dir/base.out" "$temp_dir/base.err" \
      || ! grep -q 'Undefined array key "missing"' "$temp_dir/instrumented.out" "$temp_dir/instrumented.err"; then
    fail 'missing-key warning was absent'
  fi
  compare_semantics unsupported_key.php unsupported-key-semantics-diff.txt

  capture "$temp_dir/limit.out" "$temp_dir/limit.err" "$temp_dir/limit.code" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/event_limit_events.php"
  [[ "$(<"$temp_dir/limit.code")" == 0 && "$(head -n 1 "$temp_dir/limit.out")" == 4096 && "$(sed -n '2p' "$temp_dir/limit.out")" == 1 ]] || fail 'event limit counters failed'
  tail -n 1 "$temp_dir/limit.out" > "$temp_dir/limit.json"
  php -n -r '$e=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR); exit(count($e)===4096 && $e[0]["key"]==="x" && $e[4095]["key"]==="x" ? 0 : 1);' "$temp_dir/limit.json" || fail 'event limit event data failed'
  printf 'Stored events: 4096\nDropped events: 1\nStatus: PASS\n' > "$results_dir/event-limit.txt"

  capture "$temp_dir/reset1.out" "$temp_dir/reset1.err" "$temp_dir/reset1.code" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/direct_post_events.php"
  capture "$temp_dir/reset2.out" "$temp_dir/reset2.err" "$temp_dir/reset2.code" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/control_events.php"
  tail -n 1 "$temp_dir/reset2.out" > "$temp_dir/reset2.json"
  validate_events "$temp_dir/reset2.json" '[]' || fail 'process reset failed'
  printf 'First process: POST read\nSecond independent process: zero events\nStatus: PASS\n' > "$results_dir/request-reset.txt"

  local failures=0 iteration fixture
  : > "$results_dir/stability-loop.txt"
  for iteration in $(seq 1 100); do
    for fixture in direct_post_events.php nested_events.php missing_key.php runtime_key_events.php; do
      capture "$temp_dir/stability.out" "$temp_dir/stability.err" "$temp_dir/stability.code" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
      if [[ "$(<"$temp_dir/stability.code")" != 0 ]]; then printf 'iteration %s fixture %s exit %s\n' "$iteration" "$fixture" "$(<"$temp_dir/stability.code")" >> "$results_dir/stability-loop.txt"; failures=$((failures+1)); fi
    done
  done
  printf 'Processes run: 400\nFailures: %s\nStatus: %s\n' "$failures" "$([[ $failures == 0 ]] && echo PASS || echo FAIL)" >> "$results_dir/stability-loop.txt"
  [[ $failures == 0 ]] || fail 'stability loop failed'

  capture "$temp_dir/opcache.out" "$temp_dir/opcache.err" "$temp_dir/opcache.code" php -d opcache.enable_cli=1 -d opcache.jit=0 "$phase_dir/tests/direct_get_events.php"
  tail -n 1 "$temp_dir/opcache.out" > "$temp_dir/opcache.json"
  validate_events "$temp_dir/opcache.json" '[{"source":"GET","key_type":"string","key":"id","path":["id"],"depth":1,"parameter_candidate":true,"mapped":true}]' || fail 'OPcache smoke failed'
  printf 'opcache.enable_cli=1\nopcache.jit=0\nStatus: PASS\n' > "$results_dir/opcache-smoke.txt"

  cat > "$results_dir/phase3-summary.md" <<'EOF'
# HookPhuzz opcode Phase 3 summary

## Status

PHASE_3_PASS

## Test results

| Expected | Actual | Status |
| --- | --- | --- |
| GET, POST, REQUEST runtime key, COOKIE | exact source and single path | PASS |
| Integer POST key | int and not a parameter candidate | PASS |
| Literal and runtime nested POST | propagated paths | PASS |
| Missing key and unsupported object key | stdout, stderr, exit status unchanged | PASS |
| Local/similar/case controls | zero mapped events | PASS |
| Process reset and event cap | zero next-process events; 4096 stored, 1 dropped | PASS |
| Stability | 400 independent processes, zero failures | PASS |
| Opcode scope and OPcache smoke | exactly FETCH_R/FETCH_DIM_R; JIT disabled | PASS |

## Provenance model

`FETCH_R` records exact superglobal source metadata against the active execute frame and its temporary/variable `result.var`. `FETCH_DIM_R` looks up its container operand, copies a string/int key into a new path, emits the mapped read, and stores the path against its own result slot. Frame identities stay request-local and are never exported; no zval pointers are retained.

Nested paths prove direct opcode-slot provenance only. They do not establish complete HTTP nested-parameter semantics or support assignment aliases, references, helper functions, function parameter passing, object properties, ArrayAccess, variable variables, WordPress REST objects, WordPress integration, HookPhuzz artifact/config export, or complete dynamic parameter discovery.
EOF
}

run_host() {
  clear_evidence
  if ! "${compose[@]}" build > "$results_dir/build.log" 2>&1; then write_summary PHASE_3_FAIL 'Docker build failed; see build.log'; exit 1; fi
  "${compose[@]}" run --rm phase3
}

if [[ "${1:-}" == --inside ]]; then run_inside; else run_host; fi
