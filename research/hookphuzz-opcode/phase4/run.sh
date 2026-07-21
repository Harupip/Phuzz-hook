#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase4 -f "$phase_dir/docker-compose.yml")
result_files=(raw-opcodes.txt opcode-analysis.md semantic-diff.txt event-limit.txt frame-isolation.txt stability-loop.txt phase4-summary.md)

clear_evidence() {
  mkdir -p "$results_dir"
  local item
  for item in "${result_files[@]}"; do rm -f "$results_dir/$item"; done
}

write_summary() {
  local status="$1" detail="${2:-}"
  cat > "$results_dir/phase4-summary.md" <<EOF
# HookPhuzz opcode Phase 4 summary

## Status

$status

## Result

$detail
EOF
}

fail() { write_summary PHASE_4_NOT_PASS "$1"; exit 1; }

capture() {
  local out="$1" err="$2" code="$3"
  shift 3
  set +e
  timeout 15s "$@" >"$out" 2>"$err"
  local status=$?
  set -e
  printf '%s\n' "$status" > "$code"
}

validate_events() {
  local event_file="$1" expected_file="$2"
  php -n -r '
    $events = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
    $expected = json_decode(file_get_contents($argv[2]), true, 512, JSON_THROW_ON_ERROR);
    if (!is_array($events) || count($events) !== count($expected)) exit(1);
    foreach ($expected as $index => $want) {
      $event = $events[$index] ?? null;
      if (!is_array($event) || ($event["event_type"] ?? null) !== "superglobal_dim_read") exit(1);
      if (($event["mapped"] ?? null) !== true || !is_string($event["filename"] ?? null) || ($event["line"] ?? 0) < 1) exit(1);
      foreach ($want as $field => $value) {
        if ($field === "path") continue;
        if (($event[$field] ?? null) !== $value) exit(1);
      }
      if (count($event["path"] ?? []) !== count($want["path"] ?? [])) exit(1);
      foreach ($want["path"] ?? [] as $pathIndex => $value) {
        if (($event["path"][$pathIndex]["value"] ?? null) !== $value) exit(1);
      }
    }
  ' "$event_file" "$expected_file"
}

run_event_fixture() {
  local fixture="$1" expected="$2" label="$3"
  capture "$temp_dir/$label.out" "$temp_dir/$label.err" "$temp_dir/$label.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/$fixture"
  [[ "$(<"$temp_dir/$label.code")" == 0 ]] || fail "$fixture exited $(<"$temp_dir/$label.code")"
  tail -n 1 "$temp_dir/$label.out" > "$temp_dir/$label.events.json"
  validate_events "$temp_dir/$label.events.json" "$phase_dir/expected/$expected" || fail "$fixture event attribution failed"
}

compare_semantics() {
  local fixture="$1" label="$2"
  local ok=1
  capture "$temp_dir/$label.base.out" "$temp_dir/$label.base.err" "$temp_dir/$label.base.code" \
    php -n -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/$fixture"
  capture "$temp_dir/$label.instrumented.out" "$temp_dir/$label.instrumented.err" "$temp_dir/$label.instrumented.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/$fixture"
  {
    printf '## %s\n\n' "$fixture"
    printf 'Baseline exit code: %s\nInstrumented exit code: %s\n\n' \
      "$(<"$temp_dir/$label.base.code")" "$(<"$temp_dir/$label.instrumented.code")"
    if diff -u "$temp_dir/$label.base.out" "$temp_dir/$label.instrumented.out"; then echo 'stdout: PASS'; else echo 'stdout: FAIL'; ok=0; fi
    if diff -u "$temp_dir/$label.base.err" "$temp_dir/$label.instrumented.err"; then echo 'stderr: PASS'; else echo 'stderr: FAIL'; ok=0; fi
    if [[ "$(<"$temp_dir/$label.base.code")" == "$(<"$temp_dir/$label.instrumented.code")" ]]; then echo 'exit status: PASS'; else echo 'exit status: FAIL'; ok=0; fi
    echo
  } >> "$results_dir/semantic-diff.txt"
  [[ $ok == 1 ]] || fail "$fixture changed PHP semantics"
}

check_opcode_shape() {
  php -d opcache.enable_cli=1 -d opcache.jit=0 -d opcache.opt_debug_level=0x10000 \
    "$phase_dir/fixtures/opcode_shape.php" > "$results_dir/raw-opcodes.txt" 2>&1
  local required
  for required in \
    'FETCH_IS (global) string("_GET")' \
    'FETCH_IS (global) string("_POST")' \
    'FETCH_IS (global) string("_REQUEST")' \
    'FETCH_IS (global) string("_COOKIE")' \
    'FETCH_DIM_IS T0 string("name")' \
    'FETCH_DIM_IS T1 CV0($runtimeKey)' \
    'ISSET_ISEMPTY_DIM_OBJ (isset) T0 string("name")' \
    'ISSET_ISEMPTY_DIM_OBJ (empty) T0 string("name")' \
    'FETCH_DIM_IS T0 string("settings")' \
    'ISSET_ISEMPTY_DIM_OBJ (isset) T1 string("email")' \
    'ISSET_ISEMPTY_DIM_OBJ (empty) T1 string("email")'; do
    grep -Fq "$required" "$results_dir/raw-opcodes.txt" || fail "Required PHP 8.2.10 opcode shape was absent: $required. See raw-opcodes.txt."
  done
  cat > "$results_dir/opcode-analysis.md" <<'EOF'
# Phase 4 opcode analysis

PHP 8.2.10 OPcache debug output shows `ZEND_FETCH_IS (global)` for exact silent superglobal loads. Its constant `op1` is `_GET`, `_POST`, `_REQUEST`, or `_COOKIE`; the result temporary becomes the provenance root.

`ZEND_FETCH_DIM_IS` contains the dimension key in `op2`: a literal is an opcode constant and a runtime key is a CV operand such as `CV0($runtimeKey)`. Its `op1` is the preceding fetch/dimension result. For `$_POST['settings']['email'] ?? null`, the chain is `T0 = FETCH_IS _POST`, `T1 = FETCH_DIM_IS T0 "settings"`, then `T2 = FETCH_DIM_IS T1 "email"`.

`ZEND_ISSET_ISEMPTY_DIM_OBJ` consumes the tracked container temporary in `op1`; nested `isset`/`empty` therefore use the `FETCH_DIM_IS` result (`T1`) as their container. Its dump metadata distinguishes `(isset)` from `(empty)`; in the runtime handler this is `opline->extended_value & ZEND_ISEMPTY`.

Literal and runtime keys differ only in their `op2` storage, not in the container/result chain. The handler runs before PHP's original handler and reads `op2` through `zend_get_zval_ptr`; it accepts only an already-string or already-integer zval, copies the scalar key, and otherwise emits an unmapped event without coercion or conversion.

`FETCH_DIM_IS` alone cannot prove whether a silent intermediate belongs to coalesce, nested `isset`, or nested `empty`, so Phase 4 records `access_context: "silent_read"`. Terminal `ISSET_ISEMPTY_DIM_OBJ` events are recorded exactly as `isset` or `empty`.
EOF
}

check_registered_scope() {
  php --ri hookphuzz_opcode > "$temp_dir/module-info.txt" 2>&1
  grep -Fq 'configured user opcodes => ZEND_FETCH_R, ZEND_FETCH_DIM_R, ZEND_FETCH_IS, ZEND_FETCH_DIM_IS, ZEND_ISSET_ISEMPTY_DIM_OBJ' "$temp_dir/module-info.txt" \
    || fail 'module handler scope mismatch'
  local actual
  actual="$(grep -o 'zend_set_user_opcode_handler(ZEND_[A-Z_]*' "$phase_dir/extension/hookphuzz_opcode.c" | sort -u | tr '\n' ' ')"
  [[ "$actual" == 'zend_set_user_opcode_handler(ZEND_FETCH_DIM_IS zend_set_user_opcode_handler(ZEND_FETCH_DIM_R zend_set_user_opcode_handler(ZEND_FETCH_IS zend_set_user_opcode_handler(ZEND_FETCH_R zend_set_user_opcode_handler(ZEND_ISSET_ISEMPTY_DIM_OBJ ' ]] \
    || fail 'source registers an unexpected opcode'
}

run_inside() {
  mkdir -p "$results_dir"
  temp_dir="$(mktemp -d)"
  trap 'rm -rf "$temp_dir"' EXIT
  check_opcode_shape
  check_registered_scope
  for fixture in "$phase_dir"/fixtures/*.php; do php -l "$fixture" >/dev/null; done

  run_event_fixture positive_events.php positive-events.json positive
  run_event_fixture silent_context_events.php silent-context-events.json silent
  run_event_fixture phase3_regression_events.php phase3-regression-events.json phase3

  capture "$temp_dir/phase3-control.out" "$temp_dir/phase3-control.err" "$temp_dir/phase3-control.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/phase3_control_events.php"
  [[ "$(<"$temp_dir/phase3-control.code")" == 0 && "$(tail -n 1 "$temp_dir/phase3-control.out")" == '[]' ]] \
    || fail 'Phase 3 direct-read controls emitted mapped events'

  capture "$temp_dir/negative.out" "$temp_dir/negative.err" "$temp_dir/negative.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/negative_events.php"
  [[ "$(<"$temp_dir/negative.code")" == 0 ]] || fail 'negative controls failed'
  [[ "$(tail -n 1 "$temp_dir/negative.out")" == '[]' ]] || fail 'negative controls emitted mapped request events'

  : > "$results_dir/semantic-diff.txt"
  compare_semantics semantic_matrix.php semantic-matrix
  compare_semantics phase3_missing_read.php phase3-missing-read
  compare_semantics phase3_unsupported_key.php phase3-unsupported-key
  grep -Fq '"to_string_calls":0' "$temp_dir/semantic-matrix.base.out" || fail '__toString was called in baseline semantic fixture'
  grep -Fq '"to_string_calls":0' "$temp_dir/semantic-matrix.instrumented.out" || fail 'extension called __toString'
  if grep -q TOSTRING_CALLED "$temp_dir/phase3-unsupported-key.base.out" "$temp_dir/phase3-unsupported-key.base.err" \
      "$temp_dir/phase3-unsupported-key.instrumented.out" "$temp_dir/phase3-unsupported-key.instrumented.err"; then
    fail 'direct-read object key invoked __toString'
  fi
  grep -Fq 'Undefined array key "missing"' "$temp_dir/phase3-missing-read.base.out" "$temp_dir/phase3-missing-read.base.err" || fail 'Phase 3 missing-key warning absent in baseline'

  capture "$temp_dir/limit.out" "$temp_dir/limit.err" "$temp_dir/limit.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/event_limit.php"
  [[ "$(<"$temp_dir/limit.code")" == 0 && "$(head -n 1 "$temp_dir/limit.out")" == 4096 && "$(sed -n '2p' "$temp_dir/limit.out")" == 1 ]] || fail 'event limit counters failed'
  tail -n 1 "$temp_dir/limit.out" > "$temp_dir/limit.events.json"
  php -n -r '$e=json_decode(file_get_contents($argv[1]),true,512,JSON_THROW_ON_ERROR); exit(count($e)===4096 && $e[0]["key"]==="x" && $e[4095]["key"]==="x" && $e[0]["access_context"]==="read" ? 0 : 1);' "$temp_dir/limit.events.json" \
    || fail 'event limit event data failed'
  printf 'Stored events: 4096\nDropped events: 1\nAccess context: read\nStatus: PASS\n' > "$results_dir/event-limit.txt"

  run_event_fixture frame_isolation.php frame-isolation-events.json frame
  printf 'Repeated function calls: PASS\nNested frame: PASS\nRecursion: PASS\nCompleted-frame provenance cleanup: fcall end observer\nStatus: PASS\n' > "$results_dir/frame-isolation.txt"

  capture "$temp_dir/reset-first.out" "$temp_dir/reset-first.err" "$temp_dir/reset-first.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/positive_events.php"
  capture "$temp_dir/reset-second.out" "$temp_dir/reset-second.err" "$temp_dir/reset-second.code" \
    php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/negative_events.php"
  [[ "$(<"$temp_dir/reset-first.code")" == 0 && "$(<"$temp_dir/reset-second.code")" == 0 && "$(tail -n 1 "$temp_dir/reset-second.out")" == '[]' ]] \
    || fail 'request reset failed'

  local failures=0 iteration fixture
  : > "$results_dir/stability-loop.txt"
  for iteration in $(seq 1 100); do
    for fixture in phase3_regression_events.php silent_context_events.php semantic_matrix.php frame_isolation.php; do
      capture "$temp_dir/stability.out" "$temp_dir/stability.err" "$temp_dir/stability.code" \
        php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/fixtures/$fixture"
      if [[ "$(<"$temp_dir/stability.code")" != 0 ]]; then
        printf 'iteration %s fixture %s exit %s\n' "$iteration" "$fixture" "$(<"$temp_dir/stability.code")" >> "$results_dir/stability-loop.txt"
        failures=$((failures + 1))
      fi
    done
  done
  printf 'Processes run: 400\nFailures: %s\nStatus: %s\n' "$failures" "$([[ $failures == 0 ]] && echo PASS || echo FAIL)" >> "$results_dir/stability-loop.txt"
  [[ $failures == 0 ]] || fail 'stability loop failed'

  cat > "$results_dir/phase4-summary.md" <<'EOF'
# HookPhuzz opcode Phase 4 summary

## Status

PHASE_4_PASS

## Environment

PHP 8.2.10 CLI in Docker; OPcache compiler debug enabled only for opcode evidence; JIT disabled for all checks.

## Test results

| Expected | Actual | Status |
| --- | --- | --- |
| Phase 3 direct reads, runtime/int/nested paths, controls and missing warning | exact prior attribution and unchanged semantics | PASS |
| Coalesce literal/runtime | `FETCH_IS` + `FETCH_DIM_IS`, exact path | PASS |
| isset literal/runtime | `ISSET_ISEMPTY_DIM_OBJ (isset)`, exact path | PASS |
| empty literal/runtime | `ISSET_ISEMPTY_DIM_OBJ (empty)`, exact path | PASS |
| Nested coalesce/isset/empty | temporary-slot path propagation | PASS |
| GET/POST/REQUEST/COOKIE | exact uppercase source attribution | PASS |
| Local/fake/case/property/ArrayAccess controls | zero mapped events | PASS |
| Semantics and __toString | zero unexpected differences; zero extension conversions | PASS |
| Event cap/reset/frame isolation | 4096 stored, 1 dropped; zero cross-process/frame leakage | PASS |
| Stability | 400 bounded process executions, zero failures | PASS |

## Registered user opcodes

`ZEND_FETCH_R`, `ZEND_FETCH_DIM_R`, `ZEND_FETCH_IS`, `ZEND_FETCH_DIM_IS`, and `ZEND_ISSET_ISEMPTY_DIM_OBJ` only.
EOF
}

run_host() {
  clear_evidence
  if ! timeout 300s "${compose[@]}" build; then
    write_summary PHASE_4_NOT_PASS 'Docker build failed or timed out.'
    exit 1
  fi
  timeout 300s "${compose[@]}" run --rm phase4
}

if [[ "${1:-}" == --inside ]]; then run_inside; else run_host; fi
