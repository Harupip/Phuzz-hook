#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase2 -f "$phase_dir/docker-compose.yml")
evidence_files=(
    environment.txt build.log module-info.txt php-lint.txt
    literal-key-events.json cv-key-events.json integer-key-events.json runtime-integer-key-events.json
    nested-key-events.json runtime-nested-key-events.json missing-key-events.json control-events.json
    unsupported-key-events.json event-limit-events.json event-limit.txt request-reset.txt
    missing-key-baseline.stdout.txt missing-key-baseline.stderr.txt
    missing-key-instrumented.stdout.txt missing-key-instrumented.stderr.txt missing-key-semantics-diff.txt
    semantics-baseline.stdout.txt semantics-baseline.stderr.txt
    semantics-instrumented.stdout.txt semantics-instrumented.stderr.txt semantics-diff.txt
    stability-loop.txt phase2-summary.md
)

clear_evidence() {
    local preserve_build_log="${1:-false}"
    mkdir -p "$results_dir"
    local file
    for file in "${evidence_files[@]}"; do
        if [[ "$preserve_build_log" == "true" && "$file" == "build.log" ]]; then
            continue
        fi
        rm -f "$results_dir/$file"
    done
}

write_failure_summary() {
    local reason="$1"
    cat > "$results_dir/phase2-summary.md" <<EOF
# HookPhuzz opcode Phase 2 summary

## Status

PHASE_2_FAIL

## Failure

$reason
EOF
}

fail() {
    write_failure_summary "$1"
    exit 1
}

run_capture() {
    local stdout_file="$1"
    local stderr_file="$2"
    local exit_file="$3"
    shift 3

    set +e
    "$@" > "$stdout_file" 2> "$stderr_file"
    local status=$?
    set -e
    printf '%s\n' "$status" > "$exit_file"
}

append_capture() {
    local label="$1"
    local stdout_file="$2"
    local stderr_file="$3"
    local exit_file="$4"

    printf '## %s\n\nExit code: %s\n\n### stdout\n' "$label" "$(<"$exit_file")"
    cat "$stdout_file"
    printf '\n### stderr\n'
    cat "$stderr_file"
    printf '\n'
}

validate_events() {
    local event_file="$1"
    local case_name="$2"

    php -n -r '
        $events = json_decode(file_get_contents($argv[1]), true, 512, JSON_THROW_ON_ERROR);
        $case = $argv[2];
        $fail = static function (string $message): void { fwrite(STDERR, $message . PHP_EOL); exit(1); };
        $need = static function (bool $condition, string $message) use ($fail): void { if (!$condition) { $fail($message); } };
        $event = static function (array $events, int $index) use ($fail): array { return $events[$index] ?? $fail("missing event $index"); };
        $checkCommon = static function (array $item, int $sequence) use ($need): void {
            $need(($item["sequence"] ?? null) === $sequence, "unexpected sequence");
            $need(($item["opcode"] ?? null) === "ZEND_FETCH_DIM_R", "unexpected opcode");
            $need(is_string($item["filename"] ?? null) && $item["filename"] !== "", "missing filename");
            $need(is_int($item["line"] ?? null) && $item["line"] > 0, "missing line");
            $need(is_string($item["function"] ?? null) && $item["function"] !== "", "missing function");
            $need(is_string($item["op1_operand_type"] ?? null), "missing op1 operand type");
            $need(is_string($item["op2_operand_type"] ?? null), "missing op2 operand type");
        };
        $checkString = static function (array $item, string $key, string $operand) use ($need): void {
            $need(($item["container_zval_type"] ?? null) === "array", "container is not array");
            $need(($item["op2_operand_type"] ?? null) === $operand, "unexpected key operand type");
            $need(($item["key_zval_type"] ?? null) === "string", "key is not string");
            $need(($item["key_string"] ?? null) === $key, "unexpected string key");
            $need(($item["key_int"] ?? null) === null, "string key has integer value");
        };
        $checkInt = static function (array $item, string $operand) use ($need): void {
            $need(($item["container_zval_type"] ?? null) === "array", "container is not array");
            $need(($item["op2_operand_type"] ?? null) === $operand, "unexpected key operand type");
            $need(($item["key_zval_type"] ?? null) === "int", "key is not int");
            $need(($item["key_string"] ?? null) === null, "integer key has string value");
            $need(($item["key_int"] ?? null) === 10, "unexpected integer key");
        };

        if (!is_array($events)) { $fail("events are not an array"); }
        switch ($case) {
            case "literal":
                $need(count($events) === 1, "literal event count");
                $item = $event($events, 0); $checkCommon($item, 1); $checkString($item, "username", "CONST");
                break;
            case "cv":
                $need(count($events) === 1, "CV event count");
                $item = $event($events, 0); $checkCommon($item, 1); $checkString($item, "username", "CV");
                break;
            case "integer":
                $need(count($events) === 1, "integer event count");
                $item = $event($events, 0); $checkCommon($item, 1); $checkInt($item, "CONST");
                break;
            case "runtime-integer":
                $need(count($events) === 1, "runtime integer event count");
                $item = $event($events, 0); $checkCommon($item, 1); $checkInt($item, "CV");
                break;
            case "nested":
                $need(count($events) === 2, "nested event count");
                $first = $event($events, 0); $second = $event($events, 1);
                $checkCommon($first, 1); $checkCommon($second, 2);
                $checkString($first, "user", "CONST"); $checkString($second, "name", "CONST");
                break;
            case "runtime-nested":
                $need(count($events) === 2, "runtime nested event count");
                $first = $event($events, 0); $second = $event($events, 1);
                $checkCommon($first, 1); $checkCommon($second, 2);
                $checkString($first, "user", "CV"); $checkString($second, "name", "CV");
                break;
            case "missing":
                $need(count($events) === 1, "missing-key event count");
                $item = $event($events, 0); $checkCommon($item, 1); $checkString($item, "missing", "CONST");
                break;
            case "control":
                $need(count($events) === 0, "control produced events");
                break;
            case "unsupported":
                $need(count($events) === 1, "unsupported-key event count");
                $item = $event($events, 0); $checkCommon($item, 1);
                $need(($item["container_zval_type"] ?? null) === "array", "unsupported container is not array");
                $need(($item["op2_operand_type"] ?? null) === "CV", "unsupported key is not CV");
                $need(($item["key_zval_type"] ?? null) === "object", "unsupported key is not object");
                $need(($item["key_string"] ?? null) === null && ($item["key_int"] ?? null) === null, "unsupported key was copied");
                break;
            case "limit":
                $need(count($events) === 4096, "event limit count");
                $first = $event($events, 0); $last = $event($events, 4095);
                $checkCommon($first, 1); $checkCommon($last, 4096);
                $checkString($first, "x", "CONST"); $checkString($last, "x", "CONST");
                break;
            default:
                $fail("unknown event validation case");
        }
    ' "$event_file" "$case_name"
}

run_event_fixture() {
    local fixture="$1"
    local event_file="$2"
    local case_name="$3"
    local expected_first_line="$4"
    local stdout_file="$temp_dir/${case_name}.stdout"
    local stderr_file="$temp_dir/${case_name}.stderr"
    local exit_file="$temp_dir/${case_name}.exit"

    run_capture "$stdout_file" "$stderr_file" "$exit_file" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
    [[ "$(<"$exit_file")" == "0" ]] || fail "$fixture failed; see raw output in runner failure"
    if [[ "$expected_first_line" != '__ANY__' ]]; then
        [[ "$(head -n 1 "$stdout_file")" == "$expected_first_line" ]] || fail "$fixture produced unexpected output"
    fi
    tail -n 1 "$stdout_file" > "$results_dir/$event_file"
    validate_events "$results_dir/$event_file" "$case_name" || fail "$fixture produced invalid event data; see $event_file"
}

compare_semantics() {
    local fixture="$1"
    local prefix="$2"
    local comparison_name="$3"
    local baseline_stdout="$results_dir/${prefix}-baseline.stdout.txt"
    local baseline_stderr="$results_dir/${prefix}-baseline.stderr.txt"
    local instrumented_stdout="$results_dir/${prefix}-instrumented.stdout.txt"
    local instrumented_stderr="$results_dir/${prefix}-instrumented.stderr.txt"
    local baseline_exit="$temp_dir/${prefix}-baseline.exit"
    local instrumented_exit="$temp_dir/${prefix}-instrumented.exit"
    local comparison="$results_dir/$comparison_name"
    local ok=1

    run_capture "$baseline_stdout" "$baseline_stderr" "$baseline_exit" php -n -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
    run_capture "$instrumented_stdout" "$instrumented_stderr" "$instrumented_exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
    {
        printf 'Baseline exit code: %s\nInstrumented exit code: %s\n\n' "$(<"$baseline_exit")" "$(<"$instrumented_exit")"
        if diff -u "$baseline_stdout" "$instrumented_stdout"; then echo 'stdout: PASS'; else ok=0; fi
        if diff -u "$baseline_stderr" "$instrumented_stderr"; then echo 'stderr: PASS'; else ok=0; fi
        if [[ "$(<"$baseline_exit")" == "$(<"$instrumented_exit")" ]]; then echo 'exit status: PASS'; else echo 'exit status: FAIL'; ok=0; fi
    } > "$comparison"
    (( ok )) || fail "$prefix semantic comparison failed; see $(basename "$comparison")"
}

run_inside_container() {
    clear_evidence true

    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT

    {
        echo 'Docker image: php:8.2.10-cli'
        echo
        echo 'PHP version:'
        php -v
        echo
        echo 'Zend Engine version:'
        php -r 'echo zend_version(), PHP_EOL;'
        echo
        echo 'Extension load status:'
        php -r 'echo extension_loaded("hookphuzz_opcode") ? "loaded" : "not loaded"; echo PHP_EOL;'
        echo
        echo 'OPcache and JIT status with semantic test flags:'
        php -d opcache.enable_cli=0 -d opcache.jit=0 -r 'printf("Zend OPcache loaded: %s\n", extension_loaded("Zend OPcache") ? "yes" : "no"); printf("opcache.enable_cli: %s\n", ini_get("opcache.enable_cli")); printf("opcache.jit: %s\n", ini_get("opcache.jit"));'
    } > "$results_dir/environment.txt" 2>&1

    run_capture "$temp_dir/modules.stdout" "$temp_dir/modules.stderr" "$temp_dir/modules.exit" php -m
    run_capture "$temp_dir/module-info.stdout" "$temp_dir/module-info.stderr" "$temp_dir/module-info.exit" php --ri hookphuzz_opcode
    {
        append_capture 'php -m' "$temp_dir/modules.stdout" "$temp_dir/modules.stderr" "$temp_dir/modules.exit"
        append_capture 'php --ri hookphuzz_opcode' "$temp_dir/module-info.stdout" "$temp_dir/module-info.stderr" "$temp_dir/module-info.exit"
    } > "$results_dir/module-info.txt"
    [[ "$(<"$temp_dir/modules.exit")" == "0" ]] || fail 'php -m failed; see module-info.txt'
    grep -qx 'hookphuzz_opcode' "$temp_dir/modules.stdout" || fail 'hookphuzz_opcode is absent from php -m; see module-info.txt'
    [[ "$(<"$temp_dir/module-info.exit")" == "0" ]] || fail 'php --ri hookphuzz_opcode failed; see module-info.txt'

    {
        for test_file in "$phase_dir"/tests/*.php; do php -l "$test_file"; done
    } > "$results_dir/php-lint.txt" 2>&1

    run_event_fixture literal_key_events.php literal-key-events.json literal alice
    run_event_fixture cv_key_events.php cv-key-events.json cv alice
    run_event_fixture integer_key_events.php integer-key-events.json integer ten
    run_event_fixture runtime_integer_key_events.php runtime-integer-key-events.json runtime-integer ten
    run_event_fixture nested_key_events.php nested-key-events.json nested alice
    run_event_fixture runtime_nested_key_events.php runtime-nested-key-events.json runtime-nested alice
    run_event_fixture missing_key_events.php missing-key-events.json missing __ANY__
    run_event_fixture control_events.php control-events.json control control
    run_event_fixture unsupported_key_events.php unsupported-key-events.json unsupported 'caught:TypeError'

    if grep -q 'TOSTRING_CALLED' "$temp_dir/unsupported.stdout" "$temp_dir/unsupported.stderr"; then
        fail 'unsupported key triggered __toString; see unsupported-key-events.json'
    fi

    run_capture "$temp_dir/limit.stdout" "$temp_dir/limit.stderr" "$temp_dir/limit.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/event_limit_events.php"
    [[ "$(<"$temp_dir/limit.exit")" == "0" ]] || fail 'event limit fixture failed'
    [[ "$(head -n 1 "$temp_dir/limit.stdout")" == '4097' ]] || fail 'event limit count was not 4097'
    [[ "$(sed -n '2p' "$temp_dir/limit.stdout")" == '1' ]] || fail 'event limit dropped count was not 1'
    tail -n 1 "$temp_dir/limit.stdout" > "$results_dir/event-limit-events.json"
    validate_events "$results_dir/event-limit-events.json" limit || fail 'event limit data was invalid'
    printf 'Recorded events: 4096\nDropped events: 1\nStatus: PASS\n' > "$results_dir/event-limit.txt"

    compare_semantics semantics.php semantics semantics-diff.txt
    compare_semantics missing_key.php missing-key missing-key-semantics-diff.txt
    if ! grep -q 'Undefined array key "missing"' "$results_dir/missing-key-baseline.stdout.txt" "$results_dir/missing-key-baseline.stderr.txt" \
        || ! grep -q 'Undefined array key "missing"' "$results_dir/missing-key-instrumented.stdout.txt" "$results_dir/missing-key-instrumented.stderr.txt"; then
        fail 'missing-key warning was absent; see missing-key-semantics-diff.txt'
    fi

    run_capture "$temp_dir/reset-first.stdout" "$temp_dir/reset-first.stderr" "$temp_dir/reset-first.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/literal_key_events.php"
    run_capture "$temp_dir/reset-second.stdout" "$temp_dir/reset-second.stderr" "$temp_dir/reset-second.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/control_events.php"
    {
        append_capture 'first CLI request' "$temp_dir/reset-first.stdout" "$temp_dir/reset-first.stderr" "$temp_dir/reset-first.exit"
        append_capture 'second CLI request' "$temp_dir/reset-second.stdout" "$temp_dir/reset-second.stderr" "$temp_dir/reset-second.exit"
    } > "$results_dir/request-reset.txt"
    [[ "$(<"$temp_dir/reset-first.exit")" == "0" && "$(<"$temp_dir/reset-second.exit")" == "0" ]] || fail 'request reset process failed; see request-reset.txt'
    tail -n 1 "$temp_dir/reset-second.stdout" > "$temp_dir/reset-second-events.json"
    validate_events "$temp_dir/reset-second-events.json" control || fail 'request state did not reset; see request-reset.txt'

    local stability_failures=0
    local fixture iteration
    : > "$results_dir/stability-loop.txt"
    for iteration in $(seq 1 100); do
        for fixture in literal_key_events.php cv_key_events.php nested_key_events.php missing_key.php; do
            run_capture "$temp_dir/stability.stdout" "$temp_dir/stability.stderr" "$temp_dir/stability.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/$fixture"
            if [[ "$(<"$temp_dir/stability.exit")" != "0" ]]; then
                stability_failures=$((stability_failures + 1))
                {
                    printf 'iteration %s fixture %s failed with exit %s\n' "$iteration" "$fixture" "$(<"$temp_dir/stability.exit")"
                    cat "$temp_dir/stability.stdout"
                    cat "$temp_dir/stability.stderr"
                } >> "$results_dir/stability-loop.txt"
            fi
        done
    done
    {
        printf 'Processes run: 400\n'
        printf 'Failures: %s\n' "$stability_failures"
        if (( stability_failures == 0 )); then echo 'Status: PASS'; else echo 'Status: FAIL'; fi
    } >> "$results_dir/stability-loop.txt"
    (( stability_failures == 0 )) || fail 'stability loop had failures; see stability-loop.txt'

    cat > "$results_dir/phase2-summary.md" <<'EOF'
# HookPhuzz opcode Phase 2 summary

## Status

PHASE_2_PASS

## Test results

| Expected | Actual | Status |
| --- | --- | --- |
| Literal string key, CONST, array container | `username` recorded | PASS |
| Runtime string key, CV, array container | `username` recorded | PASS |
| Literal and runtime integer key | `10` recorded as int | PASS |
| Nested and runtime nested order | `user`, then `name` | PASS |
| Missing-key semantics | stdout, stderr, exit status unchanged | PASS |
| Control | zero events | PASS |
| Request reset | second process has zero events | PASS |
| Event cap | 4096 stored, 1 dropped | PASS |
| Unsupported object key | object type only; no `__toString` | PASS |
| Stability | 400 separate PHP processes, no failures | PASS |

## Semantic safety

The extension registers only `ZEND_FETCH_DIM_R`, reads operands through PHP 8.2.10 `zend_get_zval_ptr()`, copies only stable metadata before dispatch, and always returns `ZEND_USER_OPCODE_DISPATCH`. It does not modify the opline, operands, result, or Zend VM behavior.

## Limitations

- No superglobal identification.
- No provenance tracking from `FETCH_R`.
- No key-to-HTTP-parameter mapping.
- No WordPress request artifact export.
- No HookPhuzz integration.
- Nested events do not establish nested HTTP provenance.
- This does not prove complete pure dynamic parameter discovery.
EOF
}

run_host() {
    clear_evidence
    if ! "${compose[@]}" build > "$results_dir/build.log" 2>&1; then
        write_failure_summary 'Docker image build failed; see build.log'
        cat "$results_dir/build.log"
        exit 1
    fi

    set +e
    "${compose[@]}" run --rm phase2
    local status=$?
    set -e
    if (( status != 0 )); then
        if [[ ! -f "$results_dir/phase2-summary.md" ]]; then
            write_failure_summary "Phase 2 container exited with status $status"
        fi
        exit "$status"
    fi
}

if [[ "${1:-}" == "--inside" ]]; then
    run_inside_container
else
    run_host
fi
