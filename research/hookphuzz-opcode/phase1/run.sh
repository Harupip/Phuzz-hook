#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase1 -f "$phase_dir/docker-compose.yml")
evidence_files=(
    environment.txt build.log module-info.txt php-lint.txt fetch-dim-r-count.txt
    control-no-dimension.txt request-reset.txt semantics-baseline.stdout.txt
    semantics-baseline.stderr.txt semantics-instrumented.stdout.txt
    semantics-instrumented.stderr.txt semantics-diff.txt missing-key-semantics.txt
    stability-loop.txt phase1-summary.md
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
    cat > "$results_dir/phase1-summary.md" <<EOF
# HookPhuzz opcode Phase 1 summary

## Status

PHASE_1_FAIL

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

    # Capture expected and unexpected command exits so comparisons can inspect them.
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

assert_fetch_output() {
    local stdout_file="$1"
    local stderr_file="$2"
    local exit_file="$3"
    local expected_label="$4"
    local expected_count="$5"
    local -a lines

    mapfile -t lines < "$stdout_file"
    [[ "$(<"$exit_file")" == "0" ]] || return 1
    [[ ! -s "$stderr_file" ]] || return 1
    [[ "${lines[0]:-}" == "$expected_label" ]] || return 1
    [[ "${lines[1]:-}" =~ ^[0-9]+$ ]] || return 1
    [[ "${#lines[@]}" == "2" ]] || return 1

    if [[ "$expected_count" == "positive" ]]; then
        (( lines[1] > 0 ))
    else
        [[ "${lines[1]}" == "$expected_count" ]]
    fi
}

run_inside_container() {
    clear_evidence true

    local temp_dir
    temp_dir="$(mktemp -d)"
    trap "rm -rf '$temp_dir'" EXIT

    {
        echo 'Docker image: php:8.2.10-cli'
        echo
        echo "PHP version:"
        php -v
        echo
        echo "Zend Engine version:"
        php -r 'echo zend_version(), PHP_EOL;'
        echo
        echo "Extension load status:"
        php -r 'echo extension_loaded("hookphuzz_opcode") ? "loaded" : "not loaded"; echo PHP_EOL;'
        echo
        echo "OPcache and JIT status with normal test flags:"
        php -d opcache.enable_cli=0 -d opcache.jit=0 -r 'printf("Zend OPcache loaded: %s\n", extension_loaded("Zend OPcache") ? "yes" : "no"); printf("opcache.enable_cli: %s\n", ini_get("opcache.enable_cli")); printf("opcache.jit: %s\n", ini_get("opcache.jit"));'
    } > "$results_dir/environment.txt" 2>&1

    run_capture "$temp_dir/modules.stdout" "$temp_dir/modules.stderr" "$temp_dir/modules.exit" php -m
    run_capture "$temp_dir/module-info.stdout" "$temp_dir/module-info.stderr" "$temp_dir/module-info.exit" php --ri hookphuzz_opcode
    {
        append_capture "php -m" "$temp_dir/modules.stdout" "$temp_dir/modules.stderr" "$temp_dir/modules.exit"
        append_capture "php --ri hookphuzz_opcode" "$temp_dir/module-info.stdout" "$temp_dir/module-info.stderr" "$temp_dir/module-info.exit"
    } > "$results_dir/module-info.txt"
    [[ "$(<"$temp_dir/modules.exit")" == "0" ]] || fail "php -m failed; see module-info.txt"
    grep -qx 'hookphuzz_opcode' "$temp_dir/modules.stdout" || fail "hookphuzz_opcode is absent from php -m; see module-info.txt"
    [[ "$(<"$temp_dir/module-info.exit")" == "0" ]] || fail "php --ri hookphuzz_opcode failed; see module-info.txt"

    {
        for test_file in "$phase_dir"/tests/*.php; do
            php -l "$test_file"
        done
    } > "$results_dir/php-lint.txt" 2>&1

    run_capture "$temp_dir/fetch.stdout" "$temp_dir/fetch.stderr" "$temp_dir/fetch.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/fetch_dim_r_count.php"
    append_capture "FETCH_DIM_R counter" "$temp_dir/fetch.stdout" "$temp_dir/fetch.stderr" "$temp_dir/fetch.exit" > "$results_dir/fetch-dim-r-count.txt"
    assert_fetch_output "$temp_dir/fetch.stdout" "$temp_dir/fetch.stderr" "$temp_dir/fetch.exit" alice positive || fail "FETCH_DIM_R counter test failed; see fetch-dim-r-count.txt"

    run_capture "$temp_dir/control.stdout" "$temp_dir/control.stderr" "$temp_dir/control.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/control_no_dimension.php"
    append_capture "control without dimension read" "$temp_dir/control.stdout" "$temp_dir/control.stderr" "$temp_dir/control.exit" > "$results_dir/control-no-dimension.txt"
    assert_fetch_output "$temp_dir/control.stdout" "$temp_dir/control.stderr" "$temp_dir/control.exit" control 0 || fail "control counter was not zero; see control-no-dimension.txt"

    run_capture "$temp_dir/reset-first.stdout" "$temp_dir/reset-first.stderr" "$temp_dir/reset-first.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/fetch_dim_r_count.php"
    run_capture "$temp_dir/reset-second.stdout" "$temp_dir/reset-second.stderr" "$temp_dir/reset-second.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/control_no_dimension.php"
    {
        append_capture "first CLI process" "$temp_dir/reset-first.stdout" "$temp_dir/reset-first.stderr" "$temp_dir/reset-first.exit"
        append_capture "second CLI process" "$temp_dir/reset-second.stdout" "$temp_dir/reset-second.stderr" "$temp_dir/reset-second.exit"
    } > "$results_dir/request-reset.txt"
    assert_fetch_output "$temp_dir/reset-first.stdout" "$temp_dir/reset-first.stderr" "$temp_dir/reset-first.exit" alice positive || fail "request-reset first process failed; see request-reset.txt"
    assert_fetch_output "$temp_dir/reset-second.stdout" "$temp_dir/reset-second.stderr" "$temp_dir/reset-second.exit" control 0 || fail "counter did not reset for the second process; see request-reset.txt"

    run_capture "$results_dir/semantics-baseline.stdout.txt" "$results_dir/semantics-baseline.stderr.txt" "$temp_dir/semantics-baseline.exit" php -n -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/semantics.php"
    run_capture "$results_dir/semantics-instrumented.stdout.txt" "$results_dir/semantics-instrumented.stderr.txt" "$temp_dir/semantics-instrumented.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/semantics.php"
    local semantics_ok=1
    {
        printf 'Baseline exit code: %s\nInstrumented exit code: %s\n\n' "$(<"$temp_dir/semantics-baseline.exit")" "$(<"$temp_dir/semantics-instrumented.exit")"
        if diff -u "$results_dir/semantics-baseline.stdout.txt" "$results_dir/semantics-instrumented.stdout.txt"; then
            echo 'stdout: PASS'
        else
            semantics_ok=0
        fi
        if diff -u "$results_dir/semantics-baseline.stderr.txt" "$results_dir/semantics-instrumented.stderr.txt"; then
            echo 'stderr: PASS'
        else
            semantics_ok=0
        fi
        if [[ "$(<"$temp_dir/semantics-baseline.exit")" == "$(<"$temp_dir/semantics-instrumented.exit")" ]]; then
            echo 'exit code: PASS'
        else
            echo 'exit code: FAIL'
            semantics_ok=0
        fi
    } > "$results_dir/semantics-diff.txt"
    (( semantics_ok )) || fail "baseline and instrumented semantics differ; see semantics-diff.txt"

    run_capture "$temp_dir/missing-baseline.stdout" "$temp_dir/missing-baseline.stderr" "$temp_dir/missing-baseline.exit" php -n -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/missing_key.php"
    run_capture "$temp_dir/missing-instrumented.stdout" "$temp_dir/missing-instrumented.stderr" "$temp_dir/missing-instrumented.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/missing_key.php"
    local missing_ok=1
    {
        append_capture "baseline" "$temp_dir/missing-baseline.stdout" "$temp_dir/missing-baseline.stderr" "$temp_dir/missing-baseline.exit"
        append_capture "instrumented" "$temp_dir/missing-instrumented.stdout" "$temp_dir/missing-instrumented.stderr" "$temp_dir/missing-instrumented.exit"
        echo '## Comparison'
        if diff -u "$temp_dir/missing-baseline.stdout" "$temp_dir/missing-instrumented.stdout"; then
            echo 'stdout: PASS'
        else
            missing_ok=0
        fi
        if diff -u "$temp_dir/missing-baseline.stderr" "$temp_dir/missing-instrumented.stderr"; then
            echo 'stderr: PASS'
        else
            missing_ok=0
        fi
        if [[ "$(<"$temp_dir/missing-baseline.exit")" == "$(<"$temp_dir/missing-instrumented.exit")" ]]; then
            echo 'exit code: PASS'
        else
            echo 'exit code: FAIL'
            missing_ok=0
        fi
        if grep -q 'Undefined array key' "$temp_dir/missing-baseline.stdout" "$temp_dir/missing-baseline.stderr" \
            && grep -q 'Undefined array key' "$temp_dir/missing-instrumented.stdout" "$temp_dir/missing-instrumented.stderr" \
            && grep -qx 'NULL' "$temp_dir/missing-baseline.stdout" \
            && grep -qx 'NULL' "$temp_dir/missing-instrumented.stdout"; then
            echo 'warning and NULL: PASS'
        else
            echo 'warning and NULL: FAIL'
            missing_ok=0
        fi
    } > "$results_dir/missing-key-semantics.txt"
    (( missing_ok )) || fail "missing-key semantics differ; see missing-key-semantics.txt"

    local stability_failures=0
    local iteration
    : > "$results_dir/stability-loop.txt"
    for iteration in $(seq 1 100); do
        run_capture "$temp_dir/stability-${iteration}.stdout" "$temp_dir/stability-${iteration}.stderr" "$temp_dir/stability-${iteration}.exit" php -d opcache.enable_cli=0 -d opcache.jit=0 "$phase_dir/tests/fetch_dim_r_count.php"
        if ! assert_fetch_output "$temp_dir/stability-${iteration}.stdout" "$temp_dir/stability-${iteration}.stderr" "$temp_dir/stability-${iteration}.exit" alice positive; then
            stability_failures=$((stability_failures + 1))
            printf 'iteration %s failed with exit %s\n' "$iteration" "$(<"$temp_dir/stability-${iteration}.exit")" >> "$results_dir/stability-loop.txt"
        fi
    done
    {
        printf 'Processes run: 100\n'
        printf 'Failures: %s\n' "$stability_failures"
        if (( stability_failures == 0 )); then
            echo 'Status: PASS'
        else
            echo 'Status: FAIL'
        fi
    } >> "$results_dir/stability-loop.txt"
    (( stability_failures == 0 )) || fail "stability loop had failures; see stability-loop.txt"

    cat > "$results_dir/phase1-summary.md" <<'EOF'
# HookPhuzz opcode Phase 1 summary

## Status

PHASE_1_PASS

The isolated extension built and loaded on PHP 8.2.10 CLI. It counted only runtime `ZEND_FETCH_DIM_R` invocations, dispatched execution to Zend's original handler, preserved the tested semantics, and completed 100 separate CLI processes without failure.
EOF
}

run_host() {
    clear_evidence
    if ! "${compose[@]}" build > "$results_dir/build.log" 2>&1; then
        write_failure_summary "Docker image build failed; see build.log"
        cat "$results_dir/build.log"
        exit 1
    fi

    set +e
    "${compose[@]}" run --rm phase1
    local status=$?
    set -e
    if (( status != 0 )); then
        if [[ ! -f "$results_dir/phase1-summary.md" ]]; then
            write_failure_summary "Phase 1 container exited with status $status"
        fi
        exit "$status"
    fi
}

if [[ "${1:-}" == "--inside" ]]; then
    run_inside_container
else
    run_host
fi
