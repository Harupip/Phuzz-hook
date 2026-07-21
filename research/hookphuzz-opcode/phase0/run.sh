#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase0 -f "$phase_dir/docker-compose.yml")

run_inside_container() {
    mkdir -p "$results_dir"

    {
        echo "PHP version:"
        php -v
        echo
        echo "PHP modules:"
        php -m
        echo
        echo "OPcache and JIT:"
        if [[ "$OPCODE_DUMPER" == "opcache" ]]; then
            php -d opcache.enable_cli=1 -d opcache.jit=0 -d opcache.opt_debug_level=0x10000 -i | grep -E '^(Zend OPcache|opcache\.enable_cli|opcache\.jit|opcache\.opt_debug_level)' || true
        else
            php -i | grep -E '^(Zend OPcache|opcache\.enable_cli|opcache\.jit|opcache\.opt_debug_level)' || true
        fi
        echo
        echo "Opcode dumper: ${OPCODE_DUMPER:?OPCODE_DUMPER must be set}"
    } | tee "$results_dir/environment.txt"

    if [[ "$OPCODE_DUMPER" == "vld" ]]; then
        php -d vld.active=1 -d vld.execute=0 -d vld.verbosity=3 "$phase_dir/opcode_cases.php" > "$results_dir/raw-opcodes.txt" 2>&1
    else
        php -d opcache.enable_cli=1 -d opcache.jit=0 -d opcache.opt_debug_level=0x10000 "$phase_dir/opcode_cases.php" > "$results_dir/raw-opcodes.txt" 2>&1
    fi

    cat "$results_dir/raw-opcodes.txt"
    php "$phase_dir/runtime_cases.php" 2>&1 | tee "$results_dir/runtime-semantics.txt"
}

if [[ "${1:-}" == "--inside" ]]; then
    run_inside_container
    exit 0
fi

mkdir -p "$results_dir"
vld_log="$results_dir/vld-build.log"

if "${compose[@]}" build phase0-vld > "$vld_log" 2>&1; then
    "${compose[@]}" run --rm phase0-vld
    exit 0
fi

{
    echo
    echo "VLD image build failed; using OPcache debug output instead."
} >> "$vld_log"

if "${compose[@]}" build phase0-opcache >> "$vld_log" 2>&1; then
    "${compose[@]}" run --rm phase0-opcache
    exit 0
fi

echo "Exact PHP 8.2.10 image could not build for OPcache; retrying php:8.2-cli." >> "$vld_log"
PHP_IMAGE=php:8.2-cli "${compose[@]}" build phase0-opcache >> "$vld_log" 2>&1
PHP_IMAGE=php:8.2-cli "${compose[@]}" run --rm phase0-opcache
