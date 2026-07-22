#!/usr/bin/env bash
set -uo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-demo-generic-ajax -f "$phase_dir/docker-compose.yml")
command=${1:-all}

write_failure() {
  local reason=$1
  mkdir -p "$results_dir"
  rm -f "$results_dir"/*.json "$results_dir"/build.log "$results_dir"/docker-up.log "$results_dir"/final-verdict.txt
  printf '# HookPhuzz config flow\n\nStatus: **FAIL** (`%s`)\n' "$reason" > "$results_dir/config-flow.md"
  printf 'PHASE_DEMO_GENERIC_AJAX_FAIL\nREASON=%s\n' "$reason"
}

clean() {
  timeout 120s "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$results_dir"
}

run_all() {
  local run_id
  run_id="demo-$(date -u +%Y%m%dT%H%M%SZ)-$RANDOM"
  export HOOKPHUZZ_DEMO_RUN_ID="$run_id"

  if ! timeout 900s "${compose[@]}" build >"$results_dir/build.log" 2>&1; then
    write_failure BUILD_FAIL
    return 1
  fi
  if ! timeout 300s "${compose[@]}" up -d --wait --wait-timeout 280 wordpress >"$results_dir/docker-up.log" 2>&1; then
    write_failure WORDPRESS_NOT_READY
    return 1
  fi
  printf '[1/7] WordPress ready\n'
  if ! timeout 600s "${compose[@]}" run --rm -T verifier; then
    return 1
  fi
  return 0
}

case "$command" in
  clean)
    clean
    ;;
  all)
    clean
    mkdir -p "$results_dir"
    set +e
    run_all 2>&1 | tee "$results_dir/run.stdout.log"
    status=${PIPESTATUS[0]}
    exit "$status"
    ;;
  *)
    printf 'usage: %s [all|clean]\n' "$0" >&2
    exit 2
    ;;
esac
