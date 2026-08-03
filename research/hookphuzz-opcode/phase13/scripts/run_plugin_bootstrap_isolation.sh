#!/usr/bin/env bash
set -Eeuo pipefail
[[ $# -eq 4 ]] || { echo "usage: $0 <slug> <zip> <version> <sha256>" >&2; exit 2; }
slug=$1 zip=$2 version=$3 checksum=$4
phase_dir=$(cd "$(dirname "$0")/.." && pwd)
run_id="phase13-${slug}-bootstrap-$(date -u +%Y%m%dT%H%M%SZ)-$$"
results="$phase_dir/results/$run_id"; project="hookphuzz-phase13-${slug}-${run_id,,}"; project=${project:0:63}; mkdir -p "$results"
export PHASE13_PLUGIN_ZIP="$zip" PHASE13_PLUGIN_SLUG="$slug" PHASE13_PLUGIN_VERSION="$version" PHASE13_PLUGIN_SHA256="$checksum" PHASE13_LOCAL_PASSWORD="local-$run_id" PHASE13_RESULTS_DIR="/results/$run_id" PHASE13_RUN_ID="$run_id"
compose=(docker compose --project-name "$project" --file "$phase_dir/docker-compose.yml")
redact() { sed -E 's/((password|pwd|nonce|cookie|authorization)[=:])[[:graph:]]+/\1<redacted>/Ig'; }
cleanup() { set +e; "${compose[@]}" down --volumes --remove-orphans >"$results/cleanup.raw" 2>&1; code=$?; redact <"$results/cleanup.raw" >"$results/cleanup.log"; rm -f "$results/cleanup.raw"; printf '{"exit_code":%s,"project":"%s"}\n' "$code" "$project" >"$results/cleanup-result.json"; }
trap cleanup EXIT
timeout 300s docker build --pull=false -t hookphuzz-phase13:local -f "$phase_dir/Dockerfile" "$(cd "$phase_dir/../../.." && pwd)" >"$results/build.log" 2>&1
"${compose[@]}" up -d --no-build >"$results/compose-up.log" 2>&1
set +e; timeout 240s "${compose[@]}" exec -T web bash /opt/bootstrap_plugin.sh >"$results/bootstrap.raw" 2>&1; code=$?; set -e
redact <"$results/bootstrap.raw" >"$results/bootstrap.log"; rm -f "$results/bootstrap.raw"
"${compose[@]}" ps --all >"$results/compose-ps.txt" 2>&1 || true; "${compose[@]}" logs --no-color web 2>&1 | redact >"$results/web.log" || true
web_id=$("${compose[@]}" ps -q web || true); exit_code=null; [[ -n "$web_id" ]] && exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$web_id")
printf '{"run_id":"%s","plugin":"%s","bootstrap_exit_code":%s,"web_exit_code":%s,"project":"%s"}\n' "$run_id" "$slug" "$code" "$exit_code" "$project" >"$results/host-diagnostics.json"
exit "$code"
