#!/usr/bin/env bash
set -euo pipefail

phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
results_dir="$phase_dir/results"
compose=(docker compose -p hookphuzz-opcode-phase6 -f "$phase_dir/docker-compose.yml")

cleanup() {
  "${compose[@]}" down --volumes --remove-orphans > /dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup
rm -rf "$results_dir"
mkdir -p "$results_dir"

if ! timeout 900s "${compose[@]}" build > "$results_dir/docker-build.log" 2>&1; then
  printf 'PHASE_6_FAIL\nDocker build failed or timed out. See %s/docker-build.log\n' "$results_dir"
  exit 1
fi
if ! timeout 240s "${compose[@]}" up -d --wait --wait-timeout 220 enabled disabled > "$results_dir/docker-up.log" 2>&1; then
  printf 'PHASE_6_FAIL\nWordPress Apache startup failed or timed out. See %s/docker-up.log\n' "$results_dir"
  exit 1
fi

"${compose[@]}" exec -T enabled sh -c 'php -v; php -m; php --ri hookphuzz_opcode_phase5; wp core version --path=/var/www/html --allow-root; wp plugin is-active hookphuzz-phase6-fixture --path=/var/www/html --allow-root; mariadb --version; php -i | grep -E "opcache.enable|opcache.jit|request_order|variables_order"' > "$results_dir/extension-enabled.txt" 2>&1
"${compose[@]}" exec -T disabled sh -c 'php -v; php -m; (php --ri hookphuzz_opcode_phase5 || true); wp core version --path=/var/www/html --allow-root; wp plugin is-active hookphuzz-phase6-fixture --path=/var/www/html --allow-root; mariadb --version; php -i | grep -E "opcache.enable|opcache.jit|request_order|variables_order"' > "$results_dir/extension-disabled.txt" 2>&1
cat > "$results_dir/environment.txt" <<EOF
Image: php:8.2.10-apache
Runtime: Apache + mod_php in Docker
WordPress: 6.5.5
Database: MariaDB 10.11.8
JIT: disabled
OPcache: disabled
Extension source: phase6/extension copied from proven Phase 5 source
Artifact directory: /shared/opcode-events
EOF

if ! timeout 1200s "${compose[@]}" run --rm verifier > "$results_dir/verifier.log" 2>&1; then
  printf 'PHASE_6_FAIL\n'
  [[ -f "$results_dir/final-verdict.txt" ]] && cat "$results_dir/final-verdict.txt" || cat "$results_dir/verifier.log"
  exit 1
fi
printf '\nWordPress post-test version (enabled):\n' >> "$results_dir/environment.txt"
"${compose[@]}" exec -T enabled wp core version --path=/var/www/html --allow-root >> "$results_dir/environment.txt" 2>&1
printf 'WordPress post-test version (disabled):\n' >> "$results_dir/environment.txt"
"${compose[@]}" exec -T disabled wp core version --path=/var/www/html --allow-root >> "$results_dir/environment.txt" 2>&1
printf 'PHASE_6_PASS\n'
