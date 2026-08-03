#!/usr/bin/env bash
set -Eeuo pipefail

args=(--allow-root --path=/var/www/html)
result_dir=${PHASE13_RESULTS_DIR:?PHASE13_RESULTS_DIR is required}
step_dir="$result_dir/bootstrap-steps"
mkdir -p "$step_dir"
redact_step() {
  local name=$1 classification=$2 start=$3 raw=$4 code=$5 finish
  finish=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  python3 - "$step_dir/$name.json" "$name" "$classification" "$start" "$finish" "$code" "$raw" <<'PY'
import json,re,sys
out,name,classification,start,finish,code,raw=sys.argv[1:]
text=open(raw,encoding='utf-8',errors='replace').read()
text=re.sub(r'(?im)(password|pwd|nonce|cookie|authorization)\s*[:=]\s*[^\s\'\"]+',r'\1=<redacted>',text)
json.dump({'step':name,'failure_classification':classification if int(code) else None,'started_at':start,'finished_at':finish,'exit_code':int(code),'output_redacted':text[-12000:]},open(out,'w'),indent=2,sort_keys=True)
PY
  rm -f "$raw"
}
run_step() {
  local name=$1 classification=$2; shift 2; local start raw code=0
  start=$(date -u +%Y-%m-%dT%H:%M:%SZ); raw=$(mktemp /tmp/phase13-bootstrap.XXXXXX)
  "$@" >"$raw" 2>&1 || code=$?
  redact_step "$name" "$classification" "$start" "$raw" "$code"
  if (( code != 0 )); then echo "bootstrap failure classification: $classification" >&2; exit "$code"; fi
}
trap 'code=$?; raw=$(mktemp /tmp/phase13-bootstrap.XXXXXX); printf "unexpected bootstrap failure at line %s\n" "$LINENO" >"$raw"; redact_step unexpected_err_trap unexpected_err_trap "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$raw" "$code"; exit "$code"' ERR

run_step verify_wordpress_files missing_wordpress_files bash -c 'for _ in $(seq 1 30); do [[ -f /var/www/html/wp-settings.php ]] && exit 0; sleep 1; done; echo missing_wordpress_files >&2; exit 1'
run_step create_wp_config wp_config_creation_failure bash -c '[[ -f /var/www/html/wp-config.php ]] || wp core config --dbname="$WORDPRESS_DB_NAME" --dbuser="$WORDPRESS_DB_USER" --dbpass="$WORDPRESS_DB_PASSWORD" --dbhost="$WORDPRESS_DB_HOST" --skip-check --quiet --allow-root --path=/var/www/html; test -f /var/www/html/wp-config.php'
run_step wait_for_database database_readiness_timeout bash -c 'for attempt in $(seq 1 30); do timeout 3s wp db check --allow-root --path=/var/www/html >/dev/null 2>&1 && exit 0; echo "database_not_ready attempt=$attempt" >&2; sleep 1; done; echo database_readiness_timeout >&2; exit 1'
run_step install_wordpress wordpress_installation_failure bash -c 'wp core is-installed --allow-root --path=/var/www/html >/dev/null 2>&1 || wp core install --url=http://localhost --title=Phase13 --admin_user=phase13admin --admin_password="$PHASE13_LOCAL_PASSWORD" --admin_email=admin@example.test --skip-email --quiet --allow-root --path=/var/www/html; wp core is-installed --allow-root --path=/var/www/html'
run_step verify_plugin_zip plugin_zip_missing bash -c 'test -f "/plugin-zips/$PHASE13_PLUGIN_ZIP"'
run_step verify_plugin_sha256 sha256_mismatch bash -c 'actual=$(sha256sum "/plugin-zips/$PHASE13_PLUGIN_ZIP" | awk "{print \$1}"); test "$actual" = "$PHASE13_PLUGIN_SHA256"'
run_step install_plugin plugin_install_failure wp plugin install "/plugin-zips/$PHASE13_PLUGIN_ZIP" --force --quiet "${args[@]}"
run_step activate_plugin plugin_activation_failure wp plugin activate "$PHASE13_PLUGIN_SLUG" --quiet "${args[@]}"
run_step verify_plugin_version plugin_version_mismatch bash -c 'test "$(wp plugin get "$PHASE13_PLUGIN_SLUG" --field=version --allow-root --path=/var/www/html)" = "$PHASE13_PLUGIN_VERSION"'
capture_registry() {
  local tmp="$PHASE13_RESULTS_DIR/registry.json.tmp" raw_out raw_err process validation
  raw_out=$(mktemp /tmp/phase13-registry-out.XXXXXX); raw_err=$(mktemp /tmp/phase13-registry-err.XXXXXX)
  set +e; PHASE13_REGISTRY_TMP="$tmp" wp eval-file /phase13/scripts/capture_registry.php --allow-root --path=/var/www/html >"$raw_out" 2>"$raw_err"; process=$?; set -e
  python3 - "$PHASE13_RESULTS_DIR/registry-process.json" "$process" "$tmp" "$raw_out" "$raw_err" <<'PY'
import json,os,re,sys
out,process,tmp,stdout,stderr=sys.argv[1:]
def clean(p):
 text=open(p,errors='replace').read(); return re.sub(r'(?i)(password|pwd|nonce|cookie|authorization)\s*[:=]\s*\S+',r'\1=<redacted>',text)
json.dump({'wp_eval_file_exit_code':int(process),'stdout_bytes':os.path.getsize(stdout),'stderr_bytes':os.path.getsize(stderr),'registry_exists':os.path.exists(tmp),'registry_bytes':os.path.getsize(tmp) if os.path.exists(tmp) else 0,'stdout_redacted':clean(stdout),'stderr_redacted':clean(stderr)},open(out,'w'),indent=2,sort_keys=True)
PY
  rm -f "$raw_out" "$raw_err"; (( process == 0 )) || return "$process"
  set +e; python3 -c 'import json,sys; value=json.load(open(sys.argv[1])); assert value.get("schema_version")==1 and value.get("routes")' "$tmp"; validation=$?; set -e
  python3 - "$PHASE13_RESULTS_DIR/registry-process.json" "$validation" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['json_validation_exit_code']=int(sys.argv[2]); json.dump(d,open(p,'w'),indent=2,sort_keys=True)
PY
  (( validation == 0 )) || { rm -f "$tmp"; return "$validation"; }
  mv "$tmp" "$PHASE13_RESULTS_DIR/registry.json"
}
run_step capture_registry registry_capture_failure capture_registry
