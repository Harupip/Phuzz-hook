#!/usr/bin/env bash
set -Eeuo pipefail
phase_dir=$(cd "$(dirname "$0")/.." && pwd); run_id="phase13-cf7-replay-$(date -u +%Y%m%dT%H%M%SZ)-$$"; results="$phase_dir/results/$run_id"; mkdir -p "$results/configs"
export PHASE13_PLUGIN_ZIP=contact-form-7.zip PHASE13_PLUGIN_SLUG=contact-form-7 PHASE13_PLUGIN_VERSION=5.7.7 PHASE13_PLUGIN_SHA256=913583ac1d590daac3971791d6b5441d4d4293c60ff4ec62978c88f4d45a4461 PHASE13_LOCAL_PASSWORD="local-$run_id" PHASE13_RESULTS_DIR="/results/$run_id" PHASE13_RUN_ID="$run_id"
project="hookphuzz-phase13-cf7-replay-${run_id,,}"; project=${project:0:63}; compose=(docker compose --project-name "$project" --file "$phase_dir/docker-compose.yml")
redact() { sed -E -e '/(password|pwd|nonce|cookie|authorization)/I c\<redacted sensitive line>' -e 's/((password|pwd|nonce|cookie|authorization)[=:])[[:graph:]]+/\1<redacted>/Ig'; }
cleanup(){ set +e; "${compose[@]}" down --volumes --remove-orphans >"$results/cleanup.raw" 2>&1; code=$?; redact <"$results/cleanup.raw" >"$results/cleanup.log"; rm -f "$results/cleanup.raw"; printf '{"exit_code":%s,"project":"%s"}\n' "$code" "$project" >"$results/cleanup-result.json"; }
host_diagnostics() {
  set +e
  "${compose[@]}" ps --all >"$results/compose-ps.txt" 2>&1; ps_code=$?
  "${compose[@]}" logs --no-color web >"$results/web.raw" 2>&1; logs_code=$?
  redact <"$results/web.raw" >"$results/web.log"; rm -f "$results/web.raw"
  web_id=$("${compose[@]}" ps -q web); id_code=$?
  exit_code=null; oom_killed=null
  if [[ $id_code -eq 0 && -n "$web_id" ]]; then
    exit_code=$(docker inspect -f '{{.State.ExitCode}}' "$web_id"); inspect_code=$?
    oom_killed=$(docker inspect -f '{{.State.OOMKilled}}' "$web_id"); oom_code=$?
  else
    inspect_code=0; oom_code=0
  fi
  python3 - "$results/host-diagnostics.json" "$bootstrap_code" "$ps_code" "$logs_code" "$id_code" "$inspect_code" "$oom_code" "$exit_code" "$oom_killed" "$project" <<'PY'
import json,sys
p,bootstrap,ps,logs,ident,inspect,oom,web_exit,oom_killed,project=sys.argv[1:]
json.dump({'bootstrap_exit_code':int(bootstrap),'compose_ps_exit_code':int(ps),'web_logs_exit_code':int(logs),'web_id_exit_code':int(ident),'web_inspect_exit_code':int(inspect),'web_oom_inspect_exit_code':int(oom),'web_exit_code':None if web_exit == 'null' else int(web_exit),'web_oom_killed':None if oom_killed == 'null' else oom_killed == 'true','project':project},open(p,'w'),indent=2,sort_keys=True)
PY
  set -e
}
trap cleanup EXIT
timeout 300s docker build --pull=false -t hookphuzz-phase13:local -f "$phase_dir/Dockerfile" "$(cd "$phase_dir/../../.." && pwd)" >"$results/build.log" 2>&1; "${compose[@]}" up -d --no-build >"$results/compose-up.log" 2>&1
database_probe_code=1
for _ in $(seq 1 15); do
  set +e; timeout 5s "${compose[@]}" exec -T web php -r 'mysqli_report(MYSQLI_REPORT_OFF); $db=@new mysqli(getenv("WORDPRESS_DB_HOST"),getenv("WORDPRESS_DB_USER"),getenv("WORDPRESS_DB_PASSWORD"),getenv("WORDPRESS_DB_NAME")); echo $db->connect_errno ? "database_connectivity=failed\n" : "database_connectivity=ok\n"; exit($db->connect_errno ? 1 : 0);' >"$results/database-connectivity.raw" 2>&1; database_probe_code=$?; set -e
  (( database_probe_code == 0 )) && break
  sleep 1
done
redact <"$results/database-connectivity.raw" >"$results/database-connectivity.log"; rm -f "$results/database-connectivity.raw"
printf '{"exit_code":%s}\n' "$database_probe_code" >"$results/database-connectivity.json"
set +e; timeout 240s "${compose[@]}" exec -T web bash /opt/bootstrap_plugin.sh >"$results/bootstrap.raw" 2>&1; bootstrap_code=$?; set -e
redact <"$results/bootstrap.raw" >"$results/bootstrap.log"; rm -f "$results/bootstrap.raw"
host_diagnostics
if (( bootstrap_code != 0 )); then exit "$bootstrap_code"; fi
"${compose[@]}" exec -T web mkdir -p /tmp/phase13-phuzz-work/output
network_name=$(docker network ls --filter "label=com.docker.compose.project=$project" --format '{{.Name}}' | head -n 1)
network_internal=$(docker network inspect -f '{{.Internal}}' "$network_name")
mail_filter=$("${compose[@]}" exec -T web wp eval 'echo has_filter("pre_wp_mail") ? "present" : "missing";' --allow-root --path=/var/www/html)
http_filter=$("${compose[@]}" exec -T web wp eval 'echo has_filter("pre_http_request") ? "present" : "missing";' --allow-root --path=/var/www/html)
python3 - "$results/containment.json" "$network_name" "$network_internal" "$mail_filter" "$http_filter" <<'PY'
import json,sys
json.dump({'network':sys.argv[2],'network_internal':sys.argv[3].strip() == 'true','outbound_mail_filter':sys.argv[4].strip() == 'present','outbound_http_filter':sys.argv[5].strip() == 'present'},open(sys.argv[1],'w'),indent=2,sort_keys=True)
PY
set +e; "${compose[@]}" exec -T web wp user get phase13user --field=ID --allow-root --path=/var/www/html >"$results/auth-user.raw" 2>&1; auth_user_code=$?; set -e
if (( auth_user_code != 0 )); then "${compose[@]}" exec -T web wp user create phase13user phase13user@example.test --role=contributor --user_pass="$PHASE13_LOCAL_PASSWORD" --allow-root --path=/var/www/html >"$results/auth-user.raw" 2>&1; fi
auth_user_id=$("${compose[@]}" exec -T web wp user get phase13user --field=ID --allow-root --path=/var/www/html)
auth_capability=$("${compose[@]}" exec -T web wp eval 'echo user_can(get_user_by("login", "phase13user"), "edit_posts") ? "edit_posts" : "missing";' --allow-root --path=/var/www/html)
redact <"$results/auth-user.raw" >"$results/auth-user.log"; rm -f "$results/auth-user.raw"
python3 - "$results/auth-user.json" "$auth_user_id" "$auth_capability" <<'PY'
import json,sys
json.dump({'logical_user':'phase13user','user_id':int(sys.argv[2]),'minimum_required_capability':sys.argv[3].strip(),'authentication_material':'redacted'},open(sys.argv[1],'w'),indent=2,sort_keys=True)
PY
form_id=$("${compose[@]}" exec -T web wp post create --post_type=wpcf7_contact_form --post_title=Phase13 --post_status=publish --porcelain --allow-root --path=/var/www/html)
catalog_run=phase13-contact-form-7-bootstrap-20260803T164001Z-11057; catalog="$phase_dir/results/$catalog_run/endpoint-catalog.json"; catalog_sha=$(sha256sum "$catalog" | awk '{print $1}')
python3 - "$results/configs/public.json" "$form_id" "$catalog_sha" "$catalog_run" "$run_id" <<'PY'
import json,sys
p,form,sha,source_run,replay_run=sys.argv[1:]
json.dump({'target':f'http://localhost/wp-json/contact-form-7/v1/contact-forms/{form}/feedback/schema','methods':['GET'],'print_timestamps':False,'metadata':{'source_catalog_run_id':source_run,'replay_run_id':replay_run,'source_catalog_sha256':sha,'plugin':'contact-form-7','plugin_version':'5.7.7','route':'/contact-form-7/v1/contact-forms/(?P<id>\\d+)/feedback/schema','method':'GET','authentication':'public','parameter_origins':[]}},open(p,'w'),indent=2)
PY
python3 - "$results/configs/authenticated.json" "$catalog_sha" "$catalog_run" "$run_id" <<'PY'
import json,sys
p,sha,source_run,replay_run=sys.argv[1:]
json.dump({'target':'http://localhost/wp-json/contact-form-7/v1/contact-forms','methods':['GET'],'print_timestamps':False,'metadata':{'source_catalog_run_id':source_run,'replay_run_id':replay_run,'source_catalog_sha256':sha,'plugin':'contact-form-7','plugin_version':'5.7.7','route':'/contact-form-7/v1/contact-forms','method':'GET','authentication':'authenticated','parameter_origins':[]}},open(p,'w'),indent=2)
PY
replay_failure=0
for kind in public auth-negative auth-invalid auth-valid; do raw=$(mktemp /tmp/phase13-phuzz.XXXXXX); args=(python3 /phase13/scripts/real_phuzz.py); [[ $kind == public ]] && args+=(/results/$run_id/configs/public.json) || args+=(/results/$run_id/configs/authenticated.json); [[ $kind == auth-valid ]] && args+=(--auth); [[ $kind == auth-invalid ]] && args+=(--invalid-auth); set +e; timeout 90s "${compose[@]}" exec -T -w /tmp/phase13-phuzz-work web "${args[@]}" >"$raw" 2>&1; code=$?; set -e; redact <"$raw" >"$results/$kind.log"; result=$(tail -n 1 "$raw" || true); rm -f "$raw"; (( code == 0 )) || replay_failure=1; python3 - "$results/$kind.json" "$code" "$result" <<'PY'
import json,sys
p,code,row=sys.argv[1:]
try: value=json.loads(row)
except: value={'parse_error':True}
value['process_exit_code']=int(code); json.dump(value,open(p,'w'),indent=2,sort_keys=True)
PY
done
(( replay_failure == 0 )) || exit 1
python3 "$phase_dir/scripts/check_replay.py" "$results" "$phase_dir/results/runtime" "$catalog"
