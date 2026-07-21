#!/usr/bin/env bash
# The full live path is intentionally fail-closed: every external prerequisite
# is written as a gate instead of being replaced with fixture evidence.
set -u -o pipefail

results="$1"
run_id="$2"
phase_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
input="$results/input"
mkdir -p "$input"

python3 - "$input/manifest.json" "$run_id" <<'PY'
import json, sys
path, run_id = sys.argv[1:]
gates = {name: False for name in (
 "phase9_extension_integrated", "controlled_plugin", "two_real_plugin_targets",
 "direct_superglobals", "request_resolution", "helper_discovery", "nested_preservation",
 "parameter_association", "merge_deduplication", "phuzz_config_generation", "semantic_replays", "noise_isolation")}
json.dump({"schema_version": 1, "run_id": run_id, "target_plugins": [
 {"slug": "hookphuzz-phase10-controlled", "version": "1.0.0"},
 {"slug": "crm-perks-forms", "version": "1.0.7"},
 {"slug": "contact-form-7", "version": "5.7.7"}], "gates": gates,
 "targets": {"hookphuzz-phase10-controlled": "http://web/wp-admin/admin-ajax.php",
             "crm-perks-forms": "http://web/wp-admin/admin-ajax.php",
             "contact-form-7": "http://web/wp-json/contact-form-7/v1/contact-forms"},
 "methods": {"hookphuzz-phase10-controlled": "POST", "crm-perks-forms": "POST", "contact-form-7": "GET"},
 "fixed": {}, "opcode": [], "helper": [], "static": [], "seeds": []}, open(path, "w"), indent=2)
PY

if ! timeout 20s docker version >/dev/null 2>&1; then
  printf '%s\n' 'live_harness_blocker=docker_server_unavailable' >&2
  exit 1
fi
if [[ ! -d "$phase_dir/../../../phuzz-main/code/web/applications/wordpress/_plugins/crm-perks-forms" ]]; then
  printf '%s\n' 'live_harness_blocker=crm_perks_source_missing' >&2
  exit 1
fi
if [[ ! -f "$phase_dir/targets/contact-form-7.5.7.7.zip" ]]; then
  printf '%s\n' 'live_harness_blocker=contact_form_7_5_7_7_zip_missing' >&2
  exit 1
fi

compose=(docker compose -p hookphuzz-opcode-phase10 -f "$phase_dir/docker-compose.yml")
cleanup() { "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true; }
trap cleanup EXIT
"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
timeout 900s "${compose[@]}" up -d --build db web
for _ in $(seq 1 90); do
  if "${compose[@]}" run --rm verifier curl -fsS http://web/wp-login.php >"$results/wordpress-ready.html" 2>"$results/readiness.log"; then break; fi
  sleep 2
done
[[ -s "$results/wordpress-ready.html" ]] || { printf '%s\n' 'live_harness_blocker=wordpress_not_ready' >&2; exit 1; }

request_id="$run_id-controlled"
response="$results/controlled-response.json"
"${compose[@]}" run --rm verifier curl -fsS -X POST -H "X-Fuzzer-Covid: $request_id" -H "X-Phase9-Run-ID: $run_id" \
  -b direct_cookie=PHASE10_COOKIE --data-urlencode action=hookphuzz_phase10_controlled \
  --data-urlencode direct_post=PHASE10_POST --data-urlencode request_value=PHASE10_REQUEST \
  --data-urlencode 'profile[email]=PHASE10_NESTED' --data-urlencode runtime_selector=runtime_value \
  --data-urlencode runtime_value=PHASE10_RUNTIME --data-urlencode helper_value=PHASE10_HELPER \
  --data-urlencode duplicate_value=PHASE10_DUPLICATE 'http://web/wp-admin/admin-ajax.php?direct_get=PHASE10_GET' >"$response"
artifact="$results/controlled-opcode-artifact.json"
for _ in $(seq 1 50); do
  if "${compose[@]}" exec -T web sh -c "cat /shared/opcode-events/$request_id.json" >"$artifact" 2>/dev/null; then break; fi
  sleep .2
done
"${compose[@]}" logs --no-color web >"$results/web-container.log" 2>&1 || true
"${compose[@]}" exec -T web php -i >"$results/php-environment.txt" 2>/dev/null || true
python3 - "$input/manifest.json" "$results/controlled-live-probe.json" "$artifact" "$response" "$request_id" <<'PY'
import json, sys
manifest_path, report_path, artifact_path, response_path, request_id = sys.argv[1:]
try:
    artifact=json.load(open(artifact_path)); response=json.load(open(response_path))
except Exception: artifact={}; response={}
markers=(response.get('data') or {}).get('phase10_markers') or {}
expected={'get':'PHASE10_GET','post':'PHASE10_POST','cookie':'PHASE10_COOKIE','request':'PHASE10_REQUEST','nested':'PHASE10_NESTED','runtime':'PHASE10_RUNTIME','helper':'PHASE10_HELPER','duplicate_direct':'PHASE10_DUPLICATE','duplicate_helper':'PHASE10_DUPLICATE'}
events=[e for e in artifact.get('events',[]) if (e.get('callback_context') or {}).get('root_callback')=='hookphuzz_phase10_controlled']
seen={(e.get('source'),tuple(e.get('path') or [])) for e in events}
required={('GET',('direct_get',)),('POST',('direct_post',)),('COOKIE',('direct_cookie',)),('REQUEST',('request_value',)),('POST',('profile','email')),('POST',('runtime_value',)),('POST',('helper_value',)),('POST',('duplicate_value',))}
passed=artifact.get('schema_version')==3 and artifact.get('request_id')==request_id and expected==markers and required <= seen
report={'schema_version':1,'request_id':request_id,'root_callback':'hookphuzz_phase10_controlled','markers':markers,'artifact_path':artifact_path,'response_path':response_path,'events':len(events),'passed':passed}
json.dump(report,open(report_path,'w'),indent=2)
manifest=json.load(open(manifest_path)); manifest['opcode']=[{'file':'../controlled-opcode-artifact.json','plugin':'hookphuzz-phase10-controlled','entrypoint':'wp_ajax_nopriv_hookphuzz_phase10_controlled','request_placement':'body'}]
manifest['gates'].update({'phase9_extension_integrated':passed,'controlled_plugin':passed,'direct_superglobals':passed,'request_resolution':passed,'nested_preservation':passed,'helper_discovery':passed,'parameter_association':passed})
json.dump(manifest,open(manifest_path,'w'),indent=2)
raise SystemExit(0 if passed else 1)
PY
