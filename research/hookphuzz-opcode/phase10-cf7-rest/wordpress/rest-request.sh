#!/usr/bin/env bash
set -euo pipefail
kind="$1"; request_id="$2"; marker="$3"; mode="$4"; shift 4
out=/results; jar=/tmp/phase10-cf7-rest.cookies; route='/contact-form-7/v1/contact-forms'
case "$mode" in
  canonical) url="http://localhost/wp-json$route"; fixed=() ;;
  fallback) url='http://localhost/'; fixed=(--data-urlencode "rest_route=$route") ;;
  *) echo 'invalid route mode' >&2; exit 2 ;;
esac
key=''; value=''
if [[ $# -gt 0 ]]; then key="$1"; value="$2"; shift 2; fi
[[ $# -eq 0 ]] || { echo 'parameter pairs expected' >&2; exit 2; }
value_hash=$(printf %s "$value" | sha256sum | awk '{print $1}')
mkdir -p "$out/requests"
args=(-sS -D "$out/requests/$request_id.headers" -o "$out/requests/$request_id.body" -w '%{http_code}' -G -b "$jar" -H "X-Fuzzer-Covid: $request_id" -H "X-HookPhuzz-Probe-Marker: $marker" -H "X-HookPhuzz-Expected-Key: $key" -H "X-HookPhuzz-Expected-Value-Sha256: $value_hash")
args+=("${fixed[@]}")
[[ -z "$key" ]] || args+=(--data-urlencode "$key=$value")
set +e
status=$(curl "${args[@]}" "$url")
curl_code=$?
set -e
python3 - "$out/requests/$request_id.json" "$kind" "$request_id" "$mode" "$url" "$key" "$marker" "$value_hash" "$status" "$curl_code" <<'PY'
import hashlib,json,sys,urllib.parse
p,kind,rid,mode,url,key,marker,value_hash,status,code=sys.argv[1:]
fixed={'rest_route':'/contact-form-7/v1/contact-forms'} if mode=='fallback' else {}
json.dump({'schema_version':1,'kind':kind,'request_id':rid,'route_mode':mode,'url_path':urllib.parse.urlparse(url).path,'fixed_query':fixed,'parameter_key':key or None,'marker_sha256':hashlib.sha256(marker.encode()).hexdigest(),'value_sha256':value_hash,'http_status':int(status) if status.isdigit() else None,'curl_exit':int(code),'query_redacted':{**fixed, **({key:'<redacted>'} if key else {})}},open(p,'w'),indent=2)
PY
for _ in $(seq 1 30); do [[ -f "/shared/opcode-events/$request_id.json" ]] && break; sleep .1; done
if [[ -f "/shared/opcode-events/$request_id.json" ]]; then cp "/shared/opcode-events/$request_id.json" "$out/opcode-events/$request_id.json"; fi
