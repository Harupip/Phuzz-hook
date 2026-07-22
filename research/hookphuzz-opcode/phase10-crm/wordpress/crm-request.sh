#!/usr/bin/env bash
set -euo pipefail
kind="$1"; id="$2"; marker="$3"; out=/results; jar=/tmp/phase10-crm.cookies; nonce=$(cat /tmp/phase10-crm.nonce)
case "$kind" in
 live|replay) curl -sS -D "$out/$kind-request.headers" -o "$out/$kind-response.txt" -X POST -H "X-Fuzzer-Covid: $id" -H "X-Phase9-Run-ID: $id" -b "$jar" --data-urlencode action=vx_form_save_api_settings --data-urlencode "vx_nonce=$nonce" --data-urlencode "cfx_settings[alert_emails]=$marker" http://localhost/wp-admin/admin-ajax.php ;;
 *) echo invalid_kind >&2; exit 2 ;;
esac
for _ in $(seq 1 30); do test -f "/results/runtime/$id.callback.json" && test -f "/shared/opcode-events/$id.json" && break; sleep .2; done
cp "/results/runtime/$id.callback.json" "$out/$kind-callback-evidence.json"
cp "/results/runtime/$id.helper.json" "$out/$kind-helper-events.json"
cp "/shared/opcode-events/$id.json" "$out/$kind-opcode-events.json"
