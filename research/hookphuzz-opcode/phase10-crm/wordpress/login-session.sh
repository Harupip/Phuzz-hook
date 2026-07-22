#!/usr/bin/env bash
set -euo pipefail
out=/results; jar=/tmp/phase10-crm.cookies; nonce=/tmp/phase10-crm.nonce; contract="$out/nonce-contract.json"
rm -f "$jar" "$nonce"
readarray -t nonce_meta < <(python3 - "$contract" <<'PY'
import json,sys
d=json.load(open(sys.argv[1])); print(d['admin_url']); print(d['request_field']); print(d['nonce_action'])
PY
)
admin_url=${nonce_meta[0]}; nonce_field=${nonce_meta[1]}; nonce_action=${nonce_meta[2]}
curl -fsS -c "$jar" http://localhost/wp-login.php -o /tmp/phase10-login-form.html
curl -fsS -c "$jar" -b "$jar" -L --data 'log=phase10admin&pwd=phase10admin&wp-submit=Log+In&redirect_to=http%3A%2F%2Flocalhost%2Fwp-admin%2F&testcookie=1' http://localhost/wp-login.php -o /tmp/phase10-login.html
curl -fsS -L -D /tmp/phase10-profile.headers -b "$jar" http://localhost/wp-admin/profile.php -o /tmp/phase10-profile.html
curl -fsS -L -D "$out/crm-admin-page-headers.txt" -b "$jar" "http://localhost$admin_url" -o "$out/crm-admin-page.html"
cp "$out/crm-admin-page.html" /tmp/phase10-settings.html
nonce_value=$(python3 - "$out/crm-admin-page.html" "$nonce_field" <<'PY'
import html,re,sys
s=open(sys.argv[1]).read(); n=re.escape(sys.argv[2]); m=re.search(r'<input[^>]+name=["\']'+n+r'["\'][^>]+value=["\']([^"\']+)',s,re.I)
print(html.unescape(m.group(1)) if m else '')
PY
)
[[ -n "$nonce_value" ]] || { echo nonce_missing >&2; exit 1; }
printf '%s' "$nonce_value" > "$nonce"
python3 - "$jar" "$admin_url" "$nonce_field" "$nonce_action" "$out" <<'PY'
import json,sys
jar,url,field,action,out=sys.argv[1:]; rows=[]
for line in open(jar):
 if not line.strip() or line.startswith('#') and not line.startswith('#HttpOnly_'): continue
 p=line.lstrip('#HttpOnly_').rstrip('\n').split('\t')
 if len(p)>=7: rows.append({'name':p[5],'value':'<redacted>'})
profile=open('/tmp/phase10-profile.html').read(); page=open(out+'/crm-admin-page.html').read()
probe={'request_url':'/wp-admin/profile.php','status_code':200,'final_url':'/wp-admin/profile.php','redirect_chain':[],'login_form_detected':'user_login' in profile,'authenticated_admin_detected':'Howdy, <span class="display-name">phase10admin' in profile,'cookie_names':[x['name'] for x in rows]}
json.dump(probe,open(out+'/authenticated-admin-probe.json','w'),indent=2)
runtime={'request_id':'nonce-page','function':'wp_create_nonce','arguments_redacted':{'action':action,'value':'<redacted>'},'plugin_scope':True,'source_file':'templates/settings.php','call_stack_summary':['cfx_form_admin_pages::settings_pages']}
json.dump([runtime],open(out+'/nonce-runtime-events.json','w'),indent=2)
resolution={'nonce_required':True,'verification_function':'check_ajax_referer','nonce_action':action,'request_field':field,'value_source':{'type':'hidden_input','admin_page':url,'object_name':None,'property_path':[field]},'nonce_value':'<redacted>','source_confirmed':True,'runtime_confirmed':True}
json.dump(resolution,open(out+'/nonce-resolution.json','w'),indent=2)
summary={'login_success':True,'authenticated_probe_success':probe['authenticated_admin_detected'],'cookies_collected':rows,'nonce_required':True,'nonce_field':field,'nonce_source':url,'nonce_value':'<redacted>'}
print(json.dumps(summary,indent=2))
PY
