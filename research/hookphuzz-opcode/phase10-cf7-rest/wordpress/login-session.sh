#!/usr/bin/env bash
set -euo pipefail
jar=/tmp/phase10-cf7-rest.cookies
rm -f "$jar"
readarray -t session < <(wp --path=/var/www/html --allow-root eval '$user=get_user_by("login","phase10admin"); $expires=time()+3600; $token=WP_Session_Tokens::get_instance($user->ID)->create($expires); echo LOGGED_IN_COOKIE; echo wp_generate_auth_cookie($user->ID,$expires,"logged_in",$token); echo $expires;')
printf '# Netscape HTTP Cookie File\nlocalhost\tFALSE\t/\tFALSE\t%s\t%s\t%s\n' "${session[2]}" "${session[0]}" "${session[1]}" > "$jar"
curl -fsS -L -b "$jar" http://localhost/wp-admin/profile.php -o /tmp/phase10-cf7-profile.html
python3 - "$jar" <<'PY'
import json,sys
rows=[]
for line in open(sys.argv[1]):
 if not line.strip() or (line.startswith('#') and not line.startswith('#HttpOnly_')): continue
 p=line.lstrip('#HttpOnly_').rstrip('\n').split('\t')
 if len(p)>=7: rows.append({'name':p[5],'value':'<redacted>'})
profile=open('/tmp/phase10-cf7-profile.html').read()
print(json.dumps({'authenticated_probe_success':'Howdy, <span class="display-name">phase10admin' in profile,'cookie_names':rows,'session_cookie_stored':'<redacted>'},indent=2))
PY
