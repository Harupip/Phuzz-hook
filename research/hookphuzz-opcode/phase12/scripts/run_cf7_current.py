#!/usr/bin/env python3
"""Fresh, local authenticated CF7 evidence for the Phase 12 closure run."""
from __future__ import annotations
import json, os, time
from pathlib import Path
from uuid import uuid4
import requests

RUN = os.environ['PHASE12_RUN_ID']; PROJECT = os.environ['PHASE12_COMPOSE_PROJECT']; BASE='http://localhost'; OUT=Path('/tmp/phase12-cf7'); REQUESTS=Path('/shared-tmpfs/hook-coverage/requests')
def write(name, value): OUT.mkdir(exist_ok=True); (OUT/name).write_text(json.dumps(value, indent=2, sort_keys=True))
def load(path):
    try: return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError): return {}
def main():
    before=set(REQUESTS.glob('*.json')); registration_id=f'{RUN}-cf7-register'
    requests.get(BASE+'/wp-json/',headers={'X-HookPhuzz-Request-ID':registration_id},timeout=15)
    registration={}
    for path in REQUESTS.glob('*.json'):
        if path in before: continue
        for entry in ((load(path).get('hook_coverage') or {}).get('registered_callbacks') or {}).values():
            if entry.get('entrypoint_type') == 'rest_route' and entry.get('namespace') == 'contact-form-7/v1' and entry.get('route') == '/contact-forms':
                registration=entry; break
    definitions=registration.get('rest_endpoint_definitions') or [registration]
    args=[row.get('argument_definitions') or {} for row in definitions]
    search_declared=any('search' in row for row in args)
    write('cf7-route-argument-capture.json',{'schema_version':1,'run_id':RUN,'namespace':'contact-form-7/v1','route_pattern':'/contact-forms','method':'GET','callback':registration.get('callback_repr'),'route_registration_captured':bool(registration),'argument_definitions':args,'search_declared':search_declared})
    session=requests.Session(); user=os.environ['PHASE11B_LOCAL_USERNAME']; password=os.environ['PHASE11B_LOCAL_PASSWORD']
    session.get(BASE+'/wp-login.php',timeout=15)
    login=session.post(BASE+'/wp-login.php',data={'log':user,'pwd':password,'wp-submit':'Log In','redirect_to':BASE+'/wp-admin/','testcookie':'1'},allow_redirects=True,timeout=15)
    nonce=session.get(BASE+'/wp-admin/admin-ajax.php',params={'action':'rest-nonce'},timeout=15).text.strip()
    request_id=f'{RUN}-cf7-{uuid4().hex[:12]}'; marker='HOOKPHUZZ_PHASE12_CF7_'+uuid4().hex[:12]
    response=session.get(BASE+'/wp-json/contact-form-7/v1/contact-forms',params={'search':marker},headers={'X-HookPhuzz-Request-ID':request_id,'X-WP-Nonce':nonce},timeout=15)
    callback_path=Path('/results/callbacks')/(request_id+'.json')
    for _ in range(40):
        if callback_path.exists(): break
        time.sleep(.05)
    callback=load(callback_path)
    parameter={'name':'search','schema_declared':search_declared,'schema_source':'route_declared' if search_declared else None,'runtime_observed':callback.get('parameter_observed') is True,'parameter_status':'schema_plus_runtime' if search_declared and callback.get('parameter_observed') else ('runtime_only' if callback.get('parameter_observed') else 'missing'),'type':'unknown' if not search_declared else None,'required':'unknown' if not search_declared else None}
    write('cf7-parameter-resolution.json',{'schema_version':1,'run_id':RUN,'parameter':parameter})
    replay={'schema_version':1,'run_id':RUN,'compose_project':PROJECT,'request_id':request_id,'method':'GET','route':'/contact-forms','permission_success':callback.get('permission_callback_passed') is True,'expected_callback_reached':callback.get('callback') == 'WPCF7_REST_Controller::get_contact_forms' and callback.get('callback_reached') is True,'search_observed':callback.get('parameter_observed') is True,'marker_matched':callback.get('parameter_value') == marker,'request_id_correlated':callback.get('request_id') == request_id,'http_status':response.status_code,'authentication_cookie_present':bool(session.cookies),'rest_nonce_present':bool(nonce),'pass':login.status_code == 200 and callback.get('permission_callback_passed') is True and callback.get('callback') == 'WPCF7_REST_Controller::get_contact_forms' and callback.get('parameter_value') == marker and callback.get('request_id') == request_id}
    write('cf7-replay-result.json',replay)
    write('cf7-replay-evidence.json',{'schema_version':1,'run_id':RUN,'replay':replay,'authentication_material':'redacted'})
    return 0
if __name__ == '__main__': raise SystemExit(main())
