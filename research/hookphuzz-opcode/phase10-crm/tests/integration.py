#!/usr/bin/env python3
import json,subprocess,uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
OUT=Path('/results'); JAR='/tmp/phase10-crm.cookies'; NONCE=Path('/tmp/phase10-crm.nonce').read_text()
def req(label, *, action='vx_form_save_api_settings', cookie=True, nonce=NONCE, settings='marker'):
 rid='phase10crm-neg-'+label+'-'+uuid.uuid4().hex; marker='PHASE10_CRM_'+uuid.uuid4().hex; data=[f'action={action}']
 if nonce is not None:data.append('vx_nonce='+nonce)
 if settings=='marker':data.append('cfx_settings[alert_emails]='+marker)
 elif settings=='root':data.append('cfx_settings[google_public]=x')
 cmd=['curl','-sS','-X','POST','-H',f'X-Fuzzer-Covid: {rid}']
 if cookie:cmd+=['-b',JAR]
 for item in data:cmd+=['--data-urlencode',item]
 cmd+=['http://localhost/wp-admin/admin-ajax.php']; r=subprocess.run(cmd,capture_output=True,text=True,check=True)
 return rid,r.stdout
def event(rid):
 p=Path('/shared/opcode-events')/f'{rid}.json'; return json.loads(p.read_text()) if p.exists() else {}
def callback(rid):
 p=OUT/'runtime'/f'{rid}.callback.json'; return json.loads(p.read_text()) if p.exists() else {}
def has_path(doc,path):
 return any(x.get('path')==path and x.get('operation')=='read' and (x.get('callback_context') or {}).get('root_callback')=='cfx_form_admin_pages::save_api_settings' for x in doc.get('events',[]))
def main():
 rows={}
 rid,_=req('no-action',action=''); rows['no_action']=not callback(rid).get('callback_reached',False)
 rid,_=req('bad-action',action='not_a_crm_action'); rows['unknown_action']=not callback(rid).get('callback_reached',False)
 rid,_=req('no-auth',cookie=False); rows['unauthenticated']=not callback(rid).get('callback_reached',False)
 rid,res=req('bad-nonce',nonce='bad'); rows['bad_nonce']=res.strip()=='-1' and not has_path(event(rid),['cfx_settings','alert_emails'])
 rid,_=req('missing-root',settings=None); rows['missing_cfx_settings']=not has_path(event(rid),['cfx_settings'])
 rid,_=req('missing-leaf',settings='root'); rows['missing_alert_emails']=not has_path(event(rid),['cfx_settings','alert_emails'])
 one=req('isolation-one'); two=req('isolation-two'); rows['two_markers']=event(one[0]).get('request_id')==one[0] and event(two[0]).get('request_id')==two[0] and callback(one[0]).get('marker_observed') and callback(two[0]).get('marker_observed')
 with ThreadPoolExecutor(max_workers=2) as x: parallel=list(x.map(lambda n:req('parallel-'+str(n)),range(2)))
 rows['concurrency']=all(event(r).get('request_id')==r and callback(r).get('callback_reached') for r,_ in parallel)
 OUT.joinpath('negative-tests.json').write_text(json.dumps({'passed':all(rows.values()),'tests':rows},indent=2))
 raise SystemExit(0 if all(rows.values()) else 1)
if __name__=='__main__':main()
