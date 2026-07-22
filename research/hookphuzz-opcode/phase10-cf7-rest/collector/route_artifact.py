#!/usr/bin/env python3
import argparse,json
from pathlib import Path
CALLBACK='WPCF7_REST_Controller::get_contact_forms'
def read(p): return json.loads(Path(p).read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('--runtime',required=True);p.add_argument('--request',required=True);p.add_argument('--registration',required=True);p.add_argument('--resolution',required=True);p.add_argument('--canonical-request',required=True);a=p.parse_args();d=read(a.runtime);q=read(a.request);canonical=read(a.canonical_request);route=d.get('route_registration') or {}
 reg={'schema_version':1,'bootstrap_request_id':d.get('request_id'),'namespace':route.get('namespace'),'route':route.get('route'),'allowed_methods':route.get('methods'),'callback_id':(route.get('callback_identity') or {}).get('id'),'callback_type':(route.get('callback_identity') or {}).get('type'),'permission_callback_identity':route.get('permission_callback_identity'),'registered_arguments':route.get('registered_arguments'),'plugin_attribution':route.get('plugin_attribution'),'register_rest_route_hook_seen':d.get('register_rest_route_hook_seen') is True,'route_discovered':route.get('registration_observed') is True}
 Path(a.registration).write_text(json.dumps(reg,indent=2)+'\n')
 resolution={'schema_version':1,'canonical_status':canonical.get('http_status'),'canonical_request_id':canonical.get('request_id'),'effective_mode':q.get('route_mode'),'effective_request_id':q.get('request_id'),'effective_url_path':q.get('url_path'),'fixed_query':q.get('fixed_query'),'request_sent':q.get('curl_exit')==0,'rest_api_ready':q.get('http_status')==200,'canonical_unavailable':canonical.get('http_status')!=200,'fallback_used':q.get('route_mode')=='fallback','route_callback_reached':d.get('callback_reached') is True}
 if reg['callback_id']!=CALLBACK or not resolution['rest_api_ready'] or not resolution['route_callback_reached']: raise SystemExit('runtime REST route contract failed')
 Path(a.resolution).write_text(json.dumps(resolution,indent=2)+'\n')
if __name__=='__main__':main()
