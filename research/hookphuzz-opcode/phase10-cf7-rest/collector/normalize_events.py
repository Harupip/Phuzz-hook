#!/usr/bin/env python3
import argparse,json
from pathlib import Path
EXPECTED=['per_page','offset','order','orderby','search'];CALLBACK='WPCF7_REST_Controller::get_contact_forms';ROUTE='/contact-form-7/v1/contact-forms'
def read(p): return json.loads(Path(p).read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('--runtime',required=True);p.add_argument('--source',required=True);p.add_argument('--out',required=True);p.add_argument('--raw-helper',required=True);p.add_argument('--raw-opcode',required=True);p.add_argument('--callback',required=True);a=p.parse_args();source=read(a.source);docs=[]
 for path in sorted(Path(a.runtime).glob('*probe*.rest.json')):
  d=read(path)
  if not isinstance(d.get('request_id'),str) or d['request_id'] not in path.name: raise SystemExit('runtime request id mismatch')
  docs.append(d)
 if len(docs)!=5: raise SystemExit('five discovery artifacts required')
 Path(a.raw_helper).write_text(json.dumps({'schema_version':1,'evidence_type':'raw_rest_helper_events','requests':docs},indent=2)+'\n')
 opcode=[]
 for path in sorted(Path(a.runtime).parent.joinpath('opcode-events').glob('*probe*.json')): opcode.append(read(path))
 Path(a.raw_opcode).write_text(json.dumps({'schema_version':1,'evidence_type':'actual_opcode_artifacts','requests':opcode,'cf7_parameter_opcode_events':0,'note':'CF7 parameter access is observed through WP_REST_Request helper events; no synthetic opcode events emitted.'},indent=2)+'\n')
 callbacks=[];params=[]
 for key in EXPECTED:
  matches=[]
  for d in docs:
   callbacks.append({'request_id':d['request_id'],'callback_reached':d.get('callback_reached') is True,'callback':d.get('callback')})
   for e in d.get('events',[]):
    if e.get('callback_id')==CALLBACK and e.get('parameter_key')==key and e.get('path')==[key] and e.get('input_present') and (e.get('typed_value_match') or e.get('marker_match')): matches.append((d,e))
  if len(matches)!=1: raise SystemExit(f'{key}: expected exactly one runtime event, got {len(matches)}')
  d,e=matches[0];params.append({'name':key,'path':[key],'transport_source':'GET/query','request_api':'WP_REST_Request','access_mechanism':'WP_REST_Request::get_param','entrypoint_type':'rest','method':'GET','route':ROUTE,'runtime_observed':True,'source_analysis_observed':any(x['name']==key for x in source['source_candidates']),'callback_id':CALLBACK,'request_ids':[d['request_id']],'marker_or_typed_value_matched':True})
 if not all(c['callback_reached'] for c in callbacks): raise SystemExit('callback evidence missing')
 Path(a.callback).write_text(json.dumps({'schema_version':1,'callback_id':CALLBACK,'requests':callbacks,'callback_reached':True},indent=2)+'\n')
 Path(a.out).write_text(json.dumps({'schema_version':1,'plugin':source['plugin'],'entrypoint':{'type':'rest','method':'GET','route':ROUTE},'callback':{'id':CALLBACK},'parameters':params,'source_runtime_separation_pass':all(x['source_analysis_observed'] and x['runtime_observed'] for x in params)},indent=2)+'\n')
if __name__=='__main__':main()
