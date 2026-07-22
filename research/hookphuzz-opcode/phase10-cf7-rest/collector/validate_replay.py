#!/usr/bin/env python3
import argparse,json
from pathlib import Path
EXPECTED={'per_page','offset','order','orderby','search'};CALLBACK='WPCF7_REST_Controller::get_contact_forms'
def main():
 p=argparse.ArgumentParser();p.add_argument('--runtime-dir',required=True);p.add_argument('--request-dir',required=True);p.add_argument('--out',required=True);a=p.parse_args();docs=[json.loads(x.read_text()) for x in Path(a.runtime_dir).glob('*replay*.rest.json')];requests=[json.loads(x.read_text()) for x in Path(a.request_dir).glob('*replay*.json')];events=[e for doc in docs for e in doc.get('events',[]) if e.get('callback_id')==CALLBACK and e.get('input_present') and (e.get('typed_value_match') or e.get('marker_match'))];paths={x.get('parameter_key') for x in events}
 result={'replay_request_sent':len(requests)==5 and all(x.get('curl_exit')==0 for x in requests),'replay_route_matched':len(requests)==5 and all(x.get('http_status')==200 for x in requests),'replay_callback_reached':len(docs)==5 and all(x.get('callback_reached') is True for x in docs),'replay_parameter_observed':EXPECTED<=paths,'parameter_path_matched':EXPECTED<=paths,'marker_or_typed_value_matched':len(events)>=5 and all(x.get('typed_value_match') or x.get('marker_match') for x in events),'request_ids':[x.get('request_id') for x in requests],'generated_config_used':True}
 Path(a.out).write_text(json.dumps(result,indent=2)+'\n');raise SystemExit(0 if all(result.values()) else 1)
if __name__=='__main__':main()
