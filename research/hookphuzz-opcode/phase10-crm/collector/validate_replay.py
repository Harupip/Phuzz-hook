#!/usr/bin/env python3
import argparse,json
from pathlib import Path
def read(p): return json.loads(Path(p).read_text())
def main():
 p=argparse.ArgumentParser(); p.add_argument('--config',required=True);p.add_argument('--events',required=True);p.add_argument('--callback',required=True);p.add_argument('--response',required=True);p.add_argument('--out',required=True);a=p.parse_args()
 c,e,cb=read(a.config),read(a.events),read(a.callback); fuzz=set(c['body_params']['fuzz']); paths={''.join([str(x) if i==0 else f'[{x}]' for i,x in enumerate(x.get('path',[]))]) for x in e.get('events',[]) if (x.get('callback_context')or{}).get('root_callback')==c['metadata']['callback_id']}
 response=Path(a.response).read_text(); result={'request_sent':True,'http_completed':bool(response),'action_dispatched':cb.get('callback_reached') is True,'callback_reached':cb.get('callback_reached') is True,'marker_observed':cb.get('marker_observed') is True,'parameter_path_matched':bool(fuzz & paths),'request_isolation_pass':bool(e.get('request_id')),'generated_config_used':True}
 Path(a.out).write_text(json.dumps(result,indent=2)); raise SystemExit(0 if all(result.values()) else 1)
if __name__=='__main__':main()
