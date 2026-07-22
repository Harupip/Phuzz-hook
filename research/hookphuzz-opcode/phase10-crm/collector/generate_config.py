#!/usr/bin/env python3
"""Generic normalized-path to existing PHUZZ body_params contract."""
import argparse,json
from pathlib import Path
def bracket(path): return str(path[0])+''.join(f'[{x}]' for x in path[1:])
def main():
 p=argparse.ArgumentParser(); p.add_argument('normalized'); p.add_argument('--out',required=True); p.add_argument('--summary',required=True); a=p.parse_args(); n=json.loads(Path(a.normalized).read_text())
 data=[{'name':'action','value':n['entrypoint']['name']},{'name':'vx_nonce','value':'${PHASE10_RUNTIME_NONCE}'}]; fuzz=[]
 candidates=[item for item in n.get('parameters',[]) if item.get('source')=='POST' and item.get('confidence')=='runtime_confirmed']
 # A root array read is transport/provenance evidence, not an independently
 # fuzzable leaf when a longer runtime-confirmed path has the same source.
 for item in candidates:
  path=item['path']
  if any(other['path'][:len(path)]==path and len(other['path'])>len(path) for other in candidates): continue
  name=bracket(item['path']); data.append({'name':name,'value':'fuzz'}); fuzz.append(name)
 if not fuzz: raise SystemExit('no POST runtime-confirmed parameter')
 config={'target':'http://localhost'+n['entrypoint']['endpoint'],'methods':[n['entrypoint']['method']],'entrypoint_type':'ajax_authenticated','body_params':{'data':data,'fixed':['action','vx_nonce'],'fuzz':fuzz,'weight':1},'cookies':{'data':[{'name':'runtime_session','value':'${PHASE10_RUNTIME_SESSION}'}],'fixed':['runtime_session'],'fuzz':[],'weight':0},'metadata':{'generated_from':'normalized-params.json','callback_id':n['callback']['id'],'runtime_secret_refs':['PHASE10_RUNTIME_NONCE','PHASE10_RUNTIME_SESSION']}}
 Path(a.out).write_text(json.dumps(config,indent=2)); Path(a.summary).write_text(json.dumps({'generated_config':Path(a.out).name,'fixed':['action','vx_nonce','runtime_session'],'fuzz':fuzz,'parameter_source':'normalized-params.json'},indent=2))
if __name__=='__main__':main()
