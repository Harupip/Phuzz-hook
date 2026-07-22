#!/usr/bin/env python3
import argparse,json
from pathlib import Path
SEEDS={'per_page':7,'offset':3,'order':'asc','orderby':'id','search':'hookphuzz-search-seed'}
def main():
 p=argparse.ArgumentParser();p.add_argument('--normalized',required=True);p.add_argument('--resolution',required=True);p.add_argument('--out',required=True);a=p.parse_args();n=json.loads(Path(a.normalized).read_text());r=json.loads(Path(a.resolution).read_text());names=[x['name'] for x in n['parameters']]
 if names!=list(SEEDS) or not all(x['runtime_observed'] for x in n['parameters']): raise SystemExit('only all runtime-confirmed params may generate config')
 fallback=r['effective_mode']=='fallback';data=[];fixed=[]
 if fallback:data.append({'name':'rest_route','value':'/contact-form-7/v1/contact-forms'});fixed.append('rest_route')
 data += [{'name':k,'value':v} for k,v in SEEDS.items()]
 cfg={'target':'http://web/' if fallback else 'http://web/wp-json/contact-form-7/v1/contact-forms','methods':['GET'],'entrypoint_type':'rest_route','query_params':{'data':data,'fixed':fixed,'fuzz':names,'weight':1},'cookies':{'data':[{'name':'runtime_session','value':'${PHASE10_RUNTIME_SESSION}'}],'fixed':['runtime_session'],'fuzz':[],'weight':0},'metadata':{'plugin':n['plugin'],'callback_id':n['callback']['id'],'route':'/contact-form-7/v1/contact-forms','route_provenance':r,'discovery_provenance':'normalized-params.json','runtime_secret_refs':['PHASE10_RUNTIME_SESSION'],'seed_types':{'per_page':'integer','offset':'integer','order':'enum','orderby':'enum','search':'string'}}}
 Path(a.out).write_text(json.dumps(cfg,indent=2)+'\n')
if __name__=='__main__':main()
