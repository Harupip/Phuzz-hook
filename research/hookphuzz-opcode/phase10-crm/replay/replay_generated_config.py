#!/usr/bin/env python3
import argparse,json,os,subprocess,sys,uuid
from pathlib import Path
def main():
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--out',required=True);a=p.parse_args(); c=json.loads(Path(a.config).read_text()); fuzz=c['body_params']['fuzz'];
 if len(fuzz)!=1: raise SystemExit('exactly one fuzz parameter required')
 marker='PHASE10_CRM_'+uuid.uuid4().hex; rid='phase10crm-replay-'+uuid.uuid4().hex
 cmd=['bash','/workspace/wordpress/crm-request.sh','replay',rid,marker]; subprocess.run(cmd,check=True)
 Path(a.out).write_text(json.dumps({'request_id':rid,'marker':'<redacted>','marker_prefix':'PHASE10_CRM_','config':Path(a.config).name,'fuzz_parameter':fuzz[0]},indent=2))
if __name__=='__main__':main()
