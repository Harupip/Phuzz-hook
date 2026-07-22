#!/usr/bin/env python3
import json,subprocess,sys,uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
OUT=Path('/results');RUNTIME=OUT/'runtime';ROUTE='/contact-form-7/v1/contact-forms'
mode=sys.argv[1]
def request(label,key='',value=''):
 rid='phase10cf7-neg-'+label+'-'+uuid.uuid4().hex;marker='HOOKPHUZZ_CF7_NEG_'+uuid.uuid4().hex
 subprocess.run(['bash','/workspace/wordpress/rest-request.sh','negative',rid,marker,mode,key,value],check=True,capture_output=True,text=True)
 return rid
def doc(rid):
 p=RUNTIME/f'{rid}.rest.json';return json.loads(p.read_text()) if p.exists() else {}
def callback(rid): return doc(rid).get('callback_reached') is True
def curl(label,url,method='GET',header=None):
 rid='phase10cf7-neg-'+label+'-'+uuid.uuid4().hex;args=['curl','-sS','-o','/tmp/negative.body','-w','%{http_code}','-X',method,'-b','/tmp/phase10-cf7-rest.cookies','-H',f'X-Fuzzer-Covid: {rid}']
 if header: args+=['-H',header]
 status=subprocess.run(args+[url],check=True,capture_output=True,text=True).stdout.strip();return rid,status
def main():
 tests={}
 rid,status=curl('unknown',f'http://localhost/?rest_route=/no-such-route');tests['unknown_route']=status=='404' and not callback(rid)
 base='http://localhost/' if mode=='fallback' else 'http://localhost/wp-json'+ROUTE;post=base+('?rest_route='+ROUTE if mode=='fallback' else '')
 rid,status=curl('wrong-method',post,'POST');tests['wrong_http_method']=status in {'403','404','405'} and not callback(rid)
 rid=request('missing');tests['missing_parameter']=callback(rid) and not any(e.get('input_present') for e in doc(rid).get('events',[]))
 rid=request('unknown-param','unknown_parameter','x');tests['unknown_parameter']=callback(rid) and not any(e.get('parameter_key')=='unknown_parameter' for e in doc(rid).get('events',[]))
 rid,status=curl('invalid-typed','http://localhost/?rest_route=/wp/v2/posts&per_page=not-an-int');body=Path('/tmp/negative.body').read_text(errors='replace');tests['invalid_typed_validation']=status=='400' and 'rest_invalid_param' in body and not callback(rid)
 rid=request('fallback','search','fallback-check');tests['canonical_unavailable_fallback']=mode=='fallback' and callback(rid)
 one=request('marker-one','search','marker-one');two=request('marker-two','search','marker-two');tests['marker_isolation']=doc(one).get('request_id')==one and doc(two).get('request_id')==two and doc(one).get('events')!=doc(two).get('events')
 with ThreadPoolExecutor(max_workers=2) as pool: ids=list(pool.map(lambda n:request('parallel-'+str(n),'search','parallel-'+str(n)),range(2)))
 tests['concurrency']=all(doc(x).get('request_id')==x and callback(x) for x in ids)
 before={x.name for x in RUNTIME.glob('*.rest.json')};subprocess.run(['curl','-sS','http://localhost/?rest_route='+ROUTE],check=True,capture_output=True);subprocess.run(['curl','-sS','-H','X-Fuzzer-Covid: bad/id','http://localhost/?rest_route='+ROUTE],check=True,capture_output=True);tests['missing_invalid_request_id']={x.name for x in RUNTIME.glob('*.rest.json')}==before
 subprocess.run(['wp','--path=/var/www/html','--allow-root','plugin','deactivate','contact-form-7'],check=True,capture_output=True);rid,status=curl('inactive',f'http://localhost/?rest_route={ROUTE}');subprocess.run(['wp','--path=/var/www/html','--allow-root','plugin','activate','contact-form-7'],check=True,capture_output=True);tests['plugin_inactive']=status=='404' and not callback(rid)
 OUT.joinpath('negative-tests.json').write_text(json.dumps({'passed':all(tests.values()),'tests':tests},indent=2)+'\n');raise SystemExit(0 if all(tests.values()) else 1)
if __name__=='__main__':main()
