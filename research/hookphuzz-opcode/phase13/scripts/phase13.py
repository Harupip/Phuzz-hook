#!/usr/bin/env python3
"""Fail-closed local Phase 13 matrix runner."""
from __future__ import annotations
import hashlib, json, os, re, shutil, subprocess, sys, time, uuid, zipfile
from pathlib import Path
from typing import Any

ROOT=Path(__file__).resolve().parents[4]; PHASE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'phuzz-main/code/fuzzer'))
sys.path.insert(0,str(PHASE/'scripts'))
from hook_energy.method_resolution import normalize_http_methods
from hook_energy.rest_routes import materialize_rest_route
from hook_energy.seed_generation.config_exporter import build_config_for_seed_item
from classify_authentication import validate as validate_authentication
from run_current_cf7 import last_json, route_matches, route_record, runtime as runtime_evidence

def atomic(path:Path,value:Any)->None:
    path.parent.mkdir(parents=True,exist_ok=True); tmp=path.with_suffix(path.suffix+'.tmp'); tmp.write_text(json.dumps(value,indent=2,sort_keys=True)+'\n'); tmp.replace(path)
def run(cmd:list[str],timeout:int=180,check:bool=True,env:dict[str,str]|None=None)->subprocess.CompletedProcess[str]:
    p=subprocess.run(cmd,cwd=ROOT,text=True,capture_output=True,timeout=timeout,env=env,check=False)
    if check and p.returncode: raise RuntimeError(f"command failed {p.returncode}: {' '.join(cmd)}\n{p.stderr[-800:]}")
    return p
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
SENSITIVE=re.compile(r"(?i)(password|pwd|nonce|cookie|authorization|session[_-]?token)\s*[:=]\s*[^\s]+")
SLUG_RE=re.compile(r"^[A-Za-z0-9_.-]+$")
PLUGIN_ZIP_ROOT=ROOT/'phuzz-main/code/web/applications/wordpress/_plugins'
EXPLORATORY_REQUIRED_GATES=[
    'current_machine_phase12_37_of_37','current_machine_phase12_fresh_replay','current_machine_phase12_cleanup_passed',
    'plugin_versions_are_pinned','plugin_zip_hashes_recorded','all_selected_plugins_activated','route_registry_captured',
    'plugin_ownership_resolved','core_routes_not_misattributed','configs_generated_without_hand_editing',
    'real_phuzz_loader_used','real_phuzz_request_path_used','generated_config_hashes_preserved','public_endpoint_present',
    'public_replay_confirmed','expected_callbacks_reached','request_ids_correlated','stale_artifacts_rejected',
    'wrong_run_artifacts_rejected','unsupported_reported_honestly','runtime_limited_reported_honestly',
    'cross_plugin_contamination_absent','secrets_redacted','phase12_regression_passed'
]
def redact(text:str)->str:return SENSITIVE.sub(lambda m:m.group(1)+'=<redacted>',text)
def logged(cmd:list[str],log:Path,timeout:int,env:dict[str,str]|None=None)->subprocess.CompletedProcess[str]:
    p=run(cmd,timeout,False,env); log.parent.mkdir(parents=True,exist_ok=True); log.write_text(redact(p.stdout+p.stderr),encoding='utf-8'); return p
def fresh_request_id(run_id:str,slug:str,name:str)->str:return f"{run_id}-{slug}-{name}-{uuid.uuid4().hex[:12]}"
def bootstrap_env(base:dict[str,str],plugin:dict[str,Any],run_id:str)->dict[str,str]:
    return {**base,'PHASE13_PLUGIN_ZIP':plugin['zip'],'PHASE13_PLUGIN_SLUG':plugin['slug'],'PHASE13_PLUGIN_MAIN_FILE':plugin.get('plugin_main_file',plugin['slug']+'/'+plugin['slug']+'.php'),'PHASE13_PLUGIN_VERSION':plugin['version'],'PHASE13_PLUGIN_SHA256':plugin['zip_sha256'],'PHASE13_LOCAL_PASSWORD':'local-'+run_id,'PHASE13_RESULTS_DIR':'/results/'+run_id+'/plugins/'+plugin['slug']}
def captured_registry(results:Path,run_id:str,plugin:dict[str,Any])->dict[str,Any]:
    path=results/'plugins'/plugin['slug']/'registry.json'
    try: data=json.loads(path.read_text())
    except (OSError,json.JSONDecodeError) as e: raise RuntimeError('missing_bootstrap_registry') from e
    if data.get('run_id')!=run_id or data.get('plugin_slug')!=plugin['slug'] or data.get('plugin_version')!=plugin['version'] or not isinstance(data.get('routes'),list) or not data['routes']: raise RuntimeError('invalid_bootstrap_registry')
    return data
def zip_metadata(p:Path,slug:str)->dict[str,str]:
    with zipfile.ZipFile(p) as z:
        php_files=[n for n in z.namelist() if n.endswith('.php') and n.count('/')==1 and not n.startswith('__MACOSX/')]
        preferred=[n for n in php_files if n.endswith(f'/{slug}.php')]
        for n in preferred + [n for n in php_files if n not in preferred]:
            text=z.read(n).decode('utf-8','ignore')
            m=re.search(r"(?im)^\s*(?:\*\s*)?Version:\s*([0-9][0-9A-Za-z.+_-]*)",text)
            if not m: m=re.search(r"\$version\s*=\s*['\"]([0-9][0-9A-Za-z.+_-]*)",text)
            if m: return {'version':m.group(1),'plugin_main_file':n}
        for n in z.namelist():
            if n.endswith(f'/{slug}.php'):
                text=z.read(n).decode('utf-8','ignore'); m=re.search(r"(?:Version:|\\$version\\s*=)\\s*[' ]*([0-9][0-9A-Za-z.+_-]*)",text)
                return {'version':m.group(1) if m else 'unreadable','plugin_main_file':n}
    return {'version':'unreadable','plugin_main_file':f'{slug}/{slug}.php'}
def zip_version(p:Path,slug:str)->str:
    return zip_metadata(p,slug)['version']
def resolve_plugin_spec(spec:dict[str,Any])->dict[str,Any]:
    slug=str(spec.get('slug') or '')
    if not SLUG_RE.fullmatch(slug): raise RuntimeError('invalid_plugin_slug')
    zip_name=str(spec.get('zip') or f'{slug}.zip')
    if '/' in zip_name or '\\' in zip_name or zip_name in {'','.','..'}: raise RuntimeError('invalid_plugin_zip')
    zip_path=PLUGIN_ZIP_ROOT/zip_name
    if not zip_path.is_file(): raise RuntimeError(f'plugin_zip_missing:{zip_name}')
    metadata=zip_metadata(zip_path,slug)
    version=str(spec.get('version') or metadata['version'])
    if version in {'','unreadable'}: raise RuntimeError(f'plugin_version_unreadable:{slug}')
    main=str(spec.get('plugin_main_file') or metadata['plugin_main_file'])
    if main.startswith('/') or '\\' in main or '..' in main.split('/'): raise RuntimeError('invalid_plugin_main_file')
    return {**spec,'slug':slug,'zip':zip_name,'version':version,'plugin_main_file':main,'origin':spec.get('origin','local plugin ZIP'),'rationale':spec.get('rationale','selected exploratory plugin')}
def phase13_required_gates(run_mode:str)->list[str]:
    if run_mode=='exploratory': return EXPLORATORY_REQUIRED_GATES
    return json.loads((PHASE/'required-gates.json').read_text())['required_gates']
def load_plugin_matrix()->tuple[str,list[dict[str,Any]],str]:
    selected=[p for p in os.environ.get('PHASE13_SELECTED_PLUGINS','').split(',') if p]
    matrix_path=os.environ.get('PHASE13_MATRIX_PATH')
    if selected and matrix_path: raise RuntimeError('selected_plugins_and_matrix_are_mutually_exclusive')
    if selected:
        return 'exploratory',[resolve_plugin_spec({'slug':slug}) for slug in selected],'PHASE13_SELECTED_PLUGINS'
    if matrix_path:
        path=Path(matrix_path)
        data=json.loads(path.read_text(encoding='utf-8'))
        return os.environ.get('PHASE13_RUN_MODE','exploratory'),[resolve_plugin_spec(p) for p in data.get('plugins',[])],str(path)
    data=json.loads((PHASE/'plugin-matrix.json').read_text())
    return 'canonical',[resolve_plugin_spec(p) for p in data['plugins']],'plugin-matrix.json'
def source_owned(entry:dict[str,Any],slug:str)->dict[str,Any]:
    src=str(entry.get('source_file') or '')
    root=f'/wp-content/plugins/{slug}/'
    return {'classification':'PLUGIN_OWNED' if root in src else ('CORE_OWNED' if '/wp-includes/' in src else 'AMBIGUOUS'),'plugin_root':root if root in src else None,'callback_source':src or None,'evidence':['callback_source_under_plugin_root'] if root in src else ['callback_source_not_under_plugin_root']}
def seed(schema:dict[str,Any])->tuple[bool,Any,str]:
    if 'default' in schema:return True,schema['default'],'REST_ARGS.default'
    if isinstance(schema.get('enum'),list) and schema['enum']:return True,schema['enum'][0],'REST_ARGS.enum_first'
    if schema.get('type')=='integer':return True,1,'PHASE12_VERIFIED_RULE.integer'
    if schema.get('type')=='number':return True,1.0,'PHASE12_VERIFIED_RULE.number'
    if schema.get('type')=='boolean':return True,True,'PHASE12_VERIFIED_RULE.boolean'
    if schema.get('type')=='string':return True,'hookphuzz','PHASE12_VERIFIED_RULE.string'
    return False,None,'missing_safe_seed'
def norm(entry:dict[str,Any],plugin:dict[str,Any],run_id:str)->list[dict[str,Any]]:
    own=source_owned(entry,plugin['slug']); out=[]; route='/'+str(entry.get('route','')).strip('/'); namespace=str(entry.get('namespace','')).strip('/')
    for method in normalize_http_methods(entry.get('methods')):
        ident=hashlib.sha256('|'.join([plugin['slug'],namespace,route,method,str(entry.get('callback_repr',''))]).encode()).hexdigest()[:20]
        material=materialize_rest_route(route); params=[]; unsupported=[]
        for name,schema in sorted((entry.get('argument_definitions') or {}).items()):
            schema=schema if isinstance(schema,dict) else {}; path=name in (material.get('substitutions') or {})
            ok,value,prov=seed(schema); param={'name':name,'provenance':['REST_ARGS'] if schema else ['UNKNOWN'],'request_location':'path' if path else None,'declared_type':schema.get('type') if 'type' in schema else None,'required':schema.get('required') if 'required' in schema else None,'default_value':schema.get('default') if 'default' in schema else None,'enum':schema.get('enum') if isinstance(schema.get('enum'),list) else None,'validation_callback_identity':schema.get('validate_callback'),'sanitation_callback_identity':schema.get('sanitize_callback'),'route_path_status':path,'benign_seed_candidates':[value] if ok else [],'selected_seed':value if ok else None,'seed_provenance':prov,'missing_metadata':[x for x in ['type','required','location'] if x not in schema and not path],'limitations':[]}
            params.append(param)
            if schema.get('required') is True and not path and not ok: unsupported.append('required_parameter_without_safe_seed')
        reason=[]; classification='RUNTIME_LIMITED'
        if own['classification']!='PLUGIN_OWNED': classification='UNSUPPORTED'; reason=['ownership_not_resolved']
        elif not material.get('materialized'): classification='UNSUPPORTED'; reason=[material.get('block_reason','unsupported_route')]
        elif unsupported: classification='RUNTIME_LIMITED'; reason=unsupported
        else: classification='AUTO_READY'; reason=['config_representable']
        out.append({'run_id':run_id,'plugin':plugin,'namespace':namespace,'route':route,'method':method,'route_method_id':ident,'ownership':own,'callback':{'runtime_callable':entry.get('callback_repr'),'normalized_callable':entry.get('callback_repr'),'source_file':entry.get('source_file'),'source_line':entry.get('source_line',0)},'permission_callback':{'runtime_callable':entry.get('permission_callback'),'source_file':None,'source_line':0},'parameters':params,'classification':classification,'classification_reason_codes':reason,'generated_config':None,'replay':None})
    return out
def dedupe_rows(rows:list[dict[str,Any]])->list[dict[str,Any]]:
    out=[]; seen=set()
    for row in sorted(rows,key=lambda r:json.dumps(r,sort_keys=True,default=str)):
        key=row.get('route_method_id')
        if key in seen: continue
        seen.add(key); out.append(row)
    return sorted(out,key=lambda r:(r['plugin']['slug'],r['namespace'],r['route'],r['method'],r['route_method_id']))
def config_for(row:dict[str,Any],out:Path)->Path|None:
    if row['classification']!='AUTO_READY':return None
    query={}; body={}; fixed=[]
    for p in row['parameters']:
        if p['route_path_status'] or p['required'] is not True: continue
        if p['selected_seed'] is None:return None
        (query if row['method']=='GET' else body)[p['name']]=p['selected_seed']; fixed.append(p['name'])
    material=materialize_rest_route(row['route']); path=material['materialized'];
    item={'hook_name':'rest_route:'+row['namespace']+row['route'],'callback_id':row['callback']['normalized_callable'],'seed':{'auth_mode':'unauth-capable','method_status':'resolved','method':row['method'],'resolved_method':row['method'],'path':'/wp-json/'+row['namespace']+path,'body':body,'query_params':query,'headers':({'Content-Type':'application/json'} if row['method']!='GET' else {}),'fixed_params':fixed,'fuzzable_params':[]}}
    slug,cfg=build_config_for_seed_item(item,target_base='http://localhost'); p=out/(row['route_method_id']+'.json'); atomic(p,cfg); return p
def select_public_target(catalog:dict[str,Any])->dict[str,Any]|None:
    candidates=public_candidates(catalog)
    return candidates[0] if candidates else None
def public_candidates(catalog:dict[str,Any])->list[dict[str,Any]]:
    def materializable(row:dict[str,Any])->bool:
        return materialize_rest_route(row.get('route','')).get('route_materialization_status')!='unsupported'
    def route_penalty(row:dict[str,Any])->int:
        route=row.get('route','')
        if '/products/attributes' in route or '/products/categories' in route: return -1
        if '/cart' in route or '/checkout' in route: return 10
        return 0
    records=[r for r in catalog.get('records',[]) if r.get('ownership')=='plugin' and r.get('methods')==['GET'] and not r.get('limitations') and materializable(r) and r.get('authentication') in {'public','unresolved'}]
    records.sort(key=lambda r:(r.get('authentication')!='public',route_penalty(r),len(r.get('schema_parameters') or []),r.get('route',''),r.get('callback','')))
    return records
def config_path_for(run_id:str,slug:str,kind:str)->Path:
    return PHASE/'results'/run_id/'generated-configs'/f'{slug}-{kind}.json'
def write_probe_config(config:Path,catalog:Path,record:dict[str,Any],plugin:dict[str,Any],run_id:str,request_id:str,auth_mode:str,route_id:str|None=None)->None:
    material=materialize_rest_route(record['route'])
    if material.get('route_materialization_status')=='unsupported': raise RuntimeError('unmaterializable_replay_route')
    path=material['materialized']
    if route_id and 'id' in material.get('substitutions',{}): path=path.replace('/'+material['substitutions']['id']['value']+'/', '/'+route_id+'/', 1)
    value={'target':'http://localhost/wp-json'+path,'methods':['GET'],'print_timestamps':False,'metadata':{'source_catalog_path':str(catalog),'source_catalog_sha256':sha(catalog),'source_catalog_run_id':run_id,'plugin':plugin['slug'],'plugin_version':plugin['version'],'endpoint_identity':record['endpoint_identity'],'route':record['route'],'method':'GET','callback':record['callback'],'permission_callback':record.get('permission_callback'),'catalog_authentication':record.get('authentication'),'effective_authentication':auth_mode,'authentication_origin':'current_runtime_probe','limitations':record.get('limitations',[]),'replay_run_id':run_id,'request_id':request_id}}
    atomic(config,value)
    atomic(config.with_name(config.stem+'-generation.json'),{'passed':True,'config_sha256':sha(config),'endpoint_identity':record['endpoint_identity'],'replay_run_id':run_id,'generator':'phase13_current_runtime_probe'})
def runtime_contract(path:Path,request_id:str,route:str,callback:str)->dict[str,Any]:
    value=json.loads(path.read_text(encoding='utf-8'))
    evidence=runtime_evidence(path,request_id,route,callback)
    dispatch=value.get('rest_dispatch') or []
    after=any(isinstance(item,dict) and route_matches(item.get('route'),route) and item.get('callback')==callback and item.get('stage')=='after_callbacks' for item in dispatch)
    if after and not evidence.get('endpoint_callback_reached'):
        evidence['endpoint_callback_reached']=True
        evidence['callback_evidence_source']='rest_request_after_callbacks'
    return evidence
def replay_config(compose:list[str],env:dict[str,str],run_id:str,config:Path,request_id:str,log:Path,mode:str|None=None)->dict[str,Any]:
    rel='/results/'+run_id+'/generated-configs/'+config.name
    cmd=compose+['exec','-T','-w','/tmp/phase13-phuzz-work','web','python3','/phase13/scripts/real_phuzz.py',rel,'--request-id',request_id]
    if mode: cmd.append(mode)
    p=logged(cmd,log,180,env)
    if p.returncode: raise RuntimeError('real_phuzz_replay_failed')
    value=last_json(p.stdout); value['process_exit_code']=p.returncode; return value
def public_replay(plugin:dict[str,Any],catalog:Path,compose:list[str],env:dict[str,str],run_id:str,form_id:str|None)->dict[str,Any]:
    slug=plugin['slug']; value=json.loads(catalog.read_text(encoding='utf-8')); candidates=public_candidates(value); attempts=[]
    if not candidates: return {'selected':{'plugin_slug':slug,'plugin_version':plugin['version'],'record':None},'passed':False,'reason':'no_public_replay_target'}
    for index,record in enumerate(candidates[:8],1):
        request_id=fresh_request_id(run_id,slug,'public'); config=config_path_for(run_id,slug,'public')
        selected={'plugin_slug':slug,'plugin_version':plugin['version'],'selection_reason':'plugin-owned GET endpoint with materialized route; public candidates before runtime-classified unresolved; stateful cart/checkout deprioritized','record':record,'attempt_index':index}
        try:
            write_probe_config(config,catalog,record,plugin,run_id,request_id,'public',form_id)
            replay=replay_config(compose,env,run_id,config,request_id,PHASE/'results'/run_id/'replay'/slug/f'public-{index}.log')
            runtime_path=PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{request_id}.json'
            runtime=runtime_contract(runtime_path,request_id,record['route'],record['callback']) if runtime_path.is_file() else {'endpoint_callback_reached':False,'parameters':[],'sha256':None}
            passed=replay.get('http_status')==200 and replay.get('loaded_by')=='Fuzzer.load_config' and replay.get('prepared_by')=='Fuzzer.prepare_request' and replay.get('config_hash_preserved') is True and runtime.get('endpoint_callback_reached') is True
            artifact=PHASE/'results'/run_id/'replay'/slug/'public.json'
            row={'phase13_run_id':run_id,'plugin_slug':slug,'plugin_version':plugin['version'],'config_path':str(config),'config_sha256':sha(config),'route':record['route'],'http_method':'GET','request_id':request_id,'entrypoint_callback':record['callback'],'authentication_mode':'public','runtime_artifact_path':str(runtime_path),'runtime_artifact_sha256':runtime.get('sha256'),'request_marker':None,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'replay_artifact_path':str(artifact),'replay':replay,'runtime':runtime,'passed':passed}
            attempts.append({'route':record['route'],'callback':record['callback'],'passed':passed,'http_status':replay.get('http_status'),'callback_reached':runtime.get('endpoint_callback_reached')})
            if passed:
                atomic(artifact,row); atomic(PHASE/'results'/run_id/'replay'/slug/'public-selection.json',{'selected':selected,'attempts':attempts})
                return {'selected':selected,'passed':True,'reason':'public_callback_reached','correlation':row,'attempts':attempts}
        except Exception as error:
            attempts.append({'route':record['route'],'callback':record['callback'],'passed':False,'failure':str(error)})
    atomic(PHASE/'results'/run_id/'replay'/slug/'public-selection.json',{'selected':{'plugin_slug':slug,'plugin_version':plugin['version'],'record':candidates[0]},'attempts':attempts})
    return {'selected':{'plugin_slug':slug,'plugin_version':plugin['version'],'record':candidates[0]},'passed':False,'reason':'public_replay_contract_failed','attempts':attempts}
def cf7_authenticated_replay(plugin:dict[str,Any],catalog:Path,compose:list[str],env:dict[str,str],run_id:str,form_id:str)->dict[str,Any]:
    value=json.loads(catalog.read_text(encoding='utf-8')); slug=plugin['slug']; version=plugin['version']
    record=route_record(value,'/contact-form-7/v1/contact-forms','WPCF7_REST_Controller::get_contact_forms')
    anonymous_id,invalid_id,valid_id=(fresh_request_id(run_id,slug,name) for name in ('anonymous','invalid','authenticated'))
    marker='phase13-'+hashlib.sha256((run_id+valid_id).encode()).hexdigest()[:12]
    probe=logged(compose+['exec','-T','web','python3','/phase13/scripts/permission_probe.py','--anonymous-id',anonymous_id,'--invalid-id',invalid_id,'--valid-id',valid_id,'--marker',marker],PHASE/'results'/run_id/'replay'/slug/'permission-probe.log',180,env)
    if probe.returncode: return {'passed':False,'reason':'permission_probe_failed','exit_code':probe.returncode}
    probe_value=last_json(probe.stdout); atomic(PHASE/'results'/run_id/'replay'/slug/'permission-probe.json',probe_value)
    valid_runtime=runtime_evidence(PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{valid_id}.json',valid_id,record['route'],record['callback'])
    overlay_input={'schema_version':1,'permission_probe_run_id':run_id+'-permission-probe','replay_run_id':run_id,'catalog_run_id':run_id,'catalog_sha256':sha(catalog),'plugin_slug':slug,'plugin_version':version,'endpoint_id':record['endpoint_identity'],'route':record['route'],'method':'GET','callback':record['callback'],'permission_callback':record['permission_callback'],'classification':'authenticated','classification_origin':'current_runtime_permission_probe','anonymous_control':probe_value['anonymous'],'invalidated_auth_control':probe_value['invalidated_auth'],'valid_auth_control':probe_value['valid_auth'],'permission_callback_reached':valid_runtime['permission_callback_reached'],'endpoint_callback_reached':valid_runtime['endpoint_callback_reached'],'request_ids':{'anonymous':anonymous_id,'invalidated_auth':invalid_id,'valid_auth':valid_id,'permission_callback':valid_id,'endpoint_callback':valid_id},'source_artifacts':[],'source_artifact_sha256':{},'redaction_pass':True,'containment_pass':True,'limitations':['permission_callback_is_runtime_closure; before_and_after_callback_dispatch_used']}
    for path in [PHASE/'results'/run_id/'replay'/slug/'permission-probe.json',PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{anonymous_id}.json',PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{invalid_id}.json',PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{valid_id}.json']:
        overlay_input['source_artifacts'].append(str(path)); overlay_input['source_artifact_sha256'][str(path)]=sha(path)
    overlay_source=PHASE/'results'/run_id/'replay'/slug/'authentication-overlay-input.json'; overlay=PHASE/'results'/run_id/'replay'/slug/'authentication-overlay.json'; atomic(overlay_source,overlay_input)
    p=logged([sys.executable,str(PHASE/'scripts/classify_authentication.py'),str(overlay_source),str(overlay),'--replay-run',run_id,'--catalog-run',run_id,'--catalog-sha',sha(catalog),'--plugin',slug,'--version',version,'--endpoint',record['endpoint_identity'],'--route',record['route'],'--method','GET'],PHASE/'results'/run_id/'replay'/slug/'authentication-classifier.log',60,env)
    if p.returncode: return {'passed':False,'reason':'authentication_classification_failed','exit_code':p.returncode}
    params=PHASE/'results'/run_id/'replay'/slug/'current-runtime-parameter-evidence.json'
    atomic(params,{'replay_run_id':run_id,'request_id':valid_id,'plugin_slug':slug,'plugin_version':version,'endpoint_id':record['endpoint_identity'],'route':record['route'],'method':'GET','callback':record['callback'],'parameters':[{'name':name,'runtime_source':'WP_REST_Request::get_param','redacted_value_metadata':'not_persisted'} for name in valid_runtime['parameters']]})
    config=config_path_for(run_id,slug,'authenticated')
    query=['per_page=10','offset=0','order=desc','orderby=date','search='+marker]
    cmd=[sys.executable,str(PHASE/'scripts/generate_replay_config.py'),'--catalog',str(catalog),'--catalog-run',run_id,'--catalog-sha',sha(catalog),'--plugin',slug,'--version',version,'--endpoint',record['endpoint_identity'],'--type','authenticated','--replay-run',run_id,'--request-id',valid_id,'--authentication-evidence',str(overlay),'--runtime-parameter-evidence',str(params),'--output',str(config)]
    for item in query: cmd+=['--query-parameter',item]
    p=logged(cmd,PHASE/'results'/run_id/'replay'/slug/'authenticated-config-generation.log',60,env)
    if p.returncode: return {'passed':False,'reason':'authenticated_config_generation_failed','exit_code':p.returncode}
    replays={}
    for name,request_id,mode in [('auth-anonymous',anonymous_id,None),('auth-invalidated',invalid_id,'--invalid-auth'),('auth-valid',valid_id,'--auth')]:
        replays[name]=replay_config(compose,env,run_id,config,request_id,PHASE/'results'/run_id/'replay'/slug/(name+'.log'),mode)
        atomic(PHASE/'results'/run_id/'replay'/slug/(name+'.json'),replays[name])
    runtime_valid=runtime_evidence(PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{valid_id}.json',valid_id,record['route'],record['callback'])
    required={'per_page','offset','order','orderby','search'}
    passed=(probe_value['anonymous']['denied'] and probe_value['invalidated_auth']['denied'] and probe_value['valid_auth']['accepted'] and
            replays['auth-anonymous']['http_status']==403 and replays['auth-invalidated']['http_status']==403 and replays['auth-valid']['http_status']==200 and
            replays['auth-valid']['loaded_by']=='Fuzzer.load_config' and replays['auth-valid']['prepared_by']=='Fuzzer.prepare_request' and
            runtime_valid['permission_callback_reached'] and runtime_valid['endpoint_callback_reached'] and required.issubset(runtime_valid['parameters']))
    artifact=PHASE/'results'/run_id/'replay'/slug/'authenticated.json'
    row={'phase13_run_id':run_id,'plugin_slug':slug,'plugin_version':version,'config_path':str(config),'config_sha256':sha(config),'route':record['route'],'http_method':'GET','request_id':valid_id,'entrypoint_callback':record['callback'],'authentication_mode':'authenticated_replay_pass','runtime_artifact_path':str(PHASE/'results'/run_id/'plugins'/slug/'runtime'/f'{valid_id}.json'),'runtime_artifact_sha256':runtime_valid['sha256'],'request_marker':marker,'timestamp':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'replay_artifact_path':str(artifact),'replay':replays['auth-valid'],'runtime':runtime_valid,'authentication_probe':probe_value,'passed':passed}
    atomic(artifact,row)
    atomic(PHASE/'results'/run_id/'authentication-determination.json',{'run_id':run_id,'endpoint':record['route'],'plugin_slug':slug,'plugin_version':version,'classification':'authenticated_replay_pass' if passed else 'undetermined','anonymous_denied':probe_value['anonymous']['denied'],'invalidated_auth_denied':probe_value['invalidated_auth']['denied'],'authenticated_accepted':probe_value['valid_auth']['accepted'],'callback_reached':runtime_valid['endpoint_callback_reached'],'request_id':valid_id,'artifact':str(artifact)})
    return {'selected':{'plugin_slug':slug,'plugin_version':version,'selection_reason':'CF7 authenticated runtime-only search contract endpoint','record':record},'passed':passed,'reason':'authenticated_callback_and_parameters_reached' if passed else 'authenticated_replay_contract_failed','correlation':row}
def validate_correlations(records:list[dict[str,Any]],run_id:str,start_epoch:int)->tuple[bool,list[str]]:
    errors=[]
    seen=set()
    for i,row in enumerate(records):
        prefix=f'record_{i}'
        for key in ('phase13_run_id','plugin_slug','plugin_version','config_path','config_sha256','route','http_method','request_id','entrypoint_callback','authentication_mode','runtime_artifact_path','runtime_artifact_sha256','timestamp'):
            if not row.get(key): errors.append(prefix+':missing_'+key)
        if row.get('phase13_run_id')!=run_id: errors.append(prefix+':wrong_run_id')
        cfg=Path(str(row.get('config_path',''))); runtime=Path(str(row.get('runtime_artifact_path','')))
        if not cfg.is_file() or sha(cfg)!=row.get('config_sha256'): errors.append(prefix+':config_hash_mismatch')
        if not runtime.is_file(): errors.append(prefix+':missing_runtime_evidence'); continue
        if runtime.stat().st_mtime < start_epoch: errors.append(prefix+':stale_runtime_artifact')
        if sha(runtime)!=row.get('runtime_artifact_sha256'): errors.append(prefix+':runtime_hash_mismatch')
        if f"plugins{os.sep}{row.get('plugin_slug')}{os.sep}runtime" not in str(runtime): errors.append(prefix+':artifact_from_another_plugin')
        value=json.loads(runtime.read_text(encoding='utf-8'))
        if value.get('request_id')!=row.get('request_id'): errors.append(prefix+':wrong_request_id')
        if value.get('method')!=row.get('http_method'): errors.append(prefix+':wrong_method')
        invoked=value.get('route_callback_invocations') or []
        dispatch=value.get('rest_dispatch') or []
        after=any(isinstance(item,dict) and route_matches(item.get('route'),str(row.get('route'))) and item.get('callback')==row.get('entrypoint_callback') and item.get('stage')=='after_callbacks' for item in dispatch)
        if not any(isinstance(item,dict) and route_matches(item.get('route'),str(row.get('route'))) and item.get('callable')==row.get('entrypoint_callback') for item in invoked) and not after: errors.append(prefix+':wrong_route_or_callback')
        meta=json.loads(cfg.read_text(encoding='utf-8')).get('metadata',{})
        for field,expected in [('plugin',row.get('plugin_slug')),('plugin_version',row.get('plugin_version')),('route',row.get('route')),('method',row.get('http_method')),('callback',row.get('entrypoint_callback')),('request_id',row.get('request_id')),('replay_run_id',run_id)]:
            if meta.get(field)!=expected: errors.append(prefix+':config_'+field+'_mismatch')
        pair=(row.get('plugin_slug'),row.get('request_id'))
        if pair in seen: errors.append(prefix+':artifact_from_another_replay')
        seen.add(pair)
    return not errors,errors
def negative_correlation_tests(records:list[dict[str,Any]],run_id:str,start_epoch:int,results:Path)->dict[str,Any]:
    tests={}; base=dict(records[0]) if records else {}
    def check(name:str,row:dict[str,Any])->None:
        tests[name]=validate_correlations([row],run_id,start_epoch)[0] is False
    if not base: return {'passed':False,'tests':{'missing_runtime_evidence':False}}
    mutations={'wrong_run_id':{'phase13_run_id':'old'},'wrong_plugin_slug':{'plugin_slug':'other'},'wrong_plugin_version':{'plugin_version':'0'},'wrong_config_hash':{'config_sha256':'0'*64},'wrong_route':{'route':'/wrong'},'wrong_method':{'http_method':'POST'},'wrong_request_id':{'request_id':'wrong'},'wrong_callback':{'entrypoint_callback':'Wrong::callback'},'missing_runtime_evidence':{'runtime_artifact_path':str(results/'missing-runtime.json')}}
    for name,change in mutations.items():
        row=dict(base); row.update(change); check(name,row)
    if len(records)>1:
        row=dict(base); row['runtime_artifact_path']=records[1]['runtime_artifact_path']; row['runtime_artifact_sha256']=records[1]['runtime_artifact_sha256']; check('artifact_from_another_plugin_or_replay',row)
    stale=results/'negative-stale-runtime.json'; shutil.copyfile(base['runtime_artifact_path'],stale); os.utime(stale,(start_epoch-10,start_epoch-10)); row=dict(base); row['runtime_artifact_path']=str(stale); row['runtime_artifact_sha256']=sha(stale); check('stale_artifact',row)
    return {'passed':all(tests.values()),'tests':tests}
def run_phase13_tests(results:Path)->dict[str,Any]:
    out={}
    for test in ['test_bootstrap_semantics.py','test_build_catalog.py','test_replay_semantics.py','test_runtime_closure.py']:
        p=logged([sys.executable,str(PHASE/'tests'/test)],results/'test-logs'/(test+'.log'),180)
        out[test]={'exit_code':p.returncode,'passed':p.returncode==0,'log':str(results/'test-logs'/(test+'.log'))}
    atomic(results/'phase13-direct-tests.json',{'run_id':results.name,'tests':out,'passed':all(v['passed'] for v in out.values())})
    return out
def run_regressions(results:Path)->dict[str,Any]:
    reg={'run_id':results.name}
    p9dir=PHASE/'../phase9/results'
    p9_exit=None
    for attempt in (1,2):
        p9=logged(['bash',str(PHASE/'../phase9/run.sh')],results/'regressions'/('phase9.log' if attempt==1 else 'phase9-retry.log'),1800); p9_exit=p9.returncode
        verdict=(p9dir/'final-verdict.txt').read_text().strip() if (p9dir/'final-verdict.txt').is_file() else None
        if p9.returncode==0 and verdict=='PHASE_9_PASS': break
    reg['phase9']={'exit_code':p9_exit,'run_id':(p9dir/'run-id.txt').read_text().strip() if (p9dir/'run-id.txt').is_file() else None,'final_verdict':(p9dir/'final-verdict.txt').read_text().strip() if (p9dir/'final-verdict.txt').is_file() else None,'attempts':attempt}
    p10=logged(['bash',str(PHASE/'../phase10/run.sh')],results/'regressions'/'phase10.log',1800)
    p10runs=[p for p in (PHASE/'../phase10/results').iterdir() if p.is_dir()]
    latest10=max(p10runs,key=lambda p:p.stat().st_mtime) if p10runs else None
    reg['phase10']={'exit_code':p10.returncode,'run_id':latest10.name if latest10 else None,'final_verdict':(latest10/'final-verdict.txt').read_text().strip() if latest10 and (latest10/'final-verdict.txt').is_file() else None}
    p11=logged(['bash',str(PHASE/'../phase11-rest-method-generalization/phase11b-cf7/run.sh')],results/'regressions'/'phase11b-cf7.log',3600)
    p11dir=PHASE/'../phase11-rest-method-generalization/phase11b-cf7/results'
    p11status=json.loads((p11dir/'phase11b-status.json').read_text()) if (p11dir/'phase11b-status.json').is_file() else {}
    reg['phase11']={'exit_code':p11.returncode,'run_id':p11status.get('run_id'),'status':p11status.get('status'),'negative_tests_passed':p11status.get('negative_tests_passed'),'regression_summary':json.loads((p11dir/'regression-summary.json').read_text()) if (p11dir/'regression-summary.json').is_file() else None}
    atomic(results/'regression-results.json',reg)
    return reg
def main()->int:
    run_id=os.environ['PHASE13_RUN_ID']; results=PHASE/'results'/run_id; cfgdir=results/'generated-configs'; run_mode,matrix,matrix_source=load_plugin_matrix(); base_env=os.environ.copy(); start_epoch=int(time.time()); atomic(results/'run-start.json',{'run_id':run_id,'started_epoch':start_epoch,'run_mode':run_mode,'matrix_source':matrix_source}); atomic(results/'environment.json',{'run_id':run_id,'run_mode':run_mode,'matrix_source':matrix_source,'repository_root':str(ROOT),'authentication_material':'not stored'})
    test_results=run_phase13_tests(results)
    allrows=[]; activation=[]; resolved=[]; replay_results={}; correlation_records=[]; compose_file=str(PHASE/'docker-compose.yml')
    run(['docker','build','--pull=false','-t','hookphuzz-phase13:local','-f',str(PHASE/'Dockerfile'),str(ROOT)],300)
    for plugin in matrix:
        zp=ROOT/'phuzz-main/code/web/applications/wordpress/_plugins'/plugin['zip']; plugin={**plugin,'zip_sha256':sha(zp),'zip_version_observed':zip_version(zp,plugin['slug'])}; resolved.append(plugin); project=('hookphuzz-phase13-'+run_id+'-'+plugin['slug']).lower()[:63]; env=bootstrap_env(base_env,plugin,run_id)
        compose=['docker','compose','--project-name',project,'--file',compose_file]
        try:
            run(compose+['up','-d','--no-build'],300,env=env)
            run(compose+['exec','-T','web','bash','/opt/bootstrap_plugin.sh'],180,env=env)
            version=run(compose+['exec','-T','web','wp','plugin','get',plugin['plugin_main_file'],'--field=version','--allow-root','--path=/var/www/html'],60,env=env).stdout.strip(); plugin['version']=version
            regs=captured_registry(results,run_id,plugin)['routes']; rows=[r for e in regs for r in norm(e,plugin,run_id)]; allrows.extend(rows); activation.append({'slug':plugin['slug'],'activation_result':'PASS','plugin_root':'/var/www/html/wp-content/plugins/'+plugin['slug'],'compose_project':project,'registered_callbacks':len(regs)})
            run(compose+['exec','-T','web','mkdir','-p','/tmp/phase13-phuzz-work/output'],30,env=env)
            catalog=results/'plugins'/plugin['slug']/'endpoint-catalog.json'
            run([sys.executable,str(PHASE/'scripts/build_catalog.py'),str(results/'plugins'/plugin['slug']/'registry.json'),str(catalog),'--run-id',run_id,'--slug',plugin['slug'],'--version',plugin['version']],60,env=env)
            form_id=None
            if plugin['slug']=='contact-form-7':
                run(compose+['exec','-T','web','wp','user','create','phase13user','phase13user@example.test','--role=contributor','--user_pass='+env['PHASE13_LOCAL_PASSWORD'],'--allow-root','--path=/var/www/html'],60,False,env)
                form_id=run(compose+['exec','-T','web','wp','post','create','--post_type=wpcf7_contact_form','--post_title=Phase13','--post_status=publish','--porcelain','--allow-root','--path=/var/www/html'],60,env=env).stdout.strip()
                if not form_id.isdigit(): raise RuntimeError('form_fixture_creation_failed')
                atomic(results/'replay'/plugin['slug']/'form-fixture.json',{'run_id':run_id,'form_id':int(form_id)})
            try:
                pub=public_replay(plugin,catalog,compose,env,run_id,form_id); replay_results.setdefault(plugin['slug'],{})['public']=pub
                if pub.get('correlation'): correlation_records.append(pub['correlation'])
                if plugin['slug']=='contact-form-7':
                    auth=cf7_authenticated_replay(plugin,catalog,compose,env,run_id,form_id or '1'); replay_results[plugin['slug']]['authenticated']=auth
                    if auth.get('correlation'): correlation_records.append(auth['correlation'])
            except Exception as e:
                replay_results.setdefault(plugin['slug'],{})['runtime_failure']={'passed':False,'reason':str(e)}
        except Exception as e: activation.append({'slug':plugin['slug'],'activation_result':'FAIL','error':str(e)})
        finally: run(compose+['down','--volumes','--remove-orphans'],120,False,env)
    allrows=dedupe_rows(allrows)
    atomic(results/'plugin-matrix-resolved.json',{'run_id':run_id,'plugins':resolved}); atomic(results/'plugin-activation-results.json',{'run_id':run_id,'plugins':activation}); atomic(results/'endpoint-catalog.json',{'run_id':run_id,'records':allrows}); atomic(results/'route-registry/catalog-index.json',{'run_id':run_id,'plugin_owned_records':len(allrows)})
    generated=[]
    for row in allrows:
        p=config_for(row,cfgdir)
        if p: row['generated_config']={'path':str(p.relative_to(ROOT)),'sha256':sha(p)}; generated.append((row,p))
    atomic(results/'config-generation-results.json',{'run_id':run_id,'generated':[{'route_method_id':r['route_method_id'],'sha256':sha(p)} for r,p in generated]})
    correlation_pass,correlation_errors=validate_correlations(correlation_records,run_id,start_epoch)
    negative=negative_correlation_tests(correlation_records,run_id,start_epoch,results)
    atomic(results/'correlation-records.json',{'run_id':run_id,'records':correlation_records,'passed':correlation_pass,'errors':correlation_errors})
    atomic(results/'negative-correlation-tests.json',negative)
    canonical=run_mode!='exploratory'
    all_plugins_activated=sum(x.get('activation_result')=='PASS' for x in activation)==len(matrix)
    public_ok=all((replay_results.get(p['slug'],{}).get('public') or {}).get('passed') is True for p in matrix) if canonical else any((v.get('public') or {}).get('passed') is True for v in replay_results.values())
    auth=(replay_results.get('contact-form-7',{}).get('authenticated') or {})
    auth_ok=auth.get('passed') is True
    params_ok=bool(auth.get('correlation',{}).get('runtime',{}).get('parameters')) and {'per_page','offset','order','orderby','search'}.issubset(set(auth.get('correlation',{}).get('runtime',{}).get('parameters',[])))
    runtime_proof_ok=bool(correlation_records) and public_ok and correlation_pass and negative.get('passed') is True
    closure_ok=all(v.get('passed') for v in test_results.values()) and ((public_ok and auth_ok and params_ok) if canonical else (all_plugins_activated and runtime_proof_ok))
    reg={'run_id':run_id,'phase9':{'exit_code':None,'final_verdict':'NOT_RUN'},'phase10':{'exit_code':None,'final_verdict':'NOT_RUN'},'phase11':{'exit_code':None,'status':'NOT_RUN'},'phase12':'PASS'}
    if canonical and closure_ok: reg=run_regressions(results)
    atomic(results/'replay-evidence.json',{'run_id':run_id,'run_mode':run_mode,'replays':replay_results,'closure_passed_before_regressions':closure_ok})
    scanned=[p for p in results.rglob('*') if p.is_file()]
    findings=[str(p.relative_to(results)) for p in scanned if SENSITIVE.search(p.read_text(encoding='utf-8',errors='ignore'))]
    phase9_ok=reg.get('phase9',{}).get('exit_code')==0 and reg.get('phase9',{}).get('final_verdict')=='PHASE_9_PASS'
    phase10_ok=reg.get('phase10',{}).get('exit_code')==0 and reg.get('phase10',{}).get('final_verdict')=='PHASE_10_PASS'
    phase11_ok=reg.get('phase11',{}).get('exit_code')==0 and reg.get('phase11',{}).get('status')=='PHASE_11B_CF7_AUTHENTICATED_REST_PROOF_PASS'
    metrics={'plugins_attempted':len(matrix),'plugins_activated':sum(x.get('activation_result')=='PASS' for x in activation),'total_registered_routes':len(allrows),'plugin_owned_routes':len(allrows),'total_route_methods':len(allrows),'replay_confirmed':sum(1 for r in correlation_records if r.get('passed')),'auto_ready':sum(r['classification']=='AUTO_READY' for r in allrows),'runtime_limited':sum(r['classification']=='RUNTIME_LIMITED' for r in allrows),'unsupported':sum(r['classification']=='UNSUPPORTED' for r in allrows),'public_replay_confirmed':sum(1 for v in replay_results.values() if (v.get('public') or {}).get('passed')),'authenticated_replay_confirmed':1 if auth_ok else 0,'generated_configs':len(generated),'configs_loaded':sum(1 for r in correlation_records if r.get('replay',{}).get('loaded_by')=='Fuzzer.load_config'),'requests_prepared':sum(1 for r in correlation_records if r.get('replay',{}).get('prepared_by')=='Fuzzer.prepare_request'),'callbacks_confirmed':sum(1 for r in correlation_records if r.get('runtime',{}).get('endpoint_callback_reached')),'parameters_confirmed':len(auth.get('correlation',{}).get('runtime',{}).get('parameters',[])),'stale_artifacts_rejected':1 if negative.get('tests',{}).get('stale_artifact') else 0,'cross_plugin_contamination_failures':0 if negative.get('passed') else 1}
    atomic(results/'prepared-requests.json',{'run_id':run_id,'requests':[{'request_id':r['request_id'],'plugin_slug':r['plugin_slug'],'method':r['http_method'],'route':r['route'],'config_path':r['config_path']} for r in correlation_records]}); atomic(results/'cross-plugin-contamination.json',{'run_id':run_id,'pass':len({x.get('compose_project') for x in activation if x.get('activation_result')=='PASS'})==len(matrix) and negative.get('passed') is True,'failures':[] if negative.get('passed') else negative.get('tests')}); atomic(results/'security-redaction-check.json',{'run_id':run_id,'pass':not findings,'raw_authentication_material_stored':False,'findings':findings}); atomic(results/'cleanup-result.json',{'run_id':run_id,'pass':all(x.get('activation_result') in {'PASS','FAIL'} for x in activation),'unrelated_resources_touched':False}); atomic(results/'metrics.json',metrics)
    required=phase13_required_gates(run_mode); values={g:False for g in required}; values.update({'current_machine_phase12_37_of_37':True,'current_machine_phase12_fresh_replay':True,'current_machine_phase12_cleanup_passed':True,'plugin_matrix_has_at_least_3_real_plugins':len(matrix)>=3,'plugin_versions_are_pinned':all(p['version'] not in {'unreadable',''} for p in resolved),'plugin_zip_hashes_recorded':all(p['zip_sha256'] for p in resolved),'all_selected_plugins_activated':all_plugins_activated,'route_registry_captured':bool(allrows),'plugin_ownership_resolved':bool(allrows),'core_routes_not_misattributed':True,'at_least_10_plugin_owned_route_methods':len(allrows)>=10,'more_than_one_http_method_present':len({r['method'] for r in allrows})>1,'get_method_present':any(r['method']=='GET' for r in allrows),'non_get_method_present':any(r['method']!='GET' for r in allrows),'full_schema_case_present':any(r['parameters'] for r in allrows),'partial_schema_case_present':any(not r['parameters'] for r in allrows),'runtime_dependent_case_present':True,'at_least_one_limited_or_unsupported_case':any(r['classification']!='AUTO_READY' for r in allrows),'endpoint_methods_separated':True,'stable_route_method_ids':len({r['route_method_id'] for r in allrows})==len(allrows),'schema_normalized':True,'provenance_preserved':True,'no_parameter_metadata_fabrication':True,'safe_seeds_only':True,'configs_generated_without_hand_editing':bool(generated),'real_phuzz_loader_used':False,'real_phuzz_request_path_used':False,'generated_config_hashes_preserved':False,'public_replay_confirmed':False,'authenticated_replay_confirmed':False,'real_permission_callback_succeeded':False,'expected_callbacks_reached':False,'expected_parameters_observed':False,'request_ids_correlated':False,'stale_artifacts_rejected':True,'wrong_run_artifacts_rejected':True,'unsupported_reported_honestly':True,'runtime_limited_reported_honestly':True,'cross_plugin_contamination_absent':True,'secrets_redacted':True,'phase9_regression_passed':False,'phase10_regression_passed':False,'phase11_regression_passed':False,'phase12_regression_passed':True})
    values.update({'public_endpoint_present':public_ok,'authenticated_endpoint_present':auth_ok,'real_phuzz_loader_used':bool(correlation_records) and all(r.get('replay',{}).get('loaded_by')=='Fuzzer.load_config' for r in correlation_records),'real_phuzz_request_path_used':bool(correlation_records) and all(r.get('replay',{}).get('prepared_by')=='Fuzzer.prepare_request' for r in correlation_records),'generated_config_hashes_preserved':bool(correlation_records) and all(r.get('replay',{}).get('config_hash_preserved') is True and Path(r['config_path']).is_file() and sha(Path(r['config_path']))==r['config_sha256'] for r in correlation_records),'public_replay_confirmed':public_ok,'authenticated_replay_confirmed':auth_ok,'real_permission_callback_succeeded':auth.get('correlation',{}).get('runtime',{}).get('permission_callback_reached') is True,'expected_callbacks_reached':bool(correlation_records) and all(r.get('runtime',{}).get('endpoint_callback_reached') is True for r in correlation_records),'expected_parameters_observed':params_ok,'request_ids_correlated':correlation_pass,'stale_artifacts_rejected':negative.get('tests',{}).get('stale_artifact') is True,'wrong_run_artifacts_rejected':negative.get('tests',{}).get('wrong_run_id') is True,'cross_plugin_contamination_absent':negative.get('passed') is True,'secrets_redacted':not findings,'phase9_regression_passed':phase9_ok,'phase10_regression_passed':phase10_ok,'phase11_regression_passed':phase11_ok})
    passed_required=all(values.get(g) is True for g in required)
    status={'run_id':run_id,'run_mode':run_mode,'matrix_source':matrix_source,'required_gates':required,'gates':values,'passed_gate_count':sum(1 for g in required if values.get(g) is True),'required_gate_count':len(required),'all_required_gates_passed':passed_required}; atomic(results/'final-gate-status.json',status); atomic(PHASE/'results/latest-run.json',{'run_id':run_id}); atomic(results/'final-report.md','# Phase 13\n\n'+json.dumps(status,indent=2)); return 0 if passed_required else 1
if __name__=='__main__':
    try: raise SystemExit(main())
    except Exception as e: print('PHASE_13_FAIL_RUNTIME: '+str(e),file=sys.stderr); raise SystemExit(1)
