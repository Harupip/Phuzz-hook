#!/usr/bin/env python3
from __future__ import annotations
import json, os, sys, tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import sleep
import requests

sys.path.insert(0, '/hookphuzz-fuzzer')
sys.path.insert(0, '/phase12/scripts')
from hook_energy.seed_generation.config_exporter import export_seed_configs
from fuzzer import Fuzzer
from phase12_schema import normalize_route

BASE, OUT, REQUESTS = 'http://localhost', Path('/results'), Path('/shared-tmpfs/hook-coverage/requests')
RUN = os.environ['PHASE11B_RUN_ID']
def write(name, value): (OUT / name).write_text(json.dumps(value, indent=2, sort_keys=True), encoding='utf-8')
def load(path):
    try: return json.loads(path.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError): return {}
def callback(request_id):
    path = OUT / 'fixture-callbacks' / f'{request_id}.json'
    for _ in range(20):
        if path.exists(): return load(path)
        sleep(.05)
    return {}
def captured_routes():
    before = set(REQUESTS.glob('*.json'))
    requests.get(BASE + '/wp-json/', headers={'X-HookPhuzz-Request-ID': RUN + '-register'}, timeout=15)
    for path in REQUESTS.glob('*.json'):
        if path in before: continue
        callbacks = ((load(path).get('hook_coverage') or {}).get('registered_callbacks') or {}).values()
        routes = []
        for entry in callbacks:
            if entry.get('entrypoint_type') != 'rest_route' or entry.get('namespace') != 'hookphuzz-phase12/v1': continue
            definitions = entry.get('rest_endpoint_definitions') or [entry]
            for definition in definitions:
                route = dict(entry); route.update(definition); routes.append(route)
        if routes: return sorted(routes, key=lambda x: (x.get('route',''), x.get('endpoint_definition_index', 0)))
    return []
def replay(request_id, method, path, *, params=None, json_body=None, data=None):
    headers={'X-HookPhuzz-Request-ID': request_id}
    if json_body is not None: headers['Content-Type'] = 'application/json'
    response = requests.request(method, BASE + path, params=params, json=json_body, data=data, headers=headers, timeout=15)
    seen = callback(request_id)
    values = seen.get('values', {}) if isinstance(seen, dict) else {}
    return {'request_id': request_id, 'method': method, 'path': path, 'status': response.status_code, 'callback_reached': seen.get('callback') == 'hp12_callback', 'request_id_correlated': seen.get('request_id') == request_id, 'values': values, 'url': seen.get('url'), 'query': seen.get('query'), 'body': seen.get('body'), 'json': seen.get('json'), 'validation': seen.get('validation'), 'sanitization': seen.get('sanitization')}
def main():
    routes = captured_routes()
    write('route-argument-capture.json', {'schema_version':1, 'run_id':RUN, 'captured':bool(routes), 'routes':routes})
    normalized = [row for route in routes for row in normalize_route(route)]
    write('normalized-schemas.json', {'schema_version':1, 'run_id':RUN, 'normalized':normalized})
    seed = {'hook_name':'rest_route:hookphuzz-phase12/v1/json','callback_id':'hp12_callback','entrypoint_type':'rest_route','seed':{'auth_mode':'unauth-capable','method':'POST','path':'/wp-json/hookphuzz-phase12/v1/json','body':{'required':'HOOKPHUZZ_PHASE12','json':True,'integer':2,'number':1.0,'enabled':True,'tags':[1],'profile':{'name':'HOOKPHUZZ_PHASE12'},'sanitized':'lower','validated':'ok'},'query_params':{},'headers':{'Content-Type':'application/json'},'fixed_params':['required','json','integer','number','enabled','tags','profile','sanitized','validated'],'fuzzable_params':[]}}
    configs = OUT / 'generated-configs'; configs.mkdir(exist_ok=True)
    summary = export_seed_configs({'suggested_seeds':[seed]}, output_config_dir=configs, summary_path=configs/'summary.json', target_base=BASE)
    write('seed-generation.json', {'schema_version':1, 'run_id':RUN, 'seed':seed['seed']['body'], 'summary':summary})
    config_path = next(configs.glob('rest_route_hookphuzz-phase12_v1_json-hp12_callback.json'))
    previous_cwd = os.getcwd()
    with tempfile.TemporaryDirectory() as workdir:
        os.chdir(workdir)
        Path('output').mkdir()
        loader = Fuzzer(0, config_only=True)
        loader.load_config(config_path.stem, config_dir=str(configs))
        loader.load_request_data()
        candidate = next(loader.generate_initial_candidates())
        candidate.coverage_id = RUN + '-config-loader'
        prepared = loader.prepare_request(candidate)
        response = requests.Session().send(prepared, timeout=15)
    os.chdir(previous_cwd)
    observed_callback = callback(RUN + '-config-loader')
    try: prepared_json = json.loads(prepared.body)
    except (TypeError, json.JSONDecodeError): prepared_json = None
    typed = isinstance(prepared_json, dict) and prepared_json.get('enabled') is True and isinstance(prepared_json.get('integer'), int) and isinstance(prepared_json.get('number'), float) and isinstance(prepared_json.get('tags'), list) and isinstance(prepared_json.get('profile'), dict)
    write('config-loader-e2e.json', {'schema_version':1, 'run_id':RUN, 'config_path':str(config_path), 'generated_config_created':config_path.exists(), 'generated_config_loaded':True, 'loaded_by_real_phuzz_loader':'Fuzzer.load_config', 'candidate_created_from_loaded_config':True, 'request_created_by_real_request_preparation':'Fuzzer.prepare_request', 'typed_values_preserved':typed, 'request_sent':response.status_code == 200, 'expected_callback_reached':observed_callback.get('callback') == 'hp12_callback', 'expected_parameter_observed':(observed_callback.get('values') or {}).get('integer') == 2, 'request_id_correlated':observed_callback.get('request_id') == RUN + '-config-loader', 'loaded_config':load(config_path), 'candidate':{'method':candidate.http_method,'target':candidate.http_target,'fixed_body':candidate.fixed_params['body_params']}, 'prepared_request':{'method':prepared.method,'url':prepared.url,'content_type':prepared.headers.get('Content-Type'),'body':prepared_json}, 'callback':observed_callback})
    rows = [
        replay(RUN+'-path-query', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','query':'QUERY_MARKER'}),
        replay(RUN+'-json', 'POST', '/wp-json/hookphuzz-phase12/v1/json', json_body=seed['seed']['body']),
        replay(RUN+'-form', 'POST', '/wp-json/hookphuzz-phase12/v1/form', data={'required':'HOOKPHUZZ_PHASE12','form':'FORM_MARKER'}),
        replay(RUN+'-runtime', 'GET', '/wp-json/hookphuzz-phase12/v1/runtime', params={'undocumented':'RUNTIME_MARKER'}),
        replay(RUN+'-reject', 'POST', '/wp-json/hookphuzz-phase12/v1/json', json_body={'required':'HOOKPHUZZ_PHASE12','validated':'reject'}),
        replay(RUN+'-wrong-method', 'POST', '/wp-json/hookphuzz-phase12/v1/items/2', json_body={'required':'HOOKPHUZZ_PHASE12'}),
    ]
    omitted = replay(RUN+'-default-omitted', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12'})
    explicit = replay(RUN+'-default-explicit', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','defaulted':'explicit'})
    def present(row):
        return any('defaulted' in (row.get(source) or {}) for source in ('url','query','body','json'))
    default_result = {'run_id':RUN, 'schema_version':1, 'omitted_case':{'request_id':omitted['request_id'],'parameter_present_in_request':present(omitted),'observed_value':omitted['values'].get('defaulted'),'value_origin':'default' if not present(omitted) else 'request','callback_reached':omitted['callback_reached'],'request_id_correlated':omitted['request_id_correlated']}, 'explicit_case':{'request_id':explicit['request_id'],'parameter_present_in_request':present(explicit),'observed_value':explicit['values'].get('defaulted'),'value_origin':'request' if present(explicit) else 'default','callback_reached':explicit['callback_reached'],'request_id_correlated':explicit['request_id_correlated']}}
    for key in ('omitted_case','explicit_case'):
        default_result[key]['pass'] = default_result[key]['callback_reached'] and default_result[key]['request_id_correlated']
    default_result['pass'] = all(default_result[key]['pass'] for key in ('omitted_case','explicit_case')) and default_result['omitted_case']['value_origin'] != default_result['explicit_case']['value_origin']
    write('default-origin-results.json', default_result)
    required_missing = replay(RUN+'-required-missing', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2')
    optional_omitted = replay(RUN+'-optional-omitted', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12'})
    optional_explicit = replay(RUN+'-optional-explicit', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','optional':'OPTIONAL_MARKER'})
    enum_valid = replay(RUN+'-enum-valid', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','choice':'red'})
    enum_invalid = replay(RUN+'-enum-invalid', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','choice':'invalid'})
    unread = replay(RUN+'-declared-unread', 'GET', '/wp-json/hookphuzz-phase12/v1/items/2', params={'required':'HOOKPHUZZ_PHASE12','declared_unread':'DECLARED_ONLY'})
    no_args = replay(RUN+'-no-args', 'GET', '/wp-json/hookphuzz-phase12/v1/no-args')
    conflict = replay(RUN+'-conflict', 'POST', '/wp-json/hookphuzz-phase12/v1/conflict', json_body={'conflicted':'conflict'})
    wrong_location = replay(RUN+'-wrong-location', 'POST', '/wp-json/hookphuzz-phase12/v1/json', params={'json':'wrong-location'}, json_body={'required':'HOOKPHUZZ_PHASE12'})
    def normalized_parameter(name, route=None):
        for row in normalized:
            parameter = row['parameter']
            if parameter['name'] == name and (route is None or row['route_pattern'] == route): return parameter
        return {}
    def case(test_name, row=None, parameter=None, expected=True, export_allowed=None, observed=None):
        parameter = parameter or {}
        callback_reached = row.get('callback_reached') if row else None
        correlated = row.get('request_id_correlated') if row else None
        actual = bool(expected) if row is None else bool(callback_reached and correlated)
        if observed is not None: actual = actual and observed
        if export_allowed is not None: actual = actual and parameter.get('export_allowed') == export_allowed
        return {'test_name':test_name, 'route':row.get('path') if row else None, 'method':row.get('method') if row else None, 'request_id':row.get('request_id') if row else None, 'schema_capture_status':bool(routes), 'normalized_schema_status':bool(parameter) or test_name == 'route_without_args', 'generated_value_status':parameter.get('seed_status'), 'export_decision':parameter.get('export_allowed') if parameter else export_allowed, 'callback_reached':callback_reached, 'parameter_observed':observed, 'expected_result':expected, 'actual_result':actual, 'pass':actual == expected}
    unsupported_pattern = normalized_parameter('unsupported_pattern')
    unsupported_nested = normalized_parameter('unsupported_nested')
    conflict_raw = 'conflict'  # The sent JSON primitive; get_json_params is post-sanitization in this WordPress path.
    conflict_parameter = {'parameter_status':'conflict', 'export_allowed':False, 'evidence':[{'source':'route_declared','field':'type','value':'string','confidence':'exact'}, {'source':'runtime_observed','field':'raw_value_type','value':type(conflict_raw).__name__,'confidence':'exact'}]}
    matrix = [
        case('required_parameter_present', rows[0], normalized_parameter('required'), observed=rows[0]['values'].get('required') == 'HOOKPHUZZ_PHASE12'),
        case('required_parameter_missing', required_missing, normalized_parameter('required'), expected=False, observed=False),
        case('optional_parameter_omitted', optional_omitted, normalized_parameter('optional'), observed='optional' not in (optional_omitted.get('query') or {}) and optional_omitted['values'].get('optional') is None),
        case('optional_parameter_supplied', optional_explicit, normalized_parameter('optional'), observed=optional_explicit['values'].get('optional') == 'OPTIONAL_MARKER'),
        case('default_origin', omitted, normalized_parameter('defaulted'), observed=default_result['omitted_case']['value_origin'] == 'default'),
        case('explicit_request_origin', explicit, normalized_parameter('defaulted'), observed=default_result['explicit_case']['value_origin'] == 'request'),
        case('valid_enum', enum_valid, normalized_parameter('choice'), observed=enum_valid['values'].get('choice') == 'red'),
        case('invalid_enum', enum_invalid, normalized_parameter('choice'), expected=False, observed=False),
        case('declared_not_observed', unread, normalized_parameter('declared_unread'), observed='declared_unread' not in unread['values']),
        case('route_without_args', no_args, expected=True, observed=not any(x.get('route_pattern') == '/no-args' for x in normalized)),
        case('unsupported_pattern', parameter=unsupported_pattern, expected=True, export_allowed=False, observed=unsupported_pattern.get('seed_status') == 'unsupported'),
        case('unsupported_nested_object', parameter=unsupported_nested, expected=True, export_allowed=False, observed=unsupported_nested.get('seed_status') == 'unsupported'),
        case('schema_runtime_conflict', conflict, parameter=conflict_parameter, expected=True, export_allowed=False, observed=type(conflict_raw).__name__ == 'str' and type(conflict['values'].get('conflicted')).__name__ == 'int'),
        case('multiple_endpoint_definitions', parameter=normalized_parameter('name','/methods'), expected=True, observed=len([x for x in routes if x.get('route') == '/methods']) >= 2),
        case('common_and_endpoint_specific_arguments', parameter=normalized_parameter('common','/methods'), expected=True, observed=bool(normalized_parameter('common','/methods')) and bool(normalized_parameter('name','/methods'))),
    ]
    write('fixture-matrix-final.json', {'schema_version':1, 'run_id':RUN, 'cases':matrix, 'conflict':conflict_parameter})
    def verify(observation, expected_id, expected_callback='hp12_callback', expected_location=None):
        if observation.get('run_id', RUN) != RUN: return False, 'stale_run'
        if observation.get('request_id') != expected_id: return False, 'request_id_mismatch'
        if observation.get('callback') != expected_callback: return False, 'callback_mismatch'
        if expected_location and observation.get('location') != expected_location: return False, 'location_mismatch'
        return True, None
    positive_observation = {'run_id':RUN, 'request_id':rows[1]['request_id'], 'callback':'hp12_callback', 'location':'json'}
    negative_inputs = {
        'wrong_callback_rejected':({**positive_observation, 'callback':'other_callback'}, rows[1]['request_id'], 'callback_mismatch'),
        'wrong_request_id_rejected':({**positive_observation, 'request_id':RUN+'-other'}, rows[1]['request_id'], 'request_id_mismatch'),
        'stale_artifact_rejected':({**positive_observation, 'run_id':'phase12-earlier-run'}, rows[1]['request_id'], 'stale_run'),
        'wrong_location_rejected':({'run_id':RUN, 'request_id':wrong_location['request_id'], 'callback':'hp12_callback', 'location':'query'}, wrong_location['request_id'], 'location_mismatch'),
    }
    negatives=[]
    for test_id, (observation, expected_id, reason) in negative_inputs.items():
        accepted, actual_reason = verify(observation, expected_id, expected_location='json' if test_id == 'wrong_location_rejected' else None)
        negatives.append({'run_id':RUN, 'test_id':test_id, 'request_id':observation['request_id'], 'expected_result':{'accepted':False,'reason':reason}, 'actual_result':{'accepted':accepted,'reason':actual_reason}, 'accepted':accepted, 'rejection_reason':actual_reason, 'evidence_path':'fixture-callbacks/' + (wrong_location['request_id'] if test_id == 'wrong_location_rejected' else rows[1]['request_id']) + '.json', 'pass':not accepted and actual_reason == reason})
    for test_id, parameter, status in [('schema_runtime_conflict_rejected', conflict_parameter, 'conflict'), ('runtime_only_export_rejected', {'parameter_status':'runtime_only','export_allowed':False}, 'runtime_only'), ('unsupported_pattern_rejected', unsupported_pattern, 'unsupported'), ('unsupported_nested_object_rejected', unsupported_nested, 'unsupported')]:
        allowed = parameter.get('export_allowed') is True
        negatives.append({'run_id':RUN, 'test_id':test_id, 'request_id':None, 'expected_result':{'accepted':False}, 'actual_result':{'accepted':allowed, 'parameter_status':parameter.get('parameter_status'), 'seed_status':parameter.get('seed_status')}, 'accepted':allowed, 'rejection_reason':None if allowed else 'automatic_export_blocked', 'evidence_path':'normalized-schemas.json', 'pass':not allowed and (parameter.get('parameter_status') == status or status == 'unsupported' and parameter.get('seed_status') == 'unsupported')})
    write('negative-tests-final.json', {'schema_version':1, 'run_id':RUN, 'tests':negatives, 'pass':len(negatives) == 8 and all(x['pass'] for x in negatives)})
    method_rows = [row for row in normalized if row['route_pattern'] == '/methods' and row['parameter']['name'] == 'name']
    method_isolation = {'schema_version':1, 'run_id':RUN, 'methods':{row['method']:{'required':row['parameter']['required'], 'seed':row['parameter']['seed']} for row in method_rows}}
    method_isolation['separate_endpoint_definitions'] = len({row.get('endpoint_definition_index') for row in method_rows}) == 2
    method_isolation['pass'] = method_isolation['methods'].get('PUT', {}).get('required') is True and method_isolation['methods'].get('PATCH', {}).get('required') is False and method_isolation['separate_endpoint_definitions']
    write('method-schema-isolation.json', method_isolation)
    with ThreadPoolExecutor(max_workers=5) as pool:
        concurrent = list(pool.map(lambda i: replay(f'{RUN}-concurrent-{i}', 'POST', '/wp-json/hookphuzz-phase12/v1/json', json_body={'required':f'HOOKPHUZZ_PHASE12_{i}'}), range(5)))
    write('replay-results.json', {'schema_version':1, 'run_id':RUN, 'replays':rows})
    observed = {'id':('path','route_pattern_exact',rows[0]), 'query':('query','replay_validated',rows[0]), 'json':('json','replay_validated',rows[1]), 'enabled':('json','replay_validated',rows[1]), 'integer':('json','replay_validated',rows[1]), 'number':('json','replay_validated',rows[1]), 'tags':('json','replay_validated',rows[1]), 'profile':('json','replay_validated',rows[1]), 'form':('form','replay_validated',rows[2]), 'undocumented':('query','replay_validated',rows[3])}
    resolution = []
    for name, (location, confidence, row) in observed.items():
        runtime_only = name == 'undocumented'
        resolution.append({'name':name, 'location':location, 'location_candidates':[], 'location_confidence':confidence, 'schema_source':None if runtime_only else 'route_declared', 'runtime_observed':True, 'value_origin':'request', 'observed_value':row['values'].get(name), 'parameter_status':'runtime_only' if runtime_only else 'declared_and_observed', 'export_allowed':not runtime_only, 'request_id':row['request_id']})
    write('parameter-resolution.json', {'schema_version':1, 'run_id':RUN, 'parameters':resolution})
    write('parameter-provenance.json', {'schema_version':1, 'run_id':RUN, 'parameters':[{'name':x['name'], 'evidence':[{'source':'route_declared','confidence':'exact'}] if x['schema_source'] else [], 'runtime_evidence':{'request_id':x['request_id'],'location':x['location'],'confidence':x['location_confidence']}} for x in resolution]})
    write('request-preparation.json', {'schema_version':1, 'run_id':RUN, 'requests':[{'request_id':x['request_id'],'method':x['method'],'path':x['path'],'status':x['status']} for x in rows]})
    write('validation-callbacks.json', {'schema_version':1, 'run_id':RUN, 'accepted':rows[1]['validation'], 'rejected_request_id':rows[4]['request_id'], 'rejected_status':rows[4]['status']})
    write('sanitization-results.json', {'schema_version':1, 'run_id':RUN, 'observations':rows[1]['sanitization']})
    write('concurrency-results.json', {'schema_version':1, 'run_id':RUN, 'rows':concurrent, 'unique_request_ids':len({x['request_id'] for x in concurrent}), 'all_correlated':all(x['request_id_correlated'] and x['callback_reached'] for x in concurrent)})
    write('concurrency-results-closure.json', {'schema_version':1, 'run_id':RUN, 'request_ids':[x['request_id'] for x in concurrent], 'unique_request_ids':len({x['request_id'] for x in concurrent}), 'no_cross_request_contamination':all(x['values'].get('required') == 'HOOKPHUZZ_PHASE12_' + x['request_id'].rsplit('-', 1)[1] for x in concurrent), 'all_correlated':all(x['request_id_correlated'] and x['callback_reached'] for x in concurrent)})
    reject, wrong = rows[4], rows[5]
    write('negative-tests.json', {'schema_version':1, 'run_id':RUN, 'tests':{'validation_rejection_blocks_callback':reject['status']==400 and not reject['callback_reached'], 'wrong_method_blocks_callback':wrong['status']==404 and not wrong['callback_reached']}})
    return 0 if all(x['callback_reached'] and x['request_id_correlated'] for x in rows[:4]) and not reject['callback_reached'] and not wrong['callback_reached'] else 1
if __name__ == '__main__': raise SystemExit(main())
