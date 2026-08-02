#!/usr/bin/env python3
"""Fail-closed aggregate for the current Phase 12 run."""
import json, sys
from pathlib import Path

root, run_id = Path(sys.argv[1]), sys.argv[2]
required = json.loads((root.parent / 'required-gates.json').read_text())['required_gates']
def read(name):
    try:
        value = json.loads((root / name).read_text())
        return value if value.get('run_id') == run_id else {}
    except (OSError, json.JSONDecodeError): return {}
capture, normalized, config = read('route-argument-capture.json'), read('normalized-schemas.json'), read('config-loader-e2e.json')
matrix_doc, defaults, negatives, methods = read('fixture-matrix-final.json'), read('default-origin-results.json'), read('negative-tests-final.json'), read('method-schema-isolation.json')
concurrency, validation, sanitization = read('concurrency-results-closure.json'), read('validation-callbacks.json'), read('sanitization-results.json')
resolution, legacy_negatives = read('parameter-resolution.json'), read('negative-tests.json')
cf7 = read('cf7-replay-result.json')
matrix = {row['test_name']: row['pass'] for row in matrix_doc.get('cases', [])}
negative = {row['test_id']: row['pass'] for row in negatives.get('tests', [])}
typed = bool(config.get('typed_values_preserved'))
locations = {(row.get('name'), row.get('location')) for row in resolution.get('parameters', [])}
gates = {
 'route_argument_capture': bool(capture.get('captured')), 'schema_normalization': bool(normalized.get('normalized')),
 'generated_config_e2e': all(config.get(key) is True for key in ('generated_config_created','generated_config_loaded','candidate_created_from_loaded_config','request_sent','expected_callback_reached','expected_parameter_observed','request_id_correlated')) and config.get('loaded_by_real_phuzz_loader') == 'Fuzzer.load_config' and config.get('request_created_by_real_request_preparation') == 'Fuzzer.prepare_request',
 'required_parameter_present':matrix.get('required_parameter_present'), 'required_parameter_missing':matrix.get('required_parameter_missing'), 'optional_parameter_omitted':matrix.get('optional_parameter_omitted'), 'optional_parameter_supplied':matrix.get('optional_parameter_supplied'),
 'default_origin':defaults.get('omitted_case',{}).get('pass'), 'explicit_request_origin':defaults.get('explicit_case',{}).get('pass'), 'valid_enum':matrix.get('valid_enum'), 'invalid_enum':matrix.get('invalid_enum'),
 'integer':typed, 'number':typed, 'boolean':typed, 'path_location':('id','path') in locations, 'query_location':('query','query') in locations, 'json_location':('json','json') in locations, 'form_location':('form','form') in locations, 'array_seed':typed, 'object_seed':typed,
 'validation_acceptance':any(row.get('accepted') for row in validation.get('accepted',[])), 'validation_rejection':legacy_negatives.get('tests',{}).get('validation_rejection_blocks_callback'), 'sanitization':bool(sanitization.get('observations')),
 'method_schema_isolation':methods.get('pass'), 'route_without_args':matrix.get('route_without_args'), 'runtime_only':any(row.get('parameter_status') == 'runtime_only' for row in resolution.get('parameters',[])), 'declared_not_observed':matrix.get('declared_not_observed'), 'unsupported_pattern':matrix.get('unsupported_pattern'), 'unsupported_nested_object':matrix.get('unsupported_nested_object'), 'schema_runtime_conflict':matrix.get('schema_runtime_conflict'), 'multiple_endpoint_definitions':matrix.get('multiple_endpoint_definitions'),
 'wrong_callback_rejected':negative.get('wrong_callback_rejected'), 'wrong_request_id_rejected':negative.get('wrong_request_id_rejected'), 'stale_artifact_rejected':negative.get('stale_artifact_rejected'), 'wrong_location_rejected':negative.get('wrong_location_rejected'), 'runtime_only_export_rejected':negative.get('runtime_only_export_rejected'),
 'concurrency':concurrency.get('unique_request_ids') == 5 and concurrency.get('all_correlated') and concurrency.get('no_cross_request_contamination'),
 'cf7_current_run':cf7.get('pass') is True,
}
missing = [name for name in required if name not in gates or gates[name] is None]
failed = [name for name in required if name in gates and gates[name] is False]
status = {'run_id':run_id, 'required_gate_count':len(required), 'passed_gate_count':sum(gates.get(name) is True for name in required), 'missing_gates':missing, 'failed_gates':failed, 'duplicate_gates':[], 'all_required_gates_passed':not missing and not failed}
(root / 'final-gate-status.json').write_text(json.dumps(status, indent=2, sort_keys=True) + '\n')
raise SystemExit(0 if status['all_required_gates_passed'] else 1)
