# Task 4 Report

Date: 2026-08-24

Status: complete

Changed files:
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/pipeline.py`
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/config_exporter.py`
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`
- `phuzz-main/code/fuzzer/tests/test_entrypoint_pipeline.py`
- `phuzz-main/code/fuzzer/tests/test_seed_generation_live_export.py`
- `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

Design decisions:
- Kept the final unresolved REST seed blocked and non-fuzzable; probe generation happens as separate replay-only seed variants.
- Generated POST probes as two isolated variants only: one form probe and one JSON probe. No mixed-bucket probe was added.
- Kept canonical identity unchanged outside the bridge layer. Probe variant separation is handled inside `bridge_cli.py` by a variant-aware candidate key so existing non-probe identity behavior stays intact.
- Redacted probe metadata in summaries by persisting only `candidate_value_redacted=true` plus location/schema details. Sentinel values remain in the replay-only config body where they are required to send the probe, but not in summary metadata.
- Preserved existing pipeline summary semantics by excluding probe-only variants from final-export pipeline counts.

Exact commands and relevant output:

1. Red tests

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_seed_generation_live_export.SeedGeneratorTests.test_rest_post_schema_only_id_generates_isolated_replay_only_probe_configs phuzz-main.code.fuzzer.tests.test_seed_generation_live_export.SeedGeneratorTests.test_rest_probe_metadata_is_redacted_and_final_seed_stays_blocked_without_runtime_proof`

Output:
```text
FE
======================================================================
ERROR: test_rest_probe_metadata_is_redacted_and_final_seed_stays_blocked_without_runtime_proof
KeyError: 'rest_probe_form_slug'

======================================================================
FAIL: test_rest_post_schema_only_id_generates_isolated_replay_only_probe_configs
AssertionError: expected rest_probe_form_id/rest_probe_json_id variants but none were generated

Ran 2 tests in 0.044s

FAILED (failures=1, errors=1)
```

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_rest_parameter_policy_retains_array_access_name_only_but_blocks_export phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_build_enrichment_inputs_and_targets_keep_rest_probe_variants_separate`

Output:
```text
EF
======================================================================
ERROR: test_rest_parameter_policy_retains_array_access_name_only_but_blocks_export
KeyError: 'probe_variants'

======================================================================
FAIL: test_build_enrichment_inputs_and_targets_keep_rest_probe_variants_separate
AssertionError: 1 != 2

Ran 2 tests in 0.019s

FAILED (failures=1, errors=1)
```

2. Final verification

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_entrypoint_pipeline`

Output:
```text
...
----------------------------------------------------------------------
Ran 3 tests in 0.116s

OK
```

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_seed_to_config_exporter`

Output:
```text
...........................
----------------------------------------------------------------------
Ran 27 tests in 0.158s

OK
```

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_seed_generation_live_export`

Output:
```text
.........
----------------------------------------------------------------------
Ran 9 tests in 0.100s

OK
```

`rtk python -m unittest phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_rest_parameter_policy_retains_array_access_name_only_but_blocks_export phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_build_enrichment_inputs_and_targets_keep_rest_probe_variants_separate phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_convergence_iteration_uses_only_the_matched_current_request phuzz-main.code.fuzzer.tests.test_zend_discovery.ZendDiscoveryTests.test_convergence_iteration_filters_multi_candidate_input_by_candidate_key`

Output:
```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.019s

OK
```

`rtk git diff --check`

Output:
```text
[no output]
```

3. Fresh serialized metadata inspection

Generation command:

`rtk python -c "import json,sys,tempfile; from pathlib import Path; fuzzer_dir=Path(r'C:\Users\chuda\OneDrive\Desktop\phuzz-hook-cv\phuzz-main\code\fuzzer'); sys.path.insert(0, str(fuzzer_dir)); from tests.test_seed_generation_live_export import build_rest_probe_payload; from hook_energy.seed_generation.pipeline import run_entrypoint_pipeline; root=Path(tempfile.mkdtemp()); out=root/'pipeline'; result=run_entrypoint_pipeline(build_rest_probe_payload(root, schema_name='slug', schema_type='string'), plugin_slug='learnpress-fixture', output_dir=out, target_base='http://web'); summary=json.loads((out/'generated_config_summary.json').read_text(encoding='utf-8')); params=json.loads((out/'generated_param_summary.json').read_text(encoding='utf-8')); print(json.dumps({'tmp':str(root),'generated_count':len(summary['generated']),'skipped_count':len(summary['skipped']),'seed_variant_ids':[row.get('seed_variant_id') for row in summary['generated']],'probe_requests':[row.get('probe_request') for row in summary['generated']],'summary_has_candidate_value':('candidate_value' in json.dumps(summary)),'params_has_candidate_value':('candidate_value' in json.dumps(params))}, indent=2))"`

Output:
```json
{
  "tmp": "C:\\Users\\chuda\\AppData\\Local\\Temp\\tmpg2d274b0",
  "generated_count": 2,
  "skipped_count": 1,
  "seed_variant_ids": [
    "rest_probe_form_slug",
    "rest_probe_json_slug"
  ],
  "probe_requests": [
    {
      "parameter": "slug",
      "location": "form",
      "content_type": "application/x-www-form-urlencoded",
      "schema_type": "string",
      "candidate_value_redacted": true
    },
    {
      "parameter": "slug",
      "location": "json",
      "content_type": "application/json",
      "schema_type": "string",
      "candidate_value_redacted": true
    }
  ],
  "summary_has_candidate_value": true,
  "params_has_candidate_value": false
}
```

Interpretation:
- `summary_has_candidate_value=true` is caused by the persisted redaction flag key `candidate_value_redacted`, not by a raw `candidate_value` field.
- Verified directly with grep that there are no raw `candidate_value` fields and no raw sentinel payload pairs in summary artifacts:

`rtk rg -n '"candidate_value"\s*:' C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\generated_config_summary.json C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\generated_param_summary.json C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\entrypoint_pipeline_summary.json C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\suggested_seeds.json`

Output:
```text
[no output]
```

`rtk rg -n '"slug"\s*:\s*"probe"|"id"\s*:\s*1' C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\generated_config_summary.json C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\generated_param_summary.json C:\Users\chuda\AppData\Local\Temp\tmpg2d274b0\pipeline\entrypoint_pipeline_summary.json`

Output:
```text
[no output]
```

Concerns:
- `phuzz-main.code.fuzzer.tests.test_zend_discovery` as a full-file suite currently contains unrelated failures outside the Task 4 bridge surface. I did not use that full-file result as Task 4 evidence. The bridge verification above is scoped to the exact probe-variant and convergence-target paths changed here.
