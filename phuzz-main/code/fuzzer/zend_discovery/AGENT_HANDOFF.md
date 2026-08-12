# Zend Discovery Agent Handoff

## 2026-08-13 Mainline Handoff

Current committed path is the mainline port of the proved REST and CRM runtime
work. It is intentionally narrow:

- Zend C source is owned here under `zend_discovery/extension/`.
- The extension is named `hookphuzz_opcode`, not `hookphuzz_opcode_phase9`.
- Runtime registry path is `/shared/hookphuzz-callback-registry.json`.
- REST `WP_REST_Request::get_param()` observation is produced by UOPZ, not by
  new C method-call instrumentation.
- CRM generated replay keeps the static nested leaf
  `cfx_settings[alert_emails]` when Zend observes runtime parent
  `cfx_settings`.

Fresh checkout requirements that are now tracked:

- `web/applications/wordpress/_plugins/crm-perks-forms.zip`
- `web/applications/wordpress/_plugins/hookphuzz-rest-get-param-fixture.zip`
- `fuzzer/tests/fixtures/hookphuzz-rest-get-param-fixture/`

Do not commit the extracted plugin directories under `_plugins/`; only ZIPs are
needed for normal Docker runs.

## How To Run

From repo root:

```powershell
rtk python -m unittest discover phuzz-main/code/fuzzer/tests
```

From `phuzz-main/code`, run the proved CRM flow:

```powershell
rtk powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\wordpress\run-wordpress-phuzz.ps1 `
  -PluginSlug crm-perks-forms `
  -RunGeneratedConfigs `
  -UseZendDiscovery `
  -NoFollowLogs `
  -SeedWaitSeconds 25 `
  -GeneratedConfigTimeoutSeconds 8 `
  -WebTimeoutSeconds 180
```

Expected CRM proof shape:

- `Seed export summary: registered=23`
- Pass 1 `callback_reached=1`
- convergence summary status `CONVERGED`
- two different request IDs in `zend_convergence_summary.json`
- final `generated_config_summary.json` has one `fuzzing_ready` config
- final config body fixes `action` and `vx_nonce`
- final config body fuzz list is `cfx_settings\\[alert_emails\\]`
- Zend artifact `target_loading.file_target_count > 0`
- Zend artifact `target_loading.rejected_count == 0`
- `callback_summaries` includes
  `cfx_form_admin_pages::save_api_settings`

Useful inspection command after a CRM run:

```powershell
rtk python -c "import json; from pathlib import Path; base=Path('fuzzer/output/seed_generation'); run=max((base/'zend-bridge').iterdir(), key=lambda p:p.stat().st_mtime).name; conv=json.loads((base/'zend-bridge'/run/'zend_convergence_summary.json').read_text(encoding='utf-8-sig')); summ=json.loads((base/'generated_config_summary.json').read_text(encoding='utf-8-sig')); cfg=json.loads(Path(summ['generated'][0]['config_path']).read_text(encoding='utf-8-sig')); print(run, conv.get('status'), [i.get('request_id') for i in conv.get('iterations', [])], cfg['body_params'])"
```

## Current State

Zend REST enrichment is now owned under `fuzzer/zend_discovery`.
Legacy `hook_energy` code should only orchestrate or provide compatibility imports.

Implemented pieces:

- `engine.py`: canonical identity, Pass 1 correlation, runtime evidence normalization, enrichment artifact export.
- `rest_runtime.py`: REST runtime evidence contract and fail-closed normalization.
- `convergence.py`: Phase 2 known-parameter identity, seed materialization, and merge logic.
- `extension/`: Zend-owned PHP extension source used by `web/Dockerfile.zend`.

Legacy bridge state:

- `hook_energy/seed_generation/zend_bridge.py` is a compatibility re-export only.
- `hook_energy/seed_generation/zend_bridge_cli.py` still owns CLI orchestration around legacy generated runs.
- `scripts/wordpress/run-wordpress-phuzz.ps1` still owns Docker lifecycle, Pass 1/Pass 2 replay, config export, and artifact collection.

## Required Boundaries

- Do not import, copy, execute, or depend on `research/hookphuzz-opcode/phase10` through `phase13`.
- Do not move REST decision logic back into `hook_energy`.
- Do not claim query/form/json location from method, route, schema, or `WP_REST_Request::get_param()` name alone.
- Keep `legacy_run_id` as batch identity.
- Keep `X-Fuzzer-Covid` as fresh per-request identity.
- Export fuzz configs only after current-run callback, request/run, route, and method correlation.
- Keep Phase 10-13 contracts and artifacts unchanged.

## REST Evidence Rules

Accepted REST evidence is value-free and must include:

- `request_id`
- `legacy_run_id`
- `canonical_callback`
- `namespace`
- `route_pattern`
- `materialized_route`
- `endpoint_definition_index`
- `method`
- parameter `name`
- proven `location`

Allowed locations:

- `GET` and `HEAD`: query only.
- `POST`: query, form, or json.

Blocked cases:

- missing or stale request/run correlation
- wrong callback, route, endpoint index, or method
- duplicate key across multiple locations
- ambiguous location
- nested path/key shape
- auth/security-looking parameter names
- schema-only proof
- `get_param` name-only proof unless it is correlated with the same UOPZ
  request artifact and the exact name exists in raw `query_params`

Current accepted REST `get_param()` scope:

- GET/HEAD query only.
- UOPZ event must be value-free:
  `{"accessor":"WP_REST_Request::get_param","name":"search"}`.
- `rest_runtime.py` joins that event with
  `uopz_artifact.request_params.query_params`.
- unrelated raw query keys stay excluded.
- missing event, duplicate event, missing snapshot key, nested/security-looking
  name, form, and JSON still fail closed.

## Seed Materialization

REST materialization rules:

- query evidence writes `seed.query_params[name] = "FUZZ"`.
- form evidence writes `seed.body[name] = "FUZZ"`.
- json evidence writes `seed.body[name] = "FUZZ"` and sets `Content-Type: application/json`.
- generated `input_params` use `GET`, `POST`, or `JSON` source according to proven location.

## Verification Already Run

These passed in the current implementation:

- `python -m unittest phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- `python -m unittest phuzz-main/code/fuzzer/tests/test_generated_config_runner.py phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py`
- `python -m py_compile` for Zend discovery and bridge files
- PowerShell parser check for `run-wordpress-phuzz.ps1`
- `docker compose -f phuzz-main/code/docker-compose.yml config`
- `git diff --check`

Docker build proof:

- `Dockerfile.zend` built using `COPY phuzz-main/code/fuzzer/zend_discovery/extension/ ./`.
- The extension compiled successfully during the CF7 attempt.

## CF7 Current-Run Result

Do not report CF7 as PASS yet.

Observed current run:

- run id: `legacy-20260812T163849Z-96d075af`
- generated flow reached authenticated AJAX `wp_ajax_wpcf7-update-welcome-panel`
- convergence failed with `REPLAY_FAILED: Phase 2 requires exactly one generated candidate and one replay row`

Manual REST probe:

- request id: `cf7-rest-fallback-20260812T164142-889e3b30`
- `/?rest_route=/contact-form-7/v1/contact-forms` returned HTTP 200
- UOPZ recorded `endpoint=REST:/contact-form-7/v1/contact-forms`
- Zend artifact schema was `4`
- `rest_parameter_events` was empty
- `callback_summaries` was empty

Current CF7 REST status: `BLOCKED`, because there is no fresh authenticated callback/runtime parameter proof.

## Next Work

1. Make legacy generated seed export select first-class CF7 REST route candidates instead of only the `rest_api_init` closure row.
2. Add current-run artifact test for `rest_route:contact-form-7/v1/contact-forms` route metadata from UOPZ registration.
3. Extend REST runtime only after adding raw snapshots for form/JSON; GET/query is the only accepted `get_param()` scope now.
4. Re-run `-Mode generated -PluginSlug contact-form-7 -UseZendDiscovery` with bounded timeouts.
5. Report PASS only if Pass 2 re-observes the same correlated REST parameter evidence with fresh request ids.
