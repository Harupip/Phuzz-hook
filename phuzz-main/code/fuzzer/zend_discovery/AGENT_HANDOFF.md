# Zend Discovery Agent Handoff

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
- schema-only or `get_param` name-only proof

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
3. Teach the Zend extension to attribute REST callback execution and emit concrete `rest_parameter_events` when `WP_REST_Request` access proves query/form/json location.
4. Re-run `-Mode generated -PluginSlug contact-form-7 -UseZendDiscovery` with bounded timeouts.
5. Report PASS only if Pass 2 re-observes the same correlated REST parameter evidence with fresh request ids.
