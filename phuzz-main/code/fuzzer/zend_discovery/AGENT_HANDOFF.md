# Zend Discovery Agent Handoff

## 2026-08-19 Runtime REQUEST and artifact retention update

The runtime boundary now accepts a direct correlated `$_REQUEST['name']` read
only when it can resolve the name to one existing transport:

- exact `query_params` membership -> `GET/query`
- exact `body_params` membership -> `POST/form`
- otherwise GET -> `GET/query`
- otherwise form-encoded or multipart POST -> `POST/form`
- ambiguous, JSON-only, unsupported, or uncorrelated evidence -> reject

Pass 2 applies the same resolver, so no new `REQUEST` source is introduced into
convergence or config generation.

Artifact retention runs only after convergence, final config generation, final
replay, and Pass 2 verification. `PASS`, `SUCCESS`, `CONVERGED`, and
`PASS_PARTIAL_AUTH_EXPECTED` prune current-run registry/Pass 1/targets/
iterations/logs/current artifacts while retaining the convergence summary,
final artifacts, final replay summary, and usable generated configs. Failure,
timeout, replay failure, or convergence failure preserves the entire run tree.
`-KeepDebugArtifacts` preserves all artifacts even after success. Cleanup is
validated against the exact current plugin/date run directory; it does not use
a broad `zend-bridge/*` deletion.

The public run-directory name is `<plugin-slug>-<UTC timestamp>`. The existing
`legacy_run_id` field and `--legacy-run-id` argument remain compatibility names
inside the runtime contract only.

Latest local Docker attempt:

- run ID: `show-all-comments-in-one-page-20260819T000546Z`
- Pass 1: `callback_reached=1`, `expected_auth_skip=1`
- Zend: iteration 0 observed all three `REQUEST` names; iteration 1 omitted
  `post_id`
- terminal status: `REPLAY_FAILED` during convergence
- retention: full failed run tree preserved

Do not cite this run as a Zend PASS; the remaining issue is fresh runtime
evidence/convergence, not HTTP status or the transport resolver.

## 2026-08-17 Real Plugin Counterexample Handoff

Stop adding synthetic REST fixtures for now. The current direction is real
plugin counterexample testing.

### CRM milestone

`crm-perks-forms` is `PASS_WITH_FIX`.

Fresh proof:

- run ID: `legacy-20260817T004522Z-9309b5d7`
- convergence: `CONVERGED`
- final replay: `callback_reached=1 total=1`
- Pass 2 verifier: `accepted=1 total=1`

The CRM failure boundary was `J Pass2 verification`. The generic primitive is:

- A nested POST form leaf such as `cfx_settings[alert_emails]` can be accepted
  when the generated config expects the leaf and current Zend runtime observes
  the parent `cfx_settings`.

This is implemented by the committed generic verifier fix, not by a
CRM-specific exception.

### Booking Calendar root cause

`booking-calendar` 3.2.36 did not initially reach Zend. The failure was before
Zend, in the generated Pass 1 runner:

- Pass 1 had a mixed batch: `6/9 callback_reached`,
  `3/9 registered_not_executed`.
- `generated_config_runner.py` treated the whole batch as failed unless every
  generated config reached its callback.
- `run-wordpress-phuzz.ps1` threw on that nonzero exit before
  `Invoke-ZendConvergence`, so the 6 reachable candidates never entered Zend.

There was also an auth/session routing issue:

- The 3 non-reaching rows were `wp_ajax_nopriv_*` callbacks.
- They were replayed in an authenticated context, so WordPress selected the
  authenticated `wp_ajax_*` twin action instead of the expected
  `wp_ajax_nopriv_*` callback.
- This is an auth/session mismatch, not a Zend failure.

### Implemented resolution

The generated Pass 1 runner now has an opt-in Zend mode:

- `--allow-partial-callback-reach`
- success requires no `process_failed`, no `runner_error`, and at least one
  `callback_reached`
- old all-callbacks-reached behavior remains the default
- `run-wordpress-phuzz.ps1` enables this only under `-UseZendDiscovery`

Zend convergence target selection now uses the Pass 1 run summary and includes
only rows where `callback_reached=true`. Rows such as
`registered_not_executed` stay visible in the summary but are not sent into
Zend convergence.

Auth routing now preserves `auth_mode` into generated runner rows. For
`auth_mode=unauth-capable` or `wp_ajax_nopriv_*`, the runner passes
`HOOKPHUZZ_DISABLE_AUTH_COOKIES=1`, and the fuzzer skips login cookie injection
and strips WordPress auth cookies before preparing the request.

Windows runner hardening needed for these real plugin runs:

- Zend convergence uses short target directory names such as `t0`, `t1`, ...
  instead of 64-byte candidate hashes in deep paths.
- snapshot temp paths use short `.tmp` / `.old` suffixes.
- hashing uses a .NET SHA256 helper instead of assuming `Get-FileHash` exists.

### Booking Calendar current result

Fresh booking run:

- run ID: `legacy-20260817T004926Z-bc54222e`
- Pass 1: `callback_reached=6`, `registered_not_executed=3`, `total=9`
- Zend target count: 6
- all 6 Zend targets reached `CONVERGED` in 2 iterations

Current first failing boundary is `G replay/reachability`, after Zend
convergence:

- final combined replay timed out on
  `wp_ajax_wpdevart_add_extra_field_item-a60774eb65ebb5d3bbcbee86098e4220268786ab-post`
  with `-GeneratedConfigTimeoutSeconds 8`
- the timeout cleanup command `docker rm -f ...` also timed out, so
  `final-generated_config_run_summary.json` was not written

Do not expand REST synthetic fixtures for this. The next investigation should
stay on this real plugin boundary:

1. Rerun the final replay with a larger generated-config timeout to separate
   slow callback execution from a true reachability regression.
2. Make timeout cleanup fail closed by recording a `window_elapsed` row even if
   Docker cleanup times out.
3. If the candidate still does not reach after a sane timeout, classify it under
   `G replay/reachability` or `H auth/nonce` using the exact final replay
   artifact.

Verification already run for the current committed fix:

- `rtk python -m unittest phuzz-main/code/fuzzer/tests/test_generated_config_runner.py`
- `rtk python -m unittest phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- `rtk git diff --check`

## 2026-08-14 REST Bucket And Precedence Handoff

Current Zend opcode artifacts can now prove REST parameter provenance directly
from `WP_REST_Request::$params` buckets beyond query-only GET.

Runtime-proved bucket structure for the bundled WordPress 6.1.1 core:

- `URL`
- `GET`
- `POST`
- `FILES`
- `JSON`
- `defaults`

Runtime-proved `WP_REST_Request::get_parameter_order()` precedence:

- JSON requests: `JSON`, then `POST`, `GET`, `URL`, `defaults`.
- Non-JSON body methods `POST`, `PUT`, `PATCH`, `DELETE`: `POST`, then
  `GET`, `URL`, `defaults`.
- GET without body: `GET`, then `URL`, `defaults`.

Important implementation detail for future agents:

- The extension still does not hard-code REST getter names or parameter names.
- `WP_REST_Request::$params` root provenance is created from `FETCH_OBJ_R` and
  `FETCH_OBJ_IS` against real `WP_REST_Request` objects.
- Bucket and parameter provenance is carried by generic `FETCH_DIM_R`,
  `FETCH_DIM_IS`, `ISSET_ISEMPTY_DIM_OBJ`, and `RETURN` propagation.
- Callback attribution now resolves through the current Zend frame and, when a
  user opcode fires inside an unobserved child frame, through the nearest active
  observed ancestor frame.
- Stale temp-var provenance is cleared when a result is overwritten by
  non-provenanced property or dimension fetches. This prevents ordinary
  `$foo->params` objects and normal arrays from inheriting REST state.

Proved artifact-level REST events:

- `REST | GET | search`
- `REST | POST | email`
- `REST | JSON | email`
- `REST | URL | id`
- `REST | defaults | mode`
- nested JSON: `REST | JSON | filters[name]`
- `get_param('id')` selected-bucket matrix:
  `JSON`, `POST`, `GET`, `URL`, `defaults` as each higher-priority bucket is
  removed.

Do not confuse these artifact capabilities with config export policy. This
change does not update config generation, seed generation, convergence,
fuzzability rules for defaults, or downstream nested-path normalization.
Those layers must continue to fail closed unless separately updated and
runtime-proven.

Verification commands used for this handoff:

- `python -m unittest phuzz-main/code/fuzzer/tests/test_zend_discovery.py`
- `python -m unittest discover -s phuzz-main/code/fuzzer/tests -p "test_*.py"`
- `docker build -f phuzz-main/code/web/Dockerfile.zend -t hookphuzz-rest-bucket-proof:current .`
- Docker WordPress runtime proof with request IDs `rbp-final7-*`
- VLD proof for REST bucket getters and `get_param()` precedence
- `git diff --check`

## 2026-08-13 Mainline Handoff

Current committed path is the mainline port of the proved REST and CRM runtime
work. It is intentionally narrow:

- Zend C source is owned here under `zend_discovery/extension/`.
- The extension is named `hookphuzz_opcode`, not `hookphuzz_opcode_phase9`.
- Runtime registry path is `/shared/hookphuzz-callback-registry.json`.
- REST `WP_REST_Request::get_param()` selected-bucket observation is produced
  by Zend opcode provenance on `WP_REST_Request::$params`, not by new
  method-specific C hooks.
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

- `hook_energy/seed_generation/zend_runtime/bridge.py` is the Zend convergence compatibility re-export.
- `hook_energy/seed_generation/zend_runtime/bridge_cli.py` owns Zend CLI orchestration.
- `scripts/wordpress/run-wordpress-phuzz.ps1` still owns Docker lifecycle, Pass 1/Pass 2 replay, config export, and artifact collection.

## Required Boundaries

- Do not import, copy, execute, or depend on archived Phase 10 through Phase 13 research artifacts.
- Do not move REST decision logic back into `hook_energy`.
- Do not claim query/form/json/url/default location from method, route, schema,
  or `WP_REST_Request::get_param()` name alone. Require current-run selected
  bucket provenance.
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

Currently proven Zend artifact buckets:

- `GET`
- `POST`
- `JSON`
- `URL`
- `defaults`

Current config-export locations remain narrower than artifact support:

- `GET` and `HEAD`: query only.
- `POST`: query, form, or json.
- `URL`, `defaults`, and nested paths are evidence only until their downstream
  semantics are implemented and separately tested.

Blocked cases:

- missing or stale request/run correlation
- wrong callback, route, endpoint index, or method
- duplicate key across multiple locations
- ambiguous location
- auth/security-looking parameter names
- schema-only proof
- `get_param` name-only proof without selected bucket provenance

Current Zend REST `get_param()` artifact scope:

- Direct `get_param()` can emit the bucket actually returned by WordPress
  precedence, not every bucket checked along the way.
- Intermediate core probes can exist with `callback_context.attributed=false`;
  only callback-attributed terminal `rest_parameter_events` should be treated as
  selected evidence.
- Negative controls with ordinary `$foo->params` objects and normal arrays must
  emit zero REST events.

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
3. Extend downstream config/export handling for URL, defaults, and nested REST
   paths only after separate runtime proof and policy decisions.
4. Re-run `-Mode generated -PluginSlug contact-form-7 -UseZendDiscovery` with bounded timeouts.
5. Report PASS only if Pass 2 re-observes the same correlated REST parameter evidence with fresh request ids.
