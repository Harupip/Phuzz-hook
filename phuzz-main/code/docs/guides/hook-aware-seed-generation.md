# Runtime Hook Seed Generation

Runtime hook seed generation turns uncovered WordPress callbacks into PHUZZ-compatible HTTP seed suggestions.

The generator reads a UOPZ `total_coverage.json` snapshot, finds active uncovered callbacks, maps direct WordPress HTTP hooks to endpoints, extracts callback input parameters from source, and writes machine-readable seed artifacts.

This exporter does not push seeds into PHUZZ's live `Candidate` queue by itself. The output is a discovery artifact for the next pipeline stages: classify entrypoint, generate PHUZZ config, replay, then validate callback reachability.

## Inputs

Primary input:

- `total_coverage.json`

Useful callback metadata in `registered_callbacks`:

- `hook_name`
- `callback_repr`
- `function_name`
- `class_name`
- `method_name`
- `is_static`
- `is_closure`
- `is_invokable`
- `source_file`
- `source_line`
- `start_line`
- `end_line`
- `formal_parameters`

`source_file` plus `start_line`/`end_line` lets the extractor scan only the callback body. If `end_line` is missing, it scans a bounded window after `source_line`/`start_line`.

The source file must be readable from the host running the exporter. If a coverage artifact points to a container-only path such as `/var/www/html/...` and that path is not mounted locally, the seed is still generated, but `input_params` stays empty.

## Direct HTTP Hook Mapping

The generator creates replayable seeds for these hook families:

| Hook family | Method | Path | Auth mode | Priority |
| --- | --- | --- | --- | --- |
| `wp_ajax_nopriv_*` | `POST` | `/wp-admin/admin-ajax.php` | `unauth-capable` | `highest` |
| `admin_post_nopriv_*` | `POST` | `/wp-admin/admin-post.php` | `unauth-capable` | `highest` |
| `wp_ajax_*` | `POST` | `/wp-admin/admin-ajax.php` | `authenticated` | `high` |
| `admin_post_*` | `POST` | `/wp-admin/admin-post.php` | `authenticated` | `high` |

Other hooks stay manual-only unless later code adds a supported route mapping.

## Input Signature Extraction

The extractor lives at:

- `code/fuzzer/hook_energy/seed_generation/input_extractor.py`

It uses static regex scanning. It does not require a PHP parser.

Recognized request input forms:

- `$_GET['name']`
- `$_POST['name']`
- `$_REQUEST['name']`
- `$_COOKIE['name']`
- `$_FILES['name']`
- `filter_input(INPUT_GET, 'name')`
- `filter_input(INPUT_POST, 'name')`
- `filter_input(INPUT_COOKIE, 'name')`
- wrapper calls such as `sanitize_text_field($_REQUEST['name'])`, `wp_unslash($_POST['name'])`, `absint($_GET['name'])`, and `intval($_POST['name'])`
- simple JSON body reads near `json_decode(file_get_contents('php://input'), true)`, for example `$payload['name']`

Extractor behavior:

- Deduplicates repeated `(source, name)` pairs.
- Never treats `action` as fuzzable.
- Emits `confidence: "static_regex"`.
- Uses `location` values such as `query`, `body`, `body_or_query`, and `cookie`.

Example extractor result:

```json
{
  "callback": "Example_Plugin::handle_lookup",
  "input_params": [
    {
      "name": "item_id",
      "source": "REQUEST",
      "location": "body_or_query",
      "confidence": "static_regex",
      "line": 42
    }
  ]
}
```

## Seed Output

The generator writes:

- `hook_gap_report.json`
- `suggested_seeds.json`
- `suggested_seeds.md`

Run:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python -m hook_energy.seed_generation.export_cli --coverage-file output\total_coverage.json --output-dir output\seed_generation
```

Direct script mode also works:

```powershell
python hook_energy\seed_generation\export_cli.py --coverage-file output\total_coverage.json --output-dir output\seed_generation
```

Convert unauth-capable and authenticated seed suggestions into PHUZZ config JSON:

```powershell
python hook_energy\seed_generation\seed_to_config_cli.py --suggested-seeds output\seed_generation\suggested_seeds.json --output-config-dir configs\generated-hooks --summary output\seed_generation\generated_config_summary.json
```

Generated configs can be run later with `FUZZER_CONFIG=generated-hooks/<config-slug>`. Authenticated configs rely on the existing WordPress UOPZ overrides for login, capability, and nonce checks. The converter does not perform login automation or start fuzzing the generated configs.

### Authenticated Config Runtime Proof

The authenticated path was verified against GamiPress using `wp_ajax_gamipress_get_logs`. Bootstrap completed all 10 probes and seed export produced 63 direct HTTP candidates. The generated config kept `action=gamipress_get_logs` fixed, fuzzed the 11 extracted request parameters, and PHUZZ produced a request artifact whose `executed_callbacks` contained callback ID `0c8eda78b0f602c896a900ec1cf560ba93691051` with `fired_hook=wp_ajax_gamipress_get_logs`.

Akismet also produced an authenticated seed for `wp_ajax_comment_author_deurl`, with fixed `action` and fuzzable `id`. Its static class callback is currently reported under `blindspot_callbacks`, so it cannot be used as an `executed_callbacks` proof without extending the hook instrumentation. Function callbacks such as the GamiPress target provide the current end-to-end proof boundary.

This verification runs one generated config explicitly through `FUZZER_CONFIG`; automatic config selection and batch fuzzing remain separate follow-up work.

Example `suggested_seeds.json` entry:

```json
{
  "hook_name": "wp_ajax_nopriv_example_lookup",
  "callback_id": "...",
  "callback_name": "example_lookup_handler",
  "seed_priority": "highest",
  "generation_status": "supported_http_seed",
  "seed": {
    "method": "POST",
    "path": "/wp-admin/admin-ajax.php",
    "content_type": "application/x-www-form-urlencoded",
    "body": {
      "action": "example_lookup",
      "item_id": "FUZZ"
    },
    "auth_mode": "unauth-capable",
    "fixed_params": [
      "action"
    ],
    "fuzzable_params": [
      "item_id"
    ],
    "input_params": [
      {
        "name": "item_id",
        "source": "REQUEST",
        "location": "body_or_query",
        "confidence": "static_regex",
        "line": 42
      }
    ],
    "query_params": {},
    "cookies": {}
  }
}
```

Placement rules:

- `GET` params go into `seed.query_params`.
- `COOKIE` params go into `seed.cookies`.
- `POST`, `REQUEST`, `FILES`, and `BODY_JSON` params go into `seed.body`.
- `action` stays in `fixed_params` and is not added to `fuzzable_params`.

## Entrypoint Replay Validation

Entrypoint replay validation is a runtime check for generated HTTP entrypoint candidates. It answers:

- Which registered hooks can be mapped to a concrete WordPress HTTP request?
- Can a selected candidate be replayed against a running WordPress target?
- Did that replay create fresh HookPhuzz request artifacts that show the expected hook or callback?

The pipeline is intentionally separate from PHUZZ fuzzing. It validates replayability and hook-correlation for one candidate at a time. It does not prove that PHUZZ has consumed generated seeds unless the later fuzzing run also points `FUZZER_CONFIG` at a generated adapter config.

The generic flow is:

```text
bootstrap_probe_runner.py -> entry_classifier.py -> seed_validator.py
```

### 1. Warm WordPress Entrypoints

`bootstrap_probe_runner.py` sends a fixed set of WordPress bootstrap requests and records which new `hook-coverage/requests/*.json` artifacts each probe creates.

Default probes cover:

- `/`
- `/wp-admin/admin-ajax.php?action=hookphuzz_probe`
- `/wp-admin/admin-post.php?action=hookphuzz_probe`
- `/wp-json/`
- `/?rest_route=/`
- `/wp-login.php?action=lostpassword`
- `/wp-admin/index.php`
- `/wp-admin/admin.php`
- `/xmlrpc.php`
- `/wp-cron.php`

Run:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python hook_energy\bootstrap_probe_runner.py `
  --base-url http://localhost:8080 `
  --hook-coverage-dir output\hook-coverage `
  --output-dir output\bootstrap_probe `
  --timeout 10
```

Output:

- `output/bootstrap_probe/bootstrap_probe_report.json`

The report includes per-probe method, path, status code, duration, error, and `new_request_artifacts`. Failed probes are recorded in the report instead of stopping the whole run.

### 2. Classify Entrypoint Candidates

`entry_classifier.py` reads either `total_coverage.json` or `hook_gap_report.json` and writes candidate sets grouped by replayability.

Run:

```powershell
python hook_energy\entry_classifier.py `
  --input-file output\total_coverage.json `
  --output-dir output\entry_classifier `
  --format auto `
  --pretty
```

Outputs:

- `entrypoint_candidates.json`
- `direct_http_candidates.json`
- `setup_required_candidates.json`
- `non_entry_hooks.json`

Direct HTTP candidates receive an `http_template` with method, path, and fixed params. Supported direct mappings include:

| Hook family | Entry type | Method | Path | Auth |
| --- | --- | --- | --- | --- |
| `wp_ajax_nopriv_*` | `ajax_unauthenticated` | `POST` | `/wp-admin/admin-ajax.php` | no |
| `wp_ajax_*` | `ajax_authenticated` | `POST` | `/wp-admin/admin-ajax.php` | yes |
| `admin_post_nopriv_*` | `admin_post_unauthenticated` | `POST` | `/wp-admin/admin-post.php` | no |
| `admin_post_*` | `admin_post_authenticated` | `POST` | `/wp-admin/admin-post.php` | yes |
| `admin_action_*` | `admin_action` | `GET` | `/wp-admin/admin.php` | yes |
| `login_form_*` | `login_form` | `POST` | `/wp-login.php` | no |
| `heartbeat_received` | `heartbeat_authenticated` | `POST` | `/wp-admin/admin-ajax.php` | yes |
| `heartbeat_nopriv_received` | `heartbeat_unauthenticated` | `POST` | `/wp-admin/admin-ajax.php` | no |

`setup_required` means the hook can be HTTP-relevant but needs extra setup before automatic PHUZZ config generation, for example shortcode pages, rewrite endpoints, REST route records, or XML-RPC method maps.

`non_entry` means the hook is currently treated as non-replayable or manual-only, for example lifecycle, admin menu, enqueue, or unknown custom hooks.

The classifier preserves multi-stage registration metadata when UOPZ reports that a hook was registered inside another callback. These fields include `registered_inside_callback`, `parent_callback`, `hook_level`, `parent_hook_name`, and `parent_callback_id`. They are useful for auditing level 1/level 2 child hook discovery, but they do not change entry classification by themselves. A level 2 hook is still only replayable automatically if it also matches a supported direct HTTP rule.

Compact candidate shape:

```json
{
  "candidate_id": "cb-public",
  "classification": "direct_http",
  "hook_name": "wp_ajax_nopriv_demo_lookup",
  "callback_id": "cb-public",
  "entry_type": "ajax_unauthenticated",
  "registered_inside_callback": false,
  "hook_level": 0,
  "parent_hook_name": null,
  "parent_callback_id": null,
  "action": "demo_lookup",
  "http_template": {
    "method": "POST",
    "path": "/wp-admin/admin-ajax.php",
    "query_params": {},
    "body_params": {
      "action": "demo_lookup"
    }
  },
  "auth_required": false,
  "confidence": "high"
}
```

For the detailed parent/child artifact contract, replay evidence, and current recursive-seed boundary, see `multistage-hook-discovery-metadata.md`.

### 3. Replay One Candidate

`seed_validator.py` replays one selected candidate or one single seed JSON and writes `validation_result.json`. It diffs the hook coverage request directory before and after replay, then inspects only the new artifacts created by that replay.

This validation proves that a generated entrypoint candidate can be replayed and correlated with hook coverage artifacts. It does not mean generated seeds are automatically consumed by the PHUZZ runtime.

Run against one candidate from `entrypoint_candidates.json`:

```powershell
python hook_energy\seed_validator.py `
  --base-url http://localhost:8080 `
  --candidate-file output\entry_classifier\entrypoint_candidates.json `
  --candidate-id cb-public `
  --hook-coverage-dir output\hook-coverage `
  --output-file output\validation_result.json `
  --timeout 10 `
  --pretty
```

The validator can also read one generated seed JSON directly when the file contains a `seed` object with `method`, `path`, `body`, and `query_params`.

Compact `validation_result.json` shape:

```json
{
  "schema_version": 1,
  "candidate_id": "cb-public",
  "hook_name": "wp_ajax_nopriv_demo_lookup",
  "result": {
    "expected_hook_fired": true,
    "expected_callback_reached": true,
    "confidence": "high",
    "reason": "Expected callback id was found in executed_callbacks"
  },
  "artifacts": {
    "artifact_count": 1
  },
  "observed": {
    "executed_callback_ids": [
      "cb-public"
    ],
    "executed_hook_names": [
      "wp_ajax_nopriv_demo_lookup"
    ]
  }
}
```

Result confidence:

- `high`: the expected callback id or callback repr was found in `executed_callbacks`.
- `medium`: the expected hook was observed, but the expected callback was not found in `executed_callbacks`.
- `low`: no fresh artifact was created, or the expected hook and callback were not observed.

Common failure reasons:

- `No new hook coverage request artifacts were created`: the replay did not hit instrumentation, the target was not running, or the hook coverage output path is wrong.
- `Expected callback was registered but was not executed`: the request reached a bootstrap path but did not execute the selected callback.
- `Expected callback was reported as a blindspot and was not executed`: HookPhuzz observed the callback as registered or blindspot-only, not reached.

### Focused Tests

Run the tests for this pipeline from the fuzzer directory:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python -m unittest `
  tests.test_bootstrap_probe_runner `
  tests.test_entry_classifier `
  tests.test_bootstrap_entry_discovery `
  tests.test_seed_validator `
  tests.test_uopz_multistage_metadata_contract `
  -v
```

## Report Fields

`hook_gap_report.json` keeps the richer callback context for auditing:

```json
{
  "hook_name": "wp_ajax_nopriv_example_lookup",
  "callback_name": "example_lookup_handler",
  "function_name": "example_lookup_handler",
  "class_name": null,
  "method_name": null,
  "is_static": false,
  "is_closure": false,
  "is_invokable": false,
  "formal_parameters": [],
  "source_file": "/var/www/html/wp-content/plugins/example-plugin/includes/ajax.php",
  "source_line": 39,
  "start_line": 39,
  "end_line": 70,
  "input_params": []
}
```

## Validation Boundary

The seed generator is valid when it writes deterministic discovery artifacts from `total_coverage.json`. The config converter is valid when it writes PHUZZ config JSON for unauth-capable and authenticated seeds and records unsupported seeds in `generated_config_summary.json`. Runtime validation is a separate stage: run a generated config and verify that the target callback id appears in request-level hook coverage.

If expected params are missing, first check whether `source_file` resolves on the host and whether `start_line`/`end_line` are present in the coverage artifact.

## Tests

Relevant tests:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python -m unittest tests.test_seed_generation_input_extractor tests.test_input_signature_extractor tests.test_seed_generation_with_input_params -v
python -m unittest tests.test_seed_to_config_exporter -v
```

Broader regression set:

```powershell
python -m unittest tests.test_seed_generation_live_export tests.test_seed_generation_importer tests.test_scoring_modes tests.test_hook_energy_integration tests.test_hook_energy_bridge tests.test_benchmark_summary -v
```
