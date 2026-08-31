# Zend Runtime Discovery Stage 1 and Phase 2

Stage 1 la mode Zend rieng cho generated WordPress flow. Muc tieu la lay parameter fuzzing tu bang chung Zend runtime, khong lay tu static regex/source scan.

Che do nay chi ap dung khi chay:

```powershell
.\phuzz.ps1 -Mode zend -PluginSlug <plugin-slug> -NoFollowLogs
```

`-Mode zend` dung generated flow legacy `export_cli.py -> seed_to_config_cli.py` va tu dong bat runtime-only Zend discovery. No khong bat `-UseEntrypointPipeline`; `-Mode generated` van giu flow generated khong Zend.

## Stage 1 Lam Gi

Flow co hai pass.

Pass 1 tao replay-only config tu WordPress platform metadata:

- AJAX callback dung `POST /wp-admin/admin-ajax.php`
- body co fixed `action`
- khong co synthetic fuzz field
- khong goi `InputSignatureExtractor`
- khong copy/read plugin source de quyet dinh parameter

Khi Pass 1 request chay, web container Zend target ghi raw opcode event vao:

```text
/shared/opcode-events/<request_id>.json
```

Runner copy raw UOPZ va Zend logs ve:

```text
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass1-uopz/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass1-zend/
```

Bridge chi tao parameter neu co bang chung dong thoi tu:

- same internal run-correlation field (`legacy_run_id`) trong UOPZ evidence
- same `request_id`
- same target plugin
- expected callback da execute trong UOPZ artifact
- exact Zend `callback_summaries.callback`
- Zend parameter la direct top-level `$_GET['name']` hoac `$_POST['name']`

Neu Pass 1 sinh generated candidate, Phase 2 chay REST/Zend convergence theo tung
`canonical_identity_id`. Moi target co `candidate_key` rieng va state doc lap. Identity
gom plugin, REST route pattern/materialized route, method, auth variant, callback, va
endpoint index. Chi Zend evidence cua matched artifact cung request ID duoc diff vao
state; static extraction khong the them parameter.

`CONVERGED` chi hop le khi replay hien tai duoc correlate, khong co runtime
parameter moi, va moi runtime parameter da biet deu duoc quan sat lai trong run hien
tai. Callback/correlation/replay failure ghi `REPLAY_FAILED`; hash config lap ghi
`REPEATED_CONFIG`; het `-ZendMaxIterations` ma chua hoi tu ghi `ITERATION_LIMIT`.
Zero generated candidate moi fallback ve bridge hien tai, khong chay convergence.

## Scope Stage 1

Accepted:

- direct `$_GET['x']`
- direct `$_POST['y']`
- correlated direct `$_REQUEST['x']` when the current request resolves it to
  exactly one existing `GET/query` or `POST/form` transport
- top-level path exactly one string key
- `helper_depth == 0`
- `observed_count > 0`
- exact canonical callback

Rejected/fail closed for direct Stage 1:

- direct `$_REQUEST` without a resolver-approved transport
- `$_COOKIE`
- nested paths
- helper-reader propagation
- method-only evidence
- ambiguous `$_REQUEST` transport (the name exists in both query and body)
- JSON-only or unsupported request transport for `$_REQUEST`
- UOPZ `request_params` without a matching Zend read and callback correlation
- stale/missing Zend artifacts
- HTTP 200 without matching callback and Zend parameter event
- callback reached without matching Zend parameter event

GET and POST source map independently of HTTP request method:

- Zend `source=GET` becomes PHUZZ `query_params`
- Zend `source=POST` becomes PHUZZ `body_params`

Example: a POST request that reads `$_GET['x']` still creates a query parameter `x`.

`$_REQUEST` does not create a new downstream source. The runtime boundary maps it
to the existing canonical contract using this order:

1. If the name exists in exactly one correlated `query_params` or `body_params`
   bucket, use `GET/query` or `POST/form`.
2. Otherwise, use `GET/query` for a GET request.
3. Otherwise, use `POST/form` only for a POST request with
   `application/x-www-form-urlencoded` or `multipart/form-data`.
4. Reject ambiguity, JSON-only requests, unsupported methods, and missing
   transport evidence.

Pass 2 applies the same mapping to raw Zend `REQUEST` events, so final
verification compares the existing `(name, source, location)` identity.

## Mainline CRM And REST Addendum

The current mainline keeps Stage 1 direct Zend evidence narrow, but the
compatibility generated flow may still carry source/helper seed information into the Zend
bridge. This matters for `crm-perks-forms`:

- UOPZ/coverage registers callback `cfx_form_admin_pages->save_api_settings`.
- Zend target loading needs canonical callback
  `cfx_form_admin_pages::save_api_settings`.
- Pass 1 request body must include fixed `action=vx_form_save_api_settings`.
- CRM also needs fixed `vx_nonce`.
- Runtime observes parent `cfx_settings`.
- Static/helper seed data keeps leaf `cfx_settings[alert_emails]`.
- The final fuzz config must fuzz `cfx_settings\\[alert_emails\\]`, not parent
  `cfx_settings`.

REST `WP_REST_Request::get_param()` is handled by UOPZ/Zend convergence:

- UOPZ records value-free request/callback artifacts.
- Zend records value-free runtime events such as
  `{"accessor":"WP_REST_Request::get_param","name":"search"}`.
- REST evidence is limited to `zend_rest_runtime`.
- Accepted locations are `REST_QUERY`, `REST_FORM`, and `REST_JSON`.
- Evidence must pass the same run/request/method/route/callback identity gates as
  direct Zend evidence.
- REST schema may guide JSON sentinel shape, but schema-only data cannot create a
  fuzz parameter.
- Security-looking parameter names, duplicate same-name multi-location evidence,
  stale artifacts, wrong request IDs, wrong route/method, and missing callback
  reachability fail closed.

## Runtime Evidence Contract

The generator consumes only normalized value-free evidence. Example:

```json
{
  "run_id": "<plugin>-YYYYMMDDTHHmmssZ",
  "request_id": "1786493341-...",
  "plugin_slug": "hookphuzz-entrypoint-direct-fixture",
  "callback_id": "add59b...",
  "canonical_callback": "hookphuzz_stage1_direct_ajax",
  "request_method": "POST",
  "name": "x",
  "path": ["x"],
  "source": "GET",
  "location": "query",
  "helper_depth": 0,
  "observed_count": 1,
  "evidence_kind": "zend_runtime",
  "fuzzable": true
}
```

Raw artifacts are not rewritten to insert expected identity. The normalized evidence layer is the only layer the generator may consume for Zend parameters.

Forbidden in Zend-generated seed/config/proof artifacts:

- `static_regex`
- `source_exact`
- submitted request values

Fixed platform fields still come from explicit WordPress rules. For AJAX Stage 1, `action` is fixed bootstrap data, not a fuzz parameter.

## Important Artifacts

Given:

```text
<plugin_run_id>
```

The public run-directory name is `<plugin-slug>-<UTC timestamp>`. Existing
`legacy_run_id` JSON fields and `--legacy-run-id` CLI arguments are retained as
compatibility identifiers; they do not change the directory naming policy.

Check:

```text
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/hookphuzz-callback-registry.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/zend_convergence_summary.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/iterations/<n>/state.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/targets/<candidate_key>/iterations/<n>/state.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/targets/<candidate_key>/current/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/targets/<candidate_key>/final/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/current/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/final/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/pass1-generated_config_summary.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/pass1-generated_config_run_summary.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass1-uopz/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass1-zend/
fuzzer/output/zend-discovery/<plugin_run_id>/zend_enriched_seeds.json
fuzzer/output/seed_generation/zend_merged_suggested_seeds.json
fuzzer/output/seed_generation/generated_config_summary.json
fuzzer/output/seed_generation/pass2-generated_config_run_summary.json
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass2-uopz/
fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/logs/pass2-zend/
```

The final config is written under:

```text
fuzzer/configs/generated-config/<plugin-slug>/
```

### Artifact retention

Trong khi run dang chay, tat ca registry, Pass 1, target, iteration, log va
snapshot trung gian van duoc giu de debug. Retention chi chay sau khi da ghi
convergence summary, final config va final replay/Pass 2 summary.

Voi terminal status `PASS`, `SUCCESS`, `CONVERGED` hoac
`PASS_PARTIAL_AUTH_EXPECTED`, runner giu:

- `zend-bridge/<plugin_run_id>/zend_convergence_summary.json`
- `zend-bridge/<plugin_run_id>/final/`
- `zend-bridge/<plugin_run_id>/final-generated_config_run_summary.json`
- final generated configs trong `fuzzer/configs/generated-config/<plugin-slug>/`
- final `generated_config_summary.json`, `hook_gap_report.json` va
  `zend_merged_suggested_seeds.json` neu cac file nay thuoc current seed output

Runner prune chi subtree current `<plugin_run_id>` va exact current-run
`zend-discovery/<plugin_run_id>`. Cac file nhu registry, `pass1-configs/`,
`targets/`, `iterations/`, logs, `current/`, Pass 1 summaries va
`final-generated_config_summary.json` bi xoa sau success. `suggested_seeds.json`
chi bi xoa khi noi dung da merge hoan toan vao
`zend_merged_suggested_seeds.json`.

Neu status la `FAIL`, `TIMEOUT`, `EXCEPTION`, `REPLAY_FAILED`,
`REPEATED_CONFIG` hoac `ITERATION_LIMIT`, runner khong prune gi. Co the dung
`-KeepDebugArtifacts` de giu toan bo intermediate ngay ca khi run success.

## Known Passing Fixture

The Stage 1 Docker gate uses:

```text
hookphuzz-entrypoint-direct-fixture
```

The Phase 2 fixture callback reads direct POST dimensions (not `??` / `isset`):

```php
$name = $_POST['name'];
if ($name) {
    $age = $_POST['age'];
}
```

Expected result:

- iteration 0 is action-only and discovers POST `name`
- iteration 1 sends nonempty `name` and discovers POST `age`
- iteration 2 sends both and converges with no new parameter
- all three request IDs differ, share one internal `legacy_run_id`, and one canonical candidate key
- final generated config has fixed `action` and fuzzable POST `name`, `age`

## Known Passing CRM Command

From `phuzz-main/code`:

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

Required PASS checks:

- command exits `0`
- `fuzzer/output/seed_generation/zend-bridge/<plugin_run_id>/zend_convergence_summary.json`
  has `status=CONVERGED`
- convergence iterations contain fresh request IDs
- Pass 1 and Pass 2 run summaries both have `callback_reached=1`
- Zend target loading has `file_target_count > 0` and `rejected_count == 0`
- `callback_summaries` includes
  `cfx_form_admin_pages::save_api_settings`
- final config under
  `fuzzer/configs/generated-config/crm-perks-forms/` is `fuzzing_ready`
- final config body fixes `action`, `vx_nonce`
- final config body fuzz list contains only
  `cfx_settings\\[alert_emails\\]`

Quick inspection after the run:

```powershell
rtk python -c "import json; from pathlib import Path; base=Path('fuzzer/output/seed_generation'); run=max((base/'zend-bridge').iterdir(), key=lambda p:p.stat().st_mtime).name; conv=json.loads((base/'zend-bridge'/run/'zend_convergence_summary.json').read_text(encoding='utf-8-sig')); summ=json.loads((base/'generated_config_summary.json').read_text(encoding='utf-8-sig')); cfg=json.loads(Path(summ['generated'][0]['config_path']).read_text(encoding='utf-8-sig')); print(run, conv.get('status'), [i.get('request_id') for i in conv.get('iterations', [])], cfg['body_params'])"
```

## Current Verified Proof

Historical Stage 1 proof:

```text
legacy-20260812T070836Z-3f78d654
```

Proof summary:

- Pass 1 callback reached: yes
- Pass 1 Zend observed: historical fixture GET `x`, POST `y`
- Bridge: `accepted_pass1_proof=1 final_fuzz_export_allowed=1 generated=1`
- Pass 2 callback reached: yes
- Pass 2 Zend verification: `accepted=1 total=1`
- forbidden marker scan: no `static_regex`, no `source_exact`, no `submitted`

Current REST convergence implementation proof (2026-08-13):

```powershell
rtk powershell.exe -ExecutionPolicy Bypass -File phuzz-main/code/phuzz.ps1 -Mode zend -PluginSlug hookphuzz-rest-get-param-fixture -ZendMaxIterations 5 -GeneratedConfigTimeoutSeconds 30 -NoFollowLogs -DryRun
rtk python -m unittest fuzzer.tests.test_zend_discovery fuzzer.tests.test_generated_config_runner fuzzer.tests.test_phuzz_wrapper_contract -v
rtk powershell.exe -NoProfile -Command "[void][System.Management.Automation.Language.Parser]::ParseFile('scripts/wordpress/run-wordpress-phuzz.ps1',[ref]`$null,[ref]`$null); [void][System.Management.Automation.Language.Parser]::ParseFile('phuzz.ps1',[ref]`$null,[ref]`$null); 'parser ok'"
rtk python -m py_compile fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py fuzzer/seed_generation/convergence/convergence.py
rtk git diff --check -- phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py phuzz-main/code/fuzzer/tests/test_generated_config_runner.py phuzz-main/code/fuzzer/tests/test_phuzz_wrapper_contract.py phuzz-main/code/fuzzer/tests/test_zend_discovery.py phuzz-main/code/phuzz.ps1 phuzz-main/code/scripts/wordpress/run-wordpress-phuzz.ps1 phuzz-main/code/docs/guides/zend-runtime-discovery-stage1.md
```

Result:

- wrapper dry-run exits `0` and delegates `-UseZendDiscovery -ZendMaxIterations 5`
- unittest scope exits `0`, `Ran 98 tests`, `OK`
- PowerShell parser check exits `0`
- Python bytecode compile exits `0`
- scoped `git diff --check` exits `0`

## Regression Gate

Before closing a Stage 1 change, run:

```powershell
python -m unittest discover -s fuzzer\tests -p "test_*.py"
python -c "from pathlib import Path; files=[p for p in Path('fuzzer').rglob('*.py') if '__pycache__' not in p.parts]; [compile(p.read_text(encoding='utf-8-sig'), str(p), 'exec') for p in files]; print(f'compiled {len(files)} files')"
powershell -NoProfile -ExecutionPolicy Bypass -File fuzzer\output\stage1-runtime-proof\check-powershell-parser.ps1
docker compose config -q
git diff --check
```

Do not treat HTTP 200, callback registration, schema-only data, or callback
reachability alone as proof. Zend REST convergence pass requires correlated
runtime parameter evidence and current replay re-observation.
