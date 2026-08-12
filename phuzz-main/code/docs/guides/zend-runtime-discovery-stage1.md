# Zend Runtime Discovery Stage 1

Stage 1 la che do opt-in cho generated WordPress flow. Muc tieu la lay parameter fuzzing tu bang chung Zend runtime, khong lay tu static regex/source scan.

Che do nay chi ap dung khi chay:

```powershell
.\phuzz.ps1 -Mode generated -PluginSlug <plugin-slug> -UseZendDiscovery -NoFollowLogs
```

`-UseZendDiscovery` van di qua generated mode mac dinh: `export_cli.py -> seed_to_config_cli.py`. No khong bat `-UseEntrypointPipeline`, khong thay doi default generated flow khi flag nay khong duoc truyen.

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
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass1-uopz/
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass1-zend/
```

Bridge chi tao parameter neu co bang chung dong thoi tu:

- same `legacy_run_id` trong UOPZ evidence
- same `request_id`
- same target plugin
- expected callback da execute trong UOPZ artifact
- exact Zend `callback_summaries.callback`
- Zend parameter la direct top-level `$_GET['name']` hoac `$_POST['name']`

Pass 2 replay generated config bang production `Fuzzer.load_config` va `Fuzzer.prepare_request`, voi request ID moi nhung cung `legacy_run_id`. Pass 2 chi pass neu callback dung duoc reach va Zend re-observe dung tung parameter.

## Scope Stage 1

Accepted:

- direct `$_GET['x']`
- direct `$_POST['y']`
- top-level path exactly one string key
- `helper_depth == 0`
- `observed_count > 0`
- exact canonical callback

Rejected/fail closed:

- `$_REQUEST`
- `$_COOKIE`
- REST/schema parameters
- JSON body parameters
- nested paths
- helper-reader propagation
- method-only evidence
- UOPZ `request_params`
- stale/missing Zend artifacts
- HTTP 200 without matching callback and Zend parameter event
- callback reached without matching Zend parameter event

GET and POST source map independently of HTTP request method:

- Zend `source=GET` becomes PHUZZ `query_params`
- Zend `source=POST` becomes PHUZZ `body_params`

Example: a POST request that reads `$_GET['x']` still creates a query parameter `x`.

## Runtime Evidence Contract

The generator consumes only normalized value-free evidence. Example:

```json
{
  "run_id": "legacy-...",
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
<legacy_run_id>
```

Check:

```text
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/phase9-callback-registry.json
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/pass1-generated_config_summary.json
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/pass1-generated_config_run_summary.json
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass1-uopz/
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass1-zend/
fuzzer/output/zend-discovery/<legacy_run_id>/zend_enriched_seeds.json
fuzzer/output/seed_generation/zend_merged_suggested_seeds.json
fuzzer/output/seed_generation/generated_config_summary.json
fuzzer/output/seed_generation/pass2-generated_config_run_summary.json
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass2-uopz/
fuzzer/output/seed_generation/zend-bridge/<legacy_run_id>/logs/pass2-zend/
```

The final config is written under:

```text
fuzzer/configs/generated-config/<plugin-slug>/
```

## Known Passing Fixture

The Stage 1 Docker gate uses:

```text
hookphuzz-entrypoint-direct-fixture
```

The fixture callback reads:

```php
$x = $_GET['x'] ?? null;
$y = $_POST['y'] ?? null;
```

Expected result:

- generated config method: `POST`
- `x` in `query_params.fuzz`
- `y` in `body_params.fuzz`
- fixed `action` in `body_params.fixed`
- Pass 1 request ID and Pass 2 request ID are different
- both pass IDs share the same `legacy_run_id`
- Pass 2 verifier prints `Zend Pass 2 verification: accepted=1 total=1`

## Current Verified Proof

Last verified Stage 1 proof:

```text
legacy-20260812T070836Z-3f78d654
```

Proof summary:

- Pass 1 callback reached: yes
- Pass 1 Zend observed: GET `x`, POST `y`
- Bridge: `accepted_pass1_proof=1 final_fuzz_export_allowed=1 generated=1`
- Pass 2 callback reached: yes
- Pass 2 Zend verification: `accepted=1 total=1`
- forbidden marker scan: no `static_regex`, no `source_exact`, no `submitted`

## Regression Gate

Before closing a Stage 1 change, run:

```powershell
python -m unittest discover -s fuzzer\tests -p "test_*.py"
python -c "from pathlib import Path; files=[p for p in Path('fuzzer').rglob('*.py') if '__pycache__' not in p.parts]; [compile(p.read_text(encoding='utf-8-sig'), str(p), 'exec') for p in files]; print(f'compiled {len(files)} files')"
powershell -NoProfile -ExecutionPolicy Bypass -File fuzzer\output\stage1-runtime-proof\check-powershell-parser.ps1
docker compose config -q
git diff --check
```

Do not treat HTTP 200, callback registration, or callback reachability alone as proof. Stage 1 pass requires correlated Zend runtime parameter evidence and Pass 2 re-observation.
