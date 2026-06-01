# Hook-Aware Seed Generation

Hook-aware seed generation turns uncovered WordPress callbacks into PHUZZ-compatible HTTP seed suggestions.

The generator reads a UOPZ `total_coverage.json` snapshot, finds active uncovered callbacks, maps direct WordPress HTTP hooks to endpoints, extracts callback input parameters from source, and writes machine-readable seed artifacts.

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
  "callback": "GamiPress_Ajax::get_logs",
  "input_params": [
    {
      "name": "orderby",
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

Example `suggested_seeds.json` entry:

```json
{
  "hook_name": "wp_ajax_nopriv_gamipress_get_logs",
  "callback_id": "...",
  "callback_name": "gamipress_ajax_get_logs",
  "seed_priority": "highest",
  "generation_status": "supported_http_seed",
  "seed": {
    "method": "POST",
    "path": "/wp-admin/admin-ajax.php",
    "content_type": "application/x-www-form-urlencoded",
    "body": {
      "action": "gamipress_get_logs",
      "orderby": "FUZZ"
    },
    "auth_mode": "unauth-capable",
    "fixed_params": [
      "action"
    ],
    "fuzzable_params": [
      "orderby"
    ],
    "input_params": [
      {
        "name": "orderby",
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

## Report Fields

`hook_gap_report.json` keeps the richer callback context for auditing:

```json
{
  "hook_name": "wp_ajax_nopriv_gamipress_get_logs",
  "callback_name": "gamipress_ajax_get_logs",
  "function_name": "gamipress_ajax_get_logs",
  "class_name": null,
  "method_name": null,
  "is_static": false,
  "is_closure": false,
  "is_invokable": false,
  "formal_parameters": [],
  "source_file": "/var/www/html/wp-content/plugins/gamipress/includes/ajax-functions.php",
  "source_line": 39,
  "start_line": 39,
  "end_line": 70,
  "input_params": []
}
```

## Validation Notes

For GamiPress, expected seed when callback source is readable and the callback reads `$_REQUEST['orderby']`:

- `hook_name`: `wp_ajax_nopriv_gamipress_get_logs`
- `seed.method`: `POST`
- `seed.path`: `/wp-admin/admin-ajax.php`
- `seed.body.action`: `gamipress_get_logs`
- `seed.body.orderby`: `FUZZ`
- `seed.fuzzable_params`: includes `orderby`

For Country State City Dropdown CF7, expected seeds when callback source is readable:

- `tc_csca_get_cities` includes `sid=FUZZ`
- `tc_csca_get_states` includes `cnt=FUZZ`

If those params are missing, first check whether `source_file` resolves on the host and whether `start_line`/`end_line` are present in the coverage artifact.

## Tests

Relevant tests:

```powershell
cd C:\Users\nghia.cd_extremevn\Desktop\Phuzz-hook\phuzz-main\code\fuzzer
python -m unittest tests.test_seed_generation_input_extractor tests.test_input_signature_extractor tests.test_seed_generation_with_input_params -v
```

Broader regression set:

```powershell
python -m unittest tests.test_seed_generation_live_export tests.test_seed_generation_importer tests.test_scoring_modes tests.test_hook_energy_integration tests.test_hook_energy_bridge tests.test_benchmark_summary -v
```
