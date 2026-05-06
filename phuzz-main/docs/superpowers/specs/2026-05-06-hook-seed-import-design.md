# Hook Seed Import Design

## Goal

Add a new seed-import module under `code/fuzzer/hook_energy/seed_generation` that reads seed handoff artifacts from another project and writes normalized seed artifacts into this repo for later PHUZZ seeding.

This work does not integrate imported seeds into the fuzzer runtime yet. It only generates import artifacts that can be inspected, validated, and consumed later.

## Scope

In scope:

- Read handoff files from another project.
- Treat `output/hook_gap_report.json` as the primary source of truth.
- Filter replayable callbacks using the exact import rules.
- Convert valid seeds into this project's normalized request artifact format.
- Split replayable seeds into unauthenticated-capable and authenticated-only queues.
- Send non-replayable callbacks to a manual-analysis backlog queue.
- Detect stale source artifacts and record warnings in summary output.
- Add automated tests for filtering, mapping, queue splitting, metadata preservation, and stale artifact detection.

Out of scope:

- Automatic replay of generated seeds.
- Wiring generated seeds directly into PHUZZ config loading or runtime candidate generation.
- Inventing requests for callbacks that require manual analysis.
- Regenerating source-project artifacts from this repo.

## Source Inputs

The importer reads external artifacts in this order:

1. `docs/SEED_HANDOFF_FOR_AGENTS.md`
2. `output/hook_gap_report.json`
3. `output/suggested_seeds.json`
4. `fuzzer-core/hook_energy/seed/pipeline.py`
5. `target-app/shop-demo/shop-demo.php`

`output/hook_gap_report.json` is the authoritative machine-readable input for import decisions because it contains the full callback metadata and seed payloads. `output/suggested_seeds.json` is secondary and used only for supporting context if needed.

The importer must also verify stale-artifact conditions against:

- `fuzzer-core/hook_energy/seed/pipeline.py`
- `target-app/shop-demo/shop-demo.php`

## Import Rules

Only import callbacks into replayable queues when all of these are true:

- `status == "uncovered"`
- `is_active == true`
- `direct_http_supported == true`
- `generation_status == "supported_http_seed"`
- `seed != null`

Callbacks must never be converted into replayable requests when either of these is true:

- `direct_http_supported == false`
- `generation_status == "manual_analysis_required"`

Those entries go to the manual-analysis backlog queue instead.

## WordPress Mapping Rules

Replayable HTTP seeds follow the source project's mapping rules:

- `wp_ajax_*` -> `POST /wp-admin/admin-ajax.php`
- `wp_ajax_nopriv_*` -> `POST /wp-admin/admin-ajax.php`
- `admin_post_*` -> `POST /wp-admin/admin-post.php`
- `admin_post_nopriv_*` -> `POST /wp-admin/admin-post.php`

The importer trusts the `seed` object in `hook_gap_report.json` first, but stale-artifact verification checks that the source code still contains these direct-trigger hooks and mappings.

## Auth Rules

The importer preserves `seed.auth_mode` and uses it to split queues:

- `unauth-capable` -> unauthenticated-capable queue
- `authenticated` -> authenticated-only queue

Authenticated seeds must never appear in the unauthenticated queue.

## Output Layout

Add a new package:

- `code/fuzzer/hook_energy/seed_generation/`

Expected module layout:

- `__init__.py`
- `models.py`
- `importer.py`
- `stale_check.py`

Generated artifacts should be written under:

- `code/fuzzer/output/seed_generation/`

Expected output files:

- `imported_unauth_seeds.json`
- `imported_auth_seeds.json`
- `manual_analysis_queue.json`
- `import_summary.json`

## Normalized Request Artifact Shape

Each replayable imported seed becomes one normalized artifact:

```json
{
  "request_id": "seed-import-<callback_id>",
  "source": "external-hook-gap-report",
  "http_method": "POST",
  "path": "/wp-admin/admin-ajax.php",
  "content_type": "application/x-www-form-urlencoded",
  "body": {
    "action": "shop_demo_public_ping"
  },
  "query_params": {},
  "headers": {},
  "cookies": {},
  "auth_mode": "unauth-capable",
  "metadata": {
    "hook_name": "wp_ajax_nopriv_shop_demo_public_ping",
    "callback_id": "<callback_id>",
    "callback_name": "shop_seed_ajax_public_ping",
    "seed_priority": "highest",
    "target_family": "wp_ajax_nopriv",
    "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
    "source_line": 999,
    "accepted_args": 1
  }
}
```

Required metadata fields to preserve:

- `hook_name`
- `callback_id`
- `callback_name`
- `seed_priority`
- `target_family`
- `seed.auth_mode`

Additional metadata to preserve when present:

- `source_file`
- `source_line`
- `priority`
- `accepted_args`

## Manual Queue Shape

Each manual-only entry should preserve callback context without inventing a request:

```json
{
  "callback_id": "<callback_id>",
  "hook_name": "template_redirect",
  "callback_name": "shop_render_test_ui",
  "status": "uncovered",
  "is_active": true,
  "direct_http_supported": false,
  "generation_status": "manual_analysis_required",
  "seed_priority": "low",
  "target_family": "internal_or_manual",
  "source_file": "/var/www/html/wp-content/plugins/shop-demo/shop-demo.php",
  "source_line": 321,
  "accepted_args": 1
}
```

## Stale Artifact Detection

The importer must warn when source artifacts appear stale. A stale warning is emitted when source code indicates direct HTTP seed hooks exist, but the handoff report still shows no matching replayable callbacks or `direct_http_seed_candidates == 0`.

Example stale signal:

- `shop-demo.php` contains `wp_ajax_*` or `admin_post_*` seed hooks
- but `hook_gap_report.json` summary still reports zero direct HTTP candidates

Important behavior:

- Record warnings in `import_summary.json`
- Do not fabricate replayable requests from source code
- Do not override `hook_gap_report.json` as source of truth

This preserves correctness while still surfacing likely stale source artifacts.

## Main Flow

1. Load and parse external handoff files.
2. Build replayable import candidates from `hook_gap_report.json`.
3. Filter using the exact import conditions.
4. Normalize replayable seeds into this repo's request artifact shape.
5. Split normalized artifacts by `auth_mode`.
6. Collect non-replayable uncovered callbacks into manual backlog.
7. Run stale-artifact checks against source pipeline and demo plugin files.
8. Write all output JSON files plus summary.

## Error Handling

The importer should fail clearly for missing or invalid primary inputs:

- missing `hook_gap_report.json`
- malformed JSON
- missing `callbacks` array

Secondary input handling:

- missing `suggested_seeds.json` should be a warning, not a hard failure
- stale-check files missing should be recorded as warnings if primary import can still proceed

## Testing Strategy

Tests go under `code/fuzzer/tests/`.

Required test coverage:

- imports only callbacks that satisfy all replayable-seed predicates
- preserves required metadata
- splits `unauth-capable` and `authenticated` queues correctly
- places manual-only callbacks into backlog queue without request synthesis
- uses `hook_gap_report.json` as primary truth even if `suggested_seeds.json` is incomplete
- emits stale warnings when source code shows direct-trigger hooks but report shows zero candidates
- does not emit fake replayable requests during stale conditions

## Integration Boundary

This importer remains a standalone artifact generator inside `hook_energy`.

Later work can consume generated seed files from `code/fuzzer/output/seed_generation/` and convert them into PHUZZ config inputs or runtime seed candidates. That later integration should be separate from this design so the import layer stays easy to validate and debug.
