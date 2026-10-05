# Online-linked final config export

Change date: 2026-10-05.

## What changed

Previously, `export_online_linked_batch()` selected one latest verified version
per candidate. An older verified config with different fixed branch values or
parameters could remain in campaign history without appearing in `final-configs`.

The exporter now retains distinct verified configs for each candidate. For
example, `mode=search` with fuzzable `keyword` and `mode=delete` with fuzzable
`item_id` are exported separately. Parameters are not merged into one request.

Every exported version still must satisfy the existing replay/readiness gate,
Pass 2 (`accepted == total > 0`), config hash and `fuzzing_ready` checks. Probe
and replay-only configs remain excluded. A failed latest version does not prevent
older verified versions from being exported.

## Output and compatibility

- The newest eligible config keeps the existing filename and the summary's
  `selected_version` / `config_path` fields.
- Additional distinct configs use a `.vN` suffix before `.json`.
- `exported_configs` lists all exported configs, their source paths, hashes and
  `equivalent_versions`. `state_path` links to the campaign evidence.
- Deduplication compares the full config except `metadata.online_request_seed`,
  which contains request provenance. Exported bytes retain this metadata.
  Fixed values, method, transport, auth and other options remain part of the key.
- `verified_parameters` summarizes eligible versions across requests; it does
  not claim that all parameters were read in one request. Pending observations
  and budget/limit termination can still produce `PARTIAL`.
- This change does not discover new branches or rewrite previous run outputs.
  Distinct configs are not automatically labelled as source-code branches.

## Merge checklist

When resolving conflicts in `export.py` or its tests, preserve these behaviors:

1. Iterate over all eligible versions; do not restore the old `break` after the
   first verified config.
2. Keep configs with different fixed context or transport separate, while
   recording equivalent versions without duplicate output files.
3. Preserve verification gates, exact copied bytes, fallback and filename rules.
4. Preserve `exported_configs`, evidence links and discovery summary aggregation.
5. Run the regression tests after combining changes from both branches.

Related files: `export.py` and `../tests/test_online_linked_export.py`.

## Checks

From `phuzz-main/code/fuzzer`:

```powershell
python -B -m unittest tests.test_online_linked_export tests.test_online_linked_replay_inputs tests.test_online_linked_config_comparison
```

Use a writable temporary directory. On Windows, normalize the temporary path
if short 8.3 names interfere with path-sensitive comparison tests. These tests
cover offline export/replay-input/comparison behavior; they do not establish a
fresh WordPress runtime or fuzzing PASS.
