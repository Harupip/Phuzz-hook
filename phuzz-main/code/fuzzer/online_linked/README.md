# Online-linked final config export

Reviewed against the working tree: **2026-10-09**. For the coordinator, budgets,
resume and worker lifecycle, see the [online-linked guide](../../docs/guides/online-linked-flow.md).

## What changed

`export_online_linked_batch()` retains distinct verified configs for each candidate. For
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
- `final-config-summary.json` contains one summary per candidate identity.
  `exported_configs` lists all active exports, source paths, hashes,
  `equivalent_versions` and `superseded_versions`. `state_path` links to evidence.
  `selected_version` is only the newest representative, not the full export list.
- Deduplication compares the full config except `metadata.online_request_seed`,
  and `metadata.method_evidence.request_id` / `.run_id`, which carry transient
  request provenance. Exported bytes retain this metadata.
  Fixed values, method, transport, auth and other options remain part of the key.
- `verified_parameters` summarizes eligible versions across requests; it does
  not claim that all parameters were read in one request. Pending observations
  and budget/limit termination can still produce `PARTIAL`.
- Compatible cumulative growth can supersede an older version: `{a}` becomes
  `{a,b}` only when the newer verified parameter identities cover the old set,
  existing rows/selectors and other options remain compatible, and request
  context stays the same. Fixed branch values, method, auth, transport and
  unsupported bucket shapes remain separate. No parameter union is fabricated.
- Re-export/resume reuses identical bytes. A filename collision with different
  bytes uses a content-hash suffix. Prior exports known to be equivalent or
  superseded move to `final-configs/superseded/` after hash verification; their
  bytes are retained. Unrelated prior files are not blindly deleted. Use the
  current summary to identify the active set, rather than recursing the folder.
- The exporter does not discover branches or rerun replay/fuzzing. Distinct
  configs are not automatically labelled as source-code branches. Empty export
  is valid; I/O/archive failure is `EXPORT_FAILED` and can leave partial output.

## Merge checklist

When resolving conflicts in `export.py` or its tests, preserve these behaviors:

1. Iterate over all eligible versions; do not restore the old `break` after the
   first verified config.
2. Keep different contexts separate; collapse only compatible cumulative
   growth, recording both equivalent and superseded versions.
3. Preserve verification gates, exact copied bytes, fallback and filename rules.
4. Preserve `exported_configs`, evidence links and discovery summary aggregation.
5. Preserve re-export/resume behavior and existing bytes, including the
   `superseded/` archive. Run the regression tests after merging.

Related files: `export.py` and `../tests/test_online_linked_export.py`.

## Checks

From `phuzz-main/code/fuzzer`:

```powershell
python -B -c "import subprocess,sys; r=subprocess.run([sys.executable,'-B','-m','unittest','tests.test_online_linked_export','tests.test_online_linked_replay_inputs','tests.test_online_linked_config_comparison'],timeout=180); sys.exit(r.returncode)"
```

Use a writable temporary directory. On Windows, normalize the temporary path
if short 8.3 names interfere with path-sensitive comparison tests. These tests
cover offline export/replay-input/comparison behavior; they do not establish a
fresh WordPress runtime or fuzzing PASS.
