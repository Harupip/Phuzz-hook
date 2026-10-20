# Online-linked final config export

Change date: 2026-10-05.

## Callback discovery eligibility and context scheduling

Coverage remains an execution fact: `covered`, `execute_count` and input
`executed_count` retain the observed values. The runtime seed generator adds
`discovery_eligible` separately. An active callback with a supported direct
HTTP mapping remains eligible after bootstrap execution, while internal hooks
and inactive callbacks stay out of the runtime HTTP queue. Eligibility does
not mean the candidate passed method/auth/setup gates or is ready to fuzz.

Online-linked scheduling uses a versioned context key in addition to the
existing registration identity. It includes callback identity, path, method,
content type, auth mode, request buckets, field names and roles, and fixed
values. Declared fuzzable values are replaced only in transport sections where
the config exporter treats the matching field as fuzzable; explicit fixed
selectors keep their values. Role metadata is canonicalized as sets, while
request data array order remains significant. Request provenance such as IDs,
timestamps and execution counts does not split an otherwise identical context.
Nonce/token values are normalized only when an explicit role identifies them;
unclassified header and cookie values remain fixed. Thus the same callback can
be scheduled again with a different fixed selector or transport context, while
rediscovery of the same context is deduplicated.

Candidate and batch checkpoints store `context_key_version: 1` and their
queued context keys alongside the existing queue, stage and budget state.
Resume rejects checkpoints without the supported context-key version before
starting a worker. A pending resume retains its stage and remaining deadline;
context deduplication is scoped to the campaign and does not carry into a new
campaign or a different database/setup. The exporter groups new records by
context key and uses it for distinct output filenames; records without a
context key keep the legacy identity-based grouping and filename behavior.

These rules preserve callback candidates for bounded discovery. They do not
claim that discovery is complete, a selector was inferred, a branch was
reached, or a vulnerability was proven.

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
