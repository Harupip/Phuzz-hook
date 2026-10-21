# Online-linked final config export

Reviewed against the working tree: **2026-10-09**. For the coordinator, budgets,
resume and worker lifecycle, see the [online-linked guide](../../docs/guides/online-linked-flow.md).

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

`export_online_linked_batch()` retains distinct verified configs for each candidate. For
example, `mode=search` with fuzzable `keyword` and `mode=delete` with fuzzable
`item_id` are exported separately. Parameters are not merged into one request.

Every exported version still must satisfy the existing replay/readiness gate,
Pass 2 (`accepted == total > 0`), config hash and `fuzzing_ready` checks. Probe
and replay-only configs remain excluded. A failed latest version does not prevent
older verified versions from being exported.

When a candidate stops on a budget/time/limit with observed parameters, export
also saves a draft in the sibling `partial-configs/` directory. Its filename ends
in `.partial.json`, its `config_type` is `partial`, and `metadata.fuzzing_ready`
is false. `metadata.partial_export` records the stop reason, verified and pending
parameters, source state/config, and any parameters whose transport is unresolved.
There is no parameter-count threshold. Drafts include guard-only observations;
their combined inputs may belong to incompatible branches and have not passed
replay/Pass 2 together. Form observations make the draft POST; this inference is
not runtime method proof. Drafts are for inspection, not automatic fuzzing.
The summary's separate `partial_configs` list identifies current drafts; older
draft bytes remain preserved on re-export. They never enter `exported_configs`,
`selected_version`, comparison's final-config menu, or the verified export count.

## Output and compatibility

- The newest eligible config keeps the existing filename and the summary's
  `selected_version` / `config_path` fields.
- Additional distinct configs use a `.vN` suffix before `.json`.
- `final-config-summary.json` contains one summary per request context; legacy
  records without a context key retain grouping by candidate identity.
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

Candidate time uses `progress_idle_v1`: initial window W; each newly admitted parameter renews to max(deadline, now + W + 3 * measured sender cost), bounded by campaign and any explicit `--hard-candidate-seconds`. No implicit candidate hard cap. Pending names buy no time; new callbacks only extend campaign work. Bounded probes hand off early, then service remaining probes in the same run, revalidating ancestor parents. Idle ends with `NO_NEW_PROGRESS`; pending work remains PARTIAL and exports unverified drafts. Resume retains credits/time, subtracts offline time, stores null hard remaining when uncapped, and rejects old-policy checkpoints. Replay/Pass 2 and version/count caps remain unchanged.
