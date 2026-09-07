# Online-linked completion report — 2026-09-07

## Result

Implementation and regression work completed through the bounded online-linked
campaign. Runtime acceptance is **PARTIAL**, not PASS: the campaign produced
correlated callback and convergence evidence, but no worker was allowed to run
because the selected candidates were probe-only or exhausted the per-candidate
budget. The remaining failures are recorded as runtime boundaries below.

## Source and verification

- Branch: `feature/online-linked`
- Baseline HEAD before this WIP: `2018333`
- Regression before the follow-up fixes: `187 tests OK` in `24.391s`
- Runtime command: `-Mode online-linked -UseZendDiscovery`
- Runtime budgets: `OnlineTimeoutSeconds=20`, `OnlineMaxVersions=1`,
  `OnlineMaxCandidates=9`, `OnlineCampaignTimeoutSeconds=300`

## Runtime evidence

Run ID: `hookphuzz-online-discovery-fixture-20260907T094424Z`

Primary artifact:

`fuzzer/output/online-linked/hookphuzz-online-discovery-fixture-20260907T094424Z/batch-state.json`

The batch processed 8 initial candidates and ended `campaign_status=complete`:

| Candidates | Evidence | Outcome |
| --- | --- | --- |
| 3 REST routes | `callback_reached=true`, `CONVERGED` | Probe-only; worker not started before budget expiry |
| 2 authenticated AJAX actions | `callback_reached=true`, runtime parameter discovery | Worker not started before budget expiry |
| 2 unauthenticated AJAX actions | `registered_not_executed` | Auth/session routing boundary; expected `wp_ajax_nopriv_*` did not execute |
| 1 REST URL pattern | no v0 config | `V0_PREREQUISITE_GATE_FAILED`; named route group cannot be materialized |

The run preserved request IDs, callback IDs, method variants, candidate state
paths, registry copy, replay summaries, and convergence results. The wrapper now
reports the real batch artifact at `batch-state.json`.

## Implemented scope

- v0 replay/provenance gate before worker start.
- Request-derived child values with transport, JSON type, nested path, fixed
  selector, and lineage preservation.
- Separate observed/confirmed state, bounded retries, immutable parent config,
  and explicit replay/export failure reasons.
- Runtime HTTP callback discovery with method/variant identity, dedupe,
  parent request lineage, candidate/campaign budgets, registry merge, and
  optional container registry refresh.
- Wrapper and guide coverage for the new budgets and report paths.

## Offline follow-up — four online-linked logic fixes

The follow-up kept the existing runtime artifact unchanged and addressed four
producer/consumer and lifecycle defects offline:

1. UOPZ now exports a runtime-decoded `json_params` bucket with explicit
   `json_params_status`/`json_params_error` values. The coordinator preserves
   JSON false, zero, null, empty objects, and nested values without treating
   missing or invalid JSON as observed data.
2. Empty query/form buckets are normalized only where the schema permits it.
   Cookie artifacts remain name lists; fixed cookie values are retained rather
   than replaced by cookie names, and malformed bucket types fail explicitly.
3. Discovery and batch queueing now use the same normalized identity builder;
   legacy precomputed identity strings are ignored. Route, method, and variant
   remain identity fields, with initial/runtime registration dedupe and lineage.
4. The batch campaign deadline is passed into every coordinator. Candidate
   timeout is the earlier of candidate and campaign deadlines, including v0
   replay, child replay, worker start/restart, and registry sync gates. Worker
   cleanup remains separately bounded by its Docker command timeout.

Offline verification for this follow-up:

- Coordinator regression: `48 tests OK`.
- Full coordinator/wrapper/runner/CmpLog/exporter/discovery group: `196 tests
  OK` in `46.194s`, run through `subprocess.run(..., timeout=180)`.
- `python -m py_compile` passed for the coordinator and its test module.
- `php -l web/instrumentation/hook_coverage/uopz_hook_wp.php` reported no syntax
  errors.
- `git diff --check` passed.
- No Docker command or WordPress probe was run for this follow-up. Runtime
  acceptance therefore remains **PARTIAL**; the existing runtime result is not
  promoted to PASS.

## Offline follow-up — two reproduced logic fixes

The next offline regression pass fixed the two remaining defects without
changing the existing runtime artifact:

1. The PHP producer now decodes JSON without associative-array coercion and
   exports `json_params_type`. JSON objects remain objects, JSON arrays remain
   arrays, and empty-object status is reported only for `{}`. The coordinator
   accepts an object bucket, preserves nested false/zero/null values, and
   rejects top-level arrays/scalars with an explicit type reason.
2. Runtime discovery no longer rejects a callback only because it shares the
   parent hook. It still rejects the parent callback itself, requires the
   existing lineage/HTTP/replayability gates, and uses the existing normalized
   candidate identity for dedupe.
3. Parameter admission compares PHP callback names after normalizing `->` and
   `::` to the same comparison form; the original callback representation is
   retained in the evidence/config metadata.

Offline verification for this pass:

- PHP producer regression: `3 tests OK` for object/array/scalar preservation,
  child/replay config values, and same-hook callback discovery. The producer
  was exercised through `C:\xampp\php\php.exe` and parsed by Python over a
  local HTTP harness; no WordPress process was started.
- Coordinator module: `52 tests OK` in `29.458s`.
- Wrapper contract module: `31 tests OK` in `11.868s`.
- Full coordinator/wrapper/runner/CmpLog/exporter/discovery group: `200 tests
  OK` in `31.587s`; no failures or skips. The command was bounded with
  `subprocess.run(..., timeout=180)`.
- PHP lint, Python bytecode compilation, and `git diff --check` passed.
- No Docker command or WordPress probe was run. Runtime acceptance remains
  **PARTIAL** and is not promoted to PASS by these offline tests.

## Remaining blockers

1. Re-run with a longer per-candidate budget and `OnlineMaxVersions>=3` to
   prove v0 → v1 → v2 and an actual child worker request.
2. Resolve or explicitly provision the unauthenticated AJAX runtime context;
   current evidence shows the nopriv callback is registered but not executed.
3. Add a supported concrete value for the URL route named group before claiming
   that candidate as HTTP-replayable.
4. Execute a real-plugin run and an A→B runtime registration campaign before
   marking Task 4–5 acceptance complete.
