# Photo Gallery Zend discovery: handoff 2026-09-08

## Status

This is a checkpoint, not a completed runtime fix. Resume the existing implementation; do not restart the plan.

Branch: `feature/online-linked`. Implementation/review task: `codex://threads/01a07feb-2dc1-77b3-8142-6ea1c8230d50`.

The checkpoint includes helper candidate discovery, AJAX probes, per-parameter request evidence, parent recovery, target matching, and dedupe by canonical query/form/JSON input fingerprint. It also includes the existing auth-context and wrapper changes needed to carry this workspace to another machine. Generated configs and old runtime artifacts are not part of this checkpoint.

## Resolved P2: bounded probes prioritize the accepted child

File: `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`, `_run_pending_probe`.

For calls with a deadline, `_run_pending_probe` now stops admitting optional probes as soon as accepted evidence exists. The existing child export, replay-only replay, Pass 2 verification, worker handoff, parent recovery, and failure gates remain unchanged. Calls with `deadline=None` retain unlimited batching and per-parameter evidence.

Fresh offline red/green evidence:

1. The new fake-clock regression first failed at `assertIsNotNone(result)` with the old timing estimate.
2. After the minimal guard, it passed with only probe `a`, child `v1`, replay and Pass 2 accepted `1/1`, and the active worker on `v1`; optional probe `b` was not started.
3. A failed `a` still allows `b` to run for both `deadline=None` and `deadline=31.5`.
4. Pre-accepted evidence skips optional probes only for bounded calls; unlimited calls still batch them.
5. If the deadline expires immediately after an accepted probe, no child worker starts and `BUDGET_EXPIRED` remains explicit.

Changed paths: the coordinator, its test module, this handoff, and the completed checkboxes in the continuation plan. The coordinator test's PHP producer helper now resolves `php` through `shutil.which('php')` and falls back to the historical `C:\xampp\php\php.exe`; it fails explicitly if neither exists. This is a portable test prerequisite adjustment only, not production logic.

## Verified and unverified boundaries

- Dedupe retries changed inputs in the same parent version; ignores request IDs, metadata and object-key order; preserves JSON types and array order.
- Probe target must match name/source/location with correlated read evidence.
- Child replay and Pass 2 remain required; no claim that helper depth alone proves a parameter.
- Historical checkpoint checks: coordinator 64, discovery 102, online runner 14, exporter 28, wrapper 23, request auth 2: **233 passed**, no unittest skips/failures. This remains historical evidence for the pre-P2 environment.
- Fresh continuation checks with process timeouts: coordinator **66/66 passed**, discovery **102/102 passed**, online runner **14/14 passed**, exporter **28/28 passed**, wrapper **23/23 passed**. Aggregate: **235 tests, 234 passed, 1 error, 0 failures, 0 skips, 0 timeouts**. The request-auth suite ran **2 tests: 1 passed, 1 error**; the error is PHP `Cannot redeclare uopz_set_return()` because the resolved `D:\Code\xampp\php\php.exe` loads `uopz`, while `C:\xampp\php\php.exe` is absent. Full offline verification is therefore **INCOMPLETE** due to that environment error. `git diff --check` passed.
- Photo Gallery Docker/runtime has NOT been rerun after these edits. Do not label offline tests as runtime PASS.
- Runtime acceptance still requires: raw candidate -> probe request -> correlated read -> accepted parameter -> child config -> replay -> Pass 2 -> child worker evidence, separately for guest/authenticated.

## Resume on another machine

### Follow-up fixes from `photo-gallery-20260908T230738Z`

- That campaign ended after 10 candidates with 7 `BOUNDED_ONLINE_COMPLETE`, 3 `NOT_VERIFIED`, and no child v1. Bounded completion was budget exhaustion, not parameter discovery success.
- Probe admission now normalizes instance callback notation before checking raw Zend reads. Saved guest `ajax_task` evidence has `BWG::frontend_ajax`, while the parent carries `BWG->frontend_ajax`; the old gate rejected it and the corrected gate accepts it. Correlation, depth, request-key, replay and Pass 2 checks remain required.
- When Docker reports removal already in progress, worker shutdown now checks for confirmed container absence within the existing 30-second stop budget. A stuck removal, daemon failure or timeout remains `WORKER_STOP_FAILED`.
- Fresh regression results: coordinator 68/68, discovery 102/102, online runner 14/14, exporter 28/28, wrapper 23/23. Auth remains 1 passed / 1 PHP environment error; aggregate 237 tests, 236 passed, 1 error. Both new regressions failed before their fixes and passed afterward.
- Saved-artifact admission was checked offline; no new Photo Gallery campaign has run after these fixes. The two guest v0 `no_artifact` outcomes remain unresolved. Child replay, Pass 2 and worker runtime remain `NOT_VERIFIED` for the corrected code.

1. Obtain this local checkpoint commit; it has not been pushed automatically.
2. Inspect status and this note. The older implementation plan contains historical unchecked boxes, not a fresh todo list.
3. Include the uncommitted deadline, callback normalization and shutdown fixes; rerun coordinator/discovery tests with explicit process timeouts.
4. Run Photo Gallery runtime only when requested; use fresh run IDs and preserve old artifacts.
5. Recheck wrapper options against that checkout before launching runtime. Local generated configs were intentionally excluded.
