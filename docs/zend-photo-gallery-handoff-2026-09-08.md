# Photo Gallery Zend discovery: handoff 2026-09-08

## Status

This is a checkpoint, not a completed runtime fix. Resume the existing implementation; do not restart the plan.

Branch: `feature/online-linked`. Implementation/review task: `codex://threads/01a07feb-2dc1-77b3-8142-6ea1c8230d50`.

The checkpoint includes helper candidate discovery, AJAX probes, per-parameter request evidence, parent recovery, target matching, and dedupe by canonical query/form/JSON input fingerprint. It also includes the existing auth-context and wrapper changes needed to carry this workspace to another machine. Generated configs and old runtime artifacts are not part of this checkpoint.

## Open P2: optional probe can consume the child budget

File: `phuzz-main/code/fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`, `_run_pending_probe`.

The guard reserves only one second beyond the next replay timeout. Probe preparation, worker stop, artifact collection and convergence share the same deadline but are not covered by that reservation.

Reproduced offline with the existing `OnlineLinkedCoordinatorTests.make_probe_context` fixture:

1. Create candidates `a`, `b`, with only `a` accepted.
2. Wrap `replay_runner`: after `-probe-p1`, set `coordinator.clock.now = 0.0`; after `-probe-p2`, set it to `31.5` (30 seconds replay plus 1.5 seconds orchestration).
3. Call `_run_pending_probe(..., deadline=31.5)`.
4. Actual: `child_created=False`, probe statuses `['accepted', 'failed']`, versions `['v0']`.

The existing `test_fake_clock_reserves_child_budget_after_accepted_probe` covers only the short-budget case where B is not started. It does not cover overhead after B has been admitted.

Preferred minimal follow-up: prioritize child export/replay/Pass 2 once accepted evidence exists, before optional probes. Alternatively enforce a separate deadline for the entire optional probe, not only replay. Do not merely add another arbitrary time constant or bypass replay/Pass 2.

Add the failing fake-clock regression first. Keep failed candidates from starving later candidates, retain the successful subset and per-parameter values, and preserve accurate terminal reasons.

## Verified and unverified boundaries

- Dedupe retries changed inputs in the same parent version; ignores request IDs, metadata and object-key order; preserves JSON types and array order.
- Probe target must match name/source/location with correlated read evidence.
- Child replay and Pass 2 remain required; no claim that helper depth alone proves a parameter.
- Fresh checkpoint checks: coordinator 64, discovery 102, online runner 14, exporter 28, wrapper 23, request auth 2: **233 passed**, no unittest skips/failures. Coordinator timeout 90 seconds; each other suite timeout 60 seconds. `git diff --check` passed. These tests ran in the same workspace snapshot included in this checkpoint.
- Photo Gallery Docker/runtime has NOT been rerun after these edits. Do not label offline tests as runtime PASS.
- Runtime acceptance still requires: raw candidate -> probe request -> correlated read -> accepted parameter -> child config -> replay -> Pass 2 -> child worker evidence, separately for guest/authenticated.

## Resume on another machine

1. Obtain this local checkpoint commit; it has not been pushed automatically.
2. Inspect status and this note. The older implementation plan contains historical unchecked boxes, not a fresh todo list.
3. Fix the open deadline case with a regression, then run coordinator/discovery tests with explicit process timeouts.
4. Run Photo Gallery runtime only when requested; use fresh run IDs and preserve old artifacts.
5. Recheck wrapper options against that checkout before launching runtime. Local generated configs were intentionally excluded.
