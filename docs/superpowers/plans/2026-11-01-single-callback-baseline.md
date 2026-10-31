# Single Callback Baseline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. The user chose Luna execution on a new branch. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let runtime-admitted parameters enter online-linked fuzzing after one callback baseline, without replay-input trials or mandatory Pass 2 parameter revalidation.

**Architecture:** Keep runtime parameter admission and immutable config generation. Remove the trial stage and let v0/child gates check request identity, callback execution, HTTP policy and deadlines once. Export recognizes an explicit baseline policy while retaining strict legacy Pass 2 handling for old records.

**Tech Stack:** Existing Python/unittest coordinator, PowerShell launcher, Docker Compose, instrumented WordPress/PHP. No new dependency.

**Spec:** `docs/superpowers/specs/2026-11-01-single-callback-baseline-design.md` (approved 2026-11-01).

## Global Constraints

- No new mode or CLI flag; preserve discovery admission, callback/request/run/plugin/method/auth correlation and transport/fixed selectors.
- Do not require every known parameter to be observed in a baseline; do not fabricate Pass 2 `accepted/total` results.
- Preserve existing HTTP/redirect policy, parent shutdown checks, immutable config hashes, deadlines and candidate/version limits.
- Keep standalone `verify_pass2_contract()` and its callers in `bridge_cli.py`; remove it only from online-linked readiness decisions.
- Preserve existing working-tree changes, including redirect handling and unrelated checklist rows. Inspect task-only hunks before staging; do not commit pre-existing code changes as part of this task.
- A baseline proves callback reach in the harness, not complete branch execution, complete parameter discovery or a fuzzing/vulnerability PASS.
- Update `/plugin-test-checklist.md` only for a concrete config completed and scoped validation performed; agent tests never set “Người dùng đã test”.
- Execute on `feature/single-callback-baseline`, created from the current checkout with its existing WIP preserved. Use `gpt-6-luna` for implementation, runtime testing and delegated review. Do not create another chat or worktree.
- Because relevant files already contain WIP, review task-only changes against saved working-file snapshots. Leave implementation changes uncommitted unless they can be staged without including pre-existing changes; document this in the report.

## Review Focus

- `converge_iteration()` labels missing historical parameters `REPLAY_FAILED`; Task 1 must distinguish this from actual malformed/mismatched evidence.
- An empty or forged-looking `passed: true` gate must not unlock export; Task 2 requires a recognized policy and complete matching baseline evidence.
- Removing trial selection must not replace observed branch values with `fuzz` in the baseline, or merge fixed selector contexts; Task 1 pins both behaviors.
- Deferred probes and ancestor resume must still revalidate the correct method/auth/variant once; Task 1 and Task 2 preserve pending work and saved time credits.
- A callback can be reached before a 302/403 or sender timeout; Task 1 keeps those cases behind the existing HTTP/redirect/error checks.

## Files and responsibilities

- Modify `phuzz-main/code/fuzzer/online_linked/coordinator.py`: baseline gates, child construction, trial deletion, budget and resume integration.
- Modify `phuzz-main/code/fuzzer/online_linked/export.py`: policy-aware eligibility and evidence summaries.
- Modify `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py` and `test_online_linked_export.py`: existing fixtures plus behavior regressions.
- Inspect/update affected contracts in `test_online_linked_package.py` and `test_online_linked_config_comparison.py` only where their production contract actually changes.
- Delete `phuzz-main/code/fuzzer/online_linked/replay_inputs.py` and its `tests/test_online_linked_replay_inputs.py` once the coordinator caller is removed: repository search found no other production caller. Their proposal algorithm belongs to the removed trial feature, not to runtime CMPLOG mutation.
- Modify `phuzz-main/code/fuzzer/online_linked/README.md`, `phuzz-main/code/docs/guides/online-linked-flow.md`, and `phuzz-main/code/docs/reference/architecture.md`: current behavior, not dated historical evidence.
- Create `phuzz-main/code/docs/reports/2026-11-01-callback-baseline-verification.md` after verification, recording exact commands and real outcomes.

### Task 1: One callback baseline for v0 and child workers

**Interfaces:**
- Reuse `_correlate_runtime_pair(self, version, pair) -> dict[str, Any] | None`, `_request_callback_matches()` and `_request_auth_context()`.
- Rename `_trial_identity_complete(self, request: Mapping[str, Any], zend: Mapping[str, Any], parent: Mapping[str, Any]) -> bool` to `_baseline_identity_complete` and use it for both gates; keep callback execution evidence and current identity requirements. Reject an explicit request/Zend seed variant that disagrees with the expected variant.
- Preserve `_gate_v0(self, version: dict[str, Any], config: Mapping[str, Any], *, deadline: float) -> bool` and `handoff_to_next_worker(self, parent, child, merged_report, replay_path, *, deadline=None) -> bool`.
- Produce gate records with `verification_policy: callback_baseline_v1`, `passed: bool`, existing `runner`/timing, and `baseline_evidence` containing nonempty `request_id`, `run_id`, `plugin_slug`, `callback_id`, `http_method`, `auth_context`, plus `seed_variant_id` (an empty default variant is valid). Fill these only from the successfully correlated baseline; failures do not carry a successful proof.

- [ ] **Step 1: Add failing baseline tests to `OnlineLinkedCoordinatorTests`.**
  - `test_v0_baseline_allows_missing_historical_parameter`: a structurally valid convergence result whose only failure is missing old parameters may reach the worker; independently mismatched evidence or `runtime_block_reason` still fails.
  - `test_child_baseline_sends_once_without_trials_or_pass2`: use `make_probe_context()`, count child baseline sends, make any injected Pass 2 verifier raise if called, and assert one baseline, no trial sends, new policy/evidence and no fabricated Pass 2 result.
  - `test_baseline_identity_mismatches_block_child`: subtests alter callback, request ID, run ID, plugin, method, auth or seed variant in the returned artifacts; assert child worker does not start.
  - Adapt existing branch-value, JSON-type, failed replay, redirect, timeout, parent-stop and deadline tests to assert baseline behavior rather than trial/Pass 2 callbacks.
- [ ] **Step 2: Run the new tests and confirm they fail on the old implementation.**
  From `phuzz-main/code/fuzzer`: `python -B -m unittest tests.test_online_linked_coordinator.OnlineLinkedCoordinatorTests.test_v0_baseline_allows_missing_historical_parameter tests.test_online_linked_coordinator.OnlineLinkedCoordinatorTests.test_child_baseline_sends_once_without_trials_or_pass2 tests.test_online_linked_coordinator.OnlineLinkedCoordinatorTests.test_baseline_identity_mismatches_block_child`.
- [ ] **Step 3: Implement baseline gates and remove the trial path.**
  - Keep discovery convergence/normalization. In v0 readiness, do not reject solely on `missing_parameters` or `REPLAY_FAILED` derived from those missing parameters; still reject structural exceptions, failed identity and runtime block reasons.
  - In `_handle_convergence_result()`, export the proposal, restore original/per-parameter request values using the existing code, write the immutable fuzz config and replay-only baseline config, then invoke the existing child handoff once. Do not require a selected trial to build the child. Keep semantic/context deduplication and parameter admission.
  - In both gates, reuse the correlated request/Zend evidence plus actual callback execution; apply current sender/HTTP/redirect/deadline rules and stamp the policy/evidence on success. Remove mandatory online-linked Pass 2 calls.
  - Rename/reuse identity validation; delete `_verify_replay_input_trials`, `_trial_parameter_verified`, the unused `replay_inputs.py` module/tests, and trial-only helpers/imports/constructor dependencies only after searching all callers. Keep general request restoration and probe recovery helpers still in use. Keep historical state fields readable where needed; do not add a second active trial workflow.
  - Retain context-separated evidence and fixed values. Update old trial-dependent tests to the new intended behavior rather than keeping artificial trial artifacts.
- [ ] **Step 4: Adjust measured time reservations and lifecycle tests.**
  Replace the four trial-plus-replay `3 * self._sender_seconds` reservations with `2 * self._sender_seconds` for one baseline plus one sender-sized handoff/verification allowance, keeping hard/campaign caps. Update progress/probe budget assertions. Preserve saved deadlines/credits on resume rather than recalculating old grants. Add assertions that failed baselines retain independent pending probes, resume/ancestor activation sends one fresh baseline, and late baseline output never unlocks a worker.
- [ ] **Step 5: Run Task 1 tests and review its diff.**
  Run the three new tests plus existing branch-value, HTTP/redirect, parent-stop, fake-clock budget and resume tests. Expected: all selected tests pass with the new gate, standalone parameter admission behavior unchanged, and no baseline trial send. Do not stage pre-existing coordinator/test hunks.

### Task 2: Export and resume understand the baseline policy

**Interfaces:**
- Consume the `callback_baseline_v1` gate/evidence from Task 1.
- Preserve `_verified_base(version: dict) -> tuple[bytes, dict]`, `_verified_config(version: dict) -> bytes`, export filenames/deduplication and immutable bytes.
- New-policy gates require `passed is True` and a complete baseline evidence record consistent with the version/config/runner context. No policy means legacy handling: `accepted == total > 0` and the existing gate checks. An explicit unknown policy is rejected.

- [ ] **Step 1: Add failing tests to `OnlineLinkedExportTests`.**
  - `test_baseline_policy_exports_without_pass2`: v0 and child records with complete successful new gates export, retaining exact config bytes.
  - `test_baseline_policy_rejects_missing_or_mismatched_evidence`: missing proof fields, false gate, callback/method/auth/request-run inconsistency or unknown policy do not export.
  - `test_legacy_pass2_gate_remains_strict`: legacy `(0,0)` and `(1,2)` fail; valid legacy `(1,1)` retains current behavior.
  - `test_baseline_resume_preserves_existing_exports_and_drafts`: a valid new version can export alongside historical verified bytes; replay-only/probe configs and changed hashes remain excluded; summary distinguishes baseline evidence from standalone Pass 2.
- [ ] **Step 2: Run those tests to confirm the new-policy positive cases fail before export changes.**
  From `phuzz-main/code/fuzzer`: `python -B -m unittest tests.test_online_linked_export`.
- [ ] **Step 3: Update `_verified_base()` and evidence summaries in `export.py`.**
  Branch on the explicit policy, validate the matching evidence contract, retain hash/type/path/probe checks and legacy gating. Include the policy and baseline evidence in summary diagnostics; do not label new records Pass 2 verified. Runtime-observed and baseline-admitted parameter summaries must not claim every field was read together.
- [ ] **Step 4: Complete coordinator resume integration and run regressions.**
  Preserve existing resume integrity checks and legacy exports. Revalidation stamps only fresh baseline proof, not a copied trial proof; unknown/invalid policy cannot bypass a gate. Run `python -B -m unittest tests.test_online_linked_export tests.test_online_linked_config_comparison tests.test_zend_pass2_identity` and the coordinator's pending/ancestor resume regressions. Expected: new and legacy export tests pass; standalone Pass 2 identity tests still pass.
- [ ] **Step 5: Review Task 2 changes and remove obsolete test assumptions.**
  Search for `pass2_verification`, `replay_input_trials` and `TRIAL_INPUT_SET_NOT_VERIFIED`; keep real legacy/history/standalone uses, remove assertions claiming the deleted active path is required. Do not create a new flag or generic policy framework.

### Task 3: Verify a bounded campaign and update current documentation

**Interfaces:**
- Consume Task 1/2 coordinator and exporter behavior through the existing `phuzz.ps1` launcher.
- Produce a verification report with test commands/results, campaign artifact paths, baseline send count, worker startup, final exports and explicit limits.

- [ ] **Step 1: Run the scoped Python regression suites.**
  From `phuzz-main/code/fuzzer`: `python -B -m unittest tests.test_online_linked_coordinator tests.test_online_linked_export tests.test_online_linked_config_comparison tests.test_probe_sender tests.test_redirect_gate tests.test_zend_pass2_identity`.
  Expected: changed behavior and unaffected sender/admission/legacy contracts pass. Local PHP was absent during the earlier investigation: if PHP producer tests still fail for that reason, identify the exact environment failures, report them separately, and verify producer/runtime evidence through the Docker campaign. Do not claim the full suite passed or rewrite a test to hide the missing dependency.
- [ ] **Step 2: Check Docker availability and existing work before the campaign.**
  From `phuzz-main/code`: `docker compose ps` and `docker info`. Preserve existing campaign artifacts. If a different campaign is actively using the same services, report that conflict instead of stopping unrelated work. Package the existing `fuzzer/tests/fixtures/hookphuzz-online-discovery-fixture` into `_plugins/hookphuzz-online-discovery-fixture.zip` only if its archive is absent; never overwrite an existing archive silently.
- [ ] **Step 3: Run one fresh fixture campaign.**
  From `phuzz-main/code`: `pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug hookphuzz-online-discovery-fixture -OnlineTimeoutSeconds 30 -OnlineMaxVersions 2 -OnlineMaxCandidates 4 -OnlineCampaignTimeoutSeconds 120`.
  Inspect the new batch/candidate state and request artifacts: config proposals have no trial sends, each handoff has one correctly correlated baseline, eligible workers actually start, and final exports carry the new policy without fake Pass 2 results. Record the real terminal statuses, errors and timings; exit 0/config generation alone is not a fuzzing PASS.
  Then run the existing real plugin `custom-fonts` in a separate fresh bounded campaign: `pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug custom-fonts -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -OnlineMaxCandidates 32 -OnlineCampaignTimeoutSeconds 180`. Preserve previous plugin results. Inspect callback reach, runtime parameters, baseline evidence, worker execution and exported config separately; report incomplete discovery or startup failures honestly. Do not launch an all-plugin batch.
- [ ] **Step 4: Update documentation and the verification report.**
  Document one baseline, runtime param admission, legacy-policy handling, budget reservations and the loss of pre-fuzz CMPLOG trial adjustments. Preserve dated historical reports as history. If the fixture task completes a concrete config and scoped checks, update only that config's root checklist row with exact path/date/evidence and “Pass 2 not run under callback_baseline_v1”; otherwise no completion row.
- [ ] **Step 5: Final verification and review.**
  Run `git diff --check` on task-owned files and review every changed caller, gate and exporter path against the spec. Ensure standalone `verify_pass2_contract()` still has its CLI/tests and no online-linked readiness caller remains. Save only task-owned changes; never stage or commit unrelated WIP. Report tests, campaign outcome, untouched environmental failures and any unverified limits before claiming completion.

## Execution handoff

Approved execution: the user requested a new branch and Luna to run real tests. Branch `feature/single-callback-baseline` is created. Dispatch Luna implementers sequentially for Tasks 1 and 2, then Luna for Task 3 (including the two real Docker campaigns); delegated reviews also use Luna. Preserve task-only snapshots and progress in the plan's ignored SDD workspace. These user-requested execution changes do not require another approval round.
