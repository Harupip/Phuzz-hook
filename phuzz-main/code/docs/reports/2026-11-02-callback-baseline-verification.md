# Callback baseline migration — 2026-11-02

Scope: replace online-linked replay-input trials and mandatory Pass 2 with one callback baseline. Remove the unused standalone verifier/CLI and trial proposal module. Branch: `feature/single-callback-baseline`; base: `278258288dbb3cb7cd4881fc9335ac153c7f4ab1`. User requested a local commit after verification; no push is authorized. User stopped subagents; implementation after the initial failing tests and final review were performed inline.

## Result

Code migration and scoped offline verification are complete. Fresh end-to-end campaign verification is **PARTIAL** because another Astra Sites campaign began using the shared WordPress services during the fixture run. No fuzzing or vulnerability PASS is claimed. No plugin config completed scoped validation in this task; plugin checklists were not changed.

- v0 and child gates record `verification_policy: callback_baseline_v1` and successful `baseline_evidence` containing request ID, run ID, plugin, callback ID, HTTP method, auth context and seed variant. The baseline retains observed branch input values; the immutable fuzz config retains existing placeholder semantics.
- Discovery admission remains independent and unchanged. A baseline does not require every admitted parameter to be read again. Correlation, callback execution, method/auth/variant, HTTP/error, parent-stop and deadline checks still gate worker start.
- Child creation has no trial sends and no Pass 2 call or synthetic accepted/total result. A successful baseline precedes stopping the parent and starting the child. Existing pending/ancestor resume lifecycle and immutable hashes remain covered.
- Budget reserve is two measured sender units (baseline plus handoff allowance), replacing three units for trial/replay/handoff. Saved time credits are retained on resume.
- Export checks the new policy and matching baseline runner/artifact/config evidence. Unknown or incomplete policy proof is rejected. Historical records without the new policy still require their saved Pass 2 counts; the historical verifier is not executed.
- Deleted `online_linked/replay_inputs.py`, `tests/test_online_linked_replay_inputs.py`, `tests/test_zend_pass2_identity.py`, `verify_pass2_contract()`, its private helper cluster, CLI operation `verify-pass2` and its two arguments. Mixed discovery tests retain their discovery assertions. Runtime CMPLOG mutation remains in the fuzzer.
- Config deduplication/order and the Cookie Notice v3/v4 issue were outside this change.

## Test evidence

All commands ran from the repository root through the bounded local harness `.superpowers/sdd/2026-11-01-single-callback-baseline/check.py`, which sets writable temporary directories, disables bytecode and bounds each subprocess to 180 seconds. The equivalent unittest module arguments appear below. HTTP-localhost/PHP-via-Docker tests ran outside the filesystem/network sandbox after scoped escalation.

1. Coordinator new-behavior RED: `task1-red.log`, three tests failed on the old implementation (Pass 2 still called, missing historical reads blocked v0, identity mismatch not rejected).
2. Export RED: `export-red.log`, baseline policy was rejected and unknown policy could use a legacy gate. `export-context-red.log` showed actual auth/variant mismatch was not rejected. These cases now pass.
3. Coordinator scoped GREEN: `python -B -m unittest tests.test_online_linked_coordinator` — 153 tests, 0 failures, 0 skips; `coord-final.log`, 89.113 seconds.
4. Related regression GREEN: `tests.test_online_linked_package tests.test_online_linked_config_comparison tests.test_probe_sender tests.test_zend_discovery tests.test_online_linked_export` — 172 tests, 170 passed, 2 skipped; `related-current.log`, 33.047 seconds. Later exporter hardening is included in the combined run below.
5. Final combined run: `python -B -m unittest -v tests.test_online_linked_coordinator tests.test_online_linked_export tests.test_online_linked_package tests.test_online_linked_config_comparison tests.test_probe_sender tests.test_zend_discovery` — **326 tests**, 167.114 seconds. Initial result: 322 passed, 1 failure, 1 error, 2 skips. The error was Windows `WinError 5` during an atomic state-file replacement. The comparison test failed under the short NTFS temporary path. Both were rerun without changing production code, with the normal workspace temporary path: **2/2 passed**, `failed-rerun.log`. Thus 324 distinct tests passed across the final run and targeted rerun; this is not described as one wholly green combined invocation.
6. Skips: `test_final_symlink_outside_run_is_rejected_when_supported` lacked Windows symlink privilege (`WinError 1314`); `test_fresh_docker_fixture_records_direct_nested_and_local_reads` lacked the optional `hookphuzz-zend` image. Neither was counted as passed.
7. Source AST parsing, removal/caller checks and `git diff --check` passed. Final review was self-review, per the user's no-subagent instruction; no independent reviewer or full repository suite was run.

Logs are retained in the ignored plan workspace; existing campaign artifacts and unrelated untracked files were preserved.

## Runtime attempt and limit

Both requested plugin ZIPs existed and passed ZIP integrity/root/main-file checks: `hookphuzz-online-discovery-fixture/hookphuzz-online-discovery-fixture.php` and `custom-fonts/custom-fonts.php`. The existing fixture ZIP is older than the fixture source and was preserved rather than overwritten.

Attempted from `phuzz-main/code`:

```powershell
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug hookphuzz-online-discovery-fixture -OnlineTimeoutSeconds 30 -OnlineMaxVersions 2 -OnlineMaxCandidates 4 -OnlineCampaignTimeoutSeconds 120
```

The wrapper built/started web and remained at WordPress HTTP readiness (HTTP 500). Initial Docker inventory had no active fuzz campaign. During readiness a separate container appeared: `hookphuzz-generated-1-online-linked-astra-sites-2109b3908a3378e0-versions-v0-replay-v0-replay`, with Astra Sites AJAX traffic in web logs. Only this task's fixture PowerShell process (verified command line, PID 19912) was stopped; the Astra Sites worker and shared services were left running. Wrapper stopped after 192.640 seconds, exit 4294967295. Evidence: `hookphuzz-online-discovery-fixture-run.log` and its JSON metadata in the plan workspace.

The custom-fonts campaign was **not started**, to avoid resetting shared runtime evidence while the Astra Sites campaign was active. There is no fresh fixture/custom-fonts baseline-to-worker-to-final-export runtime proof from this task. Retry these two bounded campaigns when the shared services are free; do not infer throughput or branch coverage improvements from the offline checks.

## Decisions

- User's 2026-11-02 cleanup request supersedes the old plan's instruction to retain standalone Pass 2 CLI/verifier/tests. Historical artifact eligibility remains strict.
- Work stayed in the existing branch/checkout; local commit now requested; no push or unrelated deduplication change.
- Git Bash was unavailable due MSYS named-object permissions, so native Python handled local plan scratch files.
- User stopped subagents; remaining work and review were inline.
- Shared-service conflict prevented runtime completion; no unrelated campaign was stopped and no checklist completion was recorded.

## Retest on another machine

Use a fresh checkout of this commit and a fresh campaign/run ID. Existing running Python workers do not reload the new coordinator. Do not run concurrent campaigns against the same WordPress/database/shared artifact volumes. Do not resume an unrelated machine's checkpoint with stale absolute config/artifact paths; verify resume separately using a checkpoint created locally.

Prerequisites: Python and repository dependencies, PowerShell 7 (`pwsh`), Docker Compose, instrumented web image build support, `wp-cli.phar` and plugin ZIPs. ZIPs and historical runtime outputs are local artifacts, not supplied by this commit. Check `PLUGIN_ZIP_DIR` in `phuzz-main/code/phuzz.env`; relative paths resolve from `phuzz-main/code`, with `_plugins/<slug>.zip` fallback. Keep the real plugin slug and ZIP root/main-file consistent.

Run offline checks first from `phuzz-main/code/fuzzer`:

```powershell
python -B -m unittest tests.test_online_linked_coordinator tests.test_online_linked_export tests.test_online_linked_package tests.test_online_linked_config_comparison tests.test_probe_sender tests.test_zend_discovery
```

Apply a process timeout (for example 300 seconds) in your test runner. On Windows use a writable temporary folder; record `WinError 5`, path lengths and whether an 8.3 alias is involved before interpreting a filesystem failure. Two environment-dependent skips observed here were missing symlink privilege and an absent optional `hookphuzz-zend` image; install/build prerequisites if you need those tests. Preserve any failures rather than counting skips as passes.

When shared WordPress is free, run serially from `phuzz-main/code` (bound the wrapper to 480 seconds per invocation):

```powershell
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug hookphuzz-online-discovery-fixture -OnlineTimeoutSeconds 30 -OnlineMaxVersions 2 -OnlineMaxCandidates 4 -OnlineCampaignTimeoutSeconds 120
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug custom-fonts -OnlineTimeoutSeconds 60 -OnlineMaxVersions 3 -OnlineMaxCandidates 32 -OnlineCampaignTimeoutSeconds 180
```

Inspect the new `batch-state.json`, candidate `state.json`/events and direct final exports:

- New successful v0/child gates have `verification_policy=callback_baseline_v1` and matching `baseline_evidence`; no new `pass2_verification` counters or `replay_input_trials` are produced. Historical state may still contain those old fields.
- Each child handoff sends one baseline, distinct from discovery/probe sends. Probe sends and later resume/reactivation baselines are still expected; do not count them as duplicate child trials.
- Verify callback execution, request/run/plugin/method/auth/variant identity, 2xx/transport agreement, parent stopped before child start, and actual worker start. HTTP 200 alone proves none of the full flow.
- Exported bytes/hash match the immutable source config; summary records baseline policy/proof. Legacy exports without a policy still require saved Pass 2 evidence. The removed `verify-pass2` CLI is intentionally unavailable.
- Baseline no longer readmits every parameter or adjusts pre-fuzz inputs from comparison hints. Runtime admission and worker CMPLOG remain; baseline success does not prove all parameters were used together or every branch executed.
- Retain terminal reasons, pending candidates/probes, baseline sends, worker states and export paths. `PARTIAL`/budget expiry is not a fuzzing PASS. Update the applicable plugin checklist only when a concrete config is completed with scoped evidence; do not mark user-tested until the user reports a result.

Known independent issue: [Cookie Notice v3/v4 duplication and today's investigation](2026-11-02-cookie-notice-version-investigation.md). This commit deliberately does not fix version deduplication; a duplicated version can still cost a baseline and worker handoff.
