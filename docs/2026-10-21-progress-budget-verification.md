# Progress budget implementation verification — 2026-10-21

Status: WIP / PARTIAL; user requested a local checkpoint commit. Historical acceptance evidence: 13 critical tests passed; the earlier full discovery had 676 tests, 5 baseline failures, 1 baseline error, and 3 skips. Latest pre-commit full discovery: 676 tests, 7 failures, 5 errors, 3 skips; targeted rerun: 8 tests, 7 passed, 1 WinError 5 error. The suite is not green. The original 08:49 Docker campaign below predates the correction; a separate post-correction local run is documented at the end. It produced 16 individually gated final configs and 2 partial exports, while the overall campaign remained PARTIAL. No fuzzing PASS or confirmed vulnerability is claimed.

## Implementation and test evidence

The implementation now grants a rolling `W + 3*S` candidate window on unique verified runtime progress, leaves the candidate hard cap unset unless explicitly configured, drains pending probes in both live and resume paths, hands off accepted inputs early, recovers untried probes after an input-trial failure, and preserves idle reasons so the real exporter retains partial configurations. The checkpoint policy is `progress_idle_v1`. Existing final verification gates remain in place.

- Focused lifecycle suite: 6 tests passed, including run → publish A → probe B without resume, failed input trial recovery, real coordinator → exporter idle partial, stale queue snapshot, and explicit-cap offline resume. Negative controls failed when live draining or failed-trial queue recovery were removed.
- Scoped regression: 200 tests, 1 skipped, 0 failures/errors. Log: `.superpowers/sdd/2026-10-20-progress-budget/full-regression.log`.
- Full discovery: 674 tests, 5 failures, 1 error, 3 skipped. Log: `.superpowers/sdd/2026-10-20-progress-budget/full-discovery.log`. Four subtest failures are `test_final_export_reads_deep_state_and_preserves_bytes` at path lengths 259, 286, 350, and 512; the missing `FileExistsError` behavior reproduced with the saved baseline coordinator/export snapshots. The error in `test_coordinator_mirror_and_registry_read_with_deep_root` is a missing deep-path `suggested.json`, also reproduced against the baseline snapshot. The remaining failure, `test_wordpress_bootstrap_installs_country_state_city_dependency_before_target`, expects a literal install command absent from the current checkout, whose `init.sh` uses `resolve_plugin_zip`; no unrelated WIP was changed.
- PowerShell parse and `git diff --check` passed before the live campaign.

## Ad Inserter live campaign

Run ID: `ad-inserter-20261021T084908Z`. Start/end: 2026-10-21 08:49:08.004 +07 to 09:00:48.382 +07 (11m40s). Settings remained at the current initial values: 30 seconds, 9 versions, 32 candidates, 3600-second campaign; hard campaign limits remained 128 candidates and 86400 seconds. The nested WordPress runner used `-NoFollowLogs -NoComparePrompt`; outer timeout was 1800 seconds. Wrapper result: exit 0, `timed_out=false`. Batch result: `PARTIAL`, terminal reason `NO_NEW_PROGRESS`, 29 candidates total: 4 actionable AJAX candidates and 25 `NOT_VERIFIED/V0_PREREQUISITE_GATE_FAILED` candidates.

| Hook | Elapsed | Unique progress credits | Probes | Replay-input trials | Pending probes at stop | Direct exports |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `wp_ajax_nopriv_ai_ajax` | 177.563s | 6 | 7 | 5 | 15 | 5 final / 1 partial |
| `wp_ajax_ai_ajax` | 173.344s | 6 | 7 | 5 | 15 | 5 final / 1 partial |
| `wp_ajax_ai_ajax_backend` | 86.953s | 0 | 1 | 0 | 42 | 0 final / 1 partial |
| `wp_ajax_dst_ajax_ad-inserter` | 131.219s | 5 | 6 | 6 | 7 | 5 final / 1 partial |

Three actionable candidates ran longer than 120 seconds while receiving fresh progress credits: unauthenticated `ai_ajax` (177.563s, 6 credits), authenticated `ai_ajax` (173.344s, 6), and DST AJAX (131.219s, 5). All four stopped as `PARTIAL/NO_NEW_PROGRESS`; `hard_remaining_seconds` was null. The backend spent 86.953 seconds with no verified progress, one probe attempt, 42 queued probes, 25 pending parameters, and zero replay-input trials. Its trial gate remains unverified and is an explicit live acceptance gap.

## Direct config audit

There are 15 direct final JSON files and 4 partial JSON files. Every final file is byte-identical to its source config; its canonical sorted-JSON SHA-256 matches `final-config-summary.json`. All 15 finals passed correlated replay and Pass 2 accepted=total=1/1. These are individual branch configs; they do not represent one verified union config. Each of the 4 partial files has a canonical hash matching the summary, `config_type=partial`, `fuzzing_ready=false`, and `combined_request_verified=false`.

| Final config path | Hook | Method and parameter/fuzz selector | Validation |
| --- | --- | --- | --- |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.v1.json` | `wp_ajax_nopriv_ai_ajax` | `v1` POST; body=adsense-ad-units (fuzz=adsense\-ad\-units) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.v2.json` | `wp_ajax_nopriv_ai_ajax` | `v2` GET; query=ai-get-settings (fuzz=ai\-get\-settings) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.v3.json` | `wp_ajax_nopriv_ai_ajax` | `v3` GET; query=block (fuzz=block) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.v4.json` | `wp_ajax_nopriv_ai_ajax` | `v4` GET; query=check-page (fuzz=check\-page) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.json` | `wp_ajax_nopriv_ai_ajax` | `v5` GET; query=remote-ads-txt (fuzz=remote\-ads\-txt) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.v1.json` | `wp_ajax_ai_ajax` | `v1` POST; body=adsense-ad-units (fuzz=adsense\-ad\-units) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.v2.json` | `wp_ajax_ai_ajax` | `v2` GET; query=ai-get-settings (fuzz=ai\-get\-settings) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.v3.json` | `wp_ajax_ai_ajax` | `v3` GET; query=block (fuzz=block) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.v4.json` | `wp_ajax_ai_ajax` | `v4` GET; query=check-page (fuzz=check\-page) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.json` | `wp_ajax_ai_ajax` | `v5` GET; query=remote-ads-txt (fuzz=remote\-ads\-txt) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.v1.json` | `wp_ajax_dst_ajax_ad-inserter` | `v1` POST; body=slug (fuzz=slug) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.v3.json` | `wp_ajax_dst_ajax_ad-inserter` | `v3` POST; body=slug,notice-check (fuzz=slug,notice\-check) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.v4.json` | `wp_ajax_dst_ajax_ad-inserter` | `v4` POST; body=slug,test (fuzz=slug,test) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.v5.json` | `wp_ajax_dst_ajax_ad-inserter` | `v5` POST; body=slug,values (fuzz=slug,values) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/final-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.json` | `wp_ajax_dst_ajax_ad-inserter` | `v6` POST; body=slug,notice-check,click (fuzz=slug,click) | source bytes identical; canonical hash matches summary; replay passed and Pass 2 1/1 |

| Partial config path | Hook | Discovery retained | Gate |
| --- | --- | --- | --- |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/partial-configs/fuzzer-config.wp_ajax_nopriv_ai_ajax.6aae0fe3106a3a85.13da683488b9d5ab.partial.json` | `wp_ajax_nopriv_ai_ajax` | 5 verified; 1 pending: ads-txt | `NO_NEW_PROGRESS`; `fuzzing_ready=false`; combined request not verified |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/partial-configs/fuzzer-config.wp_ajax_ai_ajax.c1f808d3f556e5bf.91b9a5055141f680.partial.json` | `wp_ajax_ai_ajax` | 5 verified; 1 pending: ads-txt | `NO_NEW_PROGRESS`; `fuzzing_ready=false`; combined request not verified |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/partial-configs/fuzzer-config.wp_ajax_ai_ajax_backend.19fbed7db7bad714.244ff012a406bf16.partial.json` | `wp_ajax_ai_ajax_backend` | 0 verified; 25 pending: ads-txt, adsense-authorization-code, adsense-client-id, adsense-code, adsense-list, check-page, css, edit, generate-code, generate-rotation-code, image, import-code, import-rotation-code, js, list, list-options, notice, notice-check, placeholder, preview, rating, search, settings, update, virtual | `NO_NEW_PROGRESS`; `fuzzing_ready=false`; combined request not verified |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/partial-configs/fuzzer-config.wp_ajax_dst_ajax_ad-inserter.a35146bbf4308840.8b6ac548ebd5d9b8.partial.json` | `wp_ajax_dst_ajax_ad-inserter` | 5 verified; 1 pending: details | `NO_NEW_PROGRESS`; `fuzzing_ready=false`; combined request not verified |

Comparison run `ad-inserter-20261019T153555Z` had 6 final and 3 partial configs. This run has 15 final and 4 partial configs. The increase records newly verified individual branches; it does not mean the campaign completed.

## Worker findings and runtime limits

The retained Docker volume `code_shared-tmpfs:/fuzzer-findings` contained four run-specific JSON reports, copied byte-for-byte to `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/finding-reports`:

| Preserved worker report | Worker run | Reported signal | Classification |
| --- | --- | --- | --- |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/finding-reports/ad-inserter-20261021T084908Z-candidate-001-wp_ajax_nopriv_ai_ajax-v1.json` | `ad-inserter-20261021T084908Z-candidate-001-wp_ajax_nopriv_ai_ajax-v1` | `PathTraversal`; `POST` `body_params.adsense-ad-units` payload `uzz`; SHA-256 `E2C89FC9454490320D39BC94A9B0C2CD7A3622F1A1916E588507FB026AB8EE18` | worker report only; not independently reproduced and detector not validated |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/finding-reports/ad-inserter-20261021T084908Z-candidate-001-wp_ajax_nopriv_ai_ajax-v5.json` | `ad-inserter-20261021T084908Z-candidate-001-wp_ajax_nopriv_ai_ajax-v5` | `PathTraversal`; `GET` `query_params.remote-ads-txt` payload `uzz`; SHA-256 `6EE06246E55896D6FA601F537366FF161BD8B2F72CF9FF50D3A25463C0E26991` | worker report only; not independently reproduced and detector not validated |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/finding-reports/ad-inserter-20261021T084908Z-candidate-002-wp_ajax_ai_ajax-v4.json` | `ad-inserter-20261021T084908Z-candidate-002-wp_ajax_ai_ajax-v4` | `PathTraversal`; `GET` `query_params.check-page` payload `uzz`; SHA-256 `191DCC86DB97E9C7940C57579E2614F25A1422F6759C362633ECB0C484C255EA` | worker report only; not independently reproduced and detector not validated |
| `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/finding-reports/ad-inserter-20261021T084908Z.json` | `ad-inserter-20261021T084908Z` | `PathTraversal`; `GET` `query_params.hookphuzz_probe` payload `uzz`; SHA-256 `8C5AA54CCC1E79CA804E6B99251758989B6DBF7149758895843F86171B116936` | worker report only; not independently reproduced and detector not validated |

The worker logs also contain PHP/WordPress errors involving `is_block_editor()` on null and null `admin-bar.php` properties during mutation traffic. These are retained as runtime diagnostics, not treated as proof of a plugin vulnerability. The run-owned fuzzer container exited 137 and is not active; shared `code-web-1` and `code-db-1` services remain running. Pre-existing GitHub MCP containers were left untouched.

## Logs, checks, and remaining proof

Runner stdout, stderr, and JSON metadata are preserved in `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z` and are byte-identical to their original files under `C:\Users\nghia.cd_extremevn\Desktop\.superpowers\sdd\2026-10-20-progress-budget\live\ad-inserter-20261021T084908Z`. That original directory is outside the repo because the wrapper path was resolved one parent too high; those originals were retained unchanged. Their hashes and the four finding-record hashes are listed in `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T084908Z/runner-copy-audit.json`.

The two checklists now contain dated run evidence, including one root checklist row per direct config path and an appended 2026-10-21 entry in the existing Ad Inserter experiment row. User-tested fields remain `Chưa`. A PathTraversal report remains an unconfirmed worker signal pending independent reproduction and detector validation; the backend still needs a replay-input trial. No source/plugin fix or unrelated WIP change was made, and no commit or push was created.

## Parent review before checkpoint correction (superseded)

After Luna 6 xhigh completed, parent reviewed the baseline-relative coordinator/export diff and lifecycle tests, reran 6 critical lifecycle/budget tests (6 passed), parsed PowerShell, and reran `git diff --check`. No new Critical/Important production finding remained. The broad recoverability of existing pending-runtime candidates predates this diff; the new pending-probe exception is restricted to input-set failure.

Parent independently checked all 15 final source/export bytes, canonical hashes and replay/Pass 2 gates, all 4 partial markers/hashes, all 19 unique checklist paths with user-tested `Chưa`, 3 runner copies, and 4 preserved finding hashes. Live events show child replay PASS followed by fresh accepted probes in each of the nopriv, authenticated and DST candidates. Progress-history deadlines reached 175.017s, 170.688s and 129.388s from their starts, independently of cleanup elapsed time; keys were unique and credit timestamps preceded prior deadlines. Backend had no renewal and no trial, so its 86.953s elapsed is not evidence of progress-based extension.

Final Docker listing confirms `code-fuzzer-wordpress-plugin-1` exited 137; no active run-owned fuzzer worker. Shared web/database and unrelated containers remain untouched. Pre-existing `phuzz.env` and `init.sh` diffs match the saved baseline exactly. Full-suite baseline failures and backend live gap remain disclosed; no vulnerability reproduction or unrelated repair was performed. No commit/push.

## Checkpoint correction within the original plan

The earlier completion/review assessment missed a real defect. Backend evidence shows an accepted `ads-txt` probe, 0.272s HTTP, 3.078s total probe time, and request/Zend evidence saved around 22.8s into a 30s candidate window. Its 42 queued contexts (24 distinct parameter identities) duplicated enough evidence to produce a 16,851,263-byte state. Code queued and checkpointed new guards before granting verified progress, then emitted each deferred event with another full checkpoint. Credit was attempted after expiry; the final event was `INSUFFICIENT_VERIFICATION_BUDGET`, with no trial.

The correction moves credit to immediately after the existing probe admission checks, before the accepted-event checkpoint. It removes the redundant later credit/admission block, checkpoints queue additions/deferred events by batch, and still appends every individual JSONL event. The existing queue, evidence and checkpoint schema are retained. Local probe allowance refresh also works at an explicit hard cap without extending that cap. Old batch-policy checkpoints now receive the original plan's explicit create-new-run guidance, matching candidate checkpoints.

A regression submits a verified probe near the deadline, discovers 100 guards and charges each checkpoint against a fake clock. It verifies early credit, one semantic progress record, real input trial and replay, all 100 pending probes and all 100 deferred events on disk, and bounded pre-trial checkpoint count. Removing early credit in an in-memory negative control makes it fail. Guard/cap and old-batch-policy tests were also observed RED then GREEN.

This is a correction to the original budget/queue contract, not an expanded feature. Formula, explicit/global caps, correlation, replay, Pass 2, mutation and plugin behavior are unchanged. Original `phuzz.env` and `init.sh` WIP diffs match the saved baseline. No config was produced in this correction, so no completion checklist row was added. Historical configs, artifacts and checklists remain intact. Docker local runtime after this correction remains unverified; no campaign, commit or push was performed in this correction.

### Final correction checks

- `checkpoint-correction-acceptance.log`: 13 tests, 13 passed, 0 failures/errors/skips, 9.407s. Covers the 100-guard real handler regression, slow error/guard refresh including explicit cap, rolling/deduplicated budget, same-run publication/recovery, idle export, capped/uncapped offline resume, batch policy rejection and fail-closed bad artifacts.
- `checkpoint-correction-complete-suite.log`: full discovery, 676 tests, 5 failures, 1 error, 3 skips, 170.880s. The remaining findings are the unchanged stale literal `init.sh` contract and the four long-path export subcases plus missing deep `suggested.json` already reproduced against the saved baseline. Budget/queue/resume did not introduce a failure in this final run. Earlier correction logs retain the observed Windows atomic-replace error, non-reproduced isolated failures and the old-policy assertion subsequently corrected; those logs are not represented as passing runs.
- `checkpoint-correction-negative-control.log`: disabling early verified credit in memory makes the 100-guard test fail; production source was not changed for the negative control.
- Independent review compared only coordinator/tests to the before-correction snapshot: no introduced Important/Critical finding. It checked admission-before-credit, queue flush on normal/error exits, individual JSONL persistence, local cap handling and old-policy refusal.
- AST scope audit: 4 existing production symbols changed (`_run_pending_probe`, `_run_pending_probe_once`, `_record_event`, `run_online_linked`); no function/class added or removed. Budget formula/caps, admission checks, replay/Pass 2 and final export gates are unchanged. PowerShell and Python syntax checks and `git diff --check` passed.
- No additional Docker campaign, plugin/config output, completion checklist row, commit or push. Runtime confirmation of the corrected backend is explicitly pending under the latest user instruction.
## Post-correction local Docker campaign

Run ID: ad-inserter-20261021T113838Z. Command used the existing settings: 30 seconds per candidate, 9 versions, 32 candidates, 3600-second initial campaign; hard campaign limits were 128 candidates and 86400 seconds. The runner started at 2026-10-21 11:38:37.930 +07 (04:38:37.930 UTC), ended at 11:48:32.389 +07 (04:48:32.389 UTC), and took **594.456 seconds (9m54.456s)** by monotonic stopwatch. Wrapper exited 0 with timed_out=false; batch status was PARTIAL, with 29 candidates (27 NOT_VERIFIED, 2 PARTIAL).

| Hook | Direct final configs | Direct partial configs |
| --- | ---: | ---: |
| wp_ajax_nopriv_ai_ajax | 5 | 1 |
| wp_ajax_ai_ajax | 5 | 1 |
| wp_ajax_ai_ajax_backend | 1 | 0 |
| wp_ajax_dst_ajax_ad-inserter | 5 | 0 |
| **Total** | **16** | **2** |

All 16 direct final exports were byte-identical to their source configs; canonical SHA-256 matched the run summary; each had fuzzing_ready=true, correlated replay passed, and Pass 2 accepted=total. The 2 direct partials had matching canonical hashes, config_type=partial, fuzzing_ready=false, and combined_request_verified=false; they were not replayed or Pass 2 validated. These are configuration/replay gates, not fuzzing PASS.

Backend: the ads-txt probe and replay-input trial were accepted, child v1 replay passed and Pass 2 was 1/1. The candidate remained NOT_VERIFIED/RESUME_PARENT_WORKER_START_FAILED: parent restart was skipped after BUDGET_EXPIRED, with 42 probes still pending. This records a budget-expired resume skip, not a Docker daemon failure.

DST: an earlier live snapshot recorded PARENT_CHECK_TIMEOUT (130.235s, 7 versions, 6 trials, 5 credits), while the final batch and candidate state record ONLINE_LINKED_COORDINATOR_ERROR: [WinError 5] Access is denied while replacing campaigns/ec5047d89b8bb822/state.json.tmp with state.json. Preserve both observations; this run did not resolve their discrepancy.

Run logs and metadata: .superpowers/sdd/2026-10-20-progress-budget/ad-inserter-local-20261021T113837Z.stdout.log, .stderr.log, and .metadata.json. Run artifacts and summary: phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T113838Z/. After cleanup, no run-specific online-linked worker remained; code-fuzzer-wordpress-plugin-1 was Exited (137), while shared code-web-1 and code-db-1 remained up. Pre-existing unrelated containers were left untouched. No source, plugin, config, or environment files were changed; no commit or push was made.
## Experiment coverage comparison for the post-correction run

Compared all 3 experiment configs against all 16 direct final configs, including methods, target, query/body/header/cookie fields, values, fixed fields and effective regex fuzz selectors. Full per-config records and semantic differences are in `phuzz-main/code/fuzzer/output/online-linked/ad-inserter-20261021T113838Z/experiment-comparison.json`; readable audit is adjacent `experiment-comparison.md`. The 2 partials are excluded from verified coverage.

| Hook | Final | Experiment | Reference fuzz fields covered | Missing reference fuzz fields | Extra fuzz fields |
| --- | ---: | ---: | ---: | ---: | ---: |
| wp_ajax_nopriv_ai_ajax | 5 | 1 | 1/4 | 3 | 4 |
| wp_ajax_ai_ajax | 5 | 1 | 1/4 | 3 | 4 |
| wp_ajax_ai_ajax_backend | 1 | 1 | 0/51 | 51 | 1 |
| wp_ajax_dst_ajax_ad-inserter | 5 | 0 | no reference | 0 | 5 |

Both ai_ajax identities cover GET block but lack query cookie_check, cookie_check_url and virtual from the reference. Their extra branches are POST adsense-ad-units and GET ai-get-settings, check-page, remote-ads-txt. Backend only covers GET ads-txt; the experiment expects POST with 35 body and 16 query fuzz fields, all absent from the exported backend config. DST has 5 final configs absent from the reference corpus. No reference hook is missing outright, but none of the 3 experiment request configurations is fully covered. Per-hook union coverage is not a combined-request verification. This comparison does not establish every reference field is a valid/reachable runtime input. No code/config changes or campaign rerun were performed for this audit.

## DST details guard and trial verification

Saved attempt-005/t0 sends POST body keys slug and values only, HTTP 200. Zend has zero dropped events and records isset(slug), isset(values), isset(details), but no read of values/details in the branch body. Expected parameters are only slug and values; saved missing_parameters is empty and Pass 2 is 1/1. Executing the current shared runtime_parameter_is_accepted checker against these exact artifacts returns true for slug/values and false for absent details. The current checker intentionally accepts correlated guard access when the key exists; these gates prove the proposed field set, not entry into the values/details body.

The probe that discovers details returns HTTP 200. Coordinator line 2704 hands off after an accepted 2xx probe and defers remaining probes with PROBE_BUDGET_RESERVED_FOR_CHILD; details remains queued. Therefore the reason label alone must not be described as proof of exhausted probe time. The trial recorded 32.047 seconds remaining when saved. The later candidate stops do not change this earlier handoff decision. No code was edited and no new runtime request/campaign was run. Reproducible audit results and source artifact paths: run dst-details-verification.json.

## Local checkpoint commit verification

The user authorized a local commit of the implemented budget/queue/checkpoint work, related partial-export implementation and tests, documentation and Ad Inserter evidence. Environment settings, WordPress init/fixtures, other plugin audit rows, plugin ZIPs and generated runtime/config artifacts remain outside the commit. Both checklist files were staged selectively: 37 new config rows from the two 2026-10-21 Ad Inserter runs and only the existing Ad Inserter experiment row.

Fresh full discovery (`.superpowers/sdd/2026-10-20-progress-budget/precommit-full-suite.log`): 676 tests in 152.142s, 7 failures, 5 errors, 3 skips. Five known assertion failures and the deep suggested.json error remain; four additional errors are WinError 5 during atomic state/batch-state replacement. Two additional assertions (budget_spent_after_replay and initial_candidate_queue all_90) failed in this run.

Targeted rerun (`precommit-targeted-rerun.log`): 8 tests in 22.469s, 7 passed, 1 error. Both additional assertions passed; three of the four state-replace errors passed, while equivalent_branch_proposal still raised WinError 5. The two checkpoint/reserve regressions passed. These reruns do not make the full suite green or establish the cause of the intermittent assertions. No unrelated repair or Docker rerun was performed for the commit.

Staged Python AST checks, PowerShell parser and staged diff whitespace checks passed. Production source bytes were unchanged during commit preparation. Known runtime limitations remain: guard-only acceptance does not prove branch-body entry; details remains pending in DST; Windows checkpoint replacement and backend budget-expired parent resumption are unresolved. This is a WIP checkpoint, not a completion or fuzzing PASS claim. No push is authorized.
