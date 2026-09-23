# Kết quả Imsanity branch replay

Cập nhật: 2026-09-22. Không commit/push. WIP, `phuzz.env` và artifact cũ được giữ nguyên.

## Verdict

**PARTIAL**.

Hai lỗi review đã được sửa và kiểm chứng bằng regression/runtime: candidate pending được xử lý tiếp hoặc retire; proposal request semantic lặp không tạo version/child/replay mới. `get_images.resume_id` có runtime evidence, coherent replay và Pass 2. `resize_image.resumable` vẫn chưa qua replay-input trial; `bulk_complete` được bỏ qua khi không có field fuzz theo scope chốt. Vì vậy đây chưa phải fuzzing PASS đầy đủ cho bốn endpoint.

## Checkpoint 1 — Repro trước sửa

- HEAD lúc bắt đầu: `b102d12660b7e971a27bed8b81d90a302a3ebcc5`.
- Artifact baseline: `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T112521Z/batch-state.json`; các run cũ và artifact trung gian được giữ nguyên.
- Regression đỏ trước implementation: 3 test mới fail (`pending` không được consume/retire; proposal tương đương tạo `v2`). Đây là repro hành vi, không chỉ repro state storage.
- Settings người dùng trong `phuzz-main/code/phuzz.env` không được đổi. Campaign dùng CLI override `120/20/32/3600`.

## Checkpoint 2 — Candidate pending và coherent replay

Thay đổi chính ở `phuzz-main/code/fuzzer/online_linked/coordinator.py`:

- `_run_pending_probe` nhóm proposal theo `request_id`, `worker/run_id` và request-parameter context; mỗi group được admit riêng, không union field/value từ request không đồng xuất hiện.
- Group chưa được chọn vẫn giữ identity/provenance trong `pending_runtime_candidates`.
- Khi child context mới xuất hiện, `_reconcile_pending_runtime_candidates` chỉ dùng identity để quyết định `REQUEUED`/`RETIRED`; candidate được probe/admit lại bằng evidence mới. Evidence parent cũ không được dùng như evidence child.
- Candidate không tái xuất được retire với `NOT_REOBSERVED_ON_CHILD`; candidate tái xuất có `FRESH_CHILD_CONTEXT`; pending cuối cùng được xóa. Deadline, parent checks, dedupe, auth/callback identity, replay và Pass 2 vẫn giữ nguyên.
- Trial lỗi không làm mất parent/candidate độc lập; trạng thái trial không còn để `exporting` giả khi proposal bị short-circuit.

Regression hành vi:

- `test_remaining_runtime_candidate_is_reprocessed_on_fresh_child_evidence`
- `test_stale_runtime_candidate_is_retired_on_fresh_child_context`
- `test_equivalent_branch_proposal_does_not_create_version_but_new_input_does`
- `test_semantic_progress_keeps_fixed_input_and_transport_changes`

Kết quả sau sửa: `4/4 PASS`; các test kiểm tra version, probe/admission, event reason và pending cuối, không chỉ state lưu candidate.

## Checkpoint 3 — Semantic progress và scope thu hẹp

- `_config_request_key` so sánh target/method/entrypoint và dữ liệu request theo section; metadata `request_id`/`run_id` không phải tiến triển. Giá trị fuzzable được canonicalize vì mutation của replay trial không phải proposal progress; fixed input và transport khác vẫn được giữ là khác.
- Recovery thường đối chiếu published `config_path`; pending-group dispatch còn đối chiếu tập parameter đã admit để không chặn candidate còn lại do seed tạm chứa field chưa được admit.
- Proposal tương đương ghi event `PARAMETER_DISCOVERY/IGNORED/NO_SEMANTIC_PROGRESS`, trial status `ignored`, không gọi tạo version, force replay hay worker child.
- Đã tách bỏ phần fixed-only mới thêm ở lượt trước khỏi coordinator/exporter/tests/docs. Exporter trở lại chỉ export config đủ gate `fuzzing_ready`; `bulk_complete` không có field fuzz thì bị skip, không gắn nhãn fuzzing-ready giả. Artifact fixed-only cũ vẫn giữ nguyên.
- Không hardcode field/value Imsanity, không dùng experiment/source làm seed, không nới gate.

## Checkpoint 4 — Fresh runtime campaign cuối

Command chạy từ repo root:

```powershell
./phuzz-main/code/phuzz.ps1 -PluginSlug imsanity -OnlineTimeoutSeconds 120 -OnlineMaxVersions 20 -OnlineMaxCandidates 32 -OnlineCampaignTimeoutSeconds 3600
```

Run cuối: `imsanity-20260922T143226Z`.

Batch evidence: `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T143226Z/batch-state.json`

Effective settings:

| Setting | Value |
|---|---:|
| `max_seconds_per_candidate` | 120 |
| `max_versions_per_candidate` | 20 |
| `max_candidates` | 32 |
| `campaign_seconds` | 3600 |
| `campaign_status` | `complete_with_skips` |
| candidates | 16 |

Campaign có `3 BOUNDED_ONLINE_COMPLETE`, `13 NOT_VERIFIED`; `final-configs` có 3 file. Đây là bounded runtime/export evidence, không phải fuzzing PASS.

### Đối chiếu bốn endpoint

Experiment chỉ dùng làm comparison reference tại `experiment/02-0day-vulns/configs/300000-imsanity.2.8.2.zip/`; không dùng làm runtime seed.

| Endpoint | Runtime parameter | Replay / Pass 2 | Final config / kết luận |
|---|---|---|---|
| `bulk_complete` / `792ca888ad3a523170342b9aa6f77c90a006be90` | `_wpnonce` accepted; `wp_lang`, `_locale` pending nhưng child không tái xuất nên `RETIRED/NOT_REOBSERVED_ON_CHILD` | 1 selected trial, Pass 2 `1/1` | Không export: chỉ có `action` + `_wpnonce`, không có field fuzz; đúng scope skip, không gọi là fuzzing PASS |
| `get_images` / `6e99b3b2fd26ea4b633bc1887ae8a49d102ac45b` | `_wpnonce`, sau đó `resume_id` accepted từ request/callback context tương quan | 2 selected child trials, cả hai Pass 2 `1/1`; pending cuối 0 | `fuzzer-config.wp_ajax_imsanity_get_images.271d3fbaad815b5e.json`; body có `action`, `_wpnonce`, `resume_id=fuzz`; resume_id được chứng minh qua coherent replay/Pass 2 |
| `remove_original` / `b668a5a3c0252177c1908dc1c060c5d5393d93b9` | `_wpnonce`, `id`, `wp_lang`, `_locale`; query/body transport được giữ riêng | 5 selected child trials, Pass 2 `1/1`; 48 proposal lặp bị `ignored/NO_SEMANTIC_PROGRESS`; pending có 4 requeue, 1 retire; pending cuối 0 | `fuzzer-config.wp_ajax_imsanity_remove_original.b010f2ded173fe65.json`; config có query `wp_lang`, `_locale` và body `id=fuzz`; `v0..v5`, không có semantic duplicate pair |
| `resize_image` / `063611685922958916bd8a11e852aa20d55d0e15` | `_wpnonce`, `id`, `wp_lang`, `_locale`, `resumable` accepted/probed | `v0..v3` có 4 Pass 2 `1/1`; trial bộ có `resumable` thất bại ở 2 trial với `TRIAL_MISSING_PARAMETER_READS` cho `wp_lang`, `_locale` | `fuzzer-config.wp_ajax_imsanity_resize_image.a76a53432f41aab6.json`; có `id=fuzz` nhưng không có `resumable`; terminal `NOT_VERIFIED/TRIAL_INPUT_SET_NOT_VERIFIED` |

State evidence của bốn primary candidate:

```text
phuzz-main/code/fuzzer/output/online-linked/eacfe375b0795d86/state.json  # bulk_complete
phuzz-main/code/fuzzer/output/online-linked/cf6bbc3b57a36d4c/state.json  # get_images
phuzz-main/code/fuzzer/output/online-linked/ecce8175de350a43/state.json  # remove_original
phuzz-main/code/fuzzer/output/online-linked/6f55cf12ed44c439/state.json  # resize_image
```

Assertion đọc state cuối: mọi `pending_runtime_candidates` của bốn endpoint đều rỗng; không còn trial status `exporting`; `remove_original` có 0 semantic duplicate pair; `get_images` final config có `resume_id`.

## Test và kiểm chứng

| Check | Pass | Fail | Skip | Evidence |
|---|---:|---:|---:|---|
| Targeted review regressions | 4 | 0 | 0 | coordinator tests nêu ở Checkpoint 2/3 |
| `python -m unittest discover -s tests -p "test_online_linked*.py" -q` | 127 | 0 | 0 | bounded subprocess; final run `145.760s` |
| `test_online_linked_export.py` | 6 | 0 | 0 | exporter fuzzing-ready và negative gates; fixed-only tests đã bỏ |
| Zend discovery | 111 | 0 | 1 | skip duy nhất: Docker image `hookphuzz-zend` chưa build |
| `py_compile` changed coordinator/export/tests | PASS | 0 | 0 | final offline checkpoint |
| Runtime state assertion | PASS | 0 | 0 | run `143226Z`, endpoint/field/version/pending/trial checks ở trên |

Các dòng fixture `GATE_NOT_VERIFIED`/`NOT_FUZZING_READY` là negative-gate behavior được test; không đếm chúng thành runtime fuzzing PASS. HTTP 200, callback reached, số file export và test offline không được dùng thay cho provenance/auth/replay/Pass 2.

## Artifact preservation và phần chưa chứng minh

- Giữ run cũ `imsanity-20260922T112521Z`, `imsanity-20260922T123847Z`, `imsanity-20260922T124453Z`, `imsanity-20260922T134835Z`, `imsanity-20260922T140703Z`; run cuối nằm ở `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T143226Z/`.
- Giữ config/replay artifact cũ dưới `phuzz-main/code/fuzzer/configs/online-linked/imsanity/`, không cleanup WIP/unrelated files.
- `bulk_complete` chưa có verified fuzz field và vì scope mới không export fixed-only.
- `resize_image.resumable` chưa có coherent replay-input trial; không thêm field để làm đủ bốn file.
- Chưa chứng minh vulnerability discovery, full coverage, mọi branch của plugin, hay semantic parity đầy đủ với experiment. Verdict `PARTIAL`, không phải fuzzing PASS.

## P2 follow-up — `_config_request_key` selector parity

### Root cause và patch nhỏ nhất

Regression trước sửa đã đỏ ở `test_config_request_key_matches_fixed_priority_and_selector_patterns`: hai config chỉ đổi fixed `nonce` (`valid-a` → `valid-b`) nhưng `_config_request_key` tạo cùng key. Nguyên nhân là semantic key dùng tập tên exact từ `fuzz`, bỏ qua regex selector và fixed precedence; trong khi `_replace_fuzzable_values_with_placeholder` dùng `re.match` và fixed thắng fuzz.

Đã thêm `_config_name_is_fuzzable` làm quy tắc selector dùng chung cho publisher và semantic key. `_config_request_key` hiện canonicalize đúng các field chỉ fuzz; field khớp cả fixed/fuzz giữ nguyên fixed value. Không đổi replay/provenance/auth/Pass 2 và không thêm framework/refactor rộng.

### Regression sau sửa

| Check | Pass | Fail | Skip | Evidence |
|---|---:|---:|---:|---|
| Selector key: fixed overlap, fuzz-only pattern, transport | 1 | 0 | 0 | `test_config_request_key_matches_fixed_priority_and_selector_patterns` |
| Dedupe gate: fixed-value change đi tiếp, proposal lặp bị `NO_SEMANTIC_PROGRESS`, input khác vẫn đi tiếp | 1 | 0 | 0 | `test_equivalent_branch_proposal_does_not_create_version_but_new_input_does` |
| Coordinator regression | 103 | 0 | 0 | `python -m unittest fuzzer.tests.test_online_linked_coordinator` (`121.693s`) |
| Bounded online-linked modules | 128 | 0 | 0 | 6 module `test_online_linked*.py`, (`144.688s`) |
| `py_compile` changed coordinator/tests | PASS | 0 | 0 | command completed without output |
| `git diff --check` | PASS | 0 | 0 | no whitespace errors |

### Runtime boundary

Không chạy lại campaign Imsanity dài theo yêu cầu. Artifact runtime trước patch vẫn giữ nguyên tại `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T143226Z/`; patch này chỉ sửa phép canonicalize/dedupe và đã được kiểm chứng qua đường gọi gate. Vì vậy không đưa ra runtime evidence mới cho bốn endpoint, `get_images.resume_id`, replay hoặc Pass 2. Kết luận runtime trước đó vẫn giữ: `bulk_complete` fixed-only bị skip, `resize_image.resumable` chưa chứng minh được, và không được coi đủ bốn file là fuzzing PASS.

Verdict: `PARTIAL`.

## 2026-09-22 — Replay helper-depth correction

Scope: sửa verifier replay-input theo provenance của request mới. Giữ evidence parent cũ, depth check exact, source/path/request/auth/callback gates, Pass 2 và fixed-only scope. Không commit/push.

### Repro và root cause

- Previous baseline state was recorded as `phuzz-main/code/fuzzer/output/online-linked/6f55cf12ed44c439/state.json`, but that path is no longer present.
- The historical report recorded parent v4 `_locale` and `wp_lang` at `helper_depth=1`, then current attributed reads at depth 2; that runtime chain is not re-verifiable from the surviving artifacts.
- This checkpoint's pre-fix regression was `test_trial_parameter_verified_accepts_legacy_summary_only_artifact` → `UnboundLocalError: check_parameter`, `1 error`.

### Patch nhỏ nhất

`_trial_parameter_verified` trong `phuzz-main/code/fuzzer/online_linked/coordinator.py` khởi tạo một bản copy parameter trước cả nhánh raw-event và summary fallback. Raw event vẫn thay `helper_depth` bằng depth exact của request mới; summary fallback ghi lại `access_forms` đã normalize và từ chối summary có source trực tiếp lệch parameter. Không mutate parameter/history. Nếu raw events có mặt mà không có event qualify thì reject; summary fallback chỉ còn cho artifact legacy không có raw events.

### Regression và gate coverage

| Check | Pass | Fail | Skip | Evidence |
|---|---:|---:|---:|---|
| RED summary-only regression trước patch | 0 | 1 | 0 | targeted terminal output; expected `UnboundLocalError` |
| Targeted summary/depth/provenance/coherent trial + Pass 2 | 7 | 0 | 0 | targeted unittest command in this checkpoint |
| `python -m unittest discover -s tests -p "test_online_linked*.py" -q` | 133 | 0 | 0 | bounded suite, 78.225s |
| `python -m unittest tests.test_zend_discovery -q` | 111 | 0 | 1 | `zend-suite-final.txt`; 1 Docker-image skip |
| `py_compile` coordinator/tests | PASS | 0 | 0 | final command |
| `git diff --check` | PASS | 0 | 0 | final command |

Negative coverage: summary without operation, wrong summary callback/source, missing request key, wrong raw callback, plus wrong root callback, source, path, request key/id/run, auth, negative depth; mixed wrong-source old-depth plus correct-source new-depth. Positive coverage includes summary-only legacy artifact, depth `1→2`, `2→1`, unchanged depth, coherent full-set trial, child replay and Pass 2. Historical parameter/evidence/parent state remains unchanged.

### Fresh runtime evidence

Command:

```powershell
./phuzz-main/code/phuzz.ps1 -PluginSlug imsanity -OnlineTimeoutSeconds 120 -OnlineMaxVersions 20 -OnlineMaxCandidates 32 -OnlineCampaignTimeoutSeconds 3600
```

Run: `imsanity-20260922T163751Z`.

Batch: `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T163751Z/batch-state.json`.

- Campaign: `complete_with_skips`; 16 candidates; `BOUNDED_ONLINE_COMPLETE=4`; `NOT_VERIFIED=12`; final-configs `3 files`, `13 skipped`.
- Outer PowerShell guard returned `124` after its bound-error line even though the runtime log reached the final batch summary and Docker containers stopped; retain this as a wrapper-status caveat, not a hidden pass.
- The main state paths used for trial → Pass 2 re-review are no longer present, including `phuzz-main/code/fuzzer/output/online-linked/ef43cb51e3798e31/state.json`; the historical `6f55cf12ed44c439/state.json` is also absent. The surviving batch summary is not enough to re-verify that chain.
- Final config: `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260922T163751Z/final-configs/fuzzer-config.wp_ajax_imsanity_resize_image.a76a53432f41aab6.json`; body `fixed` contains `action`, `_wpnonce`, `resumable`, while body `fuzz` contains only `id`. The literal string value `"fuzz"` is not proof that a field was fuzzed.
- Do not move `resumable` from fixed to fuzz in this task; that is a separate investigation. No long campaign was rerun for the summary-only regression, and no new runtime VERIFIED claim is made.
- Primary candidate config hashes are unique: `2/2`, `3/3`, `6/6`, `7/7`; repeated proposals recorded `NO_SEMANTIC_PROGRESS`, no duplicate-version hash.

### Verdict

Offline regression/gate result: `VERIFIED`. Runtime trial → Pass 2 re-verification: `BLOCKED` by missing state artifacts. Overall result: `PARTIAL`; the final config/export artifact is not a new runtime VERIFIED or fuzzing PASS.

Overall campaign remains `PARTIAL`: only 3 final configs, 12 candidates not verified, and config/export plus replay/Pass 2 do not prove full fuzzing PASS or vulnerability discovery.

## 2026-09-23 — Legacy summary row identity P2

- Root cause: `_trial_parameter_verified` unioned `access_forms` from every same-name summary row, but retained only the last row's source. GET/POST order therefore changed the verdict, and a GET `read` could rescue a POST row with no operation.
- Pre-fix regression: `test_trial_parameter_verified_legacy_summary_keeps_source_row_identity` failed on `POST read → GET read` (`False` instead of `True`).
- Patch: legacy summary fallback now matches the parameter name/path and source first, then verifies each matching row with only that row's operations. `REQUEST` still uses existing transport resolution and request-bucket membership. Raw events remain authoritative; current helper-depth and initialized `check_parameter` fixes are untouched.

| Check | Pass | Fail | Skip |
|---|---:|---:|---:|
| Targeted summary/provenance/depth/coherent-child regressions | 8 | 0 | 0 |
| Bounded `test_online_linked*.py` suite | 134 | 0 | 0 |
| `py_compile` + `git diff --check` | PASS | 0 | 0 |

Runtime: Docker/Imsanity campaign was not rerun. Existing WIP/settings/artifacts remain unchanged; this patch has no new runtime VERIFIED claim and does not move any fixed field to fuzz.

## 2026-09-23 — Timer fix and latest Imsanity campaign

Two runs after the earlier replay-helper-depth checkpoint:

- `imsanity-20260923T104233Z`: `complete_with_skips`, 16 candidates, 0 final configs. All four AJAX candidates failed with `ONLINE_LINKED_COORDINATOR_ERROR: name 'config_generation_started_at' is not defined`; 12 other candidates failed the V0 prerequisite gate.
- `imsanity-20260923T110814Z`: latest run; batch evidence at `phuzz-main/code/fuzzer/output/online-linked/imsanity-20260923T110814Z/batch-state.json`. Campaign `complete_with_skips`; 16 candidates; 3 `BOUNDED_ONLINE_COMPLETE`; 13 `NOT_VERIFIED`; 3 final configs.

The timer error did not recur in the latest run. Child states record `config_generation_seconds` from `0.015s` to `0.032s`, confirming the timer was available in the child-config path.

| Endpoint | Latest final config / fuzz selectors | Replay and Pass 2 | Candidate verdict |
|---|---|---|---|
| `bulk_complete` | No final config. V1 is replay-only; `action` and `_wpnonce` fixed, no fuzz selectors. | Callback reached; Pass 2 `1/1`. | `BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED`; fixed-only skip. |
| `get_images` | `fuzzer-config.wp_ajax_imsanity_get_images.271d3fbaad815b5e.json`; POST `resume_id=fuzz`; `action` and `_wpnonce` fixed. | V2 replay stopped on callback; matched request artifact; Pass 2 `1/1`. | `BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED`. |
| `remove_original` | `fuzzer-config.wp_ajax_imsanity_remove_original.b010f2ded173fe65.json`; POST `id=fuzz`; query `_locale`/`wp_lang` are fixed (literal `fuzz` values, `fuzz=[]`). | V5 replay stopped on callback; matched request artifact; Pass 2 `1/1`. | `BOUNDED_ONLINE_COMPLETE/BUDGET_EXPIRED`; 48 repeated proposals ignored as `NO_SEMANTIC_PROGRESS`. |
| `resize_image` | `fuzzer-config.wp_ajax_imsanity_resize_image.a76a53432f41aab6.json`; POST `id=fuzz`, `resumable=fuzz`; query `_locale`/`wp_lang` fuzz selectors. | V5 replay stopped on callback; matched request artifact; Pass 2 `1/1`. The following V6 replay had `window_elapsed`, callback false, no matched artifact, Pass 2 `0/0`, reason `SENDER_TIMEOUT`. | `NOT_VERIFIED/CHILD_REPLAY_FAILED`. |

The other 12 candidates created no V0 version and ended at `V0_PREREQUISITE_GATE_FAILED`. Docker live-container listing returned `Access is denied`; the batch state is terminal and final config files were written by 11:15:38.

Verdict: `PARTIAL`. The timer correction has runtime evidence. `resumable` is present as a fuzz selector in the resize final config, but the later V6 child replay timeout keeps that candidate `NOT_VERIFIED`. No fuzzing PASS is claimed.
