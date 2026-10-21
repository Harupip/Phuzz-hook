# Progress Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL khi được phép triển khai: superpowers:executing-plans hoặc superpowers:subagent-driven-development. Các bước dùng checkbox để theo dõi.

**Goal:** Candidate được tiếp tục khi có tiến triển runtime đã xác minh, không bị trần 120 giây tự sinh chặn; ngừng khi lặp việc cũ và giữ đầy đủ final/partial.

**Architecture:** Sửa trong coordinator hiện có. Deadline candidate là cửa sổ được gia hạn theo tiến triển, chịu trần campaign và trần candidate nếu người chạy đặt rõ. Tái sử dụng luồng kiểm chứng parent để xử lý hàng probe cả khi đang chạy và khi resume; chỉ sau đó mới ưu tiên handoff sớm.

**Tech Stack:** Python stdlib/unittest, PowerShell wrapper, PHP/WordPress và Docker hiện có. Không thêm dependency.

**Spec:** [Đề xuất ngày 2026-10-20](../../2026-10-20-online-linked-progress-budget-proposal.md).

**Trạng thái:** PARTIAL — implementation correction and automated tests are recorded above. Post-correction local Docker run ad-inserter-20261021T113838Z took 594.456s and exported 16 individually verified final configs plus 2 partial configs. The backend probe→trial→child replay/Pass 2 passed, but parent resume was skipped after BUDGET_EXPIRED with 42 probes pending; the DST candidate final state records a WinError 5 replace error, differing from an earlier live PARENT_CHECK_TIMEOUT snapshot. Overall campaign is not PASS; no fuzzing PASS is claimed. See [verification report](../../2026-10-21-progress-budget-verification.md).

## Global Constraints

- Giữ tính năng `partial-configs/*.partial.json` đã có trước task budget.
- Giữ WIP trong `phuzz.env`, WordPress `init.sh`, hai checklist và các artifact cũ.
- Không sửa plugin, mutation, checker lỗ hổng hoặc lỗi khởi động worker DST.
- Không nới callback/request/run/plugin/method correlation, replay hoặc Pass 2.
- Giữ trần tổng campaign và các giới hạn số candidate/version hiện có.
- Trần candidate được đặt rõ vẫn là trần tuyệt đối; không âm thầm vượt một tùy chọn tên `hard`.
- HTTP, Docker command, test và live run đều có timeout hữu hạn.
- Không commit/push nếu người dùng chưa yêu cầu. Không sửa memory.
- Khi được triển khai, kiểm tra lại worktree và skill using-git-worktrees; không tạo checkout thiếu các thay đổi partial-export mà task này cần.

## Review Focus

1. Deadline mới nhưng local `probe_deadline` cũ: Task 1 và Task 3 phải kiểm tra probe chậm, HTTP lỗi và guard phụ thuộc.
2. Lưu pending nhưng không xử lý trong lượt chạy hiện tại: Task 2 phải kiểm tra publish A rồi probe B, không resume và không trông chờ artifact mới.
3. Trial A thất bại làm B bị kẹt `NOT_VERIFIED`: Task 3 phải kiểm tra điều kiện recoverable và giữ fail-closed cho evidence không hợp lệ.
4. Không có hard cap nhưng resume cộng lại thời gian/credit: Task 4 phải kiểm tra null, clock epoch, offline time và old-policy rejection.
5. Idle reason bị ghi đè khiến exporter không tạo partial: Task 4 phải đi qua coordinator state thực rồi gọi exporter thực.

## 1. Hợp đồng hành vi cần đạt

### 1.1. Thời gian

Gọi `W = max_seconds`, `S = sender_seconds` đã đo, `t = thời điểm tiến triển hợp lệ`.

- Ban đầu: `deadline = now + W`, chặn bởi campaign và explicit candidate cap nếu có.
- Param mới được admit: `deadline = max(deadline, t + W + 3*S)`, sau đó chặn bởi các cap còn hiệu lực.
- Cửa sổ `W` chừa phần điều phối; `3*S` là dự trữ trial/replay/handoff theo cơ chế ước tính đang có.
- Không cộng `W` vào deadline cũ cho từng phần tử của một burst. Nếu 100 param được xác nhận cùng thời điểm và cùng chi phí S, deadline không tăng thành 100 cửa sổ.
- Không cấp lại thời gian cho cùng khóa tiến triển; evidence đến sau deadline không làm candidate sống lại.
- `pending_verification` không cấp thời gian chỉ vì thấy tên qua guard.
- Callback mới có thể cấp công việc cho campaign; không kéo dài thời gian của parent.

Bổ sung so với công thức sơ bộ trong đề xuất: phải có cả `W + 3*S`, không chỉ đúng `3*S`. Nếu cấp đúng mức dự trữ thì thời gian ghi state/chuẩn bị sẽ khiến kiểm tra admission thấy thiếu dự trữ ngay sau đó. Mọi phần cộng vẫn chịu cap.

### 1.2. Cap và trạng thái

- Không truyền `--hard-candidate-seconds`: `hard_seconds = null`, không tự sinh mốc 4×initial nữa.
- Có truyền: phải là số nguyên dương, không nhỏ hơn initial; không được vượt.
- Campaign vẫn có initial/hard budget như hiện tại; task này không đổi default campaign. Default initial 3600 giây không phải trần tuyệt đối; hard mặc định có thể tới 86400 giây.
- Không có tiến triển: reason `NO_NEW_PROGRESS`.
- Có việc chưa xong: status `PARTIAL`; giữ reason chỉ rõ nguyên nhân dừng, không thay `NO_NEW_PROGRESS` bằng thông báo chung làm mất export.
- Không gọi việc dừng do idle là đã tìm hết param hoặc fuzzing PASS.

### 1.3. Thứ tự xử lý

1. Probe xác nhận một nhóm param mới hợp lệ.
2. Nếu request phù hợp strict replay, ưu tiên trial → replay → Pass 2 → publish/handoff.
3. Nếu probe trả HTTP lỗi và lộ guard cần thiết, tiếp tục guard trong deadline đã gia hạn trước khi strict replay.
4. Sau publish hoặc một trial không thỏa input, phục vụ pending probe còn lại trong cùng lượt chạy nếu còn budget và parent có thể kiểm chứng lại.
5. Không dùng HTTP 200 một mình làm bằng chứng; giữ các gate hiện có.

## 2. File map và thứ tự phụ thuộc

Mọi đường dẫn code dưới đây tương đối với `phuzz-main/code/`.

| Task | File chính | Phụ thuộc |
| --- | --- | --- |
| 1. Deadline theo tiến triển | `fuzzer/online_linked/coordinator.py`, `fuzzer/tests/test_online_linked_coordinator.py` | Không |
| 2. Pending queue chạy được ngay trong live loop | Cùng hai file | Task 1 |
| 3. Handoff sớm và phục hồi trial | Cùng hai file | Task 1–2 |
| 4. Resume và partial export | Coordinator, `fuzzer/online_linked/export.py`, hai test module | Task 1–3 |
| 5. Tài liệu, review và live verification | Các guide/wrapper liên quan, checklist sau run | Task 1–4 |

Không thêm module điều phối hoặc tách/refactor coordinator toàn bộ. Chỉ tạo helper khi luồng live và resume thực sự dùng chung.

## Task 1: Renewable candidate deadline

**Files:** Modify `fuzzer/online_linked/coordinator.py`; Test `fuzzer/tests/test_online_linked_coordinator.py`.

**Interfaces:** Giữ constructor `hard_seconds: int | None`, `_candidate_deadline() -> float`, `_extend_progress_budget(kind: str, key: str) -> float` và `run_online_linked(args) -> int`. `None` có nghĩa không đặt trần candidate. Không thay API `_budget_pair` dùng cho các cap khác nếu không cần.

- [x] Viết test `test_verified_progress_uses_rolling_window_beyond_old_120_second_cap`: W=30, S=0, tiến triển tại 20/45/70/95/120 → deadline 50/75/100/125/150; hard cap mặc định phải null.
- [x] Viết test `test_pending_names_and_same_time_burst_do_not_bank_time`: 100 tên pending không đổi deadline; 100 verified keys cùng t=20 không đẩy quá 50 khi S=0.
- [x] Viết test duplicate/late progress: đổi request/version không tạo credit mới cho cùng callback và `(name, source, location)`; t>=deadline không gia hạn.
- [x] Viết test reserve/cap: W=30, S=20, t=20 → deadline 110; explicit cap=120 phải chặn lần gia hạn tiếp. Campaign hết giờ cũng không được hồi sinh.
- [x] Chạy riêng các test trên để thấy RED đúng hành vi, không dùng lỗi import/temp permission làm bằng chứng RED.
- [x] Sửa default/validation ở constructor và `run_online_linked`; giữ kiểm tra 0, số âm, bool và số thực không hợp lệ cho cap được đặt rõ.
- [x] Sửa credit: pending không mua giờ; verified dùng rolling formula; callback chỉ cấp campaign work. Giữ khóa dedupe đã có, không đưa request ID/version vào khóa mới.
- [x] Cập nhật mọi so sánh/tính toán với optional `_hard_deadline`; ghi null thay vì 0 khi không có trần. Không để một đường `min`/phép trừ còn giả định hard cap luôn là số.
- [x] Ghi progress history gồm kind/key, deadline trước/sau, reserve và mốc thời gian dùng để đọc log. Không thêm một framework logging mới.
- [x] Chạy GREEN cho nhóm test này và các explicit-cap/campaign tests cũ. Chỉ đổi assertion cũ nếu nó cố ý mã hóa default hard cap đã bị thay đổi; không xóa kiểm tra cap thật.

**Tiêu chí hoàn thành:** Gia hạn qua 120 giây được chứng minh bằng fake clock với tiến triển mới; lặp dữ liệu cũ không được gia hạn; global/explicit caps vẫn chặn.

## Task 2: Phục vụ pending queue trong cùng live run

**Files:** Cùng coordinator/test module.

**Interfaces:** Thêm `_drain_pending_probes(self) -> None` để luồng live và resume dùng chung. Tái sử dụng `_gate_v0`, `_start_worker`, `_stop_active_worker` và `_run_pending_probe` hiện có; không thêm queue thứ hai.

- [x] Viết test `test_live_loop_services_probe_queue_after_publication_without_resume`: simulate publish A, queue còn B, không có runtime artifact mới; `run()` vẫn gọi probe B trước khi hết giờ.
- [x] Test cùng parent: không restart/gate dư thừa khi parent đang active và context đúng.
- [x] Test ancestor parent: dừng worker hiện tại, dựng lại method/seed identity của parent, chạy gate mới, rồi mới gửi probe B; không dùng request cũ làm bằng chứng được admit.
- [x] Test queue entry đã được xử lý bởi một handoff khác không bị lặp lại do đang duyệt snapshot cũ.
- [x] Test parent/candidate identity bị sai hoặc mất: giữ evidence/state, fail rõ, không gửi request bằng auth/method suy đoán.
- [x] Chạy RED trước khi tạo helper.
- [x] Trích đúng logic parent revalidation của nhánh resume hiện có vào helper, giữ các kiểm tra và error handling.
- [x] Gọi helper ở điểm resume hiện tại và mỗi lượt live loop khi còn active worker, chưa terminal và còn deadline. Sau helper phải đọc lại active version, terminal status và deadline.
- [x] Mỗi lượt kiểm tra lại thời gian; không lặp drain đến vô hạn chỉ vì queue tự bổ sung hoặc source request không đổi.
- [x] Giữ request/run identity mới cho reactivation; không bắt buộc phải có `resume_count` trong một run mới.
- [x] Chạy GREEN các test live queue và các test resume ancestor/method context có sẵn.

**Tiêu chí hoàn thành:** Lưu pending không chỉ là khả năng resume trên giấy; A → publish → B được kiểm tra ngay trong cùng run, với gate đúng cho ancestor.

## Task 3: Handoff sớm, guard phụ thuộc và trial thất bại

**Files:** Cùng coordinator/test module.

**Interfaces:** Giữ `_run_pending_probe(...)`, `_handle_convergence_result(...)`, `_finish_replay_input_attempt(...)`. Task 2 cung cấp live drain. Không đổi tiêu chuẩn `fuzzable`, provenance hoặc Pass 2.

- [x] Test `test_bounded_probe_hands_off_first_accepted_field_and_keeps_queue`: thứ tự phải là probe A → trial A; B còn trong hàng chờ, không bị xóa.
- [x] Test trọn luồng với Task 2: probe A → publish A → probe B; cả hai bước có bằng chứng riêng, không gộp thành final trước khi trial xác minh chung.
- [x] Test `test_slow_error_probe_refreshes_guard_budget_before_strict_handoff`: initial 30, sender cost 12, A trả HTTP 400 ở t=14 và lộ B. Sau gia hạn, B phải được thử theo deadline mới, không bị chặn bởi `probe_deadline=15` cũ.
- [x] Giữ test error-response discovery → strict replay hiện có; HTTP lỗi có thể là evidence khám phá, không được tự biến thành strict final replay PASS.
- [x] Test `test_failed_input_trial_keeps_untried_probe_recoverable_but_not_bad_artifacts`: A có `TRIAL_INPUT_SET_NOT_VERIFIED`, B vẫn còn thì tiếp tục được nếu còn budget/parent hợp lệ; lỗi artifact/correlation không được hưởng cùng ngoại lệ mới này.
- [x] Test trial thất bại lặp lại không cấp thêm thời gian cho cùng key; không tạo vòng retry vô hạn.
- [x] Chạy RED.
- [x] Sau probe được admit, cấp credit một lần, cập nhật local deadline và ưu tiên handoff khi request đủ điều kiện strict replay.
- [x] Enqueue guard vừa phát hiện trước khi quyết định handoff. Với HTTP lỗi cần đi tiếp guard, làm mới cả candidate deadline và allowance của probe; luôn chừa phần thời gian cần để xác minh.
- [x] Giữ các proposal theo nhóm bằng chứng và combined-trial gate hiện có. Không biến danh sách observed thành một union final.
- [x] Chỉ mở rộng recoverability của pending-probe cho lỗi input chưa thỏa đã nêu; giữ gate fail-closed và recovery error handling.
- [x] Chạy GREEN; các test probe-all cũ chỉ được sửa thành early-handoff khi thêm assertion rằng B thật sự được xử lý tiếp, không chỉ được lưu.

**Tiêu chí hoàn thành:** Handoff không bỏ việc còn chờ, không làm kẹt candidate vì một input trial thất bại, và không dùng deadline cũ sau khi gia hạn.

## Task 4: State, resume và partial export

**Files:** Coordinator; `fuzzer/online_linked/export.py`; `fuzzer/tests/test_online_linked_coordinator.py`; `fuzzer/tests/test_online_linked_export.py`.

**Interfaces:** State và batch resume context thêm `budget_policy=progress_idle_v1`. Không có hard cap thì `hard_remaining_seconds=null`. Idle reason là `NO_NEW_PROGRESS`; verified/partial outputs vẫn riêng.

- [x] Test checkpoint uncapped: save/load null hard cap, giữ remaining seconds và progress keys qua clock epoch mới.
- [x] Test offline time bị trừ, không cấp lại W hoặc reserve khi resume; không đem monotonic timestamp cũ so trực tiếp với process mới.
- [x] Test explicit cap vẫn được bảo toàn qua resume; đổi seed/config hash/context bị từ chối như hiện tại.
- [x] Test checkpoint/batch context không có policy mới bị từ chối với hướng dẫn tạo run mới; không viết migration tự động.
- [x] Test `test_idle_completion_with_pending_probes_exports_partial_from_real_state`: coordinator ghi trạng thái dừng thật, sau đó gọi exporter thật; phải có `.partial.json`, không chỉ test exporter bằng một state tự gán reason.
- [x] Test `_write_state` không đổi NO_NEW_PROGRESS thành PENDING_RUNTIME_VERIFICATION rồi làm partial bị bỏ qua. Nếu còn queue, status là PARTIAL nhưng lý do idle vẫn đọc được.
- [x] Test chỉ có pending queue vẫn được thể hiện trong summary hoặc có bằng chứng observed tương ứng; không rơi mất param do exporter chỉ đọc loại pending khác.
- [x] Test final byte/hash không đổi; partial luôn `fuzzing_ready=false`, không vào selected/exported verified count; re-export không ghi đè bytes cũ.
- [x] Chạy RED.
- [x] Sửa các đường ghi/read state, batch resume context và optional cap; giữ dữ liệu lineage/evidence cũ.
- [x] Sửa nguyên nhân dừng và exporter predicate/summary cho NO_NEW_PROGRESS. Không nới `_verified_base` hoặc `_verified_config`.
- [x] Chạy GREEN cho coordinator, exporter, replay-input và comparison suites.

**Tiêu chí hoàn thành:** Run dừng vẫn có partial đúng; resume không biến thành một lần cấp budget mới; final giữ nguyên độ tin cậy.

## Task 5: Tài liệu, review và kiểm chứng runtime

**Files:** `fuzzer/online_linked/README.md`, `docs/guides/online-linked-flow.md`, `docs/guides/run-wordpress-plugins.md`, help trong `phuzz.ps1`; sau live run mới cập nhật hai checklist.

- [x] Sửa mô tả default: không còn candidate hard cap tự sinh 4×initial; `--hard-candidate-seconds` vẫn là absolute cap khi truyền rõ.
- [x] Ghi công thức window+reserve, chính sách pending/callback, thời điểm dừng và giới hạn version/campaign còn giữ.
- [x] Nêu checkpoint policy mới, null hard remaining và cách nhận biết partial. Không ghi thay đổi vào env/init ngoài phạm vi.
- [x] Parse PowerShell wrapper; chạy `git diff --check` trên các file thực sự đổi.
- [x] Chạy regression theo lệnh bên dưới, ghi đủ pass/skip/failure. Windows socket/temp lỗi phải được nhận diện riêng; không sửa logic để làm test môi trường xanh.
- [x] Review độc lập toàn bộ diff, kiểm tra lại cả bốn failure modes đã tìm được. Findings về queue/deadline/export phải có test tái hiện trước khi sửa.
- [x] Chỉ khi có yêu cầu triển khai và test đạt mới chạy Ad Inserter mới bằng Luna 6 theo lựa chọn trước đó của người dùng; không chạy live từ lượt chỉ lập plan này.
- [x] Dùng current initial settings để so sánh với `ad-inserter-20261019T153555Z`; không tăng initial chỉ để che lỗi.
- [x] Wrapper noninteractive, outer timeout hữu hạn, log trong run directory. Nếu outer timeout chạm thì kiểm tra và dừng chỉ worker thuộc run đó; không chạm container ngoài scope.
- [x] Audit batch state, candidate states, final/partial files và replay/Pass 2. Đếm trực tiếp, kiểm tra source hash, marker partial và worker cleanup.
- [x] Cập nhật root `plugin-test-checklist.md` theo từng config path mới và dòng Ad Inserter sẵn có trong checklist experiment, giữ evidence cũ và user-tested Chưa.

**Live acceptance:**

- Có bằng chứng deadline được gia hạn qua 120 giây do key tiến triển mới, không nhầm với lệnh Docker chạy quá giờ.
- Khi chỉ lặp key cũ, không cấp thêm time; cuối cùng dừng và xuất partial nếu còn observed work.
- Backend bắt đầu trial khi có probe hợp lệ và có budget; có final hay không phụ thuộc gate thật, không phải điều kiện bắt buộc để tuyên bố chính sách thời gian đúng.
- Có log cho việc B được xử lý sau publish A trong cùng run.
- Mọi final vẫn có replay và Pass 2 accepted==total>0; partial không được báo fuzzing PASS.
- Không còn worker thuộc run hoạt động sau khi kết thúc hoặc timeout cleanup.

## 3. Lệnh kiểm chứng dự kiến

Chạy từ `phuzz-main/code/fuzzer`. Dùng temp ngắn ở root workspace để tránh test đường dẫn Windows vượt 260 ký tự.

```powershell
$env:TEMP = 'C:/Users/nghia.cd_extremevn/Desktop/Phuzz-hook/.test-temp'
$env:TMP = $env:TEMP
python -B -c "import subprocess,sys; r=subprocess.run([sys.executable,'-B','-m','unittest','tests.test_online_linked_coordinator','tests.test_online_linked_export','tests.test_online_linked_replay_inputs','tests.test_online_linked_config_comparison','tests.test_online_linked_only','tests.test_online_linked_package'],timeout=240); sys.exit(r.returncode)"
```

Một số test chạy PHP HTTP server trên localhost. Sandbox có thể chặn socket;
chỉ dùng quyền thực thi phù hợp cho test, không bỏ các kiểm tra correlation.
Test symlink Windows có thể skip nếu thiếu privilege; phải báo số skip.

Live command dự kiến từ `phuzz-main/code`, chỉ sau khi được triển khai:

```powershell
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug ad-inserter -NoFollowLogs
```

Lệnh trên phải được bọc bằng runner có timeout, ví dụ `subprocess.run(..., timeout=1800)` với log và xử lý timeout/cleanup. Đây là giới hạn thử nghiệm ngoài, không được trình bày thành campaign hard cap mới trong sản phẩm.

## 4. Lịch sử lượt triển khai bị hủy trước khi được ủy quyền triển khai ngày 2026-10-21

- Năm clock/scheduling tests ban đầu đã thấy RED trước khi sửa.
- Một lượt regression sau đó chạy 194 test: 193 đạt, 1 skip symlink. Lượt này chưa bao phủ đủ queue lifecycle; không phải bằng chứng hoàn thành.
- Review độc lập đã tìm bốn lỗi: pending không được live drain; trial thất bại làm queue kẹt; local probe deadline cũ; idle reason làm mất partial export.
- Đã thêm test tái hiện các lỗi đó; người dùng yêu cầu hủy trước khi hoàn tất sửa chúng.
- Toàn bộ code/test/docs về budget của lượt đó đã được hoàn tác. Kết quả test cũ chỉ là evidence phục vụ plan, không mô tả code hiện tại.
- Partial-export đã có trước task này và hai run Ad Inserter cũ vẫn được giữ nguyên.

## 5. Ranh giới hoàn thành và chi phí

Plan không hứa tìm hết param hoặc bảo đảm backend có final. Candidate có tiến triển thật có thể giữ lượt lâu, làm các candidate sau chờ; không thêm round-robin trong cùng task. Trần count/version vẫn có thể dừng khám phá, phải báo đúng reason.

Không dùng tổng test pass để thay cho những test lifecycle còn thiếu. Đánh giá hoàn tất trước đó đã được thu hồi: backend có probe hợp lệ trước deadline nhưng checkpoint theo từng mục làm chậm việc cấp credit. Lượt sửa giữ đúng phạm vi Tasks 1–4; kiểm chứng bằng test tự động. Sau đó người dùng yêu cầu chạy Docker local: run `ad-inserter-20261021T113838Z` xuất 16 final và 2 partial trong 594.456s. Runtime acceptance vẫn PARTIAL: backend còn pending sau budget expiry, DST lỗi thay state trên Windows; audit thêm xác nhận gate isset chưa chứng minh đi vào thân nhánh values/details. Artifact và checklist cũ được giữ nguyên như lịch sử.

**Execution ledger:** mở lại sửa đúng yêu cầu gốc ngày 2026-10-21; người dùng sau đó yêu cầu commit local các thay đổi, không push. Checkboxes ghi công việc đã thực hiện, không thay thế bằng chứng runtime. Runtime acceptance vẫn PARTIAL. Scoped/full regression logs, live evidence and exact paths are recorded in `.superpowers/sdd/2026-10-20-progress-budget/progress.md` and the verification report. Historical section 4 describes the earlier cancelled attempt only.
