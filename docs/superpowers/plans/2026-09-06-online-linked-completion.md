# Online-linked Completion Implementation Plan

> **For agentic workers:** Use `superpowers:executing-plans` để thực hiện từng task khi người dùng yêu cầu triển khai. Thực hiện trực tiếp, không dùng subagent theo yêu cầu hiện tại của người dùng. Checklist chưa đánh dấu là công việc chưa triển khai.

**Goal:** Hoàn thiện vòng runtime `entrypoint → request → Zend → config → PHUZZ → evidence → config/entrypoint mới` theo đủ 10 bước đã thống nhất, với bằng chứng đúng run/callback và giới hạn chạy rõ ràng.

**Architecture:** Giữ `online-linked` là coordinator các config bất biến, dùng lại convergence, exporter, generated replay runner và Pass 2. Tách request làm chứng cứ với config fuzz, chỉ thăng cấp phiên bản sau replay hợp lệ; đưa đăng ký runtime mới vào hàng đợi candidate có kiểm tra và chống trùng. Không hot-reload config của worker đang chạy.

**Tech Stack:** Python unittest, PHP Zend/UOPZ, WordPress, Docker Compose, PowerShell trên Windows; không thêm dependency nếu stdlib và helper hiện có đủ dùng.

**Spec:** [Luồng online và bảng 10 bước](../../../phuzz-main/code/docs/guides/online-linked-flow.md), mục 3. Đây là mục tiêu của người dùng và baseline cần đọc cùng kế hoạch.

## Global Constraints

- Giữ nguyên hành vi mặc định và `-Mode generated`; tập trung `-Mode online-linked`. Không âm thầm thay mode `online` cũ bằng coordinator mới.
- Runtime-only: không quét source plugin, regex suy đoán tham số, dictionary hay giá trị hard-code theo plugin. Ví dụ `mode=deep` dưới đây chỉ là dữ liệu test.
- Mỗi evidence phải liên kết được request ID, run ID, plugin, canonical callback, endpoint/method và nguồn input. `$_REQUEST` chỉ được đưa vào GET/query hoặc POST/form khi có tương quan runtime rõ; không suy từ JSON hoặc transport mơ hồ.
- Giữ config bất biến, lineage và hash. Không chấp nhận HTTP 200, registration, callback reachability hoặc extension loaded riêng lẻ là PASS.
- Giữ ba sửa lỗi đã hoàn thành: stop failure chặn handoff và giữ container; lỗi ghi `NOT_VERIFIED`; hết ngân sách không bắt đầu replay/worker/restart mới.
- Không reset, stash, clean, ghi đè WIP hoặc stage toàn repo. Chỉ commit các path đã kiểm tra trong phạm vi người dùng cho phép. Không push khi chưa được yêu cầu.
- Mỗi lần chạy công cụ dài phải có timeout; `OnlineTimeoutSeconds` hiện là ngân sách từng candidate, không bao gồm toàn bộ build/bootstrap/cleanup.
- Không tự triển khai kế hoạch khi chỉ được yêu cầu đọc hoặc cập nhật tài liệu. Khi được yêu cầu một task, chỉ thực hiện task đó và dependency thực sự cần.

## Baseline và công việc đã hoàn thành

Baseline source: nhánh `feature/online-linked`, commit nền `680563e`, cộng bản sửa vòng đời worker đi cùng kế hoạch này. Khi tiếp tục, đọc lại HEAD và diff vì baseline có thể đã thay đổi.

- [x] Chặn handoff nếu dừng parent thất bại/timeout; lưu `stop_error` và tên container.
- [x] Ghi `CHILD_REPLAY_FAILED`, `CHILD_WORKER_START_FAILED`, `PARENT_WORKER_RESTART_FAILED` dưới `NOT_VERIFIED`; tách callback success khỏi Pass 2 failure.
- [x] Chặn mở rộng sau deadline, replay khi còn dưới 1 giây, worker con/restart parent khi hết thời gian.
- [x] Test coordinator/runner/wrapper đạt 108 test trước khi soạn; nhóm CmpLog đạt 9 test.
- [ ] Chạy Docker tự động toàn tuyến sau các sửa lỗi và sau từng thay đổi chức năng liên quan.

WIP không thuộc kế hoạch: ZIP/fixture test sửa từ phiên khác, configs và artifact online chưa track, kế hoạch/spec cũ ngày 2026-08-27. Không nhập chúng vào commit chỉ vì cùng tên online.

## Bản đồ file và thứ tự triển khai

Các đường dẫn code dưới đây tính từ `phuzz-main/code`.

| Task | Bước mục tiêu | File chính | Phụ thuộc |
| --- | --- | --- | --- |
| 1 | 4, 9 | `fuzzer/hook_energy/seed_generation/online_linked_coordinator.py`, `fuzzer/tests/test_online_linked_coordinator.py` | Baseline |
| 2 | 5, 9, 10 | Hai file trên; đọc `seed_generation/convergence/convergence.py` | Task 1 |
| 3 | 1, 3, 4, 5, 6 | Coordinator, `scripts/wordpress/run-wordpress-phuzz.ps1`, test coordinator/wrapper | Task 1–2 |
| 4 | 2, 9, 10 | Coordinator, wrapper, runtime entrypoint classifier, test coordinator/entrypoints | Task 3 |
| 5 | 1–10 | Test/fixture theo ca còn thiếu, tài liệu online, report trong `docs/reports/` | Task 1–4 |

Đọc các helper hiện có trước khi sửa: `build_config_for_seed_item()`, `_force_replay_only()`, `materialize_convergence_seeds()`, `converge_iteration()`, `verify_pass2_contract()`, `run_generated_configs()`, `normalize_comparison_events()`, `apply_cmplog_hint()`. Chỉ sửa helper dùng chung nếu đã kiểm tra mọi caller và có regression cho generated mode.

## Task 1: Giữ request giúp vào nhánh trong replay/config con

**Files:** Sửa coordinator và test coordinator. Đọc `fuzzer/seed_generation/convergence/convergence.py`, `fuzzer/seed_generation/config/config_exporter.py`, `fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`. Chỉ mở rộng file sửa nếu cách gọi hiện có không đáp ứng; ghi rõ lý do.

**Consumes:** `advance_online_version(evidence, deadline=...)`, cặp `evidence['request']`/`evidence['zend']`, `new_parameters` và config parent.

**Produces:** Replay child khôi phục giá trị request runtime đúng transport/path; config fuzz child có seed giữ điều kiện vào nhánh. Ghi lineage tới request chứng cứ, không gắn giá trị vĩnh viễn vào thuật toán.

- [ ] Viết test red dùng parent `mode=deep`; Zend chỉ đọc `detail` trong nhánh đó. Dùng materializer/exporter thật thay fake exporter để tái hiện việc hiện tại chuyển `mode` thành `fuzz`.
- [ ] Khẳng định dữ liệu replay và request đầu của worker con, không chỉ `callback_reached`:

```python
assert replay_body['mode'] == 'deep'
assert replay_body['detail'] == observed_request_body['detail']
assert child_initial_body['mode'] == 'deep'
assert 'detail' in child_fuzzable_parameters
```

- [ ] Ghép giá trị từ chính request đã xác nhận, theo source/location/path; giữ kiểu JSON, query/form, nested key và fixed dispatch/auth fields. Tên tham số đọc được nhưng chưa có giá trị runtime không được gắn nhãn “observed”; probe thay thế phải được đánh dấu và replay xác nhận.
- [ ] Dựng replay từ request chứng cứ trước khi áp dụng marker fuzz. Dựng config fuzz riêng, mang seed đã mở nhánh và các selector cần fuzz. Nếu exporter phải thêm tùy chọn giữ giá trị, mặc định cũ không thay đổi; kiểm chứng bằng `test_seed_to_config_exporter`.
- [ ] Test negative: sai run/callback/method, cùng tên ở query và body, tham số auth/nonce, request thiếu giá trị, JSON scalar, nested field. Không lấy nhầm giá trị từ CmpLog event hoặc request khác.
- [ ] Chạy test red rồi green; nghiệm thu runtime bằng fixture nhánh và một plugin thật trước khi đánh dấu task hoàn thành.

**Acceptance:** Replay tái đọc được tham số phụ thuộc nhánh và Pass 2 đạt; worker con bắt đầu từ request giữ điều kiện vào nhánh. Config/hash parent không đổi. Chỉ thấy callback mà không thấy tham số của nhánh là chưa đạt.

## Task 2: Tách tham số đã quan sát khỏi phiên bản đã chấp nhận

**Files:** Coordinator, test coordinator. Đọc `advance_convergence_state()` và `_missing_known_parameters()` trong bridge; không đổi nghĩa convergence dùng chung chỉ để bỏ qua gate.

**Consumes:** Evidence đã được Task 1 xác nhận, parent report/config, kết quả export/replay/worker start.

**Produces:** Một lần export/replay lỗi không làm parent coi tham số chưa triển khai là đã hoàn tất; retry có giới hạn và lịch sử rõ ràng.

- [ ] Test red: phát hiện tham số mới → export hoặc replay lỗi → parent chạy tiếp → evidence hợp lệ xuất hiện lại. Chứng minh trạng thái parent và config parent vẫn tương ứng.
- [ ] Dùng trạng thái tạm cho đề xuất; chỉ cập nhật trạng thái của phiên bản hợp lệ tại thời điểm chuyển giao đã định nghĩa. Không cập nhật `parent['known_parameters']` trước khi biết đề xuất được xử lý ra sao.

```text
observed evidence -> proposed parameters/config -> replay result
replay fail       -> giữ confirmed parent, lưu failed attempt
replay pass       -> commit trạng thái child, thử start trong deadline
```

- [ ] Phân biệt dedupe request, dedupe parameter và retry attempt. Không ghi lại cùng đường dẫn config bất biến; dùng phiên bản/attempt mới có liên kết tới lần lỗi.
- [ ] Giữ giới hạn số phiên bản và ngân sách; test evidence lặp không gây vòng vô hạn, restart lỗi không tự báo PASS, timeout không bị gọi là convergence.
- [ ] Test trạng thái convergence `REPLAY_FAILED`, `missing_parameters`, `runtime_block_reason`: coordinator phải lưu/diễn giải nguyên nhân, không chỉ nhìn `new_parameters` rồi ghi `NO_NEW_ZEND_PARAMETER`.
- [ ] Chạy hồi quy và cập nhật bảng trạng thái trong guide.

**Acceptance:** Mất/đến muộn evidence, export fail và replay fail đều có trạng thái nhất quán, không làm mất cơ hội retry hợp lệ và không thay config đang chạy.

## Task 3: Gate v0, request context và báo cáo khởi động

**Files:** Coordinator; wrapper `scripts/wordpress/run-wordpress-phuzz.ps1`; `fuzzer/tests/test_online_linked_coordinator.py`, `test_phuzz_wrapper_contract.py`. Đọc `test_seed_method_inference.py`, `test_rest_method_generalization.py`, generated runner, registry initialization và login/UOPZ hiện có.

**Consumes:** Snapshot seed/registry, method variants, auth context và replay helpers.

**Produces:** V0 probe/replay được phân biệt với v0 được phép fuzz; readiness có bằng chứng, lý do blocked và đường dẫn state thực tế.

- [ ] Test red: config có trường fuzz nhưng callback/provenance chưa xác minh không được khởi chạy fuzzing ngay. Seed không có tham số vẫn được probe có giới hạn.
- [ ] Dùng `run_generated_configs()` để replay v0 và gate callback/provenance; với config có tham số Zend, dùng Pass 2. Seed entrypoint-only không được báo Pass 2 `0/0` là đạt: tiếp tục discovery/probe hoặc ghi blocked rõ ràng.
- [ ] Kiểm chứng method và `seed_variant_id` đi xuyên seed → replay row → convergence/Pass 2. REST nhiều method không được trộn evidence hoặc mất variant khi tạo child.
- [ ] Chuẩn bị auth/cookie/nonce bằng cơ chế runtime hiện có, ghi rõ các override của môi trường instrumentation. Thiếu prerequisite thì phân loại blocked/setup-required; không invent credentials/nonce hay sửa plugin để đi qua gate.
- [ ] Kiểm chứng runtime loading của plugin, Zend/UOPZ và callback registry theo run; HTTP 200 chỉ là readiness web. Làm rõ registry cần tái nạp sau container restart.
- [ ] Sửa đường dẫn báo cáo cuối wrapper dùng `batch-state.json` và `state_path` thật của candidate; giữ storage ID ngắn. Test với tên hook dài, method variant và batch có candidate lỗi.
- [ ] Test v0 replay thành công → fuzz bắt đầu khi còn thời gian; auth skip, method ambiguous, no-parameter và registry missing có lý do cụ thể.

**Acceptance:** Mỗi candidate có bằng chứng cho phép fuzz hoặc lý do không chạy. Không gộp giả lập/bypass auth với xác minh auth nguyên bản.

## Task 4: Đóng vòng action/route mới về discovery

**Files:** Coordinator, wrapper; đọc `fuzzer/discovery/entrypoints/classifier.py`, `fuzzer/discovery/entrypoints/entrypoints.py` nếu còn đúng đường dẫn ở checkout, runtime registration tại `web/instrumentation/hook_coverage/uopz_hook_wp.php`; test `test_entrypoints.py`, `test_online_linked_coordinator.py`. Nếu module đã chuyển vị trí, tìm caller/import trước, không tạo bản sao.

**Consumes:** Delta đăng ký runtime và parent request/callback đã xác nhận; registry/seed exporter và classifier hiện có.

**Produces:** Candidate HTTP mới được đưa vào hàng đợi có dedupe, lineage, budget. Hook chưa thể map HTTP được ghi setup-required/unsupported cùng evidence, không tạo request phỏng đoán.

- [ ] Fixture test: request A đăng ký AJAX action B hoặc REST route B trong nhánh; chứng minh event đăng ký của B gắn đúng request A. Một hook nội bộ không phải HTTP là negative control.
- [ ] Thu delta registration và cập nhật registry/seed qua helper hiện có. Việc so sánh `explicit_callback` khác parent hiện tại chỉ là chỗ từ chối; không dùng nó thay bằng chứng `add_action`/route registration.
- [ ] Dùng identity gồm plugin, callback, loại entrypoint, hook/route, method và variant để chống trùng; giữ parent lineage và điều kiện tái lập registration từ Task 1.

```text
confirmed new registration
  -> classify using existing runtime metadata
  -> HTTP supported + replayable prerequisite: enqueue unseen candidate
  -> internal/ambiguous/setup missing: record blocked with evidence
confirmed new parameter on same target
  -> rebuild request/config through Tasks 1–3
```

- [ ] Làm hàng đợi tăng dần trong coordinator/batch; không chỉ lặp snapshot đầu. Bổ sung giới hạn candidate tổng và ngân sách toàn campaign trước khi mở rộng tự động; giữ timeout từng candidate riêng và ghi cả hai trong state.
- [ ] Test registration lặp, chu trình A→B→A, hai route cùng callback, route nhiều method, auth-only registration, hook chỉ tồn tại trong request parent, hết ngân sách và lỗi refresh registry.
- [ ] Chỉ gỡ `ACTION_EXPANSION_NOT_IMPLEMENTED` cho loại đã có test và runtime proof. Không tuyên bố mọi `add_action` đều trở thành HTTP endpoint.

**Acceptance:** Runtime A→B được khám phá và replay trong cùng campaign; B có provenance và prerequisite hợp lệ. Lặp đăng ký không gây nổ candidate. Hook nội bộ vẫn được phân loại đúng.

## Task 5: Nghiệm thu tự động đủ 10 bước và cập nhật tài liệu

**Files:** Các test đã nêu; fixture mới chỉ khi fixture hiện có thiếu tình huống; `phuzz-main/code/docs/guides/online-linked-flow.md`; tạo report có ngày trong `phuzz-main/code/docs/reports/` khi chạy thật.

- [ ] Chạy fixture AJAX và REST qua hai lần mở rộng `v0 → v1 → v2`; có một giá trị so sánh do CmpLog cung cấp, nhánh đọc tham số mới, replay giữ nhánh và PHUZZ con thực sự gửi request.
- [ ] Chạy action/route expansion A→B và xác nhận quay lại bước 2–5, không chỉ thấy event registration.
- [ ] Chạy ít nhất một plugin thật phù hợp từng khả năng cần chứng minh; chọn theo runtime/source hiện tại khi thực thi, không gọi fixture là proof plugin thật.
- [ ] Negative runs: no params, auth/setup missing, replay fail, parent stop timeout, child start fail, delayed/stale evidence, version/candidate/time limit. Kiểm tra không sót worker; nếu Docker cleanup lỗi thì báo container còn chưa xác nhận dừng.
- [ ] Kiểm chứng stop-on-vulnerability trong replay, worker và batch; không gán `VULN_FOUND` của candidate trước cho candidate sau qua marker dùng chung. Theo yêu cầu dừng sau vulnerability đầu tiên, nghiệm thu không tiếp tục fuzz dài khi đã có proof; mọi thay đổi semantics batch phải nêu rõ và test.
- [ ] Lưu run ID, commit/config hash, registry, request/Zend pairs, generated configs, replay summaries, Pass 2, worker lifecycle, coverage/CmpLog và vulnerability evidence. Không commit secret/cookie thực hoặc toàn bộ artifact dump.
- [ ] Cập nhật bảng 10 bước bằng trạng thái source và runtime riêng; ghi first failed boundary nếu partial. Chỉ đánh dấu hoàn thành khi toàn bộ acceptance tương ứng có artifact mới.

## Lệnh kiểm tra và giao việc phiên sau

Từ `phuzz-main/code`, chạy nhóm hồi quy nền với timeout 180 giây:

```powershell
rtk proxy python -c "import subprocess,sys; r=subprocess.run([sys.executable,'-m','unittest','fuzzer.tests.test_online_linked_coordinator','fuzzer.tests.test_online_config_runner','fuzzer.tests.test_phuzz_wrapper_contract','fuzzer.tests.test_generated_config_runner','fuzzer.tests.test_cmplog','fuzzer.tests.test_cmplog_extension','fuzzer.tests.test_seed_to_config_exporter'],timeout=180); sys.exit(r.returncode)"
```

Cho từng task: viết test tình huống cụ thể trước, chạy thấy lỗi đúng nguyên nhân, sửa nhỏ nhất, chạy lại nhóm liên quan. Trước commit chạy `rtk git diff --check`, xem diff/index rồi stage đúng path; không tự bỏ test fixture chỉ vì thiếu ZIP trên máy.

Lệnh runtime và cách tìm artifact ở guide. Trước chạy full batch phải kiểm tra số candidate và đặt timeout toàn tiến trình phù hợp; không suy ra thời gian toàn batch từ `OnlineTimeoutSeconds`.

Ví dụ yêu cầu để tiếp tục:

> Đọc `docs/superpowers/plans/2026-09-06-online-linked-completion.md` và guide được liên kết. Kiểm tra HEAD/WIP, thực hiện Task 1 trực tiếp, không subagent. Giữ generated mode, dùng evidence runtime, thêm test red/green và báo rõ phần nào có runtime proof. Chưa triển khai Task 4.

Không cần làm lại baseline đã hoàn thành nếu test/source vẫn xác nhận; không tự coi artifact cũ là proof cho phiên bản code mới.
