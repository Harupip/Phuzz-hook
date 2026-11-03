# Bổ sung toàn bộ param từ một trace Zend

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Mỗi request có bằng chứng Zend hợp lệ bổ sung toàn bộ param quan sát được vào một config của candidate, kể cả `isset()` và `empty()`, trong một lần cập nhật.

**Architecture:** Dùng normalizer, convergence, materializer và gate callback hiện có. Thay bước yêu cầu từng field phải được gửi rồi probe riêng bằng nhận cả nhóm field trong cùng trace. Config kế tiếp tích lũy các field đã biết của cùng candidate và request context.

**Tech Stack:** Python, unittest, PowerShell, WordPress, Zend runtime artifacts.

**Spec:** Yêu cầu trong chat ngày 03/11/2026. Người dùng đã chốt đưa cả field chỉ thấy qua `isset()` và `empty()` vào config để fuzz. Nonce giữ vai trò cố định theo exporter hiện có.

## Phạm vi và kết quả mong đợi

- Phạm vi triển khai là online-linked AJAX, gồm field GET/query và POST/form có transport rõ ràng. Cookie vẫn theo setting và quy tắc transport hiện có. REST dùng bộ chuẩn hóa riêng hiện có.
- Một lượt nghĩa là một cặp request artifact và Zend artifact cùng request ID, run ID, callback, plugin và HTTP method.
- Một trace có N param hợp lệ thì một lần convergence bổ sung cả N, khử trùng theo source và path. Một tên có mặt ở GET và POST được giữ ở cả hai vị trí.
- Field chưa có trong request vẫn được bổ sung nếu Zend đã đọc hoặc kiểm tra nó trong callback hoặc helper được quy thuộc đúng callback.
- Chỉ tạo version mới khi tập field của config có thêm thông tin. Version là lịch sử cập nhật theo trace, không phải số thứ tự từng param.
- Tập field của version kế tiếp là hợp của tập đã biết và tập mới trong cùng candidate/context. Việc trace mới không chạm lại field cũ không làm mất field đã biết.
- Context gồm endpoint, callback, auth và method. Bằng chứng của context khác được xử lý trong candidate tương ứng.
- Config tổng hợp phải qua gate callback hiện có trước khi thành final. Nếu replay thất bại, lưu trạng thái và draft theo luồng partial hiện có, kèm lý do và đầy đủ tập field đã quan sát. Final đã xác minh trước đó tiếp tục dùng được.
- Param từ guard là bằng chứng quan sát truy cập. Gate callback xác nhận request chạy tới callback. Báo cáo giữ rõ hai mức bằng chứng này.

## Ví dụ nghiệm thu Cookie Notice

Trace p1 đã lưu tại `phuzz-main/code/fuzzer/output/online-linked/cookie-notice-20261103T093458Z/campaigns/089caeb9698720d4/versions/v0/probe/p1/` có 5 tên POST.

Một config được dựng từ trace đó phải có body như sau.

| Vai trò | Param |
|---|---|
| Fixed | `nonce` |
| Fuzz | `cn_network`, `notice_action`, `save_cookie_notice_options`, `reset_cookie_notice_options` |

Nếu trace sau quan sát thêm `param`, một version kế tiếp bổ sung `param` vào tập fuzz. Việc quan sát được tên field không chứng minh nhánh xử lý đã thực thi.

## Những điểm cần kiểm tra khi review

1. Helper guard có provenance đúng nhưng key vắng mặt vẫn được nhận. Event sai callback hoặc run bị loại.
2. GET bootstrap gặp POST access phải xác minh chuyển method bằng một POST request. Các field từ trace POST được nhận cả nhóm.
3. Trace mới chỉ đọc một phần field cũ vẫn giữ đủ tập tích lũy, cùng source/path rõ ràng.
4. Replay config tổng hợp thất bại phải để lại draft đầy đủ và lý do. Việc retry hoặc resume không tạo thêm version cho cùng tập field.
5. Field save/reset cùng xuất hiện làm nhánh save được ưu tiên. CmpLog hiện có hỗ trợ EMPTY đổi giá trị và ISSET xóa key. Gửi chuỗi rỗng vẫn làm `isset()` đúng.

## Task 1 — Nhận cả nhóm field từ cùng trace

**Files**

- `phuzz-main/code/fuzzer/zend_discovery/engine.py`
- `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py`
- `phuzz-main/code/fuzzer/seed_generation/convergence/convergence.py`
- `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`

**Interfaces**

Giữ cấu trúc kết quả `converge_iteration()` với `observed_parameters`, `new_parameters`, `known_parameters` và `pending_probes`. Dùng `advance_convergence_state()` và `materialize_convergence_seeds()` hiện có để tích lũy và dựng một seed.

- [ ] Viết regression test trace có read, isset và empty trên nhiều field, gồm key vắng mặt và helper. Assert toàn bộ field hợp lệ được trả về trong cùng `new_parameters`, một seed chứa đủ field và không sinh pending probe theo từng field.
- [ ] Test GET/POST cùng tên giữ hai transport. Test fixed selector và nonce giữ đúng vai trò. Test attribution, plugin, request/run và method sai bị loại.
- [ ] Chạy test mới để xác nhận thất bại trước khi sửa.
- [ ] Sửa `runtime_parameter_is_accepted()` và `normalize_runtime_evidence()` để AJAX nhận truy cập hợp lệ trên transport rõ ràng ngay từ trace. Giữ các kiểm tra correlation, attribution và method, cùng cách nhận REQUEST khi đã giải được transport.
- [ ] Sửa `converge_iteration()` để materialize toàn bộ nhóm ngay. Với GET bootstrap cần chuyển POST, dùng một method probe rồi lấy toàn bộ trace POST. Tránh tạo một probe cho từng POST field.
- [ ] Dùng hợp tập param trong convergence. Field cũ vắng trong trace mới trở thành thông tin đường chạy, không xóa khỏi tập tích lũy.
- [ ] Chạy lại regression tests và suite Zend discovery. Ghi riêng test skip cùng lý do.

## Task 2 — Một lần dựng config và replay cho cả nhóm

**Files**

- `phuzz-main/code/fuzzer/online_linked/coordinator.py`
- `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`
- `phuzz-main/code/fuzzer/online_linked/export.py` nếu cần điều chỉnh quy tắc superseded cho tập tích lũy
- `phuzz-main/code/fuzzer/tests/test_online_linked_export.py`

**Interfaces**

`_handle_convergence_result()` nhận danh sách param của cả trace. `_run_pending_probe()` và `_run_pending_probe_once()` chuyển đủ danh sách trong nhánh method transition hoặc checkpoint cũ. Gate giữ `verification_policy=callback_baseline_v1`.

- [ ] Viết test nhiều param từ một trace tạo đúng một child, một lần replay callback và một worker handoff. Test helper isset/empty không bị chặn lại ở `_probe_admission_complete()` vì request thiếu key.
- [ ] Test GET sang POST chỉ cần một POST method probe và một baseline. Mọi param hợp lệ trong trace POST đi vào cùng child.
- [ ] Test trace mới thêm một field giữ mọi field cũ. Trace lặp hoặc resume cùng tập field không tạo version trùng.
- [ ] Test replay thất bại giữ tập param tổng hợp trong draft và lỗi được ghi rõ. Callback, auth hoặc method sai vẫn chặn publish.
- [ ] Chạy test mới để xác nhận thất bại trước khi sửa.
- [ ] Sửa các caller nêu trên để truyền cả nhóm. Gỡ lọc theo một `target_key` ở nhánh nhận cả trace, và gỡ fallback tạo config con theo từng param trong luồng AJAX này.
- [ ] Bỏ nhánh thu nhỏ config theo `_coherent_only` cho các quan sát AJAX đã hợp lệ. Ghi một discovery event chứa cả nhóm và provenance của trace.
- [ ] Dùng exporter hiện có để supersede config cũ khi bản tổng hợp đã qua gate và bao phủ nó. Test final menu không còn nhiều file chỉ vì từng param được admit riêng. Lịch sử version vẫn truy vết được.
- [ ] Chạy test coordinator và exporter, xác nhận đọc được checkpoint/state lịch sử. Đối với hàng đợi probe cũ, xử lý cả nhóm quan sát mới và khử pending field đã được nhận.

## Task 3 — Xác minh với artifact và pipeline CmpLog

**Files**

- `phuzz-main/code/fuzzer/tests/test_cmplog.py`
- `phuzz-main/code/fuzzer/online_linked/README.md`
- `plugin-test-checklist.md` nếu thực sự tạo hoặc sửa config và hoàn thành kiểm tra scoped cho config đó

- [ ] Chạy lại các test CmpLog hiện có về EMPTY, ISSET remove và việc key đã xóa tiếp tục vắng trong HTTP request. Kiểm tra fixed/nonce và attribution được bảo vệ.
- [ ] Đọc lại cặp artifact p1 của Cookie Notice, normalize và materialize offline. Assert đúng 5 tên POST duy nhất, nonce fixed và 4 field fuzz như bảng nghiệm thu. Báo cáo đây là kiểm tra offline artifact.
- [ ] Với một lượt Cookie Notice mới, ghi run ID và kiểm tra version đầu tiên có param đã chứa trọn nhóm từ trace đầu tiên tương ứng. Xác minh gate callback, export và hoạt động worker bằng bằng chứng riêng.
- [ ] Kiểm tra hint CmpLog EMPTY/ISSET trong lượt mới bằng artifact và request sau mutation. Nếu chưa xuất hiện hint hoặc path mới, ghi đúng giới hạn quan sát.
- [ ] Cập nhật README mô tả nhận cả trace, tập tích lũy, gate callback và cách lưu partial khi replay thất bại.
- [ ] Khi hoàn thành kiểm tra config mới, cập nhật đúng row trong checklist với config path, ngày, bằng chứng và verdict. Fuzzing PASS chỉ ghi khi có kết quả tương ứng.
- [ ] Chạy `git diff --check`, review phạm vi và báo số test pass, fail, skip cùng giới hạn runtime. Chỉ stage các file thuộc yêu cầu khi được yêu cầu commit.

## Lệnh kiểm tra

Chạy ở `phuzz-main/code`. Đặt giới hạn 240 giây cho nhóm suite, ghi lại output khi timeout và không gọi kết quả đó là pass.

```powershell
python -c "import subprocess,sys; sys.exit(subprocess.run([sys.executable,'-m','unittest','fuzzer.tests.test_zend_discovery','fuzzer.tests.test_online_linked_coordinator','fuzzer.tests.test_online_linked_export','fuzzer.tests.test_cmplog'],timeout=240).returncode)"
```

Nếu Windows sandbox chặn temp directory bằng WinError 5, dùng temp root được phép hoặc chạy lại cùng test với quyền phù hợp. Phân biệt lỗi môi trường với assertion thất bại.

## Trạng thái plan

Plan mới được viết. Thay đổi triển khai thử trước đó đã được hoàn tác. Các bước trên cần được thực hiện và xác minh trong lượt triển khai.
