# Callback Context Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Đề xuất thực hiện trực tiếp trong chat hiện tại; chưa triển khai trong task lập kế hoạch.

**Goal:** Bootstrap đã chạy callback không làm mất candidate HTTP còn cần discovery; context tương đương không tạo vòng lặp hoặc nhận thêm budget.

**Architecture:** Tách coverage fact khỏi seed eligibility trong generator. Generator không quyết định callback đã được khám phá hết; coordinator dùng request-context key và checkpoint hiện có để quản lý công việc trong campaign. Giữ nguyên gate method, auth/setup, replay, Pass 2 và export.

**Tech Stack:** Python/unittest, PHP WordPress fixture, Windows PowerShell/pwsh, Docker Compose; không thêm dependency.

**Spec:** Yêu cầu mục 1 trong chat hiện tại; đối chiếu mục 1 của `docs/research/2026-10-20-deeper-config-discovery.md` và chat `codex://threads/01a159c3-132b-7a33-a126-13a19fc0b32e`.

## Phạm vi và giả định

- Thay đổi hành vi discovery của online-linked/runtime generator. Giữ hành vi mặc định của StaticSeedGenerator/generated mode và WIP hiện có. Đây là giả định phạm vi để tránh tác động chung từ lớp base.
- `status=covered/uncovered`, `execute_count` trong report và `executed_count` trong input vẫn mô tả thực thi thật. Không sửa số đếm, kể cả trên bản deepcopy.
- Callback có context đã xác minh vẫn có thể có context khác chưa xử lý. Không có trạng thái callback-level `discovery_complete`.
- Context được xác minh nghĩa là config cụ thể đạt gate tương ứng. Không đồng nhất với khám phá hết nhánh, semantic success hoặc vulnerability proof.
- Mục 2–5 của nghiên cứu không thuộc thay đổi này: không thêm selector hints, promotion theo branch coverage, bootstrap matrix, generic admin-post method probing hay resource recipes.
- Giới hạn dedupe/resume là cùng campaign và cùng môi trường đầu vào. Campaign mới được chạy lại; không tạo cache toàn cục giữa các DB/plugin/setup khác nhau.

## Bằng chứng source đã đối chiếu

- `seed_generation/skeleton/common_generator.py`: `build_reports()` lọc `uncovered`; `_generate_seed_templates()` trả `already_covered`. Hai gate đều cần xử lý, không chỉ bỏ một điều kiện.
- `seed_generation/skeleton/candidate_generator.py`: ngoại lệ admin-post hiện deepcopy payload rồi đặt `executed_count=0`; method correlation cần giữ, thủ thuật sửa coverage cần bỏ.
- `seed_generation/source_assisted/static_generator.py` dùng chung base. `seed_generation/skeleton/importer.py` còn kiểm tra `status == uncovered` trong `_is_replayable()` và `_is_manual_only()`.
- `online_linked/coordinator.py`: `_candidate_identity()` đã chuẩn hóa plugin/callback/entrypoint/hook/route/method/variant; chưa biểu diễn toàn bộ auth/fixed input/transport. Batch đã có `queued_ids`, checkpoint, progress keys và resume; không cần scheduler mới.
- `_config_request_key()` và `_probe_context_key()` đã phân biệt request context ở các bước sau. Phải tái sử dụng quy tắc hiện có, không tạo identity callback thứ hai.
- Coverage aggregate PHP giữ request ID/method/plugin/endpoint; request đầy đủ nằm ở artifact riêng. Có count hoặc method không đủ để dựng lại request đã chạy.

Các đường dẫn code trong tài liệu tính từ `phuzz-main/code/fuzzer/`, trừ khi ghi rõ từ repo root.

## Global Constraints

- Chỉ sửa file cần thiết; không reset/stash/xóa/ghi đè WIP, không stage bằng wildcard.
- Không cho hook nội bộ tự thành HTTP config. Inactive callback vẫn bị chặn.
- Không suy ra method/auth/setup đã xác minh từ việc callback từng chạy. Evidence sai callback/action/request/plugin không được dùng làm transport proof.
- Runtime generation tiếp tục không đọc source plugin.
- Config immutable; giữ lineage, hash, replay và Pass 2. Callback reached hoặc HTTP 200 không phải fuzzing PASS.
- Mọi test/Docker command có timeout hữu hạn. Không tăng ngân sách để che vòng lặp.
- Nếu tạo/fix config và hoàn thành scoped checks khi triển khai, cập nhật đúng hàng trong `plugin-test-checklist.md`, cùng task. Agent test không đánh dấu “Người dùng đã test”. Task chỉ lập kế hoạch không thêm hàng hoàn thành.

## Review Focus

1. Covered callback thiếu request artifact: vẫn có candidate template nếu entrypoint hợp lệ; không nâng metadata thành verified request.
2. Admin-post evidence sai action/method: có thể còn template ambiguous, nhưng tuyệt đối không kế thừa method đã bị bác bỏ.
3. Request ID, số lần chạy, timestamp hoặc thứ tự key thay đổi: không sinh context/budget mới.
4. Cùng callback khác auth, method, transport hoặc fixed selector: không bị gộp; context A verified không đóng context B.
5. Resume sau lỗi/gián đoạn: phục hồi pending work và ngân sách đã tiêu; không chạy lại terminal context từ đầu hoặc tự reset budget.

## Task 1: Tách seed eligibility khỏi coverage

**Files:**
- Modify: `seed_generation/skeleton/common_generator.py`
- Modify: `seed_generation/skeleton/candidate_generator.py`
- Modify: `seed_generation/skeleton/importer.py`
- Test: `tests/test_seed_generation_live_export.py`, `tests/test_seed_generation_importer.py`, `tests/test_seed_method_inference.py`
- Read/regression: `seed_generation/source_assisted/static_generator.py`, `cli/export_zend_seeds.py`, `seed_generation/config/config_exporter.py`

**Interfaces:**
- Giữ `build_reports(coverage_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]`.
- Thêm policy `_is_discovery_eligible(self, hook_name: str, is_active: bool, coverage_status: str, callback_metadata: dict[str, Any]) -> bool` ở base; runtime subclass override.
- Row và compact suggestion có additive `discovery_eligible: bool`, `discovery_reason: str`. Không đổi nghĩa field `status`.
- Base mặc định giữ active/uncovered. Runtime cho covered callback active có direct HTTP mapping thuộc các family đã hỗ trợ tiếp tục tạo template. Uncovered manual entries vẫn được report như trước.

- [x] Viết regression `test_bootstrap_execution_does_not_remove_runtime_http_candidate`: cùng AJAX callback với count 0 và 5 đều có seed; count 5 vẫn `covered`, `execute_count=5`, input không đổi, `fuzzing_ready=False` khi chưa có fuzzable field.
- [x] Thêm case REST đã chạy, inactive, hook nội bộ đã chạy, payload callback dạng mapping/list; chỉ entrypoint hợp lệ được admit. Static generator vẫn có output cũ với cùng fixture.
- [x] Chạy test để xác nhận case covered AJAX fail đúng ở eligibility, không do fixture/setup.
- [x] Dùng một policy cho cả chọn suggestion và tạo template. Bỏ mutation count trong runtime `build_reports()`; giữ kiểm tra correlation của admin-post trong method resolution.
- [x] Giữ `active_uncovered_callbacks` đếm đúng active/uncovered, không đổi thành số eligible. Thêm counter `discovery_eligible_callbacks` cho report; sửa thông báo Markdown không còn khẳng định mọi suggestion đều uncovered.
- [x] Importer ưu tiên `discovery_eligible` khi field có mặt; artifact cũ thiếu field dùng fallback `status == uncovered`. Giữ các gate seed shape/method/auth hiện có. Test import covered eligible, explicit ineligible và legacy artifact.
- [x] Điều chỉnh test admin-post mismatch: không còn buộc callback biến mất; assert method sai không được dùng, template ambiguous không trở thành replayable/fuzzing-ready config. Giữ case probe đúng vẫn dùng POST và coverage thật.
- [x] Chạy ba module test của task. Deliverable: covered HTTP callback tới được report/import/config admission, coverage vẫn trung thực và generated mode không đổi.

## Task 2: Dedupe theo context và giữ tiến độ qua resume

**Files:**
- Modify: `online_linked/coordinator.py`
- Test: `tests/test_online_linked_coordinator.py`
- Read/regression: `online_linked/export.py`, `tests/test_online_linked_export.py`

**Interfaces:**
- Giữ `_candidate_identity(item: Mapping[str, Any], plugin_slug: str) -> str` làm identity registration/target; không thay canonical callback ID hay registry format.
- Thêm `_candidate_context_key(item: Mapping[str, Any], plugin_slug: str) -> str` cho scheduling. Key là hash của identity hiện có cộng request descriptor chuẩn hóa từ seed: path/method/content type, auth mode, query/body/JSON/header/cookie placement, tên/role field và fixed values.
- Giá trị field được khai báo fuzzable dùng placeholder như `_config_request_key()`. Bỏ provenance/request ID/timestamp/count khỏi key; giữ kiểu dữ liệu và thứ tự array. Giá trị selector cố định phải khác key. Chỉ normalize nonce/token khi có role rõ ràng; không đoán theo tên field hoặc bỏ mọi cookie/header.
- Lưu context key ở candidate record và tập key đã enqueue trong batch/candidate checkpoint hiện có. Registration identity vẫn phục vụ registry/lineage; không dùng nó một mình để quyết định context đã xử lý.
- Giữ stage/terminal status và replay/Pass 2 evidence hiện có làm trạng thái context. Không thêm một state machine song song. “Đã thử nhưng bị chặn” khác “đã xác minh”, dù cả hai đều không được tự enqueue lặp lại.

- [x] Viết test duplicate initial seed + runtime rediscovery: enqueue một logical context; không cộng progress credit hoặc kéo dài deadline. Thay request ID/count/key order vẫn cùng key.
- [x] Viết test cùng callback khác auth, GET/POST, query/body và fixed `mode=list`/`mode=preview`: key khác; verified A không chặn B. Chỉ thay payload fuzzable không sinh key mới.
- [x] Viết test terminal failed/verified không tự enqueue lại; interrupted/pending resume đúng stage, giữ deadline/progress keys. Retry/replay có chủ đích vẫn được phép trong attempt cap hiện có, không đòi mỗi HTTP request chỉ được gửi một lần.
- [x] Chạy các test mới để xác nhận fail tại dedupe/context boundary hiện tại.
- [x] Gắn context key vào initial queue, runtime queue admission và resume/checkpoint; tái sử dụng batch state và budget helpers hiện có. Hai cách tới cùng context phải tạo cùng key.
- [x] Checkpoint cũ thiếu context-key version phải bị từ chối rõ ràng trước khi chạy worker; không tự diễn giải identity cũ thành context mới hoặc reset budget. Không sửa artifact cũ tại chỗ.
- [x] Đảm bảo snapshot input/registry/bootstrap vẫn được kiểm tra khi resume. Dedupe chỉ áp dụng trong campaign; không tái dùng kết quả khi người dùng chạy campaign mới với DB/setup khác.
- [x] Chạy coordinator/export regressions: normalization identity cũ giữ nguyên, queue hữu hạn, không thêm budget do coverage count, replay fail/Pass 2 reject không thành verified/exported.

## Task 3: Nghiệm thu callback thoát sớm từ bootstrap tới discovery

**Files:**
- Modify: `tests/fixtures/hookphuzz-online-discovery-fixture/hookphuzz-online-discovery-fixture.php`
- Test: `tests/test_seed_generation_live_export.py`, `tests/test_online_linked_coordinator.py`
- Modify: `online_linked/README.md`
- Modify khi có config đủ scoped checks: repo root `plugin-test-checklist.md`

- [x] Thêm một AJAX action fixture riêng, giữ endpoint cũ: thiếu `mode` thì return; có `mode` mới đọc `payload`. Không thêm source hints/selector search vào engine để làm fixture qua gate.
- [x] Offline integration: coverage bootstrap ghi count > 0; export giữ candidate, config builder nhận request replay-only, coordinator enqueue đúng một context. Chứng minh riêng candidate retention, chưa gắn nhãn deep-discovery PASS.
- [ ] Docker smoke trên fixture: pin code snapshot, fixture ZIP hash, DB/auth context và budget. Bootstrap gọi action thiếu `mode`, lưu request artifact chứng minh callback reached/early return; lấy snapshot rồi export và chạy campaign hữu hạn.
- [ ] Assert artifact mới: candidate không mất sau bootstrap; duplicate observation không thêm context/budget; resume không reset stage/deadline. Internal hook và method/auth evidence sai vẫn fail-closed.
- [ ] Request bootstrap chỉ được dùng nguyên request làm initial seed nếu artifact hiện có correlate đủ request/run/plugin/callback/hook/endpoint/method/auth và transport. Thiếu artifact thì dùng template và ghi rõ chưa tái sử dụng request. Không thêm collector/HAR/source extraction trong thay đổi này; việc nối một nguồn request mới là follow-up nếu chưa có đường nạp artifact phù hợp.
- [ ] Nếu kiểm tra đường sâu bằng request cung cấp sẵn `mode`, ghi đây là input của fixture test, không phải selector engine tự khám phá. Nếu phát sinh final config, giữ evidence replay và Pass 2 riêng; chưa qua gate thì verdict PARTIAL/NOT_VERIFIED, không ghi “Config xong”.
- [x] Ghi README về coverage/eligibility/context state, key normalization, giới hạn campaign và checkpoint compatibility. Không tạo config nên checklist không đổi.

Runtime evidence status (2026-10-20): NOT_VERIFIED. Read-only `docker ps` could not connect to the Docker Desktop Linux engine named pipe, so no WordPress containers, database, or authentication state were inspected or changed. Offline integration used the generated covered-callback template and did not reuse a bootstrap request artifact.

## Lệnh kiểm tra khi triển khai

Chạy từ `phuzz-main/code/fuzzer`, qua `rtk`; wrapper subprocess bảo đảm timeout 120 giây:

```powershell
rtk proxy python -c "import subprocess,sys; subprocess.run([sys.executable,'-m','unittest','tests.test_seed_generation_live_export','tests.test_seed_generation_importer','tests.test_seed_method_inference','tests.test_seed_to_config_exporter','tests.test_online_linked_coordinator','tests.test_online_linked_export','tests.test_phuzz_wrapper_contract','tests.test_online_linked_only'],timeout=120,check=True)"
```

Docker smoke dùng campaign cap 120 giây, candidate cap 4, version cap 2, outer process timeout 300 giây; mọi container exec/request có timeout. Lưu command thực tế và run ID vào evidence. Không chạy fuzz campaign dài để nghiệm thu sửa eligibility.

## Điều kiện hoàn tất

1. Count > 0 không tự loại callback HTTP active khỏi discovery; cả report và input coverage giữ số đếm thật.
2. Request context trùng không tạo vòng lặp hoặc budget mới, kể cả qua runtime rediscovery/resume.
3. Context khác của cùng callback vẫn được xét; verified context không đóng toàn callback.
4. HTTP/method/auth/setup/dedupe/replay/Pass 2 vẫn được kiểm tra riêng. Generated-mode regressions và offline suite qua; runtime kết luận dựa trên artifact mới.
5. Review diff chỉ gồm scope trên; chỉ stage các file đã chọn khi có yêu cầu commit. Checklist đồng bộ nếu tạo/fix config và hoàn thành validation.

## Baseline của task lập kế hoạch — 2026-10-20

- Đã đọc chat tham chiếu và source hiện tại; chưa sửa implementation/config/fixture.
- 42 test offline PASS trong 1,031 giây: `test_seed_generation_live_export`, `test_seed_generation_importer`, `test_seed_method_inference` và test coordinator `test_candidate_identity_uses_one_normalized_contract_and_ignores_legacy_identity`; outer timeout 120 giây.
- Chưa chạy Docker mới. Hiệu quả tăng discovery và runtime nghiệm thu thay đổi: NOT_VERIFIED.
- Kế hoạch tự review: mỗi tiêu chí nghiệm thu có task/test; chưa yêu cầu selector discovery hoặc tuyên bố callback đã khám phá hết. Rủi ro chính là candidate tăng và fingerprint gộp nhầm context; giữ hard cap và test cả equal/distinct context.

## Parent review và xác minh cuối — 2026-10-20

- GPT-6 Luna xhigh triển khai phần còn lại; parent review yêu cầu sửa mask field trùng tên giữa các transport, nested fixed data và canonicalization role metadata. Các regression đã RED → GREEN; parent kiểm tra lại ba repro độc lập đều PASS.
- Parent chạy lại tám module dự kiến: **247 test PASS trong 41,313 giây**, outer timeout 120 giây. PHP lint và harness riêng kiểm tra callback early return/payload đều PASS; `git diff --check` PASS.
- Không còn finding bắt buộc sửa trong scope đã review. Task 1–2 hoàn tất phần code/offline; Task 3 còn **PARTIAL** ở Docker smoke: named pipe `dockerDesktopLinuxEngine` không kết nối được. Chưa có bằng chứng runtime/fuzzing mới.
- Không tạo config bền vững, không thêm hàng checklist; không stage/commit/push. Checkpoint trước context-key v1 bị từ chối khi resume như thiết kế, không tự migrate hoặc reset budget.
