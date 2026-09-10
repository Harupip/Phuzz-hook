# Online Entrypoint Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task; use superpowers:subagent-driven-development only when delegation is authorized. Steps use checkbox (- [ ]) syntax for tracking.

**Goal:** Sửa các lỗi chọn mục tiêu online, hoàn thiện entrypoint đã có và bổ sung entrypoint còn thiếu với bằng chứng runtime từ request tới tham số và final replay.

**Architecture:** Giữ pipeline Python/UOPZ/Zend hiện tại. Chuẩn hóa cách chọn identity, cho online sử dụng toàn bộ callback đang active, thêm một vòng probe có giới hạn trước khi khởi động worker, rồi mở rộng lần lượt transport và loại entrypoint. Mỗi giai đoạn có thể nghiệm thu riêng; không viết lại coordinator hoặc thêm database/message queue.

**Tech Stack:** Python unittest, PHP WordPress/UOPZ, C Zend extension, PowerShell, Docker Compose.

**Spec:** [Audit 2026-09-07](C:/Users/hieu/Desktop/Phuzz-hook/Phuzz-hook/phuzz-main/code/docs/reports/online-entrypoint-audit-2026-09-07.md), kết hợp ràng buộc runtime trong [AGENT_HANDOFF.md](C:/Users/hieu/Desktop/Phuzz-hook/Phuzz-hook/phuzz-main/code/fuzzer/zend_discovery/AGENT_HANDOFF.md).

## 1. Mốc triển khai và phạm vi

- Checkout lúc lập kế hoạch: **codex/entrypoint-coverage-fixes**, HEAD **fcd1451**. Thay đổi heartbeat POST tương đương nội dung d619a48 trong audit; git diff giữa hai mốc không có thay đổi nội dung.
- Đây là kế hoạch; chưa triển khai các task bên dưới. Baseline 252/253 là kết quả audit trước, không phải kết quả test mới của lượt lập kế hoạch.
- ROOT trong tài liệu là C:/Users/hieu/Desktop/Phuzz-hook/Phuzz-hook/phuzz-main/code. Các đường dẫn trong bảng Files được tính từ ROOT.
- Triển khai theo A → B → C → D → E → F. Trong một giai đoạn vẫn theo phụ thuộc từng task; chưa cần chạy nhiều agent.
- Các loại endpoint mới có thể dùng setup recipe được khai báo rõ. Recipe hỗ trợ chuẩn bị request, không được dùng làm bằng chứng callback/parameter đã thực thi.
- Phủ đầy đủ báo cáo không đồng nghĩa tự xử lý mọi plugin WordPress: regex/schema/protocol không thuộc tập hỗ trợ phải có trạng thái blocked với lý do cụ thể.

## 2. Ràng buộc chung

1. Không thay đổi, stage hoặc xóa các file untracked không thuộc task, đặc biệt research/ và output/config do lượt chạy khác tạo ra.
2. Runtime-only không đọc source plugin để đoán tham số. Schema, tên accessor và regex chỉ cung cấp candidate/probe; tham số fuzz phải có runtime provenance.
3. Không tắt callback correlation, request/run/plugin identity, method, auth hoặc kiểm tra event loss để làm test qua.
4. Không coi HTTP 200, callback_reached hay CONVERGED riêng lẻ là fuzzing-ready. Có thể callback đã tới nhưng không có đầu vào HTTP fuzz được.
5. Giữ config worker bất biến. Chỉ chuyển sang child sau replay đúng target và provenance của tham số mới được xác minh.
6. Dùng Python unittest hiện có; không bắt buộc thêm pytest, thư viện sinh regex hoặc framework workflow.
7. Giữ chức năng source-assisted và compatibility reexports. Thay implementation ở module chủ quản, không nhân đôi logic trong shim hook_energy.
8. Nonce/auth là dữ liệu cố định hoặc recipe runtime. Không ghi giá trị credential/nonce vào báo cáo, comparison dictionary hay log công khai. Negative control dùng verifier thật khi đánh giá strict proof.
9. Live acceptance chạy WordPress fixture trong môi trường test có run-id riêng. Setup page/post/rewrite/file chỉ chạm tài nguyên tạo cho run đó; lưu manifest cleanup, không reset DB dùng chung.
10. Unit test dùng fake clock/runner/artifact loader; không khởi động container ngầm. PHP/C acceptance dùng image Dockerfile.zend đang có.

## 3. Quyết định thiết kế

Có ba hướng: vá riêng từng plugin; viết lại toàn bộ discovery; hoặc sửa lõi rồi bổ sung từng adapter. Chọn hướng thứ ba vì giữ được correlation/replay hiện có và mỗi phần có thể kiểm chứng độc lập.

### 3.1 Identity và candidate

Tái sử dụng candidate_from_seed_item(), canonical_identity_id() và khóa variant hiện có trong bridge_cli. Khóa chọn worker phải phân biệt plugin, callback, entrypoint/dispatcher, action hoặc route, HTTP method, auth variant và seed_variant_id. Không dùng request_id/run_id làm identity ổn định giữa các version.

Cùng URL nhưng khác action không khớp. Cùng callback nhưng GET/POST là hai target. Nếu bootstrap thiếu auth/callback metadata và có nhiều lựa chọn còn phù hợp, trả BLOCKED_BOOTSTRAP_AMBIGUOUS; không lấy phần tử đầu.

### 3.2 Trạng thái và bằng chứng

Giữ state hiện tại, thêm các trường vào summary; không thay schema cũ bằng một schema mới bắt buộc:

```json
{
  "candidate_key": "stable-id::variant",
  "entrypoint_type": "ajax",
  "registration_seen": true,
  "probe_attempted": true,
  "callback_reached": true,
  "observed_parameter_count": 1,
  "exported_fuzz_parameter_count": 1,
  "final_replay_status": "PASS",
  "outcome": "VERIFIED_FUZZABLE",
  "reason": ""
}
```

Outcomes: VERIFIED_FUZZABLE, VERIFIED_REPLAY_ONLY, BLOCKED, FAILED, NOT_ATTEMPTED_BUDGET. Convergence vẫn là trạng thái thuật toán, không thay outcome. VERIFIED_REPLAY_ONLY phải có callback proof nhưng 0 fuzz parameter; không tự nâng thành VERIFIED_FUZZABLE. Campaign không có target hợp lệ là NO_ELIGIBLE_TARGETS, không PASS.

### 3.3 Giới hạn mặc định được đề xuất

Giữ deadline online hiện tại 60 giây. Bổ sung max_targets=8 (1..32), max_probe_requests_per_target=2 (1..8), probe_timeout_seconds=8 (1..15), max_versions_per_target=2 (1..20), max_total_worker_starts=20 (1..100). Mọi timeout cấp con phải min(timeout cấu hình, deadline còn lại). Hết budget ghi NOT_ATTEMPTED_BUDGET cho phần chưa chạy.

Depth provenance mặc định 4, tối đa 8; nested path tối đa 8 segment; tối đa 64 leaf parameter/target. Schema/probe body tối đa 16 KiB. Đây là giới hạn mới của kế hoạch, không phải khả năng đã có. Instrumentation không đủ bằng chứng hoặc vượt giới hạn phải báo lý do, không âm thầm cắt dữ liệu rồi coi là đủ.

## 4. Bản đồ file và trách nhiệm

| Nhóm | File hiện có cần chỉnh | File mới dự kiến |
| --- | --- | --- |
| Identity/V0 | fuzzer/hook_energy/seed_generation/online_config_runner.py; online_linked_coordinator.py; zend_runtime/bridge_cli.py | Không cần module identity mới nếu helper hiện tại đủ dùng. |
| Catalog | fuzzer/seed_generation/skeleton/common_generator.py; candidate_generator.py; pipeline/pipeline.py; fuzzer/cli/export_zend_seeds.py | Không tạo catalog format mới. |
| Auth/probe/setup | fuzzer/discovery/wordpress/bootstrap_probe_runner.py; fuzzer/fuzzer.py; scripts/wordpress/run-wordpress-phuzz.ps1 | fuzzer/discovery/wordpress/entrypoint_probes.py; setup_recipes.py |
| Provenance | fuzzer/zend_discovery/engine.py; extension/hookphuzz_opcode.c; extension/php_hookphuzz_opcode.h; fuzzer/instrumentation/zend/rest/runtime.py | Test fixture/proof files theo task. |
| Export/request | fuzzer/seed_generation/config/config_exporter.py; convergence/convergence.py; fuzzer/core/candidate.py; fuzzer/fuzzer.py | fuzzer/core/body_serialization.py cho XML/multipart. |
| Campaign | online_linked_coordinator.py; wrapper PowerShell | fuzzer/hook_energy/seed_generation/online_campaign.py |
| Registration | web/instrumentation/hook_coverage/uopz_hook_wp.php; fuzzer/discovery/entrypoints/classifier.py; entrypoints.py | Fixture shortcode/rewrite/XML-RPC. |
| Acceptance | tests hiện có; scripts/wordpress/run-wordpress-plugin-matrix.ps1 | scripts/wordpress/build-test-fixtures.py; fuzzer/cli/summarize_entrypoint_acceptance.py |

Các tên viết ngắn trong mục Files được resolve theo quy ước duy nhất dưới đây (đều tương đối với ROOT). Đây cũng là danh sách vị trí chỉnh implementation, không sửa shim tương thích thay cho module chủ quản:

| Tên viết ngắn | Vị trí đầy đủ |
| --- | --- |
| online_config_runner.py / online_linked_coordinator.py / online_campaign.py / generated_config_runner.py | fuzzer/hook_energy/seed_generation/<tên file> |
| zend_runtime/bridge_cli.py | fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py |
| skeleton/* / pipeline/* / convergence/* khi nói về seed generation | fuzzer/seed_generation/<đường dẫn> |
| discovery/* / instrumentation/* / zend_discovery/* / core/* | fuzzer/<đường dẫn> |
| entrypoint_probes.py / setup_recipes.py | fuzzer/discovery/wordpress/<tên file> |
| uopz_hook_wp.php | web/instrumentation/hook_coverage/uopz_hook_wp.php |
| test_*.py / tests/test_*.py | fuzzer/tests/<tên file> |
| fixtures/<slug>/<file.php> | fuzzer/tests/fixtures/<slug>/<file.php> |
| hookphuzz-rest-probe-only-fixture khi không ghi file | fuzzer/tests/fixtures/hookphuzz-rest-probe-only-fixture/hookphuzz-rest-probe-only-fixture.php |

Tên file mới là quyết định của kế hoạch; chưa tồn tại. Các signature/test snippets là contract dự kiến để người triển khai viết regression, không phải mã đã cài.

## 5. Giai đoạn A — Sửa lỗi lõi, tái lập baseline

### Task 01 — Fixture có thể dựng lại từ checkout sạch

**Files:** Create scripts/wordpress/build-test-fixtures.py; modify fuzzer/tests/test_online_plugin_fixture.py; bổ sung fixture heartbeat đang untracked vào change có chủ đích. Output ZIP: web/applications/wordpress/_plugins/<slug>.zip.

**Phụ thuộc:** Không. **Đầu ra:** CLI nhận --slug, chỉ đọc tests/fixtures/<slug>; đóng ZIP với root <slug>/, thứ tự member ổn định, timestamp ZIP cố định. Thiếu source hoặc slug đi ra ngoài fixtures trả lỗi.

- [ ] Thêm regression trong test_online_plugin_fixture: đóng archive vào TemporaryDirectory và so source member với file gốc; không để unit test phụ thuộc ZIP generated nằm trong checkout.
- [ ] Kiểm thử slug không tồn tại và ../escape đều bị từ chối; thiếu source không sinh ZIP rỗng.
- [ ] Cài packager bằng zipfile stdlib; live wrapper/acceptance gọi packager cho fixture trước khi kiểm tra plugin ZIP. Không đổi cơ chế plugin thật.
- [ ] Chạy lệnh dưới; kiểm tra manifest ZIP và nguồn bằng digest.
- [ ] Commit riêng: build: make WordPress fixtures reproducible.

```powershell
# Chạy tại ROOT
python scripts/wordpress/build-test-fixtures.py --slug hookphuzz-online-discovery-fixture
python scripts/wordpress/build-test-fixtures.py --slug hookphuzz-heartbeat-fixture
# Chạy tại ROOT/fuzzer
python -m unittest discover -s tests -p 'test_online_plugin_fixture.py' -v
```

**Nghiệm thu:** Clone/checkout sạch dựng được fixture; test không đòi artifact từ máy trước. Unit ZIP test PASS và fixture ZIP dùng được với wrapper.

### Task 02 — Sửa bootstrap selector để không ghép nhầm action

**Files:** Modify online_config_runner.py, online_linked_coordinator.py; test fuzzer/tests/test_online_config_runner.py và test_online_linked_coordinator.py.

**Phụ thuộc:** 01. **Interface giữ:** _seed_matches_target(item, config) -> bool; thêm helper select_bootstrap_seed(items, config) -> item, hoặc raise OnlineConfigError với BOOTSTRAP_NO_MATCH/BOOTSTRAP_AMBIGUOUS.

- [ ] Thêm test alpha/beta theo regression audit. Test action ở query string URL, query_params và body_params; action trùng nhưng values khác ở query/body phải reject.
- [ ] Chạy test để xác nhận code cũ ghép alpha cho beta.
- [ ] Chuẩn hóa selectors từ URL và các section fixed; so method/auth/callback metadata nếu có. Metadata không được ghi đè identity bootstrap đã khai báo khác. Bootstrap thiếu auth chỉ được chọn khi duy nhất, sau replay xác nhận đúng context.
- [ ] Collect tất cả match rồi yêu cầu duy nhất; không return ở match đầu. REST đối chiếu namespace/path gồm fallback ?rest_route=.
- [ ] Chạy các test và commit: fix: bind bootstrap configs to exact entrypoint identity.

```python
# Regression cốt lõi trong unittest; dữ liệu alpha/beta dùng builder seed_item/config hiện có.
self.assertFalse(_seed_matches_target(alpha_item, beta_bootstrap))
self.assertTrue(_seed_matches_target(beta_item, beta_bootstrap))
self.assertEqual(select_bootstrap_seed([alpha_item, beta_item], beta_bootstrap), beta_item)
```

**Nghiệm thu:** AJAX/admin-post khác action không bao giờ ghép; REST fallback đúng; auth/method mâu thuẫn fail có lý do. Không phụ thuộc thứ tự seed.

### Task 03 — Chọn đúng method/variant của REST target

**Files:** Modify online_linked_coordinator.py, zend_runtime/bridge_cli.py; test test_online_linked_coordinator.py, test_zend_discovery.py.

**Phụ thuộc:** 02. **Interface mới:** seed_target_key(item, *, plugin_slug) -> str trong bridge_cli; dùng canonical_identity_id(candidate_from_seed_item(...)) cộng suffix seed_variant_id. Các hàm _candidate_iteration_key đang có gọi cùng helper; legacy_run_id vẫn truyền vào nơi cần correlation nhưng không nằm trong khóa ổn định.

- [ ] Test generator REST thật tạo GET/POST; exporter thật xác nhận cả hai hợp lệ; selector chọn đúng variant chứ không None.
- [ ] Test form/JSON probe variants cùng callback không bị gộp; đổi run-id không đổi stable key, đổi method/auth/action đổi key.
- [ ] Thay matching hook+callback bằng seed_target_key của config/item đã chọn. Selection thử target tiếp theo nếu item hiện tại không hợp lệ, giữ reason riêng thay vì hỏng cả danh sách.
- [ ] Dùng đúng key xuyên suốt _target_key, materialize/export/replay và metadata child; không chọn lại bằng callback-only khi handoff.
- [ ] Chạy test và commit: fix: select online REST targets by method and variant.

```python
self.assertNotEqual(seed_target_key(get_item, plugin_slug='fixture'),
                    seed_target_key(post_item, plugin_slug='fixture'))
self.assertEqual(selected_key, seed_target_key(selected_item, plugin_slug='fixture'))
```

**Nghiệm thu:** GET/POST và form/JSON có thể được chọn độc lập; replay GET không thỏa proof cho POST; trace không thay callback giữa các version.

### Task 04 — Giữ covered callback trong catalog online

**Files:** Modify skeleton/common_generator.py, skeleton/candidate_generator.py, pipeline/pipeline.py, fuzzer/cli/export_zend_seeds.py, scripts/wordpress/run-wordpress-phuzz.ps1; tests test_seed_generation_live_export.py, test_entrypoint_pipeline.py, test_phuzz_wrapper_contract.py.

**Phụ thuộc:** 03. **Interface mới:** build_reports(payload, *, include_covered=False); write_artifacts(payload, output_dir, *, include_covered=False); run_entrypoint_pipeline(..., include_covered=False). CLI thêm --include-covered. Truyền tham số xuống gate tạo template, không sửa executed_count thành 0.

- [ ] Test cùng registration count=0/count=1 cho online vẫn sinh target. inactive bị loại; uncovered report mặc định giữ behavior cũ.
- [ ] Giữ status=covered và counters thật; tính số online candidate riêng, không gọi covered là uncovered.
- [ ] Wrapper truyền --include-covered cho RunOnline/RunOnlineLinked. Candidate registry theo plugin hiện tại phải bao gồm callback covered để Zend target loading có thể theo dõi nó.
- [ ] Test CLI thật đọc fixture JSON và output file; không chỉ assert chuỗi flag trong PowerShell.
- [ ] Chạy test và commit: fix: retain active covered callbacks for online discovery.

```python
_, report = generator.build_reports(covered_payload, include_covered=True)
self.assertEqual(len(report['suggested_seeds']), 1)
self.assertEqual(report['suggested_seeds'][0]['status'], 'covered')
```

**Nghiệm thu:** Bootstrap đã gọi AJAX/REST vẫn chọn được V0; báo cáo coverage cũ không bị đổi ý nghĩa. Chưa đưa inactive callback vào worker.

### Task 05 — Cố định đường dẫn và hoàn tất LearnPress nonce proof

**Files:** Modify scripts/wordpress/run-wordpress-phuzz.ps1; tests test_learnpress_admin_post_proof.py, test_phuzz_wrapper_contract.py.

**Phụ thuộc:** 04. **Interface:** Một $activeSeedOutputDir và $activeSuggestedSeedsPath resolve sau khi chọn mode; export, nonce injection, registry và coordinator dùng chung. Tách helper PowerShell chỉ khi cần để test bằng dot-source mà không chạy main.

- [ ] Test online path khác legacy path; helper phải chỉ thay file online và giữ file cũ byte-for-byte. Exact target count=0/2 trả lỗi có thông tin target.
- [ ] Sửa path; truyền key/path rõ ràng, không đọc file từ lượt trước nếu thiếu file current run.
- [ ] Tái kiểm tra blocker nonce-eval cũ trong runtime test. Thu stdout/stderr/exit code/type riêng; parse JSON object có sentinel riêng và không in nonce. Test stdout nhiều dòng, stderr warning, output rỗng và exit !=0.
- [ ] Live negative control nonce sai bị reject; nonce hợp lệ được original verifier chấp nhận, đúng callback và một parameter path được Zend quan sát; final replay fresh cùng auth context.
- [ ] Commit: fix: scope LearnPress nonce enrichment to current run.

```text
input: online run X + stale legacy seed Y
expected: only X changes; callback/action equal proof; Y unchanged
invalid nonce: original verifier rejects, handler false
valid nonce: original verifier accepts, callback true, exported parameter >=1, final replay PASS
```

**Nghiệm thu A:** Ba regression P1 không tái hiện; ZIP fixture tái lập; path injection đúng; LearnPress có valid nonce, observed parameter và fresh final replay. Có thể giao riêng bản sửa 01–04 trước; nếu nonce orchestration còn blocked thì task 05 và gate A đầy đủ vẫn chưa hoàn tất, phải giữ issue/bằng chứng nguyên nhân.

## 6. Giai đoạn B — Hoàn thiện entrypoint HTTP đã có

### Task 06 — Kiểm chứng auth/anonymous đúng context

**Files:** Modify fuzzer/fuzzer.py, seed_generation/config/config_exporter.py, online_config_runner.py, generated_config_runner.py, web/applications/wordpress/_overrides/99-wordpress.php; tests test_online_config_runner.py, test_generated_config_runner.py; create tests/test_entrypoint_auth_context.py.

**Phụ thuộc:** 02, 04. **Interface:** Giữ auth_mode của seed; bổ sung proof auth_context = {authenticated: bool, user_id: int, role: str}. Metadata report chỉ lưu trạng thái, không cookie. Không đổi unauth-capable toàn hệ thống thành authenticated khi một replay thất bại.

- [ ] Test request prepared của nopriv không mang WordPress login/auth header/cookie kể cả bootstrap/session có dữ liệu cũ. Cookie ứng dụng không phải auth vẫn được giữ để task 12 có thể fuzz.
- [ ] Test authenticated target với public proof không qua; nopriv target với authenticated proof không qua. Endpoint có cả hai hook phải chạy hai request tách context.
- [ ] Đối chiếu _disable_auth_cookies/_without_auth_cookies hiện có trước khi sửa; trace runtime override có ép login hay không. Chỉ sửa lớp gây sai context.
- [ ] Đưa auth proof vào correlation/final validation. Thiếu credential dùng BLOCKED_AUTH_REQUIRED; thiếu auth evidence dùng AUTH_CONTEXT_UNVERIFIED, không tự nhận expected_auth_skip.
- [ ] Live fixture có callback auth và nopriv trả marker riêng; lưu hai artifact request-id khác nhau. Commit: fix: verify authentication context per entrypoint.

```python
self.assertFalse(anonymous_proof['authenticated'])
self.assertEqual(anonymous_proof['user_id'], 0)
self.assertTrue(authenticated_proof['authenticated'])
self.assertNotEqual(auth_request_id, anonymous_request_id)
```

**Nghiệm thu:** Hai branch đều có proof độc lập, nopriv không được đánh dấu pass từ authenticated counterpart.

### Task 07 — Cho action-only/replay-only seed bắt đầu bằng probe có giới hạn

**Files:** Create fuzzer/discovery/wordpress/entrypoint_probes.py; modify online_linked_coordinator.py, zend_runtime/bridge_cli.py, skeleton/candidate_generator.py; create tests/test_entrypoint_probes.py, extend test_online_linked_coordinator.py.

**Phụ thuộc:** 03, 04, 06. **Interfaces mới:**

```python
# entrypoint_probes.py
build_probe_requests(item: dict, *, max_requests: int = 2) -> list[dict]
# mỗi dict: method, path, query_params, body, headers, auth_mode, probe_variant_id
# giá trị request chỉ nằm trong artifact riêng của test/run, không summary công khai
# coordinator method
bootstrap_target(item: dict, *, deadline: float) -> dict
# trả outcome, reason, candidate_key, seed_item; không khởi chạy fuzz worker khi replay_only
```

- [ ] Test seed chỉ action không bị loại ngay bởi validate_v0_config; thay vì vậy probe POST/GET được gọi trong budget và chỉ khi method hợp lệ cho family.
- [ ] Test callback-only proof nhưng không có param trả VERIFIED_REPLAY_ONLY; không tạo worker giả với action hoặc nonce làm fuzzable.
- [ ] AJAX/admin-post/admin_action/login: probe method chưa rõ bằng template riêng, giữ action cố định. Method probe là giả thuyết; chỉ runtime observation correlate đúng mới là method evidence.
- [ ] REST dùng declared methods và schema/name-only để tạo probe-only typed sentinel; không nâng schema thành fuzz evidence. Chạy normalize/convergence hiện có sau khi request/Zend artifacts được correlate.
- [ ] Tất cả I/O nhận deadline; budget hết giữa hai probe không chạy request tiếp. Missing artifact ghi BLOCKED_NO_PROBE_EVIDENCE, không reuse artifact cũ.
- [ ] Sau proof và export_count>=1 mới replay config rồi start V0; input bootstrap config sẵn fuzz vẫn phải được correlate. Commit: feat: bootstrap online discovery from replay-only seeds.

```text
action-only → probe callback → Zend sees query q → export q → fresh replay → start V0
control 1: callback true, no q evidence → VERIFIED_REPLAY_ONLY, worker starts=0
control 2: wrong request-id → BLOCKED, worker starts=0
control 3: deadline expired → NOT_ATTEMPTED_BUDGET
```

**Nghiệm thu:** Không còn vòng phụ thuộc “phải có fuzz param mới khám phá được fuzz param”; vẫn không fuzz khi chỉ có method/schema suy đoán.

### Task 08 — Bổ sung admin_action và probe action/method tổng quát

**Files:** Modify discovery/entrypoints/entrypoints.py, skeleton/common_generator.py, skeleton/candidate_generator.py, discovery/wordpress/entrypoint_probes.py, scripts/wordpress/run-wordpress-phuzz.ps1; extend fixtures/hookphuzz-entrypoint-direct-fixture/hookphuzz-entrypoint-direct-fixture.php; tests test_entrypoints.py, test_seed_generation_live_export.py, test_entrypoint_probes.py.

**Phụ thuộc:** 07. **Đầu ra:** admin_action_* đi qua allowlist/template/export/replay; admin-post/login không chỉ dựa vào adapter plugin cụ thể. Probe registration lặp theo action mới, tối đa max_targets, không scan source.

- [ ] Fixture thêm AJAX GET-only và POST-only, admin_post auth/nopriv, admin_action và login_form_custom với marker và HTTP input riêng.
- [ ] Test admin_action tạo seed path /wp-admin/admin.php, action cố định đúng transport. Registry-only chưa đủ method vẫn probe-only; không gọi GET suy đoán là runtime_observed.
- [ ] Probe các action lấy từ runtime registrations; sau mỗi request merge registrations mới cùng plugin và dedupe stable key. Conditional registration dựa trên action được kiểm tra bằng fixture.
- [ ] Login action trên query string kể cả POST body có input; không làm mất action khi _place_action_for_method chạy. Capability/nonce thiếu trả reason setup/auth riêng.
- [ ] Chạy fixture từng family với positive và wrong-action negative control; commit: feat: probe direct WordPress entrypoints by action.

```python
self.assertEqual(admin_action_seed['path'], '/wp-admin/admin.php')
self.assertEqual(login_post_seed['query_params']['action'], 'hookphuzz_login_probe')
self.assertNotIn('action', login_post_seed['fuzzable_params'])
```

**Nghiệm thu:** admin_action được export/replay thực; AJAX GET-only có GET proof; admin_post/login plugin action không phải LearnPress cũng được thăm. Hết budget báo các action chưa thử, không gọi chúng là unsupported.

### Task 09 — Hoàn tất heartbeat từ callback argument tới final replay

**Files:** Modify fixtures/hookphuzz-heartbeat-fixture/hookphuzz-heartbeat-fixture.php, entrypoint_probes.py, zend_discovery/extension/hookphuzz_opcode.c và php_hookphuzz_opcode.h nếu trace chỉ ra thiếu propagation, zend_discovery/engine.py, convergence/convergence.py; tests test_zend_discovery.py; create tests/test_heartbeat_runtime_contract.py.

**Phụ thuộc:** 06, 07. **Đầu ra:** provenance của HTTP POST data[hookphuzz_probe] qua filter argument vẫn giữ source=POST và path=['data','hookphuzz_probe']; screen_id là input riêng nếu được quan sát. Để fixture thành regression tracked trong task 01.

- [ ] Tái hiện run heartbeat trong môi trường test; xem lần lượt HTTP request, UOPZ callback, Zend argument/array provenance, engine normalization và final export. Lưu root cause trước khi sửa C.
- [ ] Test đối số local array cùng tên không có HTTP origin phải bị loại. Thêm fixture đọc $_POST trực tiếp làm positive control để phân biệt mất instrumentation và mất propagation.
- [ ] Sửa propagation ở lớp làm mất nguồn; nested path được serialize bracket notation. Tách selector cố định action/_nonce khỏi field dữ liệu probe: data[hookphuzz_probe] có thể fuzz sau khi có proof, không khóa nó vĩnh viễn vì nằm trong template ban đầu.
- [ ] Chuẩn bị nonce heartbeat thật cho authenticated context trong strict proof. Chạy public hook với session anonymous từ task 06; nonce policy thực tế tuân WordPress local runtime, không ép public dùng user đã login.
- [ ] Final replay fresh: callback đúng auth variant, nested field đúng request transport, ít nhất một field dữ liệu fuzzable; negative control thiếu data hoặc sai nonce/auth không được công nhận pass.
- [ ] Commit: fix: preserve heartbeat input provenance through filter callbacks.

```json
{
  "source": "POST",
  "path": ["data", "hookphuzz_probe"],
  "name": "data[hookphuzz_probe]",
  "location": "form",
  "fuzzable": true
}
```

**Nghiệm thu B:** AJAX GET/POST, auth/nopriv admin-post, admin_action, custom login và hai heartbeat hooks có fixture proof độc lập. Heartbeat callback-only không còn được ghi như fuzz success. Nếu plugin không có HTTP input thực thì VERIFIED_REPLAY_ONLY là kết quả hợp lệ, không tạo input giả.

## 7. Giai đoạn C — Hoàn thiện tham số và transport

### Task 10 — Nested parameters và helper-call provenance

**Files:** Modify zend_discovery/engine.py, zend_discovery/extension/hookphuzz_opcode.c, extension/php_hookphuzz_opcode.h, zend_runtime/bridge_cli.py, seed_generation/convergence/convergence.py, seed_generation/parameters/parameter_seeds.py; extend fixtures/hookphuzz-dynamic-helper-fixture/hookphuzz-dynamic-helper-fixture.php; tests test_zend_discovery.py, test_cmplog_extension.py.

**Phụ thuộc:** 09. **Interface:** unique_parameters giữ path dạng list[str|int], source, helper_depth, origin_callback, request_id, call ancestry token. Dùng field provenance extension đã có nếu đáp ứng; thêm field optional khi thiếu, bảo toàn reader artifact cũ.

- [ ] Regression $_POST['settings']['email'], helper đọc input rồi trả kết quả, hai callback gọi cùng helper, nested integer index và parent+leaf xuất hiện đồng thời.
- [ ] Trace extension trước khi bỏ len(path)==1/helper_depth==0 trong Python. Chỉ nhận helper có ancestry gắn target callback của cùng request; không coi mọi helper-depth>0 là hợp lệ.
- [ ] Serialize settings[email] cho form/query, giữ nested object cho JSON. Khi leaf có bằng chứng, không fuzz parent thay cho leaf; parent-only được ghi riêng và chưa suy ra mọi child.
- [ ] Áp dụng giới hạn depth/path/leaf ở mục 3.3; quá giới hạn ghi PROVENANCE_DEPTH_EXCEEDED hoặc PARAMETER_LIMIT_EXCEEDED. Event loss/partial registry vẫn fail closed.
- [ ] Sửa pass2 verifier dùng cùng identity/path normalization để không có trường hợp exporter nhận nhưng verifier bỏ. Chạy C/runtime fixture và unit tests, commit: feat: retain bounded nested and helper input provenance.

```python
self.assertIn(('POST', ('settings', 'email')), observed_identities)
self.assertNotIn(('POST', ('settings',)), exported_leaf_identities)
self.assertEqual(unrelated_helper_parameters, [])
```

**Nghiệm thu:** Direct/helper path có cùng identity đầu vào, không lẫn callback hoặc run; final replay chứng minh đúng leaf.

### Task 11 — Mở rộng REST route và schema có giới hạn

**Files:** Modify discovery/wordpress/rest_routes.py, seed_generation/pipeline/pipeline.py, instrumentation/zend/rest/runtime.py, seed_generation/convergence/convergence.py; extend fixtures/hookphuzz-rest-probe-only-fixture; tests test_rest_method_generalization.py, test_rest_argument_schema_export.py, test_entrypoint_pipeline.py.

**Phụ thuộc:** 07, 10. **Interface:** materialize_rest_route(pattern, *, route_examples=None) giữ return shape hiện tại; route_examples là map group→typed example lấy từ recipe/runtime. Schema builder thêm bounded object/array trong probe_request, không tự thêm fuzzable_params.

- [ ] Test numeric, slug [a-z0-9-]+, [^/]+ và pattern có anchor; named group phải có substitution phù hợp, fullmatch kiểm tra. Generic recursion/backreference/lookaround vẫn blocked UNSUPPORTED_ROUTE_REGEX.
- [ ] Với optional/nested regex: cho phép request example từ recipe được match toàn pattern và ghi nguồn recipe; không viết general regex generator. Không có ví dụ hợp lệ thì block rõ ràng.
- [ ] Numeric ID dùng fixture/setup-created resource hoặc runtime-observed ID nếu có; nếu chỉ sentinel 1 và resource không tồn tại thì RESOURCE_PREREQUISITE_MISSING, không báo method/callback hỏng.
- [ ] Schema object/array primitive: depth<=4, array length<=2, enum primitive, required fields, typed boolean/number/string; hỗ trợ query/form/JSON qua proof. oneOf/allOf/custom schema không đủ recipe bị UNSUPPORTED_REST_SCHEMA.
- [ ] Test cùng key thấy ở nhiều location vẫn ambiguous; schema defaults không thành fuzz evidence; payload quá 16 KiB bị reject trước request. Commit: feat: materialize bounded REST routes and structured probes.

```text
/items/(?P<slug>[a-z0-9-]+) + example 'audit-item' → matching route
/items/(?P<id>\d+) + created resource id → callback reached
nested schema only → probe_only; nested runtime JSON event → export JSON leaf
same field GET+JSON without unique transport → BLOCKED_AMBIGUOUS_TRANSPORT
```

**Nghiệm thu:** Slug/resource route thực chạy được với request setup; JSON object/array không bị flatten sai transport; pattern/schema ngoài tập hỗ trợ có lý do hữu ích.

### Task 12 — COOKIE trong tuyến online-linked

**Files:** Modify zend_discovery/engine.py, seed_generation/config/config_exporter.py, seed_generation/convergence/convergence.py, zend_runtime/bridge_cli.py, online_linked_coordinator.py; tests test_zend_discovery.py, test_seed_to_config_exporter.py, test_entrypoint_auth_context.py.

**Phụ thuộc:** 06, 10. **Interface:** location='cookie', source='COOKIE', path chuẩn; config.cookies.data/fixed/fuzz hiện có. Cookie được tính vào fuzz parameter count nếu không phải auth/security.

- [ ] Test callback chỉ đọc cookie ứng dụng vẫn được export fuzzing_ready và online V0 nhận; đây là regression cho exporter hiện chỉ đếm query/body.
- [ ] Tái sử dụng cơ chế filter auth cookie task 06. Test cookie login/session/nonce bị giữ fixed hoặc reject; arbitrary cookie ứng dụng không bị loại chỉ vì source COOKIE.
- [ ] Mở normalization, materialization và pass2 identity đồng bộ cho COOKIE; request proof phải có cookie tương ứng được gửi, không lấy cookie value server tự sinh làm HTTP provenance.
- [ ] Live fixture anonymous đọc cookie audit_theme; verify request Cookie header đúng và auth user_id=0. Commit: feat: support application cookie discovery in linked workers.

```python
self.assertEqual(cookie_only_config['config_type'], 'fuzzing_ready')
self.assertIn('audit_theme', cookie_only_config['cookies']['fuzz'])
self.assertNotIn('wordpress_logged_in_test', cookie_only_config['cookies']['fuzz'])
```

### Task 13 — FILES/multipart có request serialization thực

**Files:** Create fuzzer/core/body_serialization.py; modify fuzzer/core/candidate.py, fuzzer/fuzzer.py, seed_generation/config/config_exporter.py, convergence/convergence.py, zend_discovery/engine.py, zend_runtime/bridge_cli.py; create tests/test_body_serialization.py; fixture upload bổ sung trong hookphuzz-entrypoint-direct-fixture.

**Phụ thuộc:** 07, 10. **Interface mới:** config.file_params có data=[{name, filename, content_base64, content_type}], fixed/fuzz giống section khác; serialize_multipart(candidate) trả text fields và requests-compatible files. File probe mặc định 32 byte, mutation cap 64 KiB. tmp_name server-side không bao giờ là field fuzz.

- [ ] Test prepared HTTP request là multipart có boundary thật, text action/nonce giữ nguyên và file có đúng field name/content. Không tự set Content-Type thiếu boundary.
- [ ] Zend FILES evidence liên kết field upload; name/type/content có nguồn client, error/size/tmp_name chỉ diagnostic hoặc derived, không tự coi mọi subfield là input độc lập.
- [ ] Tích hợp file_params vào candidate clone/mutation/hash, config export, replay-only freeze và pass2 evidence. Pipeline cũ GET/form/JSON không thay bytes ngoài header nondeterministic được phép.
- [ ] Fixture chỉ đọc upload hoặc lưu vào thư mục run-owned trong test; cleanup manifest liệt kê đúng file. Không nhận local arbitrary path từ config để upload; dùng content bytes inline/fixture-owned file.
- [ ] Live multipart callback và FILES proof fresh; commit: feat: serialize bounded multipart inputs for generated configs.

```text
file field document + text action=upload_probe
expected: multipart boundary, filename audit.txt, 32 bytes, callback reached
exported: document input; excluded: document[tmp_name]
```

**Nghiệm thu C:** Một fixture mỗi transport GET/form/JSON/URL/COOKIE/FILES, direct và helper/nested phù hợp, có request→provenance→export→final replay. Không nới gate khi dữ liệu ambiguous hoặc bị mất.

## 8. Giai đoạn D — Chạy nhiều entrypoint và báo đúng mức hoàn thành

### Task 14 — Campaign tuần tự cho nhiều target/action

**Files:** Create fuzzer/hook_energy/seed_generation/online_campaign.py; modify online_linked_coordinator.py, scripts/wordpress/run-wordpress-phuzz.ps1; create tests/test_online_campaign.py; extend test_phuzz_wrapper_contract.py.

**Phụ thuộc:** 03, 04, 07. Có thể nghiệm thu sau B, không cần đợi tất cả transport C. **Interfaces:** run_campaign(items, *, deadline, max_targets, max_total_worker_starts, coordinator_factory) -> dict; coordinator nhận candidate_key cụ thể và budget còn lại. Một target giữ lineage riêng; campaign chỉ quản lý thứ tự và tổng budget.

- [ ] Test hai AJAX action và REST GET/POST thành bốn target distinct, auth/nopriv distinct. Target đầu blocked/failed vẫn xét target sau nếu còn budget.
- [ ] Queue FIFO có stable order, dedupe theo task 03; một worker hoạt động tại một thời điểm. Giữ lệnh single-target cũ, wrapper mới dùng campaign khi max_targets>1.
- [ ] Refresh registrations từ request hiện tại sau probe/replay; action mới đúng plugin được đưa queue nếu chưa có key và còn quota. Lưu parent discovery request-id; không lấy callback lạ chỉ từ payload không được registry xác thực.
- [ ] Tách version id theo target directory để v0 của hai callback không đè file; không truyền known_parameters của target A cho B. Giữ nguyên config hash qua vòng đời worker.
- [ ] Test fake clock deadline toàn campaign, restart thất bại, cleanup worker và pending target marked NOT_ATTEMPTED_BUDGET. Không nhân 60 giây với số target mà báo tổng vẫn 60.
- [ ] Commit: feat: schedule bounded online entrypoint campaigns.

```python
self.assertEqual(len({row['candidate_key'] for row in summary['targets']}), 4)
self.assertLessEqual(summary['worker_starts'], 20)
self.assertEqual(summary['targets'][-1]['outcome'], 'NOT_ATTEMPTED_BUDGET')
```

**Nghiệm thu:** Có thể khám phá và chạy action mới trong cùng campaign; không dừng toàn bộ vì một target lỗi; không vượt tổng budget có cấu hình.

### Task 15 — Phân biệt hội tụ, replay-only và fuzz verified

**Files:** Modify online_campaign.py, online_linked_coordinator.py, generated_config_runner.py, zend_runtime/bridge_cli.py, seed_generation/config/config_exporter.py; create fuzzer/cli/summarize_entrypoint_acceptance.py; tests test_generated_config_runner.py, test_online_campaign.py; create tests/test_entrypoint_acceptance.py.

**Phụ thuộc:** 07, 14. **Interface:** summary fields/outcomes mục 3.2, entrypoint family aggregate counts gồm registered/eligible/attempted/callback/observed/exported/final_verified/blocked/budget_skipped. Lưu previous artifact paths và reason, không cần database.

- [ ] Test CONVERGED+0 params không thành VERIFIED_FUZZABLE; run_summary.runs=[] không thành PASS. Có proof callback và final replay-only thì VERIFIED_REPLAY_ONLY.
- [ ] Test callback true nhưng verifier parameter mismatch trả FAILED với PARAMETER_REPLAY_MISMATCH; auth skip/budget skip không đếm verified.
- [ ] Thêm explicit per-stage facts trước khi suy outcome. Schema mới additive; reader summary cũ thiếu fields trả unknown, không suy ra zero hay pass.
- [ ] CLI xuất JSON và Markdown ma trận theo family/target có link artifact. Mỗi campaign giữ báo cáo theo run-id; không ghi đè audit hoặc summary của lượt khác.
- [ ] Commit: feat: report verified entrypoint coverage by stage.

```python
self.assertEqual(classify_result(callback=True, observed=0, exported=0,
                                 replay='PASS'), 'VERIFIED_REPLAY_ONLY')
self.assertNotEqual(classify_result(callback=False, observed=0, exported=0,
                                    replay='NOT_RUN'), 'VERIFIED_FUZZABLE')
```

Trong snippet trên classify_result là helper mới thuộc summarize_entrypoint_acceptance.py, nhận các keyword và trả outcome theo bảng mục 3.2; runtime report cung cấp dữ liệu đã verify, CLI không tự xác minh callback từ HTTP status.

**Nghiệm thu D:** Báo cáo trả lời được còn bao nhiêu entrypoint chưa thử, bị chặn vì gì và bao nhiêu cái thực sự fuzz được; zero-run không mang nghĩa thành công.

## 9. Giai đoạn E — Thêm entrypoint cần setup/protocol

### Task 16 — Setup recipe nhỏ, có tài nguyên và cleanup theo run

**Files:** Create fuzzer/discovery/wordpress/setup_recipes.py; modify entrypoint_probes.py, online_campaign.py, scripts/wordpress/run-wordpress-phuzz.ps1; create tests/test_wordpress_setup_recipes.py.

**Phụ thuộc:** 06, 07, 15. **Interfaces:** prepare_setup(recipe, *, run_id, runner) -> manifest; cleanup_setup(manifest, *, runner) -> result. Recipe JSON khai báo kind, fixed context và typed inputs; runner là command interface có sẵn cho WP-CLI/Docker, không nhận chuỗi PHP/shell tùy ý từ plugin metadata.

```json
{
  "schema_version": 1,
  "kind": "shortcode_page",
  "tag": "hookphuzz_card",
  "attributes": {"mode": "probe"},
  "auth_mode": "unauth-capable"
}
```

- [ ] Test prepare idempotent trong cùng run; hai run không tái sử dụng page/post ID. Manifest chứa created ids, resource types và run ownership marker, không chứa token.
- [ ] Implement allowlist kind shortcode_page, rewrite_context, xmlrpc_context; resource action cụ thể tạo page/post/dữ liệu fixture theo recipe và lấy URL thực trả về. Recipe cần admin chuẩn bị nhưng public replay dùng session khác.
- [ ] Cleanup chỉ xóa object có ID và ownership marker khớp; thiếu/khác marker báo CLEANUP_OWNERSHIP_MISMATCH. Timeout vẫn lưu manifest và resource chưa cleanup.
- [ ] Test lỗi giữa setup vẫn cleanup phần đã tạo trong finally. Với recipe yêu cầu tài nguyên có sẵn ngoài ownership, dùng read-only lookup và không xóa.
- [ ] Commit: feat: prepare run-scoped WordPress entrypoint recipes.

**Nghiệm thu:** Setup có thể chuẩn bị/thu hồi tài nguyên test đúng run; unsupported recipe trả SETUP_RECIPE_UNSUPPORTED thay vì thực thi tùy ý.

### Task 17 — Shortcode registration → page request → callback proof

**Files:** Modify web/instrumentation/hook_coverage/uopz_hook_wp.php, discovery/entrypoints/classifier.py, entrypoints.py, skeleton/common_generator.py, setup_recipes.py; create fixtures/hookphuzz-shortcode-fixture/hookphuzz-shortcode-fixture.php, tests/test_shortcode_entrypoints.py; update packager allowlist/fixture metadata nếu có.

**Phụ thuộc:** 10, 16. **Registration shape:** entrypoint_type='shortcode', shortcode_tag, callback identity/source, registration provenance. Callback ID giữ tag để cùng function đăng ký nhiều tag không bị gộp.

- [ ] Capture add_shortcode runtime và remove_shortcode/removal khi cần; metadata có tag/callback thật, không suy từ hook name chứa chữ shortcode. Test inactive/replaced registration.
- [ ] Fixture đăng ký tag, đọc một query input trong callback và một fixed shortcode attribute; recipe tạo page có [tag mode="probe"], lấy permalink thực.
- [ ] Request page → UOPZ/Zend prove shortcode callback → query input export → final replay đúng page/callback. Không map tag trực tiếp thành URL giả.
- [ ] Fixed attributes/content chỉ là setup, không coi chúng là HTTP query param. Với plugin chỉ nhận attributes, recipe cung cấp thử nghiệm thay content trên page thuộc run rồi render lại; ghi source='SETUP_ATTRIBUTE' và outcome riêng REPLAY_ONLY nếu chưa có HTTP fuzz input. Không đưa attribute vào worker HTTP thông thường.
- [ ] Negative controls: page không chứa tag, tag đã removed, callback đọc local literal array. Thực thi cleanup. Commit: feat: discover and replay shortcode entrypoints through pages.

```text
registration hookphuzz_card → owned page → GET permalink?q=sentinel
proof: exact shortcode callback + GET q event → exported q → final replay PASS
attribute-only shortcode: setup/render proof; HTTP fuzz count=0, VERIFIED_REPLAY_ONLY
```

**Nghiệm thu:** Tự capture và tạo page/replay shortcode; HTTP input có runtime proof được fuzz. Attribute-only được phân biệt đúng, không quảng cáo như direct HTTP fuzz.

### Task 18 — Rewrite rule/endpoint → URL → runtime handler

**Files:** Modify uopz_hook_wp.php, discovery/entrypoints/classifier.py, entrypoints.py, discovery/wordpress/rest_routes.py chỉ khi trích helper materialization dùng chung có ích, setup_recipes.py, zend_discovery/extension/hookphuzz_opcode.c nếu thiếu query-var provenance; create fixtures/hookphuzz-rewrite-fixture/hookphuzz-rewrite-fixture.php và tests/test_rewrite_entrypoints.py.

**Phụ thuộc:** 10, 11, 16. **Registration shape:** entrypoint_type='rewrite_rule' hoặc 'rewrite_endpoint', pattern/name, query target, position/mask, owner/source. Rule không tự có callback: chỉ gắn handler sau runtime request evidence, không invent callback ID từ tên rule.

- [ ] Capture add_rewrite_rule/add_rewrite_endpoint và resolved WP rewrite metadata. Capture provenance owner để không lấy rule core/plugin khác làm mục tiêu.
- [ ] Recipe dựng permalink/query-var context trên môi trường test; flush rewrite chỉ sau khi registry đổi, không flush mỗi mutation. Nếu cần thay option, lưu giá trị trước và phục hồi chỉ khi trạng thái vẫn do run sở hữu.
- [ ] Materialize pattern trong tập hỗ trợ task 11 hoặc dùng recipe route example được fullmatch. Probe URL thực; correlate request path→query vars→handler callback đã chạy.
- [ ] Đầu vào query $_GET sẵn dùng bình thường. Route capture chuyển thành query variable chỉ được fuzz nếu có đường liên kết runtime giữa URL segment, query var và callback read; get_query_var name-only không đủ.
- [ ] Negative controls URL không match, rule bị thay thế, query var không được đọc, pattern unsupported. Cleanup context và final replay. Commit: feat: materialize and verify WordPress rewrite entrypoints.

```text
/audit/(?P<slug>[a-z0-9-]+) → index.php?audit_slug=$matches[1]
request /audit/probe → runtime handler reads audit_slug → URL-origin proof
wrong /other/probe → no target callback proof
```

**Nghiệm thu:** Ít nhất một rewrite rule và một rewrite endpoint có URL chạy được và callback proof. Template_redirect/init handler chỉ được coi reachable từ URL khi request chứng minh; không biến toàn bộ lifecycle hook thành direct endpoint.

### Task 19 — XML-RPC method map, XML body và replay

**Files:** Modify uopz_hook_wp.php, discovery/entrypoints/classifier.py, entrypoints.py, setup_recipes.py, core/body_serialization.py, core/candidate.py, fuzzer/fuzzer.py, seed_generation/config/config_exporter.py, zend_discovery/engine.py; create fixtures/hookphuzz-xmlrpc-fixture/hookphuzz-xmlrpc-fixture.php, tests/test_xmlrpc_entrypoints.py; extend test_body_serialization.py.

**Phụ thuộc:** 10, 13 (shared serialization boundary), 16. **Interfaces:** resolved method_map sau xmlrpc_methods filter là name→callable; seed.xmlrpc = {method_name, params:[typed value]}. Serializer dựng XML bằng xml.etree.ElementTree, không nối chuỗi XML với fuzz text. Entrypoint identity thêm XML-RPC method name.

- [ ] Capture map sau filters đã chạy hoặc từ server registry đã resolve, không chỉ hook registration xmlrpc_methods. Loại method removed/replaced; callback map giữ đúng callable.
- [ ] Recipe cung cấp arity/type và credential context khi cần; method map không có signature thì BLOCKED_XMLRPC_SIGNATURE_REQUIRED. system.listMethods chỉ dùng inventory, không chứng minh các method đã gọi.
- [ ] Dựng POST /xmlrpc.php, Content-Type text/xml, methodCall/methodName/params/value kiểu string/int/boolean/array/struct với depth/budget task 11. Giữ methodName và credentials fixed; escaped XML dùng chuẩn serializer.
- [ ] Instrument callback arguments có origin XML-RPC parsed HTTP body; path ví dụ ['params', 0] phải liên kết vào request hiện tại. Chỉ recipe names/type mà không runtime read thì probe/replay-only.
- [ ] Phân biệt transport lỗi, XML parse fault, auth fault và callback reached dù trả application fault; final parameter proof vẫn bắt buộc khi ghi VERIFIED_FUZZABLE.
- [ ] Tests input chứa <>& không tạo XML sai; wrong method/arity/auth rejected; final fresh replay. Commit: feat: generate and verify typed XML-RPC method requests.

```text
hookphuzz.echo(string) → escaped XML string sentinel → exact callback → arg[0] HTTP origin
unknown.method → method fault, callback false
known.method + no signature recipe → BLOCKED_XMLRPC_SIGNATURE_REQUIRED
```

**Nghiệm thu E:** Shortcode page, rewrite URL và XML-RPC body có capture/setup/replay thật. Các input chưa chứng minh được nguồn HTTP không được nâng thành fuzzable chỉ để hoàn thành ma trận.

## 10. Giai đoạn F — Nghiệm thu tích hợp, tài liệu và phát hành thay đổi

### Task 20 — Ma trận acceptance, kiểm tra hồi quy và cập nhật tài liệu

**Files:** Modify scripts/wordpress/run-wordpress-plugin-matrix.ps1, fuzzer/cli/summarize_entrypoint_acceptance.py, fuzzer/README.md, docs/reports/online-entrypoint-audit-2026-09-07.md bằng phụ lục liên kết kết quả mới; create docs/reports/entrypoint-acceptance/<run-id>/summary.json và summary.md khi thực thi. Test test_entrypoint_acceptance.py, test_online_campaign.py.

**Phụ thuộc:** A–E. **Đầu ra:** một báo cáo versioned có commit SHA, plugin/fixture hash, runtime version, config mode, limits và paths tới request/Zend/final artifacts.

- [ ] Chạy toàn bộ focused test set ở mục 11; check import compatibility/source-assisted tests. So baseline, giải thích riêng nếu test ngoài phạm vi có lỗi có sẵn.
- [ ] Chạy mỗi fixture case ở ma trận mục 12 bằng budget hữu hạn; tối thiểu 3 lượt run-id mới/case để phát hiện artifact stale hoặc phụ thuộc ordering. Không rerun vô hạn khi fail; giữ artifact và reason của failure đầu.
- [ ] Smoke plugin thật: show-all-comments-in-one-page, crm-perks-forms, contact-form-7, LearnPress. Dùng request/recipe đã xác nhận và môi trường test; plugin thực tế không có family nào thì N/A, không fake PASS.
- [ ] Đối chiếu số target registry với attempted/blocked/skipped; duplicate/covered/multi-method không mất âm thầm. Mỗi claim VERIFIED_FUZZABLE phải có final proof mới và exported input path tương ứng.
- [ ] Ghi tài liệu flags, probe/setup schema, auth behavior, serializer limits, known unsupported grammar/schema, cách dựng fixture và xem artifact. Audit cũ giữ kết quả lịch sử, thêm link tới acceptance mới.
- [ ] Review diff theo task, commit riêng từng phần; merge/release theo quy trình repository khi có chỉ thị triển khai. Nếu regression, revert commit/task tương ứng; không xóa DB/shared artifacts để làm kết quả sạch.

**Nghiệm thu cuối:** Tất cả lỗi P1/P2 trong audit đã được sửa và regression test PASS; nếu còn issue bắt buộc chưa đóng, ghi rõ release checkpoint nào đã đạt và không gọi toàn bộ kế hoạch hoàn tất. Fixtures trong tập hỗ trợ có proof đúng mức; các trường hợp ngoài tập hỗ trợ có blocked reason và recipe cần thiết.

## 11. Lệnh kiểm thử và cách chạy từng task

Từ ROOT/fuzzer, mỗi task chạy test module được nêu trong Files với unittest discover. Ví dụ (test hiện có hoặc test được task tạo):

```powershell
python -m unittest discover -s tests -p 'test_online_config_runner.py' -v
python -m unittest discover -s tests -p 'test_online_linked_coordinator.py' -v
python -m unittest discover -s tests -p 'test_seed_generation_live_export.py' -v
python -m unittest discover -s tests -p 'test_entrypoint_pipeline.py' -v
python -m unittest discover -s tests -p 'test_phuzz_wrapper_contract.py' -v
python -m unittest discover -s tests -p 'test_learnpress_admin_post_proof.py' -v
python -m unittest discover -s tests -p 'test_zend_discovery.py' -v
python -m unittest discover -s tests -p 'test_generated_config_runner.py' -v
python -m unittest discover -s tests -p 'test_rest_method_generalization.py' -v
python -m unittest discover -s tests -p 'test_rest_argument_schema_export.py' -v
python -m unittest discover -s tests -p 'test_entrypoint_*.py' -v
python -m unittest discover -s tests -p 'test_online_campaign.py' -v
python -m unittest discover -s tests -p 'test_body_serialization.py' -v
python -m unittest discover -s tests -p 'test_wordpress_setup_recipes.py' -v
python -m unittest discover -s tests -p 'test_shortcode_entrypoints.py' -v
python -m unittest discover -s tests -p 'test_rewrite_entrypoints.py' -v
python -m unittest discover -s tests -p 'test_xmlrpc_entrypoints.py' -v
python -m unittest discover -s tests -p 'test_heartbeat_runtime_contract.py' -v
```

Các test mới phải được chạy trước khi cài behavior tương ứng và thất bại đúng nguyên nhân. Sau cài đặt chạy lại rồi review/commit task. Chỉ thay đổi doc/đóng gói nhỏ không cần áp đặt test mô phỏng implementation; fixture archive test kiểm chứng artifact thực.

Live smoke sau khi fixture packager và auth/probe đã hoàn tất, chạy tại ROOT (lệnh hiện có, không dùng flag được đề xuất nhưng chưa cài):

```powershell
python scripts/wordpress/build-test-fixtures.py --slug hookphuzz-online-discovery-fixture
powershell -NoProfile -File scripts/wordpress/run-wordpress-phuzz.ps1 -PluginSlug hookphuzz-online-discovery-fixture -BootstrapConfigSlug wordpress/hookphuzz-online-discovery-fixture -UseZendDiscovery -RunOnlineLinked -OnlineTimeoutSeconds 60 -OnlineMaxVersions 2 -NoFollowLogs
```

Các case có bootstrap riêng dùng config fixture tương ứng. Với endpoint chỉ cần probe, task 07 phải cho phép entry trước worker mà vẫn giữ tham số wrapper tương thích. Task 14 cập nhật CLI/PowerShell flags và test help/validation cùng lúc; không hướng dẫn người dùng chạy flag chưa tồn tại.

Với PHP/C: build qua cấu hình Dockerfile.zend của wrapper; lấy PHP version và extension loading từ container vừa build. Chạy PHP lint cho file chỉnh và fixture trong container này; host hiện không có PHP CLI. Không hard-code container name của một lượt cũ.

Sau mỗi task: git diff --check; git diff --stat; review chỉ file của task; commit với thông điệp ở task. Không git add toàn bộ workspace. Các lệnh commit là bước của triển khai tương lai, không được chạy chỉ để hoàn thành lượt lập kế hoạch này.

## 12. Ma trận acceptance bắt buộc

| Case | Positive proof | Negative control | Gate |
| --- | --- | --- | --- |
| AJAX POST/auth | callback + body leaf + final replay | sai action, anonymous context | B |
| AJAX GET/nopriv | callback + query leaf + user_id=0 | POST-only attempt không thay GET proof | B |
| Bootstrap shared URL | beta request gắn beta callback | alpha không được chọn | A |
| Covered callback | có target dù bootstrap executed_count>0 | inactive không được chọn | A |
| REST GET/POST cùng callback | hai stable keys, replay method riêng | dùng GET artifact cho POST bị reject | A/B |
| REST query/form/JSON/URL | parameter đúng bucket/path | same key nhiều transport ambiguous | C |
| REST slug/resource | URL match và resource tồn tại | missing resource ghi prerequisite | C |
| Admin-post auth/nopriv | từng action/auth có proof | nonce sai/auth sai | B |
| Admin-action | admin.php action đúng callback | action khác không match | B |
| Login custom action | action trong query và input đúng method | chỉ probe lostpassword không thỏa | B |
| Heartbeat auth/nopriv | hai proof riêng; data leaf export/replay | no data, sai auth/nonce | B/C |
| Helper/nested | cùng source/path xuyên helper và export | helper callback khác/local array bị loại | C |
| Cookie-only | cookie ứng dụng đủ làm fuzz-ready | auth cookie không fuzz | C |
| Multipart | prepared body đúng boundary và FILES proof | tmp_name không được fuzz | C |
| Multi-target/action mới | queue thêm target cùng plugin | target khác plugin/repeated bị loại | D |
| Zero parameters/runs | replay-only/blocked đúng trạng thái | không VERIFIED_FUZZABLE | D |
| Shortcode | page thật gọi shortcode, HTTP query param proof | page thiếu tag/callback removed | E |
| Rewrite | URL→query-var→handler có nguồn runtime | URL sai, rule khác, name-only | E |
| XML-RPC | escaped typed body→method→argument proof | unknown method/arity/auth fault | E |
| Stale/lossy artifacts | fresh correlated artifacts được nhận | old run, wrong ID, event loss bị loại | Mọi gate |

Mỗi dòng cần artifact đủ nhận diện plugin/run/request/callback/method/auth/parameter path. Các dòng hỗ trợ setup-only được đánh dấu VERIFIED_REPLAY_ONLY nếu không có HTTP fuzz input; không tăng bộ đếm fuzz verified.

## 13. Phụ thuộc và thứ tự commit

```text
01 → 02 → 03 → 04 → 05                         A: lỗi lõi
          02,04 → 06 → 07 → 08                 B: auth + probe + direct hooks
                       07,06 → 09             B: heartbeat
                                09 → 10       C: helper/nested
                          07,10 → 11          C: REST
                          06,10 → 12          C: COOKIE
                          07,10 → 13          C: FILES
                    03,04,07 → 14 → 15        D: campaign/report
                          06,07,15 → 16       E: setup
                              10,16 → 17      E: shortcode
                           10,11,16 → 18      E: rewrite
                           10,13,16 → 19      E: XML-RPC
                              01..19 → 20     F: acceptance
```

Mốc có thể giao nhận: A sửa lỗi chọn target; B hoàn thiện direct HTTP; C mở transport/provenance; D phủ nhiều target có budget; E thêm setup/protocol; F xác minh tích hợp. Không cần đợi E/F mới đưa bản sửa A vào nhánh tích hợp sau review.

## 14. Checklist đối chiếu báo cáo

| Yêu cầu từ audit | Task |
| --- | --- |
| Sai action/bootstrap identity | 02 |
| REST multi-method V0 | 03 |
| Covered bị mất | 04 |
| LearnPress sai path và kiểm tra lại nonce blocker | 05 |
| ZIP fixture thiếu | 01 |
| Anonymous/auth không có proof riêng | 06 |
| Action-only không start được discovery | 07 |
| AJAX GET-only; admin_post/login action probes; admin_action thiếu | 08 |
| Heartbeat pass1 có nhưng final fail | 09, 10, 15 |
| Helper/nested bị bỏ | 10 |
| REST regex/schema/resource prerequisite | 11 |
| COOKIE/FILES thiếu trong linked pipeline | 12, 13 |
| Một callback, action expansion chưa làm | 14 |
| CONVERGED/zero-run gây hiểu sai | 15 |
| Shortcode/rewrite/XML-RPC thiếu setup | 16–19 |
| Frontend/lifecycle callback cần URL/context | 16, 18; không auto-map mọi lifecycle hook |
| Thiếu bằng chứng live trọn luồng | 20 |

Kế hoạch không đặt thời hạn cố định cho phần C extension chưa xác định root cause. Task 09 bắt buộc có trace trước khi sửa; nếu origin bị mất ở WordPress argument handling, thay đổi C tập trung vào đúng propagation đó. Việc blocked do prerequisite hoặc grammar ngoài tập hỗ trợ phải được ghi nhận rõ, không giải quyết bằng cách hạ chuẩn evidence.
