# Audit entrypoint — feature/online-linked — 2026-09-07

Bắt đầu audit tại HEAD dbf67318aa258230ef8298906b7f6e0d5dc7e2f4 và kiểm tra cả working tree. Trong lúc audit, thay đổi thêm POST cho heartbeat và test tương ứng được commit thành d619a48. HEAD cuối audit là d619a48, ahead origin 1 commit. Nội dung đã test trùng với hai file trong commit mới; các kết luận dưới đây vẫn áp dụng.

Đã đọc tuyến registration → seed/config → online V0 → convergence/replay, chạy unit/contract tests và tái hiện tối thiểu trong thư mục tạm. Không sửa mã triển khai hoặc chạy chiến dịch fuzz mới. Artifact runtime dưới đây có sẵn trong workspace.

## Lỗi cần ưu tiên

1. **P1 — Bootstrap ghép nhầm action/callback.** online_config_runner.py:284 chỉ so path trong _seed_matches_target. Selector lấy seed đầu tiên cùng URL rồi gắn metadata vào bootstrap. Online-linked dùng lại selector này khi fallback. Tái hiện với seed alpha/beta và bootstrap action=beta: callback được chọn là wp_ajax_nopriv_alpha, request vẫn action=beta, metadata cũng ghi alpha. Worker gọi một action còn correlation theo callback khác. Cần match action/fixed selectors, method và auth cùng endpoint.

2. **P1 — REST nhiều method không chọn được V0.** online_linked_coordinator.py:559 chỉ match hook_name + callback_id rồi yêu cầu đúng một convergence target. Targets thực tế phân biệt method/variant. Tái hiện một callback GET/POST có hai config fuzzing_ready: _select_v0 trả None; bỏ POST, giữ GET thì chọn được. run() sẽ dừng V0_PREREQUISITE_GATE_FAILED. Cần match canonical identity/method/variant của config đã chọn.

3. **P1 — Callback bootstrap đã gọi bị loại khỏi đầu vào online.** common_generator.py:21 chỉ đưa uncovered vào suggested_seeds; gate dòng 286 cũng không tạo seed cho covered. Tái hiện AJAX executed_count=0 cho 1 suggestion; count=1 cho 0 suggestion; ngay cả bootstrap hợp lệ cũng không chọn được V0. Quy tắc báo cáo khoảng trống coverage đang ngăn khám phá tiếp tham số/nhánh của callback đã được bootstrap chạm tới. Runtime generator chỉ có ngoại lệ admin-post correlate đúng. Cần catalog online riêng với danh sách uncovered.

4. **P2 — LearnPress online ghi nonce vào sai file.** run-wordpress-phuzz.ps1:1505 export online vào fuzzer/output/online-seed-generation/<run-id>, nhưng Add-LearnPressNonceToSuggestedSeeds ngay sau đó vẫn nhận fuzzer/output/seed_generation/suggested_seeds.json. Coordinator đọc thư mục online. Nếu proof thành công, nonce/parameter được ghi vào file cũ; nếu file cũ thiếu exact target thì helper throw. Xác nhận luồng code; chưa replay live LearnPress trong audit này. Dùng cùng đường dẫn theo run xuyên suốt.

5. **P2 — Thiếu ZIP fixture online.** test_online_plugin_fixture.py:42 fail vì thiếu web/applications/wordpress/_plugins/hookphuzz-online-discovery-fixture.zip. Source/config có trong Git, ZIP không nằm trong danh sách tracked hiện tại. Wrapper yêu cầu ZIP trước khi khởi động. Cần đóng gói fixture hoặc bổ sung bước dựng tái lập.

## Ma trận hỗ trợ

| Entrypoint | Đã có | Còn thiếu/vướng |
| --- | --- | --- |
| wp_ajax_* | Capture, mapping, seed POST runtime, export/replay/discovery; artifact plugin thật callback reached. | Lỗi bootstrap và covered; runtime candidate chỉ probe POST, chưa tự thăm GET-only; online-linked chưa duyệt mọi action. |
| wp_ajax_nopriv_* | Mapping/auth variant, seed/config. | Cần proof anonymous riêng. Một số artifact registered_not_executed; authenticated counterpart không chứng minh nhánh public. |
| register_rest_route | Capture route/method/callback/permission; query/form/JSON/URL evidence; export/verification. | V0 lỗi nhiều method. Materializer chỉ thay named group dạng (?P<id>\d+) bằng 1; slug/optional/nested regex chưa tự dựng. ID 1 chưa chắc tồn tại. Schema phức tạp/location chưa rõ bị blocked hoặc probe-only. |
| admin_post_* | Mapping, seed/config khi có method evidence; fixture và adapter LearnPress. | Registry-only còn ambiguous_http_method. Wrapper có probe đặc biệt hp-ap/LearnPress, chưa tổng quát hóa action/method/nonce; LearnPress online sai đường dẫn. |
| admin_post_nopriv_* | Mapping/auth variant. | Cần exact action/method evidence và proof anonymous; audit chưa xác minh trọn luồng. |
| login_form_* | Mapping wp-login.php?action=..., generator/export. | Runtime registry-only ambiguous_http_method. Bootstrap mặc định chỉ có lostpassword, chưa probe từng action plugin; chưa xác minh runtime trọn luồng. |
| admin_action_* | Classifier/map admin.php?action=.... | Thiếu trong allowlist sinh seed ở common_generator.py:289; kết quả manual_analysis_required. |
| heartbeat_received | Mapping/body; commit d619a48 thêm POST; artifact mới nhất callback reached ở pass 1. | Final pass 2 thất bại, không có tham số mới; chưa fuzzing-ready trọn luồng. |
| heartbeat_nopriv_received | Mapping unauth; commit d619a48 thêm POST. | Artifact mới nhất registered_not_executed; chưa có proof anonymous. |
| add_shortcode | Phân loại metadata shortcode được cung cấp. | Chưa capture như entrypoint HTTP độc lập; thiếu tạo nội dung/page và replay. |
| add_rewrite_rule / add_rewrite_endpoint | Classifier nhận metadata rewrite. | Thiếu capture registration, materialize URL và setup rewrite để sinh/replay request. |
| xmlrpc_methods | Bootstrap system.listMethods; phân loại method-map. | Chưa lấy từng method cụ thể và dựng XML methodCall/config. |

Các hook init/admin_menu/plugins_loaded không tự động là endpoint HTTP độc lập. Hành vi nhận query ở frontend/lifecycle hook vẫn cần discovery/setup riêng nếu muốn phủ bề mặt đó.

## Heartbeat: bằng chứng mới hơn audit cũ

Run có sẵn: hookphuzz-heartbeat-fixture-20260907T001729Z, dưới fuzzer/output/seed_generation/zend-bridge.

- pass1-generated_config_run_summary.json: authenticated callback reached; nopriv registered_not_executed.
- zend_convergence_summary.json: target CONVERGED nhưng observed/new/known parameters đều rỗng; trạng thái tổng REPLAY_FAILED.
- final-generated_config_run_summary.json: runs rỗng, total=0.

CONVERGED ở đây chỉ là không tìm thêm tham số; chưa chứng minh config fuzz hữu ích. Fixture đọc qua đối số $data/$screen_id: cần kiểm tra provenance từ HTTP qua đối số filter và nested data. Audit chưa xác định chính xác điểm mất provenance trong extension; không kết luận nonce là nguyên nhân khi authenticated callback đã tới.

## Giới hạn online-linked

- Chọn một V0/callback, phát triển các phiên bản config của callback đó. Không duyệt mọi entrypoint; action mới bị ghi ACTION_EXPANSION_NOT_IMPLEMENTED ở online_linked_coordinator.py:254.
- V0 cần sẵn ít nhất một tham số fuzz. Runtime-only generator ban đầu không trích tham số; nếu thiếu seed enrich hoặc bootstrap phù hợp, không tự bắt đầu từ action-only/replay-only seed.
- Nhánh non-REST của zend_discovery/engine.py:212 chỉ nhận path một phần tử, helper_depth=0, GET/POST hoặc REQUEST resolve được. Path nhiều phần tử, helper-depth >0, COOKIE/FILES chưa được nhận tại bước này. Không đồng nhất khả năng COOKIE của online_config_runner với tuyến online-linked → convergence → engine.

## Kiểm chứng

253 test đã chạy: **252 pass, 1 fail** do thiếu ZIP fixture online. Dùng unittest; môi trường không cài pytest.

- Online runner/coordinator/fixture: 30 test, 1 failure.
- Entrypoint/classifier/pipeline, live export, seed-to-config, REST schema, bootstrap, Zend discovery, LearnPress contract: 162/162 pass.
- REST method generalization, seed method inference, generated config runner: 61/61 pass.
- Tái hiện riêng: bootstrap action khác callback; REST hai method không chọn V0; covered callback mất seed dù bootstrap hợp lệ.

Đây là unit/contract và đọc artifact, không phải replay live mới. Chưa xác nhận lại blocker nonce-eval LearnPress của báo cáo cũ.

Ưu tiên: sửa bootstrap selector và identity nhiều method → giữ catalog cho covered callback → sửa đường dẫn LearnPress → thêm admin_action/action-aware probes → hoàn tất heartbeat parameter/final replay → mở rộng shortcode/rewrite/XML-RPC.
