# Kế hoạch tiếp tục khám phá tham số từ replay AJAX

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Khôi phục discovery của `cn_nonce` trong Cookie Notice và giữ cách phân loại POST `action` của experiment.

**Architecture:** Dùng trace replay đã qua callback baseline để đề xuất probe cho field còn thiếu. Gửi probe bằng light sender với dữ liệu của request đã vào đúng callback, rồi đưa kết quả vào luồng admission hiện có. Hoàn thành lượt probe trong budget trước khi bàn giao sang worker dùng config fuzz.

**Tech Stack:** Python, unittest, Zend artifacts, WordPress, PowerShell.

**Spec:** Yêu cầu trong chat ngày 04/11/2026. Query `action=cn-get-group-rules-values` fixed. POST `action` và `cn_param` fuzz. POST `cn_nonce` fixed.

## Bối cảnh

Cookie Notice 2.4.8 có callback `get_group_rule_values`. PHP kiểm tra `isset($_POST['action'], $_POST['cn_param'], $_POST['cn_nonce'])` từ trái sang phải, dừng ở field đầu tiên chưa có hoặc bằng null. Sau đó code mới xác minh nonce. Xem `phuzz-main/code/web/applications/wordpress/_plugins/cookie-notice/cookie-notice/includes/settings.php:2021`.

| Bước | Lượt cũ `20261103T093458Z` | Lượt batch `20261103T161734Z` |
|---|---|---|
| 1 | `p1` chỉ gửi POST action đúng. Zend thấy `isset(cn_param)`. | Cùng trace, batch nhận luôn `cn_param` và tạo v1. |
| 2 | `p2` gửi action đúng và `cn_param`. Zend thấy `isset(cn_nonce)`. | Replay v1 gửi đúng hai field đó. Trace `r-d3a09a5f7ada3751159811dc` cũng thấy `isset(cn_nonce)`. |
| 3 | Probe `p3` thêm `cn_nonce`, trả `{"select":""}`, tạo v2 có nonce fixed. | **Replay chỉ dùng để xác nhận callback.** Trace nonce được lưu nhưng không sinh probe tiếp theo. |
| 4 | Có config v2 đủ ba field. | **Worker v1 dùng POST `action=fuzz`.** WordPress ưu tiên giá trị này trong run đã quan sát. 0/439 request worker lưu được chạm callback đích. Run hết budget và export v1 thiếu nonce. |

`f266e784` cho phép fuzz POST action. `350df27b` nhận field từ guard AJAX ngay cả khi field chưa được gửi, nên lượt batch chuyển sớm sang replay v1. Hai lượt trước, `20261102T091138Z` và `20261103T093458Z`, đều có probe nonce và v2 đủ field.

Bằng chứng nằm trong `phuzz-main/code/fuzzer/output/online-linked/`. Xem candidate `5779335ea6d6923b` của lượt batch, file `campaigns/5779335ea6d6923b/versions/v1/replay/zend/r-d3a09a5f7ada3751159811dc.json` và `state.json` cùng campaign. Đối chiếu `campaigns/af910911a6d61bdb/state.json` của lượt cũ. Diff config nằm trong `docs/reports/2026-11-04-cookie-notice-latest-experiment-comparison.json`.

## Phạm vi và quyết định

- Giữ `query_params.fixed=[action]` và giá trị `cn-get-group-rules-values`. Trong body, giữ `action` và `cn_param` fuzz, `cn_nonce` fixed khi đã được xác nhận. Giá trị nonce trong experiment là placeholder. Replay dùng giá trị đã được môi trường test chấp nhận.
- Đề xuất dùng trace baseline làm đầu vào discovery. Việc cố định POST action trong config export sẽ đổi phạm vi fuzz đã yêu cầu. Việc tăng budget vẫn để worker gửi POST action sai.
- Replay/probe giữ POST action đúng để vào callback. Trong fuzzing, mutation của POST action vẫn có thể đổi callback. Kết quả discovery không phụ thuộc vào việc worker tìm lại action đúng.
- Chỉ xét guard `isset` hoặc `empty` của field GET/POST chưa gửi, chưa biết, có transport rõ ràng và được quy thuộc đúng callback AJAX. Dùng cặp artifact đã qua kiểm tra identity và correlation. Một guard quan sát được chỉ tạo đề xuất probe, chưa xác nhận giá trị hoặc nhánh.
- Giữ giới hạn probe/version/deadline và export gate hiện có. Giữ artifact và lý do nếu probe thất bại hoặc thiếu budget. Nếu v1 đã qua gate, nó vẫn là kết quả có bằng chứng ở mức callback và được báo thiếu coverage nonce.

## Triển khai

**Files:** `phuzz-main/code/fuzzer/online_linked/coordinator.py`, `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`. Chỉ chạm `phuzz-main/code/fuzzer/hook_energy/seed_generation/zend_runtime/bridge_cli.py` nếu cần tái sử dụng đường materialize probe từ guard mà chế độ batch đang nhận trực tiếp.

- [ ] Thêm regression test `test_ajax_child_replay_probes_missing_guard_before_worker_handoff`. Mock replay v1 có body action đúng, `cn_param=fuzz`, trace ghi `isset(cn_nonce)` và chưa gửi nonce. Assert có đúng một probe gửi ba field, probe chạy trước lần khởi động worker tiếp theo, và config cuối giữ nonce fixed, body action cùng cn_param fuzz. Assert child có nonce vẫn qua callback baseline của chính nó.
- [ ] Chạy test trên code hiện tại. Expected fail vì worker v1 được start ngay và không có request probe nonce. Dùng fixture và fake sender sẵn trong `OnlineLinkedCoordinatorTests`.
- [ ] Tại `handoff_to_next_worker()`, sau khi baseline thành công và trước `_stop_worker()` / `_start_worker()`, chuyển cặp request/Zend của replay sang logic discovery hiện có với identity của replay. Tạo probe cho guard chưa được gửi. Trường hợp batch đã đánh dấu guard là admissible vì thấy `isset`, vẫn tạo đề xuất probe ở bước này để thử field thật. Dùng request replay làm nền, giữ đúng method, auth, query và POST action. Dùng `_run_pending_probe_once()` hoặc đường pending hiện có để giữ correlation và admission.
- [ ] Dựng child tiếp theo qua đường tạo version/replay hiện có từ probe đã xác nhận, dùng parent đang chạy để gửi request. Giữ quan hệ với version v1 trong state. Xử lý các đề xuất trong vòng lặp có giới hạn, giữ dedup và checkpoint, tránh gọi lại handoff lồng nhau. Chỉ bàn giao một worker sau khi chọn được version đã qua gate.
- [ ] Bổ sung test đối chứng trong cùng suite. Trace không có field mới giữ handoff thường. Trace sai callback hoặc correlation không tạo probe. Guard lặp không gửi lại. Probe trả lỗi hoặc hết budget giữ bằng chứng và verdict đúng, không đánh dấu nonce đã xác nhận. Entry point ngoài AJAX giữ đường chạy cũ.
- [ ] Từ `phuzz-main/code/fuzzer`, chạy suite với timeout. Xem mọi failure, error và skip trước khi kết luận.

```powershell
python -B -c "import subprocess,sys; sys.exit(subprocess.run([sys.executable,'-B','-m','unittest','tests.test_online_linked_coordinator','tests.test_zend_discovery','tests.test_online_linked_export'], timeout=300).returncode)"
```

## Nghiệm thu runtime

- [ ] Kiểm tra WordPress, Docker và campaign đang chạy. Dùng campaign mới, một plugin, input riêng và budget hữu hạn. Từ `phuzz-main/code`, chạy `pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -Mode online-linked -PluginSlug cookie-notice -OnlineTimeoutSeconds 90`. Chạy qua terminal có giám sát và giới hạn thời gian cho cả lượt.
- [ ] Đối chiếu artifacts của `wp_ajax_cn-get-group-rules-values`. Cần trace replay có `isset(cn_nonce)`, probe tương quan gửi đúng action và đủ ba field, kết quả ứng dụng dạng `{"select":...}`, baseline của version cuối, canonical export hash, và đúng phân loại query/body theo experiment.
- [ ] Chạy comparator semantic cho config cuối và experiment. Tách chênh lệch header hoặc giá trị placeholder khỏi chênh lệch field và selector. Một HTTP 200 hoặc callback baseline riêng lẻ chưa chứng minh nonce đã qua guard.
- [ ] Cập nhật đúng dòng config trong `plugin-test-checklist.md` theo kết quả thực tế. Ghi riêng config, replay/guard và fuzzing. Nếu Docker/WordPress hoặc budget cản bước cần thiết, ghi PARTIAL hoặc BLOCKED kèm bằng chứng.

