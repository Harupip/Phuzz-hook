# Online-linked: ngân sách, hàng đợi và resume — note phục vụ review

Ngày: 2026-10-05.

**Note tạm: xóa file này sau khi review xong.** Trước khi xóa, chuyển các vấn đề còn mở sang nơi theo dõi phù hợp. Việc xóa note không thay thế kiểm chứng runtime còn thiếu.

## Yêu cầu và phạm vi

- Hoàn thiện WIP bị dừng ở scheduling, budget, trạng thái và kiểm thử liên quan.
- Không mở rộng khả năng tấn công, payload hoặc mục tiêu. Giữ các gate provenance, callback, replay, Pass 2 và export.
- Đọc AGENTS.md, diff, callers và tests trước khi sửa; giữ WIP không liên quan.
- Tách ngân sách khởi đầu và hard cap cho số candidate, thời gian candidate, thời gian campaign và số version. Validate đầu vào; giải thích defaults.
- Callback mới hợp lệ có thể tăng queue vượt mức khởi đầu, nhưng không vượt hard cap. Duplicate không nhận thêm credit.
- Tiến triển hợp lệ có thể gia hạn candidate và campaign. Burst callback phải nhận thời gian cộng dồn; `now + max_seconds` không tự bảo đảm đủ thời gian cho toàn queue. Mọi gia hạn phải nằm trong hard cap.
- Pending/resume phải lưu payload, lineage, config/evidence references và trạng thái; có đường nạp lại, không chạy lại candidate đã hoàn tất, kiểm tra lại ngữ cảnh. Không dùng lại trực tiếp timestamp monotonic giữa các lần chạy; không reset budget hoặc credit.
- PARTIAL phải truyền từ candidate lên campaign, giữ lý do dừng cụ thể; còn pending thì không báo complete.
- Bỏ gate max_versions cũ ở đầu discovery, nhưng giữ giới hạn khi tạo version. Tests phải chứng minh soft/hard limit, không chỉ bỏ assertion cũ.
- Mọi lần chạy kiểm chứng có timeout. Không tuyên bố runtime/Docker PASS khi chưa chạy. Chỉ sửa engine thì không thêm dòng hoàn thành plugin config checklist.
- Yêu cầu ban đầu không commit/push; yêu cầu tiếp theo cho phép commit phần sửa và note này. Không push.

## Phần đã sửa

Hai file engine/tests:

- `phuzz-main/code/fuzzer/online_linked/coordinator.py`
- `phuzz-main/code/fuzzer/tests/test_online_linked_coordinator.py`

Thay đổi gồm WIP ngân sách trước đó và phần hoàn thiện trong lần này:

1. Dùng validation chung cho các cặp ngân sách: số nguyên dương, hard cap không nhỏ hơn mức khởi đầu; giữ giới hạn đầu vào khởi đầu hiện hữu.
2. Cấp credit theo tiến triển có danh tính ngữ nghĩa. Callback trùng hoặc đã có trong danh sách khởi đầu không nhận thêm credit campaign. Proposal chỉ thuộc child không mua thêm budget cho parent.
3. Cộng thời gian theo từng tiến triển thay vì chỉ kéo deadline tới `now + max_seconds`; clamp candidate/campaign vào hard cap. Timeout startup và inspection cũng theo thời gian còn lại.
4. Giữ discovery callback/convergence ở gate ngay cả khi không còn slot version; chặn tạo version tại ngân sách hiệu lực hoặc hard cap, giữ proposal pending và lý do PARTIAL.
5. Lưu checkpoint campaign/candidate, queue đang chạy/chờ, payload proposal, lineage, reports, references, counters, progress keys và thời lượng còn lại. Ghi JSON qua helper atomic hiện hữu.
6. Thêm `--resume`. Nạp checkpoint cùng run ID, đối chiếu input/context/budget/config hashes, bỏ candidate đã hoàn tất; tái lập deadline theo clock mới, giữ budget/credit/version/probe counters. Thời gian dừng vẫn bị trừ khỏi budget.
7. Resume chạy lại gate trong ngữ cảnh mới trước khi gửi pending probe. Evidence cũ chỉ là proposal; request mới dùng run ID mới. Giữ lịch sử lý do dừng/readiness, xử lý worker cũ của candidate trước khi tiếp tục.
8. Campaign giữ PARTIAL khi candidate còn PARTIAL hoặc queue còn pending, đồng thời lưu lý do dừng cụ thể.

Defaults của CLI:

| Ngân sách | Khởi đầu | Hard cap nếu không khai báo |
|---|---:|---:|
| Số candidate | 32 | max(128, khởi đầu) |
| Thời gian candidate | 120 giây | 4 × khởi đầu, mặc định 480 giây |
| Thời gian campaign | 3.600 giây | max(86.400, khởi đầu) giây |
| Version, gồm v0 | 2 | max(20, 4 × khởi đầu), mặc định 20 |

## Kiểm chứng

Đã kiểm tra:

- Callback thứ 33 được chạy khi mức khởi đầu là 32; hard cap 32 giữ callback đó trong pending.
- Tiến triển gần deadline gia hạn cả candidate và campaign.
- Burst callback nhận các lượt riêng; duplicate không thêm credit; child-only proposal không thêm credit parent.
- Chạm hard cap count/time/version và giữ pending, không cấp budget vượt cap.
- PARTIAL candidate truyền lên campaign với lý do cụ thể.
- Lưu/nạp queue rồi chạy tiếp, không chạy lại parent đã hoàn tất; giữ budget và credit qua clock epoch khác.
- Resume pending probe chạy gate mới trước sender; config hash hoặc giới hạn khai báo đổi thì từ chối resume.
- Các tests input, provenance, callback, replay, Pass 2 và export hiện hữu nằm trong lần chạy toàn suite.

Kết quả trên diff cuối:

- `tests/test_online_linked_coordinator.py`: **128 pass, 0 fail, 0 skip**, 157,792 giây; timeout 240 giây.
- Toàn bộ `tests`: **603 pass, 1 fail, 3 skip** trên 607 tests, 218,957 giây; timeout 360 giây.
- `py_compile` và `git diff --check`: pass; timeout 30 giây cho mỗi lệnh kiểm tra.

Ba mục review cũ đã xác minh lại:

- `test_gate_respects_version_limit_and_discovers_sibling_callbacks`: thay bằng `test_gate_discovers_siblings_even_at_hard_version_cap`; thêm kiểm tra hard cap và `test_soft_version_limit_includes_v0_but_verified_progress_can_grow`. Các tests pass.
- `test_measured_sender_cost_reserves_time_for_trial_and_replay`: pass; hard time budget được khai báo để giữ ý nghĩa dành thời gian cho trial/replay.
- `test_online_max_versions_includes_v0`: pass; chứng minh hard cap gồm v0, giữ pending và lý do `HARD_VERSION_CAP`.

## Vấn đề còn mở và phần chưa kiểm chứng

- **Fail ngoài phần scheduling đang sửa:** `test_online_linked_config_comparison.OnlineLinkedConfigComparisonFilesystemTests.test_state_update_failure_keeps_old_state_after_report_write`, assertion `paths["report"].exists()` tại dòng 439. Chạy riêng vẫn fail. Không sửa module/test config-comparison trong task này.
- **Skip:** CF7 plugin/source smoke chưa bật opt-in; Windows thiếu quyền tạo symlink; image `hookphuzz-zend` chưa build.
- **Chưa chạy runtime/Docker campaign.** Unit tests có dependency giả không chứng minh runtime, replay/Pass 2 thực tế hay fuzzing PASS.
- WIP ở `phuzz-main/code/web/applications/wordpress/init.sh`, `plugin-test-checklist.md` và các artifact/file ngoài phạm vi được giữ nguyên, không đưa vào commit này.

Log kiểm chứng trên máy hiện tại:

- `C:/Users/nghia.cd_extremevn/.codex/visualizations/2026/10/05/01a10b5c-6a21-7de1-833f-3d6961a5ff79/coordinator-tests.log`
- `C:/Users/nghia.cd_extremevn/.codex/visualizations/2026/10/05/01a10b5c-6a21-7de1-833f-3d6961a5ff79/fuzzer-tests.log`

Các log trên là artifact cục bộ, không nằm trong commit.
