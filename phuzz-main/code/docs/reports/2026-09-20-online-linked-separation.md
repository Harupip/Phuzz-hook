# Tách package online-linked — 2026-09-20

## Phạm vi và trạng thái

Đã tách mã riêng của `online-linked` trên nhánh `feature/separate-online-linked`,
tạo từ `c2c5e73` của `feature/import-02-0day-vulns`. Thay đổi chưa commit/push.
Giữ nguyên public CLI `phuzz.ps1 -Mode online-linked`, ngân sách, định dạng
config/state, replay/Pass 2, thuật toán discovery và các mode khác.

| Thành phần | Vị trí hiện tại |
| --- | --- |
| Coordinator, campaign, version/handoff | `fuzzer/online_linked/coordinator.py` |
| Đọc runtime evidence | `fuzzer/online_linked/evidence.py` |
| Đề xuất replay input | `fuzzer/online_linked/replay_inputs.py` |
| Probe trong worker | `fuzzer/online_linked/probe_sender.py` |
| Final export | `fuzzer/online_linked/export.py` |
| Entrypoint package | `python -m online_linked` |
| Launcher PowerShell | `scripts/wordpress/invoke-online-linked.ps1` |
| Chọn v0, validation, hash, artifact helpers dùng chung | `fuzzer/hook_energy/seed_generation/online_common.py` |

`online-linked` không còn import/khởi tạo `OnlineCoordinator` của mode `online`
cũ. `fuzzer.py` không còn nhánh `--online-linked-probe`; probe chạy bằng
`python -m online_linked.probe_sender`. Adapter config-to-request nằm trong
sender; phần dựng request/auth/cookie dùng bởi fuzzing thường vẫn ở fuzzer chung.

Launcher giữ cwd ở thư mục `code` cho Docker Compose, truyền import path cho
Python, dừng bootstrap trước khi chạy coordinator và khôi phục cwd,
`COMPOSE_FILE`, `PYTHONPATH` trong `finally`.

Zend, CmpLog, convergence, Pass 2, config exporter, generated runner,
instrumentation và bootstrap vẫn dùng chung. Mã coordinator được chuyển cơ học,
không viết lại thuật toán. Các tên module/đường dẫn nội bộ cũ đã được chuyển;
test imports, mock patch targets và guide đang dùng đã được cập nhật.

## Kiểm tra source và tests

- Kiểm tra caller lần hai trước khi sửa; không chuyển/xoá nguyên khối các dịch vụ dùng chung.
- Test mới về ranh giới package/CLI/selector và launcher được chạy FAIL trước khi triển khai, rồi PASS.
- Sau tách Python: **181 tests OK**.
- Full suite qua tên module `fuzzer.tests.test_*`: **597 tests, OK, skipped=2**.
- Kiểm tra cuối wrapper/package/probe sau cập nhật contract: **46 tests OK**.
- `git diff --check`: đạt.
- Reviewer độc lập, chỉ đọc: không phát hiện hồi quy cụ thể; các helper/adapter chuyển sang nơi mới giữ nguyên body, khác biệt coordinator nằm ở imports và lời gọi selector chung.

Hai vấn đề môi trường/cách gọi test đã được ghi riêng:

1. Baseline 221 test trước khi sửa có một lỗi PHP: `Cannot redeclare uopz_set_return()`.
   PHP máy đang nạp UOPZ thật trong khi test định nghĩa stub cùng tên. Full suite
   sử dụng `PHPRC` trỏ vào ini rỗng và `PHP_INI_SCAN_DIR` riêng cho subprocess;
   không đổi PHP ini của máy hay sửa production code để vượt test.
2. `unittest discover -s fuzzer/tests` chạy 597 test nhưng gặp lỗi import ở
   `test_guest_header_cannot_be_mutated_and_auth_cookies_are_removed`:
   `'fuzzer' is not a package`. Chạy toàn bộ file test bằng tên module đầy đủ
   tránh xung đột namespace/module này và cho kết quả full suite ở trên.

Log và các lệnh kiểm tra của lượt làm việc được giữ tại
`.git/online-linked-separation/` ở repository root. Full suite được giới hạn
600 giây bằng outer subprocess; các lượt focused và Docker đều có timeout.

## Bằng chứng Docker

Fixture ZIP được tạo từ source đã có trong
`fuzzer/tests/fixtures/hookphuzz-online-discovery-fixture/`, không thêm seed
plugin giả. Snapshot bootstrap thực tế có `registered=10`,
`bootstrap_candidates=9`.

### Qua wrapper công khai

Run: `hookphuzz-online-discovery-fixture-20260920T214929Z`.
Ngân sách: 40 giây/candidate, tối đa 2 version, 2 candidate, 100 giây/campaign.

Launcher mới và generated replay chạy được, callback được chạm. Hai candidate
kết thúc trong ngân sách; không xuất final config vì probe evidence chưa được
lưu thành công. Đường dẫn request artifact dài 268 ký tự trên checkout Windows;
phép ghi chẩn đoán cùng độ dài cũng trả `FileNotFoundError` dù thư mục cha tồn tại.
Hàm ghi artifact giữ nguyên nội dung so với trước khi tách.

### Với config/output root ngắn và registry đã khởi tạo

Run: `sep-1789921308`. Dùng cùng snapshot seed/registry thực tế, không sửa input
để ép qua gate. Config được bind-mount vào `/app/configs` bằng Compose override
tạm; source/runtime vẫn là checkout hiện tại. Ngân sách: 90 giây/candidate,
2 version, 1 candidate, 100 giây/campaign.

| Kiểm tra | Kết quả |
| --- | --- |
| Candidate thực thi | 1 |
| v0 | `replay_only`, worker đã chạy và dừng |
| Probe | 3 `ACCEPTED / CORRELATED_ZEND_READ` |
| Replay-input trial | Chọn `t0` |
| v1 | `fuzzing_ready`, worker đã chạy và dừng |
| Pass 2 của v1 | `accepted=1`, `total=1` |
| Final export | 1 config, khớp byte với config v1 đã xác minh |
| Kết thúc candidate | `BOUNDED_ONLINE_COMPLETE / BUDGET_EXPIRED` |
| Vulnerability | Không ghi nhận trong lượt fixture này |

Artifacts:

- [Batch state](C:/Users/chuda/.codex/tmp/sep-1789921308/online-linked/sep-1789921308/batch-state.json)
- [Candidate state](C:/Users/chuda/.codex/tmp/sep-1789921308/online-linked/8516f7f875b4330b/state.json)
- [Final configs](C:/Users/chuda/.codex/tmp/sep-1789921308/online-linked/sep-1789921308/final-configs)

Một lượt thử trước đó sau khi web bị dừng chưa khởi tạo lại callback registry,
nên không có raw Zend candidate; đã được giữ riêng trong log. Một lượt với chỉ
output root ngắn đã nhận đủ 3 probe nhưng vướng đường dẫn dài lúc xuất config
cho replay-input trial. Kết quả đạt trong bảng là lượt dùng cả hai root ngắn và
registry đúng, không gộp bằng chứng giữa các run.

### Mode online cũ

Smoke độc lập với ngân sách 5 giây, một version, cùng fixture và config root
ngắn: tạo/chạy v0 và kết thúc `BOUNDED_ONLINE_COMPLETE`, exit code 0. Không còn
worker online chạy sau lượt này. Đây là bằng chứng vòng đời/selector của mode
cũ; không coi trạng thái đó là chứng minh vulnerability hoặc Pass 2.

[Lineage của online cũ](C:/Users/chuda/.codex/tmp/sep-1789921308/old-online/online/sep-1789921308-old/lineage.json).

## Giới hạn và bảo toàn WIP

Giới hạn đường dẫn dài trên Windows chưa được sửa trong lần tách này. Lệnh
wrapper mặc định vẫn dùng các thư mục cũ để giữ tương thích. Bằng chứng
`v0 → v1 → Pass 2 → export` phía trên áp dụng cho fixture với root ngắn;
không tuyên bố mọi real plugin hoặc mọi nhánh runtime đã được xác minh.
Runtime registration child và nhánh phục hồi khi child thất bại được kiểm tra
bằng tests, chưa có Docker proof mới riêng trong lượt này.

Các file WIP so sánh config (`config_comparison/README.md`,
`config_comparison/online_linked.py`, `tests/test_online_linked_config_comparison.py`)
giữ nguyên SHA256. Không thiếu file untracked nào đã có trước khi làm.
Không stage WIP, không commit/push, không xoá artifacts hay container cũ ngoài
phạm vi kiểm thử của lượt này.
