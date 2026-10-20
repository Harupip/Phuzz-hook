# HookPhuzz

HookPhuzz mở rộng PHUZZ để khám phá endpoint và tham số WordPress bằng UOPZ/Zend runtime, kiểm chứng request, rồi fuzz bằng config bất biến. Workflow WordPress hiện tại là **online-linked**; các công cụ HAR, Compose, benchmark và so sánh config vẫn là công cụ riêng.

Tài liệu đối chiếu code ngày **2026-10-09**, gồm thay đổi chưa commit trong working tree. Đây là mô tả triển khai, không phải xác nhận mọi plugin đã chạy thành công.

## Chạy nhanh

Từ thư mục repo, cần Docker Desktop/Compose, PowerShell 7, Python và thư viện trong `phuzz-main/code/fuzzer/requirements.txt`:

```powershell
Set-Location phuzz-main/code
pwsh -NoProfile -File ./phuzz.ps1 -PluginSlug imsanity -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug imsanity
```

Chuẩn bị `<slug>.zip` trong `PLUGIN_ZIP_DIR` của [phuzz.env](phuzz-main/code/phuzz.env) hoặc `web/applications/wordpress/_plugins/`. Không cần config thủ công cùng slug. `-DryRun` chỉ in lệnh và budget, chưa kiểm tra Docker hay nội dung ZIP.

```powershell
# Chạy tuần tự mọi ZIP trực tiếp trong thư mục đã chọn
pwsh -NoProfile -File ./phuzz.ps1 -AllPlugins -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -AllPlugins
```

## Đọc tài liệu

| Cần làm | Tài liệu |
| --- | --- |
| Chạy một plugin hoặc batch, chọn ZIP, cấu hình budget | [Hướng dẫn chạy](phuzz-main/code/docs/guides/run-wordpress-plugins.md) |
| Hiểu discovery, probe, coherent replay, handoff, resume và export | [Luồng online-linked](phuzz-main/code/docs/guides/online-linked-flow.md) |
| Tìm module sở hữu chức năng, input/output và test | [Kiến trúc và chức năng](phuzz-main/code/docs/reference/architecture.md) |
| Đọc kết quả từng bước | [Walkthrough](wordpress-phuzz-walkthrough.md) |
| Tìm wrapper và implementation | [Script map](phuzz-main/code/scripts/README.md) |
| So sánh config với experiment | [Config comparison](phuzz-main/code/fuzzer/config_comparison/README.md) |
| Đọc contract xuất config cuối | [Final config export](phuzz-main/code/fuzzer/online_linked/README.md) |
| Xem scoring và hook feedback | [Scoring reference](phuzz-main/code/docs/reference/scoring-modes-mini.md) |
| Xem phạm vi rà doc lần này | [Review 2026-10-09](phuzz-main/code/docs/reports/2026-10-09-documentation-review.md) |
| Tìm toàn bộ guide/reference/report | [Docs index](phuzz-main/code/docs/README.md) |

[PHUZZ gốc và trích dẫn nghiên cứu](phuzz-main/README.md) giữ thông tin công trình ban đầu. `experiment/`, các kế hoạch có ngày và báo cáo plugin là bằng chứng lịch sử; chúng không thay thế code hay artifact của lượt chạy hiện tại.

## Đọc đúng kết quả

Mở `phuzz-main/code/fuzzer/output/online-linked/<run-id>/batch-state.json`, theo `state_path` của candidate, rồi đối chiếu `final-config-summary.json` và `final-configs/*.json`. `selected_version` chỉ là trường tương thích; `exported_configs` mới liệt kê đủ config được xuất.

HTTP 200, callback registered/reached, config tạo được, replay/Pass 2 đạt và worker chạy là các mốc riêng. Exit code 0, hết budget hoặc có final config đều chưa chứng minh fuzzing/vulnerability PASS.
