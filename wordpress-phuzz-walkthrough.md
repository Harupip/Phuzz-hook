# HookPhuzz WordPress walkthrough

Cập nhật **2026-10-09**, theo code trong working tree. Hướng dẫn dùng workflow `online-linked`; các mô tả manual Compose trước đây đã được thay bằng luồng runner hiện tại. Bản cập nhật doc này không xác nhận plugin nào fuzzing PASS.

## 1. Chuẩn bị đúng context

Từ repo root:

```powershell
Set-Location phuzz-main/code
```

Cần PowerShell 7, Python có dependencies `fuzzer/requirements.txt`, Docker Desktop/Compose, `web/applications/wordpress/wp-cli.phar` và bootstrap config `fuzzer/configs/wordpress/bootstrap-generated.json`. Chuẩn bị `<slug>.zip` trong `PLUGIN_ZIP_DIR` của [phuzz.env](phuzz-main/code/phuzz.env) hoặc `web/applications/wordpress/_plugins/`. Không cần `fuzzer/configs/wordpress/<slug>.json` để discovery plugin đó.

Tên ZIP, version và dependency ảnh hưởng endpoint đăng ký; prefix/version trong tên file không được tự normalize thành slug. Xem [run guide](phuzz-main/code/docs/guides/run-wordpress-plugins.md).

## 2. Xem settings trước khi chạy

```powershell
pwsh -NoProfile -File ./phuzz.ps1 -PluginSlug imsanity -DryRun
```

Dry-run in lệnh delegated và initial budgets, chưa kiểm tra Docker/plugin hay replay. CLI override file env; file override loader defaults. Initial budget có thể tăng với progress đã xác minh, tới hard cap; xem [budget reference](phuzz-main/code/docs/guides/online-linked-flow.md#initial-budget-và-hard-cap).

## 3. Chạy một plugin hoặc batch

```powershell
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -PluginSlug imsanity
# Hoặc mọi ZIP trực tiếp trong thư mục đã chọn, chạy tuần tự
pwsh -NoProfile -File ./phuzz.ps1 -AllPlugins -DryRun
pwsh -NoProfile -NonInteractive -File ./phuzz.ps1 -AllPlugins
```

Không kết hợp `-AllPlugins` với `-PluginSlug`. Batch tắt comparison prompt, tiếp tục sau runner lỗi và trả 1 nếu có run lỗi. Mỗi plugin có campaign budget/output riêng. `-NoFollowLogs` không tắt single-plugin comparison prompt; dùng non-interactive terminal hoặc `ONLINE_COMPARE_PROMPT=0`.

Runner tạo Compose override bật PHP Zend image/UOPZ/CMPLOG, cài target, bootstrap REST và export seed/registry. Coordinator dừng bootstrap worker, gate v0, khám phá tham số qua request/Zend, kiểm tra coherent input rồi replay/Pass 2 child trong parent. Chỉ khi gate đạt mới dừng parent để start child.

## 4. Kiểm tra kết quả theo đúng bước

Từ `phuzz-main/code`, mở:

```text
fuzzer/output/online-seed-generation/<run-id>/suggested_seeds.json
fuzzer/output/online-linked/<run-id>/batch-state.json
fuzzer/output/online-linked/<run-id>/final-config-summary.json
fuzzer/output/online-linked/<run-id>/final-configs/*.json
```

| Bước | Bằng chứng cần đọc |
| --- | --- |
| Candidate được đưa vào queue | `batch-state.json`: identity, hook, method/auth context, source, lineage. |
| Runtime callback/parameter | Theo `state_path`, đối chiếu request/Zend pair đúng run/request/plugin/callback/source/transport. |
| v0 đạt gate | Version `readiness`, convergence, config type và Pass 2 khi fuzzing-ready. |
| Input ghép dùng được | `replay_input_trials`, selected trial, expected/missing parameters và artifact. |
| Child config được xác minh | `replay_result.passed`, Pass 2 `accepted == total > 0`, config/replay hashes. |
| Worker thực sự chạy | `workers`, version `worker_status`, timing, events/logs; replay đạt chưa chứng minh worker started. |
| Config cuối đầy đủ | `final-config-summary.json`: `exported_configs`, skipped/equivalent/superseded versions. |
| Fuzz/coverage/CMPLOG/finding | Worker request/coverage, comparison và finding artifacts cùng run; tái hiện finding riêng. |

Một candidate có thể xuất nhiều config cho context khác nhau. `{a}` được thay bởi `{a,b}` chỉ khi tương thích và đã xác minh. `selected_version` chỉ giữ bản đại diện; dùng `exported_configs` để lấy đủ. `final-configs/superseded/` giữ bản cũ, không phải active export.

`complete_with_skips`, `PARTIAL`, `BOUNDED_ONLINE_COMPLETE`, exit 0 hoặc `BUDGET_EXPIRED` chưa phải PASS. Callback chưa đăng ký có thể do dependency/setup, không phải budget ngắn. `request=probe` có thể không mở nhánh whitelist; tăng timeout không sửa giá trị selector sai.

## 5. So sánh config với experiment

[Comparator](phuzz-main/code/fuzzer/config_comparison/README.md) đọc config offline, không chạy HTTP/replay:

```powershell
# Hai path trong phuzz.env: CONFIG_COMPARE_EXPECTED / CONFIG_COMPARE_ACTUAL
pwsh -NoProfile -File ./compare-configs.ps1
# Một config cuối của run cụ thể và một reference
python -m fuzzer.config_comparison.online_linked --compare-final-config <final.json> --compare-with <reference.json>
```

Lệnh final-config comparison bỏ top-level metadata; strict/semantic CLI tổng quát có policy riêng. MATCH chỉ chứng minh parity declaration theo policy, không chứng minh runtime/vulnerability parity.

## 6. Giữ artifact và resume

PowerShell runner giữ host campaign history, reset runtime artifacts trên shared volume. Fuzzer reset `output/workers/fuzzer-N` khi cùng node khởi động; Bash wrapper xóa `fuzzer/output` trước run. Đừng dùng worker folder cũ thay state của campaign cần kiểm tra.

Resume qua Python `--resume` yêu cầu seed/registry/bootstrap/config/budget và Compose context cũ; revalidate gates bằng request mới, không reset remaining budget. Runner đã xóa override tạm khi kết thúc. [Resume contract](phuzz-main/code/docs/guides/online-linked-flow.md#checkpoint-và-resume).

[Kiến trúc/source map](phuzz-main/code/docs/reference/architecture.md) và [docs index](phuzz-main/code/docs/README.md) chỉ tới từng module và guide. Historical plans/reports giữ bằng chứng tại ngày ghi; không áp dụng kết quả cũ làm acceptance hiện tại.
