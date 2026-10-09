# Documentation review — 2026-10-09

## Phạm vi và cách đọc

Repo vận hành PHUZZ cho WordPress trong Docker, thêm runtime hook/parameter discovery, replay-gated immutable workers, hook scoring/CMPLOG và export/config comparison. Giả định sử dụng: một người vận hành cục bộ; campaign online-linked và batch ZIP chạy tuần tự.

Review theo working tree tại HEAD `54ccd416`, gồm WIP có sẵn ở `phuzz.ps1`, `phuzz.env`, env loader, WordPress runner và `init.sh`, cùng test batch/ZIP và fixture CMB2 chưa track. Tài liệu mô tả cả phần này nhưng không coi nó đã commit/deploy hay runtime-verified. Task chỉ sửa Markdown.

Rà entrypoints, Docker/build/dependencies, canonical modules, callers và tests theo luồng: wrapper → WordPress/UOPZ/Zend → seed/registry → queue/v0 gate → evidence/probe/convergence → coherent trial → child replay/Pass 2 → handoff → final export/comparison. Rà scoring/core/findings và map các tool HAR/crawler/Compose/matrix/benchmark/retention/source-assisted riêng. [Architecture](../reference/architecture.md) chỉ tới source sở hữu từng chức năng.

Không đọc từng dòng WordPress/plugin bên thứ ba, không audit mọi sink bảo mật hoặc mọi dòng C/PHP, không rerun toàn bộ experiment. Không build image, chạy campaign plugin, replay acceptance thực hoặc fuzzing trong task doc này. Report có ngày, kế hoạch và handoff cũ giữ kết quả lịch sử; thêm current pointers khi cần.

## Drift đã sửa

| Doc trước | Code đang có / doc sau | Source đối chiếu |
| --- | --- | --- |
| Quick run dùng upstream clone/service tên cũ, manual config cùng slug | Entrypoint `phuzz.ps1`, bootstrap-generated config, không cần manual plugin config | [wrapper](../../phuzz.ps1), [runner](../../scripts/wordpress/run-wordpress-phuzz.ps1) |
| Chỉ nêu ZIP trong `_plugins` | `PLUGIN_ZIP_DIR`, fallback theo target/dependency, mount read-only riêng; batch chỉ quét folder được chọn | [env/ZIP loader](../../scripts/wordpress/read-phuzz-env.ps1), [init](../../web/applications/wordpress/init.sh) |
| Thiếu batch online-linked | `-AllPlugins`: ZIP trực tiếp, sorted, sequential, continue on error, suppress comparison prompt | [wrapper](../../phuzz.ps1), [batch tests](../../fuzzer/tests/test_phuzz_plugin_batch.py) |
| Initial flags là cap cứng và env snapshot cũ | Initial/hard caps riêng, progress dedupe, initial queue capacity, effective budget trong checkpoint | [coordinator](../../fuzzer/online_linked/coordinator.py) |
| Thiếu resume/checkpoint | Python `--resume`, hash/context validation, fresh gate, pending/lineage giữ lại, offline time trừ budget | [coordinator](../../fuzzer/online_linked/coordinator.py) |
| Sơ đồ dừng parent trước replay child | Child replay/Pass 2 trong parent, chỉ đạt rồi stop parent/start child | `handoff_to_next_worker()` trong coordinator |
| Mỗi candidate một final config, không summary/re-export | Distinct contexts, equivalent dedupe, compatible cumulative supersession, exact bytes, summary và archive | [exporter](../../fuzzer/online_linked/export.py) |
| Probe error response luôn bỏ evidence | Correlated pending probe có thể dùng HTTP 400–599 reads; final replay gates giữ nguyên | [runner artifact reader](../../fuzzer/hook_energy/seed_generation/generated_config_runner.py), coordinator |
| Canonical seed/scoring modules ở layout cũ | `seed_generation`, `discovery`, `hook_guidance`, CLI và shared Zend bridge được map rõ | [architecture](../reference/architecture.md) |
| Retention/`-KeepDebugArtifacts` như flag hiện tại | Generated-run API riêng; online-linked wrapper không expose flag này | [retention](../../fuzzer/artifacts/retention/generated_runs.py), runner |
| Scoring scale chỉ dựa candidate hiện tại | Tracker giữ maximum base scale từng thấy trong worker | [scoring](../../fuzzer/core/scoring.py), [integration](../../fuzzer/hook_guidance/integration/integration.py) |
| Config schema có `fuzz: ["*"]` | Regex `.*`, fixed thắng fuzz, empty fuzz mặc định fuzz còn lại; JSON dùng body bucket | [config exporter](../../fuzzer/seed_generation/config/config_exporter.py), [fuzzer loader](../../fuzzer/fuzzer.py) |
| Snapshot Imsanity như current acceptance | Label historical; không suy ra runtime acceptance working tree hiện tại | Historical results + flow snapshot |

## Điểm cần giữ rõ

1. **Run ID chưa chuyển UTC trước khi thêm `Z`.** Runner dùng `Get-Date -Format "yyyyMMddTHHmmssZ"` theo timezone host. Doc ghi đúng giới hạn; chưa sửa logic timestamp vì task chỉ cập nhật doc.
2. **Prompt và budget cần phân biệt.** `-NoFollowLogs` không tắt comparison prompt. Các initial `Online*` budgets có thể tăng tới hard cap; bootstrap/build/cleanup nằm ngoài campaign budget.
3. **Evidence không tương đương PASS.** HTTP/callback/config/replay/worker/coverage/finding là các mốc riêng; summary `selected_version` không đại diện toàn bộ export và `NOT_ASSESSED` không chứng minh discovery đầy đủ.

## Kiểm chứng

Các test sử dụng timeout ngoài tiến trình; không thay test assertions hoặc implementation để vượt môi trường.

| Kiểm tra cuối | Kết quả |
| --- | --- |
| Contract suite, 17 modules, Python 3.12, timeout 240s | **258 tests: 256 đạt, 0 fail, 0 error, 2 skip**, 139.615s; exit 0. [Log](2026-10-09-documentation-review-contracts.log). |
| Link Markdown cục bộ và code fences | 20 tài liệu, 193 link tới file/thư mục tồn tại; code fences cân bằng. Không kiểm tra URL bên ngoài. |
| Ví dụ CLI hiện hành | 22 ví dụ wrapper và 1 resume example: flags tồn tại trong parameter block/parser; không kiểm tra execution của placeholder command. |
| Python source inventory/syntax | AST parse 156 file do dự án quản lý, gồm tests batch/ZIP WIP; không có syntax error. Đây không phải runtime test từng module. |
| Dry-run wrapper | `imsanity`: resolve `30s / 9 versions / 32 candidates / 3600s`, Zend enabled; không khởi động Docker. |
| Diff whitespace | `git diff --check` đạt. |

Hai skip: test symlink escape thiếu privilege Windows (`WinError 1314`); test CF7 ZIP/source smoke opt-in chưa bật `HOOKPHUZZ_COMPARISON_PLUGIN_SMOKE=1`. Chúng không được tính là pass. Suite bao gồm coordinator, export, evidence, replay inputs, final comparison, wrapper, batch/ZIP, retired-mode contract, comparator/normalizer/reference/experiment, scoring/hook integration và auth context. Có `docker compose config` kiểm tra render mount, không khởi động container; PHP producer tests có loopback fixture, không chạy WordPress/plugin campaign.

Lượt sandbox ban đầu không kết luận được: thư mục temp mặc định bị chặn ghi (`PermissionError`/WinError 5). Lượt temp trong workspace dài chạm giới hạn cleanup và timeout 240s. Lượt temp extended-path hoàn tất 258 tests nhưng có 27 failure records, 2 errors, 2 skips; lỗi quan sát gồm loopback bị sandbox chặn (WinError 10013), PowerShell `AuthorizationManager check failed`, temp path dài và atomic replace bị từ chối. Không đánh dấu các lượt này PASS, cũng không tự phân loại mọi lỗi là baseline.

Kiểm chứng cuối dùng temp ngắn `.dt` dưới repo và chạy ngoài sandbox để tách giới hạn môi trường; kết quả ở bảng trên. Temp riêng của task được dọn sau khi lưu log. Không dùng kết quả lịch sử làm số test hiện tại.

## Tài liệu hiện tại

Điểm vào: [repository README](../../../../README.md), [code README](../../README.md), [docs index](../README.md), [walkthrough](../../../../wordpress-phuzz-walkthrough.md). Chi tiết: [run guide](../guides/run-wordpress-plugins.md), [flow](../guides/online-linked-flow.md), [architecture](../reference/architecture.md), [script map](../../scripts/README.md), [fuzzer](../../fuzzer/README.md), [export](../../fuzzer/online_linked/README.md), [comparison](../../fuzzer/config_comparison/README.md), [config schema](../../fuzzer/configs/README.md), [Zend bridge](../../fuzzer/hook_energy/seed_generation/zend_runtime/README.md), [web](../../web/README.md), [scoring](../reference/scoring-modes-mini.md).

Không tạo/sửa config trong task này nên không thêm completion row hoặc thay verdict checklist plugin. Commit tài liệu theo yêu cầu sau review; không push. WIP và artifact trước task được giữ ngoài commit.
