# Remove Compatibility Wrappers — Luna Implementation Plan

## Review follow-up — 2026-09-21

- Fixed test module import (`fuzzer`) and Windows directory identity comparison (`Path.samefile`), preserving behavior assertions.
- Raised only the redirect test budget from 0.2 to 2 seconds; added sender result to assertion diagnostics. A controlled 0.3-second preparation delay failed before and passed after. Forcing redirects in memory still made the test fail.
- Latest full unittest run: 541 tests, 539 passed, 0 failures, 0 errors, 2 skipped (CF7 opt-in smoke and unavailable hookphuzz-zend image), 91.788 seconds. Earlier baseline/after counts below describe earlier checkpoints.
- Runtime verification remains partial; unit-test success does not establish fuzzing or discovery runtime success.

> **For agentic workers:** Use `superpowers:executing-plans` to implement task-by-task. Luna thực hiện trực tiếp; không cần subagent. Đánh dấu checkbox theo bằng chứng thực tế.

**Goal:** Xóa đúng 42 wrapper trong danh sách, chuyển caller sang module thật và chứng minh luồng được hỗ trợ không phát sinh regression.

**Architecture:** Giữ nguyên implementation; chỉ đổi import, đường dẫn CLI, test tương thích cũ và hướng dẫn đang dùng. Không tạo shim mới, không gom hoặc di chuyển module thật.

**Tech Stack:** Python, unittest, PowerShell, Docker/WordPress nếu môi trường runtime có sẵn.

**Spec:** [Danh sách 42 wrapper](../../compatibility-wrapper-removal-list.md). Bảng trong tài liệu này là allowlist xóa; cột file đích là bản đồ chuyển import. Repo root khi lập plan: `C:/Users/nghia.cd_extremevn/Desktop/Phuzz-hook`; các đường dẫn bên dưới tính từ repo root.

## Global Constraints

- HEAD khi lập plan: `7f81ce6`, branch `feature/separate-online-linked`, commit `refactor!: keep only online-linked workflow`. Kiểm tra lại trước khi sửa.
- Bảo toàn WIP: có tài liệu, ZIP/plugin, config online-linked và log chưa track. Không clean/reset/stash toàn repo, không sửa artifact cũ.
- Không commit/push nếu chưa được yêu cầu. Không thêm dependency hoặc cơ chế compatibility mới.
- Không sửa thuật toán discovery, convergence, replay, auth/nonce, config export, deadline, queue hay worker.
- Không xóa cả thư mục, `__init__.py`, CLI chứa logic thật hoặc các runner chỉ vì file ngắn.
- Thay đổi có chủ đích: các đường import/CLI wrapper cũ ngừng được hỗ trợ. Code nội bộ và hướng dẫn hiện hành phải dùng đường mới; không hứa script ngoài repo vẫn chạy nguyên trạng.
- Tất cả test/process dài phải có timeout. Nếu timeout, kết luận chưa xác minh; không bỏ test để lấy PASS.
- Chỉ plan được tạo ở lượt này. Chưa xóa wrapper hoặc chạy test baseline.

## Review Focus

1. Import tương đối, package `__init__`, import động, mock target hoặc tên module trong string còn trỏ đường cũ — rà ở Task 1/2, kiểm tra sau xóa ở Task 3.
2. CLI chạy khác working directory mất `sys.path` hoặc đổi default output — kiểm tra parser và subprocess ở Task 2/4.
3. `bridge.py → compat.py → convergence.py` là chuỗi hai wrapper — chuyển thẳng module cuối ở Task 2.
4. Alias `LiveHookSeedGenerator` và private exports của `pipeline.py`/`entry_classifier.py` — bảo toàn symbol thật khi chuyển import ở Task 2.
5. Test lỗi sẵn có do workflow cũ đã bị bỏ ở HEAD — giữ baseline, không phục hồi tính năng đã bỏ hoặc xóa assertion hành vi để xanh ở Task 1/4.

## Task 1 — Chốt phạm vi và baseline

**Files:** Đọc allowlist; `phuzz-main/code/fuzzer/tests/`; các caller Python/PowerShell/shell/Docker và hướng dẫn tìm được. Chưa sửa code.

**Produces:** Danh sách tham chiếu cần đổi, trạng thái baseline và log trong thư mục tạm mới ngoài artifact runtime cũ.

- [x] Đọc AGENTS.md áp dụng; chạy `git status --short`, `git diff --stat`, `git rev-parse HEAD`. Ghi WIP ban đầu.
- [x] Đọc đủ 42 wrapper, xác minh file đích và symbol thực sự được re-export. Không có khác biệt allowlist.
- [x] Dùng `rg --files --hidden -g '!.git'`/AST/text scan rà code, test, shell, Docker và hướng dẫn theo module cũ; đã kiểm tra import tương đối, import động, mock target, subprocess và Path.
- [x] Tách kết quả thành caller thực thi, hướng dẫn hiện hành và ghi chép lịch sử; caller hiện hành ghi ở Task 2, lịch sử/allowlist/plan giữ tên cũ.
- [x] Baseline full unittest: 542 run, 2 failure, 1 error, 2 skip; log tạm đã ghi trong ledger.
- [x] Baseline import 39 đích: 38 pass, 1 dependency error (`bleach`); baseline 9/9 CLI `--help` pass.

Chạy từ `phuzz-main/code/fuzzer`; dùng Python harness sau trong phiên tạm, không thêm test runner vào sản phẩm:

```python
import subprocess, sys, tempfile
from pathlib import Path

log_dir = Path(tempfile.mkdtemp(prefix="phuzz-wrapper-cleanup-"))
print(log_dir)
with (log_dir / "baseline-unittest.log").open("w", encoding="utf-8") as log:
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"],
        stdout=log, stderr=subprocess.STDOUT, timeout=900,
    )
print("exit_code", result.returncode)
```

- [x] Checkpoint: 42 file, caller và baseline đã báo; runtime chưa được kết luận từ baseline offline.

## Task 2 — Chuyển caller và giữ kiểm tra hành vi

**Modify:** Các file dưới đây cộng caller thực thi/hướng dẫn đã xác minh ở Task 1. Không sửa file chỉ vì khớp text lịch sử.

**Consumes:** Bản đồ wrapper → module thật. **Produces:** Caller không cần wrapper; test còn kiểm tra hợp đồng hành vi.

- [x] `phuzz-main/code/fuzzer/tests/test_seed_to_config_exporter.py`: thay import bằng:

```python
from seed_generation.convergence.convergence import merge_enriched_seeds
```

- [x] `phuzz-main/code/fuzzer/tests/test_core_module_paths.py`: bỏ import/assert compatibility; giữ assertion `canonical_get_file_path("/resources")` so với fuzzer root.
- [x] `phuzz-main/code/fuzzer/tests/test_hook_guidance_cli_paths.py`: bỏ `legacy_parser`; giữ đủ ba assertion trên parser đích.
- [x] `phuzz-main/code/fuzzer/tests/test_zend_discovery.py`: bỏ riêng compatibility assertion; giữ test chức năng convergence, provenance và replay; test giảm 1.
- [x] `generator.py`: rà caller; không còn caller dùng alias cũ, không sửa module thật và không thêm alias.
- [x] Private symbols đã được rà; caller hiện hành dùng module thật, không dùng `import *` để lấy private symbol.
- [x] Chuyển caller còn lại: test CLI paths, merge import, current guide, README và handoff đã dùng đích cuối; mock target hiện hành không trỏ wrapper.
- [x] `phuzz-main/code/docs/guides/hook-aware-seed-generation.md`: lệnh seed validator dùng `python -m seed_generation.verification.seed_validator` từ fuzzer root, giữ flags.
- [x] Cập nhật hướng dẫn hiện hành khác tìm được (`README.md`, `zend_discovery/AGENT_HANDOFF.md`); lịch sử giữ tên cũ.
- [x] Bốn file test liên quan chạy discovery, timeout 300 giây/file: 1/1, 1/1, 31/31, 110/110 (1 skip), đều exit 0; log tạm trong ledger.

## Task 3 — Xóa đúng allowlist

**Delete:** Chính xác 42 file trong spec, bao gồm `seed_generation/convergence/compat.py`. Không thêm file khác.

- [x] Trước khi xóa, resolve 42 đường dẫn tuyệt đối trong repo/fuzzer root; tất cả tracked sạch, không có WIP mới.
- [x] Xóa chính xác từng file allowlist bằng patch `Delete File`; không recursive delete, không file ngoài danh sách.
- [x] Rà lại tham chiếu Task 1: active caller old-module/path = 0; tên cũ chỉ còn trong lịch sử/plan/allowlist.
- [x] Xác minh 42 đường cũ không tồn tại; 41 đích cuối tồn tại, `compat.py` không tồn tại theo ngoại lệ bridge/compat.
- [x] `git diff --name-status`: đúng 42 deletion, 12 modification đều có lý do; `git diff --check` không báo lỗi whitespace (chỉ cảnh báo line-ending).

## Task 4 — Chứng minh không phát sinh regression

**Produces:** Log sau sửa, đối chiếu baseline, verdict có giới hạn bằng chứng rõ ràng.

- [x] Process Python mới import 39 module đích cuối (bỏ compat.py/bridge target); timeout 30 giây/import; 38 pass, 1 lỗi dependency nền `core.vulncheck` thiếu `bleach`, giống baseline.
- [x] Chạy 9 CLI đích bằng `sys.executable -m MODULE --help`, cwd=fuzzer root, timeout 30 giây/CLI; 9/9 exit 0 và có usage/options.

```text
discovery.wordpress.bootstrap_probe_runner
discovery.entrypoints.classifier
hook_guidance.coverage.cli
cli.export_seeds
cli.entrypoint_pipeline
cli.seed_to_config
cli.export_zend_seeds
seed_generation.verification.seed_validator
artifacts.retention.generated_runs
```

- [x] Kiểm tra invocation launcher từ `phuzz-main/code` bằng `phuzz.ps1 -Mode online-linked ... -DryRun`; `--help` từ fuzzer root không được coi là launcher proof.
- [x] Full unittest sau sửa: 541 run, 2 failure, 1 error, 2 skip; log cuối trong ledger, timeout 900 giây; failure/error/skip giữ nguyên baseline, test compatibility giảm đúng 1.
- [x] Đã đọc riêng nhóm online-linked, auth, replay inputs, config export, hook guidance, CmpLog và Zend discovery; không gọi suite xanh.
- [x] Docker/WordPress smoke bounded chạy bằng entrypoint hiện hành với fixture, 1 candidate/1 version; startup, Zend registry và worker request có log mới, nhưng `GATE_NOT_VERIFIED`, 0 final configs, `CANDIDATE_BUDGET_EXPIRED`; không coi là fuzzing PASS.
- [x] Runtime có chạy bounded nhưng admission chưa xác minh; không dùng HTTP 200/CLI help/unit tests để tuyên bố hệ thống runtime bình thường.
- [x] Diff/WIP cuối đang được kiểm tra; checklist allowlist đã cập nhật; không commit/push.

## Báo cáo bàn giao bắt buộc

Trả một báo cáo ngắn gồm:

1. Đã xóa bao nhiêu/42 file; caller/test/docs nào đã đổi; wrapper còn lại và lý do nếu có.
2. Baseline và sau sửa: run/failure/error/skip; test compatibility bị bỏ; đường dẫn log.
3. Import và CLI: tổng số đạt/lỗi; runtime smoke chạy hay chưa và bằng chứng.
4. Diff ngoài phạm vi: phải không có; WIP ban đầu vẫn được bảo toàn.
5. Một verdict: **VERIFIED** nếu hoàn tất scope, các gate đều đạt và smoke runtime được xác minh; **PARTIAL** nếu cleanup/offline đạt nhưng runtime hoặc baseline còn thiếu; **BLOCKED** nếu còn caller lỗi/regression chưa giải quyết. Nêu chính xác giới hạn, không viết “hoạt động bình thường” khi còn gate chưa chạy.
