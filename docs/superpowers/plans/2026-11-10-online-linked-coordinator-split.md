# Kế hoạch tách Online-linked Coordinator

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal** — Giảm khoảng 900–1.000 dòng trong `coordinator.py` bằng cách chuyển các phần có ranh giới rõ vào `online_linked/coordination/`.

**Architecture** — `OnlineLinkedCoordinator` điều phối vòng đời một candidate và là nơi cập nhật state, deadline và thứ tự chuyển worker. Campaign gọi coordinator, còn coordinator gọi các hàm xử lý request, evidence và Docker với dữ liệu tường minh.

**Tech Stack** — Python, unittest, PowerShell, RTK.

**Spec** — Yêu cầu trong chat ngày 10/11/2026 về việc chia nhỏ `coordinator.py` và gom các module tách ra vào một thư mục con. Kế hoạch chọn đợt tách đầu tiên dựa trên các ranh giới có thể kiểm tra bằng test hiện có. Dự kiến còn khoảng 3.800–3.900 dòng sau đợt này.

## Phạm vi

- Mốc khảo sát là `d187146fd9b63ea0f1d6445db62efb279b70ae62` trên `feature/single-callback-baseline`. File có 4.757 dòng.
- Giữ `from online_linked.coordinator import OnlineLinkedCoordinator`, lệnh `python -m online_linked`, cờ CLI và mã thoát. Giữ cả điểm chạy trực tiếp `python -m online_linked.coordinator`.
- Giữ cấu trúc JSON, đường dẫn artifact, thứ tự ghi checkpoint, thuật toán hash và `_CANDIDATE_CONTEXT_KEY_VERSION = 1`. `--resume` tiếp tục đọc dữ liệu cũ với cùng điều kiện chấp nhận. Giữ chính sách replay, pause/ACK, budget, stop-on-vulnerability và cấp priority seed một lần.
- Vòng lặp probe, convergence, handoff, chính sách resume và quyền ghi state tiếp tục nằm trong coordinator ở đợt này. Chuyển từng phần cùng các test tương ứng, với thứ tự kiểm tra hiện tại.
- Phạm vi sửa gồm code trong package online-linked và các test trực tiếp liên quan. Đây là refactor cấu trúc. Các lỗi baseline đường dẫn dài được theo dõi riêng.

## Cấu trúc sau khi tách

```text
phuzz-main/code/fuzzer/online_linked/
├── __main__.py                  # Gọi coordination.campaign.main
├── coordinator.py               # Vòng đời candidate, state, probe, handoff
├── coordination/
│   ├── __init__.py              # Package marker, không import các module con
│   ├── campaign.py              # CLI, hàng đợi, campaign resume và final export
│   ├── candidate_identity.py    # Identity và context key dùng chung
│   ├── errors.py                # Kiểu lỗi dùng chung trong coordinator và replay
│   ├── replay_request.py        # Dựng lại giá trị request cho replay
│   ├── replay_artifacts.py      # Kiểm tra và lưu artifact của lượt replay
│   └── worker.py               # Giao tiếp Docker và lệnh pause/ACK/resume
├── evidence.py                 # Đọc batch và đối chiếu cặp request/Zend
├── export.py
└── probe_sender.py
```

## 0. Chốt baseline

- [x] Chạy `rtk git status --short --branch` và `rtk git rev-parse HEAD`. Ghi lại WIP và mốc đang kiểm tra trước khi sửa.
- [x] Chạy sáu suite theo lệnh bên dưới. Tại mốc khảo sát, 218 test đã chạy với 10 failures từ hai test export có nhiều subtest, và 1 error tại `test_coordinator_mirror_and_registry_read_with_deep_root` khi `_write_state` đọc `suggested.json` qua đường dẫn Windows sâu. Cả ba test thuộc `test_online_linked_long_paths`. Ghi lại danh tính subtest và lỗi thực tế nếu môi trường cho kết quả khác.

Chạy từ `phuzz-main/code/fuzzer` trong PowerShell. Với từng đợt, đổi `$Suite` thành tên suite hoặc tên test đã liệt kê. Giữ bộ sáu suite cho lần chạy đầu và lần chạy cuối.

```powershell
$Suite = @(
    'test_online_linked_coordinator',
    'test_online_linked_priority_handoff',
    'test_online_linked_long_paths',
    'test_online_linked_package',
    'test_online_linked_evidence',
    'test_phuzz_wrapper_contract'
)
@'
import subprocess
import sys

runner = (
    "import sys, unittest\n"
    "sys.path.insert(0, 'tests')\n"
    "unittest.main(module=None, argv=['unittest', '-q', *sys.argv[1:]])"
)
result = subprocess.run([sys.executable, "-B", "-c", runner, *sys.argv[1:]], timeout=120)
raise SystemExit(result.returncode)
'@ | rtk proxy python -B - @Suite
```

## 1. Tách campaign và candidate identity

**Tệp** — Tạo `coordination/__init__.py`, `coordination/campaign.py` và `coordination/candidate_identity.py`. Sửa `coordinator.py`, `__main__.py`, `tests/test_online_linked_coordinator.py` và `tests/test_online_linked_package.py`.

- [x] Trước khi chuyển code, bổ sung assertion vào test context key hiện có để kiểm tra giá trị chính xác. Chạy test trước và sau khi chuyển. Các test so sánh hai key với nhau có thể vẫn pass khi cả hai hash đã đổi.

```python
self.assertEqual(
    _candidate_context_key(seed_item(), "fixture"),
    "8b7b3ed1b0fcaf9eeeaeeea7577e5f8e0245214074a65c13b09a0829b5fc2570",
)
```

- [x] Chuyển cụm `_canonical_callback_name`, `_candidate_slug`, `_normalize_identity_route`, `_candidate_identity`, `_batch_candidate_identity`, `_candidate_context_key` và `_CANDIDATE_CONTEXT_KEY_VERSION` vào `candidate_identity.py`. Hai bên import cùng module. Giữ nguyên chữ ký, logic chuẩn hoá và dữ liệu đầu vào hash. `_request_id` ở coordinator, nơi định nghĩa đang có hiệu lực trả `r-` và 24 ký tự hex.
- [x] Chuyển `_sync_callback_registry_to_web(registry_path: Path) -> None`, `run_online_linked(args: argparse.Namespace) -> int`, `build_argument_parser() -> argparse.ArgumentParser` và `main(argv: Sequence[str] | None = None) -> int` vào `campaign.py`. Campaign import `OnlineLinkedCoordinator` và `_budget_pair` từ coordinator. Giữ `_budget_pair` ở vị trí hiện tại để dùng chung.
- [x] Cho package `__main__.py` import `main` từ `coordination.campaign`. Trong `coordinator.py`, import `main` cục bộ dưới guard `if __name__ == "__main__"` để giữ lệnh chạy trực tiếp và tránh vòng import khi import class.
- [x] Đổi import và mock của campaign trong test sang nơi tra cứu mới. Các mock `OnlineLinkedCoordinator`, `export_online_linked_batch`, `_sync_callback_registry_to_web` và `_write_json` dành cho campaign trỏ vào `online_linked.coordination.campaign`. Các mock và import kiểm tra checkpoint của candidate giữ đích ở coordinator. Cho package test kiểm tra cả điểm chạy trực tiếp và duyệt module con bằng `rglob('*.py')`.
- [x] Chạy `test_online_linked_coordinator`, `test_online_linked_package` và `test_phuzz_wrapper_contract`. Các test kiểm tra context key, dedupe, campaign resume và CLI phải pass. Đối chiếu hành vi lỗi khi registry sync bị gián đoạn qua `test_campaign_resume_after_runtime_registry_merge_retains_integrity`.

## 2. Tách đối chiếu evidence và chuẩn bị replay

**Tệp** — Sửa `evidence.py` và `coordinator.py`. Tạo `coordination/errors.py`, `coordination/replay_request.py` và `coordination/replay_artifacts.py`.

- [x] Chuyển thân `_correlate_runtime_pair` sang `evidence.correlate_runtime_pair(version: Mapping[str, Any], pair: Mapping[str, Any], *, plugin_slug: str) -> dict[str, Any] | None`. Gọi hàm ở hai luồng đọc evidence worker và gate. Giữ nguyên đối chiếu tên file, request ID, run ID và plugin. Giữ dedupe, deadline, khám phá callback và checkpoint tại nơi gọi.
- [x] Chuyển `OnlineLinkedError` và `ReplayArtifactError` sang `coordination/errors.py`. Import lại hai tên vào coordinator để các caller và test thấy cùng kiểu exception.
- [x] Chuyển `_request_bucket_values` cùng thân `_restore_request_values` sang `replay_request.py`. Hàm `restore_request_values(config, evidence, parent, *, only_parameters=None) -> None` giữ nguyên kiểu tham số, sửa `config` tại chỗ và gọi hàm đọc bucket trong cùng module. Giữ method `_restore_request_values` làm điểm gọi hiện tại. Kiểm tra giá trị JSON lồng, kiểu dữ liệu, selector fixed/fuzz, cookie thiếu giá trị và metadata nguồn evidence.
- [x] Chuyển thân `_save_replay_artifacts` và `_validate_artifact_payload` sang `replay_artifacts.py`. Hàm `save_replay_artifacts(row, request_dir, zend_dir, *, strict_correlation, load_request, load_zend, list_zend, write_json) -> None` nhận đúng các hàm mà coordinator đang dùng. Giữ method `_save_replay_artifacts` để truyền các dependency, kể cả `self._copy_json`. Truyền `list_zend=lambda: self.list_zend_artifacts()` để chỉ tra cứu và gọi loader này ở nhánh fallback. Giữ chế độ strict/lenient, thứ tự ghi độc quyền và giá trị `ReplayArtifactError.stage`.
- [x] Chạy `test_online_linked_coordinator`, `test_online_linked_evidence` và `test_online_linked_long_paths`. Các test `test_php_json_values_reach_child_and_replay_with_original_types`, `test_malformed_request_bucket_is_rejected_with_reason`, `test_replay_artifact_payloads_are_saved_without_reload_and_classify_failures` và `test_deep_request_zend_pair_keeps_strict_correlation` phải pass. Suite long paths chỉ được có các lỗi đã tái hiện ở baseline.

## 3. Tách giao tiếp Docker của worker

**Tệp** — Tạo `coordination/worker.py`. Sửa `coordinator.py` và vị trí đọc source trong `tests/test_phuzz_wrapper_contract.py`.

- [x] Chuyển phần dựng argv của `_start_worker` sang `worker_start_command(version, *, container_name, runtime_slug, service, priority_seed) -> list[str]`. `version` đã có `worker_run_id` và `handoff_key` từ coordinator. Truyền priority seed khi coordinator đã quyết định cấp. Giữ thứ tự argv, CmpLog, namespace, finding path và JSON của priority seed. Giữ việc gọi Docker start, xử lý lỗi, ghi version và checkpoint tại coordinator.
- [x] Chuyển I/O của `_worker_exit_code` và `_handoff_command` sang `worker_exit_code(container_name, *, timeout, run_command) -> int | None` và `handoff_command(container_name, *args, deadline, clock, run_command) -> dict[str, Any] | None`. Giữ timeout hiện tại và dùng lại `ParentInspectionError`, `ParentInspectionTimeout` từ `probe_sender.py`. Các method hiện tại gọi helper và vẫn là điểm dùng trong flow.
- [x] Chuyển lệnh remove và vòng đợi Docker hoàn tất remove sang `remove_container(container_name, *, clock, sleeper, run_command) -> tuple[bool, str]`. `_stop_worker` áp dụng kết quả vào worker record và checkpoint như cũ. Giữ logic kiểm tra ACK khớp token/run ID, resume khi bị từ chối và quyết định có được start child ở coordinator.
- [x] Đổi đúng kiểm tra nguồn của `HOOKPHUZZ_CMPLOG=1` sang `coordination/worker.py`. Chạy `test_online_linked_coordinator`, `test_online_linked_priority_handoff` và `test_phuzz_wrapper_contract`. Các test kiểm tra ACK đến muộn, resume khi replay bị từ chối, thứ tự stop/start, lỗi remove, lỗi start child và priority seed cấp một lần phải pass.

## 4. Kiểm tra kết quả

- [x] Chạy lại sáu suite với timeout 120 giây. So sánh theo tên test, subtest và nguyên nhân với baseline. Truy ra đợt thay đổi đầu tiên nếu xuất hiện lỗi mới.
- [x] Chạy `rtk git diff --check` và kiểm tra cả tracked diff lẫn tệp mới qua `rtk git status --short`. So số dòng với mốc 4.757 và đọc lại luồng `run` → probe → replay → handoff để kiểm tra thứ tự cập nhật state, checkpoint và worker.
- [x] Báo số dòng thực tế, kết quả test và lỗi baseline còn tái hiện. Ghi rõ phạm vi kiểm chứng là unit/contract test. Kết quả runtime WordPress hoặc fuzzing cần lượt chạy riêng.

## Ghi chú thực thi

- Các loader request và Zend được tra cứu khi nhánh đọc thật sự cần chúng. Kiểm tra hồi quy đã xác nhận đường lưu artifact có payload sẵn không phụ thuộc vào loader.

- Kết quả trên checkout hiện tại. Coordinator còn 3.831 dòng, giảm 926 dòng. Đợt kiểm tra worker và CLI qua 200 test. Lần chạy cuối gồm 218 test, tái hiện đúng 10 failures và 1 error của baseline long paths theo tên test, subtest và lỗi.
