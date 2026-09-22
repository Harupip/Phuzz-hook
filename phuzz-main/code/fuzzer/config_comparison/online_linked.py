from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .cli import _build_report, _exit_code, _load_json
from .comparator import compare_configs
from .models import Status
from .policy import ComparisonPolicy


COMPARISON_POLICY = ComparisonPolicy(
    mode="semantic",
    ignored_metadata_paths={"/metadata"},
)

_VALID_CAMPAIGN_STATUSES = frozenset({
    "complete",
    "complete_with_skips",
    "CANDIDATE_BUDGET_EXPIRED",
    "CAMPAIGN_BUDGET_EXPIRED",
})


def _is_inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _same_path(left: Path, right: Path) -> bool:
    left_resolved = left.resolve()
    right_resolved = right.resolve()
    if left_resolved == right_resolved or os.path.normcase(str(left_resolved)) == os.path.normcase(str(right_resolved)):
        return True
    try:
        return left.exists() and right.exists() and left.samefile(right)
    except OSError:
        return False


def _output_conflicts(output: Path, inputs: list[Path]) -> bool:
    output_resolved = output.resolve()
    for input_path in inputs:
        input_resolved = input_path.resolve()
        if _same_path(output, input_path):
            return True
        if input_path.is_dir() and _is_inside(output_resolved, input_resolved):
            return True
    return False


def _safe_batch_path(path: Path, batch_dir: Path) -> bool:
    return path.resolve().parent == batch_dir


def _write_json_atomic(path: Path, payload: dict) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(payload, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _input_failure(path: Path, message: str) -> int:
    print(f"Config comparison input error: {path}: {message}", file=sys.stderr)
    return 2


def _resolve_run_paths(final_path: Path, reference_path: Path) -> tuple[Path, Path, Path, Path] | None:
    try:
        requested_final_dir = final_path.parent.resolve()
        actual_path = final_path.resolve()
        if requested_final_dir.name != "final-configs" or actual_path.parent != requested_final_dir:
            raise ValueError("final config must be a direct child of final-configs")
        expected_path = reference_path.resolve()
    except (OSError, RuntimeError, ValueError) as exc:
        _input_failure(final_path, str(exc))
        return None

    batch_dir = requested_final_dir.parent
    return actual_path, expected_path, batch_dir / "batch-state.json", batch_dir / "config-comparison.json"


def _validate_batch(batch: Any, batch_dir: Path) -> str | None:
    if not isinstance(batch, dict):
        return "batch state must be a JSON object"
    if batch.get("mode") != "online-linked-batch":
        return "batch state mode is not online-linked-batch"
    if batch.get("legacy_run_id") != batch_dir.name:
        return "batch state legacy_run_id does not match the run directory"
    if batch.get("campaign_status") not in _VALID_CAMPAIGN_STATUSES:
        return "batch campaign_status is not a completed comparison state"
    return None


def run_comparison(final_path: Path, reference_path: Path) -> int:
    final_path = Path(final_path)
    reference_path = Path(reference_path)
    resolved = _resolve_run_paths(final_path, reference_path)
    if resolved is None:
        return 2
    actual_path, expected_path, batch_state_path, report_path = resolved
    batch_dir = batch_state_path.parent

    if not _safe_batch_path(batch_state_path, batch_dir):
        return _input_failure(batch_state_path, "batch state path resolves outside the batch directory")
    batch, batch_error = _load_json(batch_state_path)
    if batch_error is not None:
        return _input_failure(batch_state_path, batch_error["message"])
    validation_error = _validate_batch(batch, batch_dir)
    if validation_error is not None:
        return _input_failure(batch_state_path, validation_error)

    if not _safe_batch_path(report_path, batch_dir):
        return _input_failure(report_path, "report path resolves outside the batch directory")
    if _same_path(report_path, batch_state_path):
        return _input_failure(report_path, "report path aliases batch state")
    if _output_conflicts(report_path, [actual_path, expected_path, batch_state_path]):
        return _input_failure(report_path, "report or batch state would overwrite an input")
    if _output_conflicts(batch_state_path, [actual_path, expected_path]):
        return _input_failure(batch_state_path, "batch state would overwrite an input")

    expected, expected_error = _load_json(expected_path)
    actual, actual_error = _load_json(actual_path)
    input_errors = [error for error in (expected_error, actual_error) if error is not None]
    results = [] if input_errors else [compare_configs(expected, actual, COMPARISON_POLICY)]
    report = _build_report(
        policy=COMPARISON_POLICY,
        expected_path=expected_path,
        actual_path=actual_path,
        results=results,
        actual_paths=[actual_path],
        reference_paths=[expected_path],
        reference_errors=[],
        input_errors=input_errors,
    )
    comparison_exit_code = _exit_code(report)

    try:
        _write_json_atomic(report_path, report)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Config comparison report write failed at {report_path}: {exc}", file=sys.stderr)
        return 2

    batch["config_comparison"] = {
        "status": report["results"][0]["status"] if report["results"] else "INPUT_ERROR",
        "exit_code": comparison_exit_code,
        "report_path": str(report_path),
        "expected": str(expected_path),
        "actual": str(actual_path),
        "counts": report["counts"],
    }
    try:
        _write_json_atomic(batch_state_path, batch)
    except (OSError, TypeError, ValueError) as exc:
        print(
            f"Config comparison report written to {report_path}, but batch state "
            f"was not updated at {batch_state_path}: {exc}",
            file=sys.stderr,
        )
        return 2

    counts = " ".join(f"{status.value}={report['counts'][status.value]}" for status in Status)
    print(f"Config comparison: expected={expected_path} actual={actual_path}")
    print(f"Config comparison counts: {counts}")
    print(f"Config comparison report: {report_path}")
    return comparison_exit_code


def prompt_comparison(batch_dir: Path) -> int:
    if not sys.stdin.isatty():
        print("Config comparison prompt skipped: no interactive terminal.")
        return 0
    final_configs = sorted(path for path in (batch_dir / "final-configs").glob("*.json") if path.is_file())
    if not final_configs:
        print("Config comparison skipped: no final configs exported.")
        return 0
    try:
        if input("Compare an online-linked final config? [y/N]: ").strip().lower() not in {"y", "yes"}:
            return 0
        for index, path in enumerate(final_configs, 1):
            print(f"  {index}) {path.name}")
        selection = input("Select final config number (Enter to cancel): ").strip()
        if not selection:
            return 0
        if not selection.isdecimal() or not 1 <= int(selection) <= len(final_configs):
            return _input_failure(batch_dir, "invalid final config selection")
        reference = input("Experiment reference config path (Enter to cancel): ").strip().strip('\"').strip("'")
        if not reference:
            return 0
        return run_comparison(final_configs[int(selection) - 1], Path(reference))
    except (EOFError, KeyboardInterrupt):
        print("\nConfig comparison cancelled.")
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare one online-linked final config with one experiment config")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--compare-final-config")
    source.add_argument("--prompt-batch", type=Path)
    parser.add_argument("--compare-with")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.prompt_batch is not None and args.compare_with:
        parser.error("--compare-with cannot be combined with --prompt-batch")
    if args.prompt_batch is None and not args.compare_with:
        parser.error("--compare-with is required with --compare-final-config")
    try:
        if args.prompt_batch is not None:
            return prompt_comparison(args.prompt_batch)
        return run_comparison(Path(args.compare_final_config), Path(args.compare_with))
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"Config comparison failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
