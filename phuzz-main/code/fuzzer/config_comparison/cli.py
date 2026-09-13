from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .comparator import compare_configs
from .models import CompareResult, Status
from .policy import ComparisonPolicy
from .reference_index import compare_many, prepare_references


class DuplicateJSONKeyError(ValueError):
    pass


def _object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJSONKeyError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _input_error(path: Path | str, message: str) -> dict[str, str]:
    return {"kind": "INPUT_ERROR", "path": str(path), "message": message}


def _load_json(path: Path) -> tuple[Any | None, dict[str, str] | None]:
    try:
        text = path.read_text(encoding="utf-8-sig")
        return json.loads(text, object_pairs_hook=_object_pairs_hook), None
    except DuplicateJSONKeyError as exc:
        return None, _input_error(path, str(exc))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, _input_error(path, str(exc))


def _path_is_inside(path: Path, directory: Path) -> bool:
    try:
        path.relative_to(directory)
    except ValueError:
        return False
    return True


def _output_conflict(output: Path, inputs: list[Path]) -> bool:
    output_resolved = output.resolve()
    for input_path in inputs:
        resolved = input_path.resolve()
        if input_path.is_dir():
            if _path_is_inside(output_resolved, resolved):
                return True
        elif output_resolved == resolved:
            return True
    return False


def _load_input(path_value: str) -> tuple[list[Any], list[Path], list[dict[str, str]], bool]:
    path = Path(path_value)
    if not path.exists():
        return [], [], [_input_error(path, "input does not exist")], False
    if path.is_file():
        value, error = _load_json(path)
        return ([] if error else [value]), ([] if error else [path]), ([error] if error else []), False
    if not path.is_dir():
        return [], [], [_input_error(path, "input is not a file or directory")], False

    root = path.resolve()
    files = sorted(path.rglob("*.json"), key=lambda item: str(item).casefold())
    if not files:
        return [], [], [_input_error(path, "empty input folder")], True

    values: list[Any] = []
    paths: list[Path] = []
    errors: list[dict[str, str]] = []
    marker_names = {"generated_config_summary.json", "generated_param_summary.json", "manifest.json"}
    for file_path in files:
        if file_path.is_symlink() and not _path_is_inside(file_path.resolve(), root):
            errors.append(_input_error(file_path, "symlink resolves outside input tree"))
            continue
        if file_path.name in marker_names or any(part.lower() == "artifacts" for part in file_path.parts):
            errors.append(_input_error(file_path, "summary/artifact/manifest is not a raw PHUZZ config"))
            continue
        value, error = _load_json(file_path)
        if error:
            errors.append(error)
            continue
        values.append(value)
        paths.append(file_path)
    return values, paths, errors, True


def _policy_dict(policy: ComparisonPolicy) -> dict[str, Any]:
    return {
        "mode": policy.mode,
        "allowed_extra_parameters": [list(item) for item in sorted(policy.allowed_extra_parameters)],
        "ignored_metadata_paths": sorted(policy.ignored_metadata_paths),
    }


def _result_dict(result: CompareResult, actual_paths: list[Path], reference_paths: list[Path]) -> dict[str, Any]:
    value = result.to_dict()
    if result.actual_index is not None and result.actual_index < len(actual_paths):
        value["actual_path"] = str(actual_paths[result.actual_index])
    if result.reference_indices is not None:
        value["reference_paths"] = [
            str(reference_paths[index]) for index in result.reference_indices if index < len(reference_paths)
        ]
    return value


def _build_report(
    *,
    policy: ComparisonPolicy,
    expected_path: Path,
    actual_path: Path,
    results: list[CompareResult],
    actual_paths: list[Path],
    reference_paths: list[Path],
    reference_errors: list[dict[str, Any]],
    input_errors: list[dict[str, str]],
) -> dict[str, Any]:
    counts = {status.value: 0 for status in Status}
    for result in results:
        counts[result.status.value] += 1
    return {
        "policy": _policy_dict(policy),
        "expected": str(expected_path),
        "actual": str(actual_path),
        "counts": counts,
        "results": [_result_dict(result, actual_paths, reference_paths) for result in results],
        "reference_errors": reference_errors,
        "input_errors": input_errors,
    }


def _exit_code(report: dict[str, Any]) -> int:
    if report["input_errors"] or report["reference_errors"] or report["counts"][Status.INVALID.value]:
        return 2
    if any(report["counts"][status.value] for status in (Status.MISMATCH, Status.NO_REFERENCE, Status.AMBIGUOUS)):
        return 1
    if report["counts"][Status.MATCH.value] > 0:
        return 0
    return 2


def _text_report(report: dict[str, Any]) -> str:
    lines = [
        f"MATCH={report['counts']['MATCH']} MISMATCH={report['counts']['MISMATCH']} "
        f"NO_REFERENCE={report['counts']['NO_REFERENCE']} AMBIGUOUS={report['counts']['AMBIGUOUS']} "
        f"INVALID={report['counts']['INVALID']}",
    ]
    for result in report["results"]:
        lines.append(f"{result['status']} {result.get('actual_path', '')}".rstrip())
        for difference in result["differences"]:
            lines.append(f"  {difference['kind']} {difference['path']}")
    for error in report["input_errors"]:
        lines.append(f"INPUT_ERROR {error['path']}: {error['message']}")
    return "\n".join(lines)


def _parse_allowed_extra(values: list[str], parser: argparse.ArgumentParser) -> set[tuple[str, str]]:
    allowed: set[tuple[str, str]] = set()
    for value in values:
        source, separator, name = value.partition(":")
        if not separator or not source or not name:
            parser.error("--allow-extra must be SOURCE:NAME")
        allowed.add((source, name))
    return allowed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Compare raw PHUZZ configs with reference configs")
    parser.add_argument("--expected", required=True)
    parser.add_argument("--actual", required=True)
    parser.add_argument("--policy", choices=("strict", "semantic"), default="strict")
    parser.add_argument("--allow-extra", action="append", default=[])
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--output")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    allowed = _parse_allowed_extra(args.allow_extra, parser)
    try:
        policy = ComparisonPolicy(mode=args.policy, allowed_extra_parameters=allowed)
    except ValueError as exc:
        parser.error(str(exc))

    expected_path = Path(args.expected)
    actual_path = Path(args.actual)
    input_errors: list[dict[str, str]] = []
    if args.output and _output_conflict(Path(args.output), [expected_path, actual_path]):
        input_errors.append(_input_error(args.output, "output may not overwrite or live inside an input tree"))
        report = _build_report(
            policy=policy,
            expected_path=expected_path,
            actual_path=actual_path,
            results=[],
            actual_paths=[],
            reference_paths=[],
            reference_errors=[],
            input_errors=input_errors,
        )
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 2

    expected_values, expected_paths, expected_errors, expected_is_folder = _load_input(args.expected)
    actual_values, actual_paths, actual_errors, actual_is_folder = _load_input(args.actual)
    input_errors.extend(expected_errors)
    input_errors.extend(actual_errors)
    results: list[CompareResult] = []
    reference_errors: list[dict[str, Any]] = []

    if not input_errors and expected_values and actual_values:
        if not expected_is_folder and not actual_is_folder:
            results = [compare_configs(expected_values[0], actual_values[0], policy)]
        else:
            prepared = prepare_references(expected_values, policy)
            results = compare_many(actual_values, prepared)
            reference_errors = [error.to_dict() for error in prepared.reference_errors]
    report = _build_report(
        policy=policy,
        expected_path=expected_path,
        actual_path=actual_path,
        results=results,
        actual_paths=actual_paths,
        reference_paths=expected_paths,
        reference_errors=reference_errors,
        input_errors=input_errors,
    )

    if args.output:
        output_path = Path(args.output)
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        except OSError as exc:
            report["input_errors"].append(_input_error(output_path, str(exc)))
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return 2
    elif args.format == "text":
        print(_text_report(report))
    else:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    return _exit_code(report)


if __name__ == "__main__":
    sys.exit(main())

