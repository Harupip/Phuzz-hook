from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hook_energy.entrypoints import direct_http_details
else:
    from .entrypoints import direct_http_details

SETUP_REQUIRED_HOOKS = {
    "rest_api_init": ("rest_route", "REST route records require route-to-config support before PHUZZ config generation"),
    "xmlrpc_methods": ("xmlrpc_method_map", "XML-RPC method maps require method extraction before PHUZZ config generation"),
}

NON_ENTRY_HOOKS = {
    "admin_menu",
    "init",
    "plugins_loaded",
    "wp_loaded",
}

ARTIFACT_FILTERS = {
    "entrypoint_candidates": None,
    "direct_http_candidates": "direct_http",
    "setup_required_candidates": "setup_required",
    "non_entry_hooks": "non_entry",
}


@dataclass(frozen=True)
class NormalizedCallback:
    hook_name: str | None
    callback_id: str | None
    callback_repr: str | None
    callback_type: str | None
    function_name: str | None
    class_name: str | None
    method_name: str | None
    source_file: str | None
    source_line: int | None
    accepted_args: int | None
    priority: int | None
    status: str | None
    executed_count: int | None
    registered_inside_callback: bool | None
    parent_callback: dict[str, Any] | None
    hook_level: int | None
    parent_hook_name: str | None
    parent_callback_id: str | None
    parent_callback_repr: str | None
    registration_stack_depth: int | None
    raw: dict[str, Any]


def load_registry(input_file: Path, input_format: str) -> tuple[list[NormalizedCallback], str]:
    payload = json.loads(Path(input_file).read_text(encoding="utf-8-sig"))
    detected_format = _detect_format(payload, input_format)
    if detected_format == "total_coverage":
        return _load_total_coverage(payload), detected_format
    if detected_format == "hook_gap_report":
        return _load_hook_gap_report(payload), detected_format
    raise ValueError(f"Unsupported registry format: {detected_format}")


def classify_callbacks(callbacks: list[NormalizedCallback], source_file: str) -> dict[str, Any]:
    candidates = [_classify_callback(callback, index) for index, callback in enumerate(callbacks, start=1)]
    return _build_report(source_file=source_file, candidates=candidates)


def write_classification_artifacts(report: dict[str, Any], output_dir: Path, pretty: bool = False) -> dict[str, Path]:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}
    for artifact_name, classification in ARTIFACT_FILTERS.items():
        filtered = _filter_report(report, classification)
        artifact_path = output_path / f"{artifact_name}.json"
        artifact_path.write_text(
            json.dumps(filtered, indent=2 if pretty else None, ensure_ascii=False),
            encoding="utf-8",
        )
        paths[artifact_name] = artifact_path
    return paths


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Classify HookPhuzz runtime hook registry entry points.")
    parser.add_argument("--input-file", required=True, help="Path to total_coverage.json or hook_gap_report.json.")
    parser.add_argument("--output-dir", required=True, help="Directory to write entry classifier artifacts.")
    parser.add_argument(
        "--format",
        choices=("auto", "total_coverage", "hook_gap_report"),
        default="auto",
        help="Input registry format.",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    callbacks, _ = load_registry(Path(args.input_file), args.format)
    report = classify_callbacks(callbacks, str(Path(args.input_file)))
    paths = write_classification_artifacts(report, Path(args.output_dir), pretty=args.pretty)
    counts = report["counts"]
    print(
        "Entry classifier summary: "
        f"direct_http={counts['direct_http']} "
        f"setup_required={counts['setup_required']} "
        f"non_entry={counts['non_entry']} "
        f"output={paths['entrypoint_candidates']}"
    )
    return 0


def _detect_format(payload: dict[str, Any], requested_format: str) -> str:
    if requested_format != "auto":
        return requested_format
    data = payload.get("data")
    if isinstance(data, dict) and "registered_callbacks" in data:
        return "total_coverage"
    if isinstance(payload.get("callbacks"), list):
        return "hook_gap_report"
    raise ValueError("Could not auto-detect registry format")


def _load_total_coverage(payload: dict[str, Any]) -> list[NormalizedCallback]:
    data = payload.get("data", {})
    registered_callbacks = data.get("registered_callbacks", {})
    executed_callbacks = data.get("executed_callbacks", {})
    if not isinstance(registered_callbacks, dict):
        raise ValueError("total_coverage input must contain data.registered_callbacks mapping")
    if not isinstance(executed_callbacks, dict):
        executed_callbacks = {}

    callbacks: list[NormalizedCallback] = []
    for callback_id, row in sorted(registered_callbacks.items()):
        if not isinstance(row, dict):
            continue
        merged = dict(row)
        merged.setdefault("callback_id", str(callback_id))
        executed_row = executed_callbacks.get(callback_id)
        if isinstance(executed_row, dict) and "executed_count" in executed_row:
            merged["executed_count"] = executed_row.get("executed_count")
        callbacks.append(_normalize_callback(merged))
    return callbacks


def _load_hook_gap_report(payload: dict[str, Any]) -> list[NormalizedCallback]:
    rows = payload.get("callbacks", [])
    if not isinstance(rows, list):
        raise ValueError("hook_gap_report input must contain callbacks array")
    return [_normalize_callback(row) for row in rows if isinstance(row, dict)]


def _normalize_callback(row: dict[str, Any]) -> NormalizedCallback:
    return NormalizedCallback(
        hook_name=_optional_string(row.get("hook_name")),
        callback_id=_optional_string(row.get("callback_id")),
        callback_repr=_optional_string(row.get("callback_repr", row.get("callback_raw", row.get("callback_name")))),
        callback_type=_optional_string(row.get("callback_type", row.get("type"))),
        function_name=_optional_string(row.get("function_name")),
        class_name=_optional_string(row.get("class_name")),
        method_name=_optional_string(row.get("method_name")),
        source_file=_optional_string(row.get("source_file")),
        source_line=_optional_int(row.get("source_line")),
        accepted_args=_optional_int(row.get("accepted_args")),
        priority=_optional_int(row.get("priority")),
        status=_optional_string(row.get("status", row.get("registration_status"))),
        executed_count=_optional_int(row.get("executed_count", row.get("execute_count"))),
        registered_inside_callback=_optional_bool(row.get("registered_inside_callback")),
        parent_callback=dict(row["parent_callback"]) if isinstance(row.get("parent_callback"), dict) else None,
        hook_level=_optional_int(row.get("hook_level")),
        parent_hook_name=_optional_string(row.get("parent_hook_name")),
        parent_callback_id=_optional_string(row.get("parent_callback_id")),
        parent_callback_repr=_optional_string(row.get("parent_callback_repr")),
        registration_stack_depth=_optional_int(row.get("registration_stack_depth")),
        raw=dict(row),
    )


def _classify_callback(callback: NormalizedCallback, index: int) -> dict[str, Any]:
    direct = _direct_http_details(callback)
    if direct is not None:
        classification = "direct_http"
        details = direct
    else:
        setup = _setup_required_details(callback)
        if setup is not None:
            classification = "setup_required"
            details = setup
        else:
            classification = "non_entry"
            details = _non_entry_details(callback.hook_name)

    return {
        "candidate_id": _candidate_id(callback, index),
        "classification": classification,
        **_callback_payload(callback),
        **details,
    }


def _direct_http_details(callback: NormalizedCallback) -> dict[str, Any] | None:
    return direct_http_details(callback.hook_name, callback.raw)


def _setup_required_details(callback: NormalizedCallback) -> dict[str, Any] | None:
    hook_name = callback.hook_name or ""
    lowered_hook = hook_name.lower()
    raw = callback.raw

    if "shortcode" in lowered_hook or any(key in raw for key in ("shortcode", "shortcode_tag")):
        return _manual_details(
            "setup_required",
            "shortcode",
            "Shortcode callbacks require page/content setup before they are directly reachable over HTTP",
        )
    if "rewrite" in lowered_hook or any(key in raw for key in ("rewrite_rule", "rewrite_endpoint")):
        return _manual_details(
            "setup_required",
            "rewrite",
            "Rewrite callbacks require endpoint setup before PHUZZ config generation",
        )
    if _has_rest_record(callback):
        entry_type, reason = SETUP_REQUIRED_HOOKS["rest_api_init"]
        return _manual_details("setup_required", entry_type, reason)
    if _has_xmlrpc_record(callback):
        entry_type, reason = SETUP_REQUIRED_HOOKS["xmlrpc_methods"]
        return _manual_details("setup_required", entry_type, reason)
    return None


def _has_rest_record(callback: NormalizedCallback) -> bool:
    raw = callback.raw
    hook_name = callback.hook_name
    return hook_name == "rest_api_init" and any(key in raw for key in ("rest_route", "route", "namespace"))


def _has_xmlrpc_record(callback: NormalizedCallback) -> bool:
    raw = callback.raw
    hook_name = callback.hook_name
    return hook_name == "xmlrpc_methods" and any(key in raw for key in ("method_map", "xmlrpc_method", "methods"))


def _non_entry_details(hook_name: str | None) -> dict[str, Any]:
    reason = "Hook is not directly invokable over HTTP and has no known setup workflow yet"
    lowered = (hook_name or "").lower()
    if hook_name in NON_ENTRY_HOOKS or "enqueue" in lowered:
        reason = "WordPress lifecycle, admin, or enqueue hook is not a direct HTTP entry point"
    return _manual_details("non_entry", None, reason)


def _manual_details(classification: str, entry_type: str | None, reason: str) -> dict[str, Any]:
    return {
        "entry_type": entry_type,
        "action": None,
        "http_template": None,
        "auth_required": None,
        "confidence": "medium" if classification == "setup_required" else "low",
        "reason": reason,
    }


def _callback_payload(callback: NormalizedCallback) -> dict[str, Any]:
    payload = asdict(callback)
    payload.pop("raw")
    return payload


def _candidate_id(callback: NormalizedCallback, index: int) -> str:
    if callback.callback_id:
        return callback.callback_id
    if callback.hook_name:
        return f"{_safe_slug(callback.hook_name)}-{index}"
    return f"callback-{index}"


def _build_report(source_file: str, candidates: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source_file": source_file,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": _counts_for(candidates),
        "candidates": candidates,
    }


def _filter_report(report: dict[str, Any], classification: str | None) -> dict[str, Any]:
    if classification is None:
        candidates = list(report["candidates"])
    else:
        candidates = [item for item in report["candidates"] if item["classification"] == classification]
    return {
        "schema_version": report["schema_version"],
        "source_file": report["source_file"],
        "generated_at": report["generated_at"],
        "counts": _counts_for(candidates),
        "candidates": candidates,
    }


def _counts_for(candidates: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "direct_http": sum(1 for item in candidates if item["classification"] == "direct_http"),
        "setup_required": sum(1 for item in candidates if item["classification"] == "setup_required"),
        "non_entry": sum(1 for item in candidates if item["classification"] == "non_entry"),
    }


def _optional_string(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _optional_bool(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    return bool(value)


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return slug.strip("._-") or "callback"


if __name__ == "__main__":
    raise SystemExit(main())
