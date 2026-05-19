from __future__ import annotations

import argparse
import csv
import json
import math
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse


def _parse_timestamp(raw_value: Any) -> datetime | None:
    if not raw_value:
        return None

    if isinstance(raw_value, (int, float)):
        return datetime.fromtimestamp(float(raw_value), tz=timezone.utc).replace(tzinfo=None)

    value = str(raw_value).strip()
    if not value:
        return None

    try:
        if value.replace(".", "", 1).isdigit():
            return datetime.fromtimestamp(float(value), tz=timezone.utc).replace(tzinfo=None)
    except (OSError, OverflowError, ValueError):
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).replace(tzinfo=None)
            return parsed
        except ValueError:
            continue
    return None


def _epoch_from_coverage_id(coverage_id: str) -> datetime | None:
    prefix = str(coverage_id).split("-", 1)[0].strip()
    if not prefix.isdigit():
        return None
    return datetime.fromtimestamp(int(prefix), tz=timezone.utc).replace(tzinfo=None)


def _load_json(path: Path) -> dict[str, Any] | list[Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(payload, (dict, list)):
        return payload
    return None


def _extract_coverage_id(request_payload: dict[str, Any]) -> str:
    params = request_payload.get("request_params", {})
    if not isinstance(params, dict):
        return ""
    headers = params.get("headers", {})
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == "x-fuzzer-covid":
            return str(value).strip()
    return ""


def _extract_executed_callback_ids(request_payload: dict[str, Any]) -> set[str]:
    hook_coverage = request_payload.get("hook_coverage", {})
    if not isinstance(hook_coverage, dict):
        return set()

    payload = hook_coverage.get("executed_callbacks", {})
    if isinstance(payload, dict):
        return {str(key) for key in payload.keys()}
    if isinstance(payload, list):
        callback_ids = set()
        for item in payload:
            if isinstance(item, dict) and item.get("callback_id"):
                callback_ids.add(str(item["callback_id"]))
        return callback_ids
    return set()


def _request_target_path(record: dict[str, Any]) -> str:
    payload = record.get("payload", {})
    if not isinstance(payload, dict):
        return ""
    target = str(payload.get("http_target", "")).strip()
    parsed = urlparse(target)
    return parsed.path or target


def _classify_target_surface(request_records: list[dict[str, Any]]) -> str:
    if not request_records:
        return "unknown"

    direct_count = 0
    mediated_count = 0
    for record in request_records:
        path = _request_target_path(record)
        if path.startswith("/wp-content/plugins/"):
            direct_count += 1
        elif path:
            mediated_count += 1

    if direct_count > 0 and direct_count >= mediated_count:
        return "direct-file"
    return "wordpress-mediated"


def _load_scheduler_decisions(run_path: Path) -> list[dict[str, Any]]:
    candidates = [
        run_path / "fuzzer-output" / "hook-energy-decisions.jsonl",
        run_path / "hook-energy-decisions.jsonl",
    ]
    path = next((item for item in candidates if item.exists()), None)
    if path is None:
        return []

    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def _energy_delta(decision: dict[str, Any]) -> int | None:
    try:
        return int(decision.get("final_energy")) - int(decision.get("base_energy"))
    except (TypeError, ValueError):
        return None


def _load_fuzzer_request_event_records(fuzzer_output_dir: Path) -> list[dict[str, Any]]:
    path = fuzzer_output_dir / "request-events.jsonl"
    if not path.exists():
        return []

    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        records.append(
            {
                "request_id": str(payload.get("request_id") or payload.get("coverage_id") or path.stem),
                "coverage_id": str(payload.get("coverage_id", "")).strip(),
                "timestamp": _parse_timestamp(payload.get("timestamp")),
                "executed_callback_ids": set(),
                "payload": payload,
            }
        )

    records.sort(
        key=lambda item: (
            item["timestamp"] or datetime.max,
            item["request_id"],
        )
    )
    for index, record in enumerate(records, start=1):
        record["ordinal"] = index
    return records


def _load_request_records(requests_dir: Path, fuzzer_output_dir: Path | None = None) -> list[dict[str, Any]]:
    if not requests_dir.exists():
        return _load_fuzzer_request_event_records(fuzzer_output_dir) if fuzzer_output_dir is not None else []

    records: list[dict[str, Any]] = []
    for path in sorted(requests_dir.glob("*.json")):
        payload = _load_json(path)
        if not isinstance(payload, dict):
            continue
        timestamp = _parse_timestamp(payload.get("timestamp"))
        records.append(
            {
                "request_id": str(payload.get("request_id", path.stem)),
                "coverage_id": _extract_coverage_id(payload),
                "timestamp": timestamp,
                "executed_callback_ids": _extract_executed_callback_ids(payload),
                "payload": payload,
            }
        )

    records.sort(
        key=lambda item: (
            item["timestamp"] or datetime.max,
            item["request_id"],
        )
    )
    for index, record in enumerate(records, start=1):
        record["ordinal"] = index
    if records:
        return records
    return _load_fuzzer_request_event_records(fuzzer_output_dir) if fuzzer_output_dir is not None else []


def _normalize_endpoint(candidate: dict[str, Any]) -> str:
    http_method = str(candidate.get("http_method", "GET")).upper()
    target = str(candidate.get("http_target", "")).strip()
    parsed = urlparse(target)
    path = parsed.path or target or "unknown-target"

    fixed_params = candidate.get("fixed_params", {})
    action = ""
    if isinstance(fixed_params, dict):
        for params_key in ("query_params", "body_params"):
            params = fixed_params.get(params_key, {})
            if isinstance(params, dict) and params.get("action"):
                action = str(params["action"])
                break

    if not action and parsed.query:
        query = parse_qs(parsed.query)
        action_values = query.get("action", [])
        if action_values:
            action = str(action_values[0])

    if action and path.endswith("/wp-admin/admin-ajax.php"):
        return f"{http_method} {path}?action={action}"
    return f"{http_method} {path}"


def _normalize_mutated_param(candidate: dict[str, Any]) -> str:
    mutated_type = str(candidate.get("mutated_param_type", "")).strip() or "unknown"
    mutated_name = str(candidate.get("mutated_param_name", "")).strip() or "unknown"
    return f"{mutated_type}:{mutated_name}"


def _extract_location_tokens(candidate: dict[str, Any]) -> list[str]:
    tokens: set[str] = set()

    for item in candidate.get("errors") or []:
        if not isinstance(item, dict):
            continue
        errfile = str(item.get("errfile", "")).strip()
        errline = str(item.get("errline", "")).strip()
        if errfile or errline:
            tokens.add(f"error:{errfile}:{errline}")

    exceptions = candidate.get("exceptions")
    if isinstance(exceptions, dict):
        errfile = str(exceptions.get("file", "")).strip()
        errline = str(exceptions.get("line", "")).strip()
        if errfile or errline:
            tokens.add(f"exception:{errfile}:{errline}")
    elif isinstance(exceptions, list):
        for item in exceptions:
            if not isinstance(item, dict):
                continue
            errfile = str(item.get("file", "")).strip()
            errline = str(item.get("line", "")).strip()
            if errfile or errline:
                tokens.add(f"exception:{errfile}:{errline}")

    if tokens:
        return sorted(tokens)

    for path_entry in candidate.get("paths") or []:
        raw_value = str(path_entry)
        if "::::" in raw_value:
            filename, _, lines = raw_value.partition("::::")
            tokens.add(f"path:{filename}:{lines}")
        elif raw_value:
            tokens.add(f"path:{raw_value}")
        if tokens:
            break

    return sorted(tokens)


def _build_vulnerability_signature(vuln_type: str, candidate: dict[str, Any]) -> str:
    endpoint = _normalize_endpoint(candidate)
    mutated_param = _normalize_mutated_param(candidate)
    locations = _extract_location_tokens(candidate)
    location_fingerprint = "|".join(locations) if locations else "no-location"
    return " :: ".join([vuln_type, endpoint, mutated_param, location_fingerprint])


def _flatten_vulnerabilities(
    vulnerable_payload: dict[str, Any],
    request_records_by_coverage_id: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    for vuln_type, candidates in vulnerable_payload.items():
        if not isinstance(candidates, list):
            continue
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            coverage_id = str(candidate.get("coverage_id", "")).strip()
            request_record = request_records_by_coverage_id.get(coverage_id)
            request_timestamp = request_record.get("timestamp") if request_record else _epoch_from_coverage_id(coverage_id)
            request_ordinal = request_record.get("ordinal") if request_record else None

            rows.append(
                {
                    "coverage_id": coverage_id,
                    "vuln_type": str(vuln_type),
                    "signature": _build_vulnerability_signature(str(vuln_type), candidate),
                    "request_timestamp": request_timestamp,
                    "request_ordinal": request_ordinal,
                }
            )

    rows.sort(
        key=lambda item: (
            item["request_timestamp"] or datetime.max,
            item["request_ordinal"] if item["request_ordinal"] is not None else 10**12,
            item["coverage_id"],
            item["signature"],
        )
    )
    return rows


def _median(values: list[float | int | None]) -> float | None:
    normalized = [float(value) for value in values if value is not None]
    if not normalized:
        return None
    return float(statistics.median(normalized))


def _build_coverage_timeline(
    request_records: list[dict[str, Any]],
    unique_vulns: list[dict[str, Any]],
    *,
    time_budget_seconds: int,
    bucket_minutes: int,
) -> list[dict[str, Any]]:
    if not request_records:
        return []

    bucket_seconds = max(1, int(bucket_minutes) * 60)
    total_seconds = max(bucket_seconds, int(time_budget_seconds))
    bucket_count = max(1, int(math.ceil(total_seconds / bucket_seconds)))
    first_request_timestamp = request_records[0]["timestamp"]
    cumulative_callbacks: set[str] = set()
    seen_vuln_signatures: set[str] = set()
    rows: list[dict[str, Any]] = []

    def seconds_since_start(timestamp: datetime | None) -> int | None:
        if first_request_timestamp is None or timestamp is None:
            return None
        return max(0, int(round((timestamp - first_request_timestamp).total_seconds())))

    for bucket_index in range(bucket_count):
        bucket_start = bucket_index * bucket_seconds
        bucket_end = min((bucket_index + 1) * bucket_seconds, total_seconds)
        bucket_requests = 0

        for record in request_records:
            elapsed = seconds_since_start(record["timestamp"])
            if elapsed is None:
                elapsed = int(record.get("ordinal", 1)) - 1
            if bucket_start <= elapsed < bucket_end:
                bucket_requests += 1
            if elapsed < bucket_end:
                cumulative_callbacks.update(record["executed_callback_ids"])

        for vuln in unique_vulns:
            elapsed = seconds_since_start(vuln.get("request_timestamp"))
            if elapsed is None:
                ordinal = vuln.get("request_ordinal")
                elapsed = int(ordinal) - 1 if ordinal is not None else 0
            if elapsed < bucket_end:
                seen_vuln_signatures.add(str(vuln.get("signature", "")))

        rows.append(
            {
                "bucket_index": bucket_index + 1,
                "elapsed_start_seconds": bucket_start,
                "elapsed_end_seconds": bucket_end,
                "requests": bucket_requests,
                "requests_per_second": bucket_requests / bucket_seconds,
                "requests_per_minute": bucket_requests / (bucket_seconds / 60),
                "cumulative_unique_callbacks": len(cumulative_callbacks),
                "blindspots_reduced": len(cumulative_callbacks),
                "unique_vulns": len([item for item in seen_vuln_signatures if item]),
            }
        )

    return rows


def analyze_run(
    run_dir: str | Path,
    *,
    plugin: str,
    mode_label: str,
    mode_value: int,
    run_id: int,
    time_budget_seconds: int = 1800,
    bucket_minutes: int = 5,
) -> dict[str, Any]:
    run_path = Path(run_dir)
    requests_dir = run_path / "requests"
    fuzzer_output_dir = run_path / "fuzzer-output"
    vulnerable_candidates_path = fuzzer_output_dir / "vulnerable-candidates.json"
    vulnerable_payload = _load_json(vulnerable_candidates_path)
    total_coverage_payload = _load_json(run_path / "total_coverage.json")
    scheduler_decisions = _load_scheduler_decisions(run_path)

    notes: list[str] = []
    request_records = _load_request_records(requests_dir, fuzzer_output_dir)
    if not request_records:
        notes.append("missing request artifacts")

    request_records_by_coverage_id = {
        record["coverage_id"]: record
        for record in request_records
        if record.get("coverage_id")
    }
    first_request_timestamp = request_records[0]["timestamp"] if request_records else None
    total_requests = len(request_records)
    cutoff_timestamp = None
    if first_request_timestamp is not None:
        cutoff_timestamp = first_request_timestamp.timestamp() + int(time_budget_seconds)

    has_other_fuzzer_output = fuzzer_output_dir.exists() and any(
        child.is_file() for child in fuzzer_output_dir.iterdir()
    )
    if not isinstance(vulnerable_payload, dict):
        if vulnerable_candidates_path.exists():
            notes.append("invalid vulnerable-candidates.json")
        elif not has_other_fuzzer_output:
            notes.append("missing vulnerable-candidates.json")
        vulnerable_payload = {}

    vulnerability_rows = _flatten_vulnerabilities(vulnerable_payload, request_records_by_coverage_id)
    seen_signatures: set[str] = set()
    unique_vulns: list[dict[str, Any]] = []
    for row in vulnerability_rows:
        if row["signature"] in seen_signatures:
            continue
        seen_signatures.add(row["signature"])
        unique_vulns.append(row)

    def _seconds_since_start(timestamp: datetime | None) -> int | None:
        if first_request_timestamp is None or timestamp is None:
            return None
        delta = int(round((timestamp - first_request_timestamp).total_seconds()))
        return max(0, delta)

    first_unique = unique_vulns[0] if unique_vulns else None
    third_unique = unique_vulns[2] if len(unique_vulns) >= 3 else None

    unique_vulns_within_budget = []
    for row in unique_vulns:
        if cutoff_timestamp is None or row["request_timestamp"] is None:
            unique_vulns_within_budget.append(row)
            continue
        if row["request_timestamp"].timestamp() <= cutoff_timestamp:
            unique_vulns_within_budget.append(row)

    executed_callback_ids: set[str] = set()
    requests_with_executed_callbacks = 0
    for record in request_records:
        if cutoff_timestamp is not None and record["timestamp"] is not None:
            if record["timestamp"].timestamp() > cutoff_timestamp:
                continue
        if record["executed_callback_ids"]:
            requests_with_executed_callbacks += 1
        executed_callback_ids.update(record["executed_callback_ids"])

    blindspots_reduced = None
    if isinstance(total_coverage_payload, dict):
        metadata = total_coverage_payload.get("metadata", {})
        data = total_coverage_payload.get("data", {})
        if isinstance(metadata, dict) and isinstance(data, dict):
            registered_total = metadata.get("total_registered_callbacks")
            blindspot_payload = data.get("blindspot_callbacks", {})
            blindspot_count = len(blindspot_payload) if isinstance(blindspot_payload, dict) else None
            if isinstance(registered_total, int) and blindspot_count is not None:
                blindspots_reduced = max(0, int(registered_total) - int(blindspot_count))
    else:
        notes.append("missing total_coverage.json")

    unique_count = len(unique_vulns_within_budget)
    requests_per_unique_vuln = None
    if unique_count > 0 and total_requests > 0:
        requests_per_unique_vuln = total_requests / unique_count
    requests_per_second = total_requests / int(time_budget_seconds) if int(time_budget_seconds) > 0 else None
    requests_per_minute = requests_per_second * 60 if requests_per_second is not None else None

    target_surface = _classify_target_surface(request_records)
    hook_signal_request_ratio = (requests_with_executed_callbacks / total_requests) if total_requests else None
    decisions_with_hook_energy = [
        item for item in scheduler_decisions if float(item.get("hook_energy") or 0.0) > 0.0
    ]
    energy_deltas = [delta for delta in (_energy_delta(item) for item in scheduler_decisions) if delta is not None]
    coverage_timeline = _build_coverage_timeline(
        request_records,
        unique_vulns_within_budget,
        time_budget_seconds=time_budget_seconds,
        bucket_minutes=bucket_minutes,
    )

    summary = {
        "plugin": plugin,
        "mode": mode_label,
        "mode_value": int(mode_value),
        "run": int(run_id),
        "run_dir": str(run_path),
        "time_budget_seconds": int(time_budget_seconds),
        "bucket_minutes": int(bucket_minutes),
        "total_requests": total_requests,
        "requests_per_second": requests_per_second,
        "requests_per_minute": requests_per_minute,
        "time_to_first_unique_vuln_seconds": _seconds_since_start(first_unique["request_timestamp"]) if first_unique else None,
        "requests_to_first_unique_vuln": first_unique["request_ordinal"] if first_unique else None,
        "time_to_3_unique_vulns_seconds": _seconds_since_start(third_unique["request_timestamp"]) if third_unique else None,
        "requests_to_3_unique_vulns": third_unique["request_ordinal"] if third_unique else None,
        "unique_vulns_found_within_budget": unique_count,
        "unique_vulns_found_after_30min": unique_count,
        "requests_per_unique_vuln": requests_per_unique_vuln,
        "unique_executed_callbacks": len(executed_callback_ids),
        "requests_with_executed_callbacks": requests_with_executed_callbacks,
        "hook_signal_request_ratio": hook_signal_request_ratio,
        "target_surface": target_surface,
        "low_hook_signal": target_surface == "direct-file" or hook_signal_request_ratio == 0.0,
        "scheduler_decisions": len(scheduler_decisions),
        "scheduler_decisions_with_hook_energy": len(decisions_with_hook_energy),
        "scheduler_decisions_with_hook_energy_ratio": (
            len(decisions_with_hook_energy) / len(scheduler_decisions) if scheduler_decisions else None
        ),
        "median_energy_delta": _median(energy_deltas),
        "max_energy_delta": max(energy_deltas) if energy_deltas else None,
        "uopz_overhead_ratio": None,
        "blindspots_reduced": blindspots_reduced,
        "notes": "; ".join(notes),
        "unique_vuln_signatures": [row["signature"] for row in unique_vulns_within_budget],
        "coverage_timeline": coverage_timeline,
    }
    return summary


def aggregate_results(run_summaries: list[dict[str, Any]]) -> dict[str, Any]:
    if not run_summaries:
        return {
            "plugin": "",
            "total_runs": 0,
            "modes": [],
        }

    plugin_names = sorted({str(item.get("plugin", "")) for item in run_summaries})
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in run_summaries:
        grouped[str(item.get("mode", "UNKNOWN"))].append(item)

    mode_summaries = []
    for mode_name, items in sorted(grouped.items()):
        mode_summaries.append(
            {
                "mode": mode_name,
                "runs": len(items),
                "median_time_to_first_unique_vuln_seconds": _median(
                    [item.get("time_to_first_unique_vuln_seconds") for item in items]
                ),
                "median_requests_to_first_unique_vuln": _median(
                    [item.get("requests_to_first_unique_vuln") for item in items]
                ),
                "median_time_to_3_unique_vulns_seconds": _median(
                    [item.get("time_to_3_unique_vulns_seconds") for item in items]
                ),
                "median_requests_to_3_unique_vulns": _median(
                    [item.get("requests_to_3_unique_vulns") for item in items]
                ),
                "median_unique_vulns_found_after_30min": _median(
                    [item.get("unique_vulns_found_after_30min") for item in items]
                ),
                "median_requests_per_unique_vuln": _median(
                    [item.get("requests_per_unique_vuln") for item in items]
                ),
                "median_requests_per_second": _median(
                    [item.get("requests_per_second") for item in items]
                ),
                "median_requests_per_minute": _median(
                    [item.get("requests_per_minute") for item in items]
                ),
                "median_unique_executed_callbacks": _median(
                    [item.get("unique_executed_callbacks") for item in items]
                ),
                "median_blindspots_reduced": _median(
                    [item.get("blindspots_reduced") for item in items]
                ),
                "median_scheduler_decisions": _median(
                    [item.get("scheduler_decisions") for item in items]
                ),
                "median_scheduler_decisions_with_hook_energy": _median(
                    [item.get("scheduler_decisions_with_hook_energy") for item in items]
                ),
                "median_scheduler_decisions_with_hook_energy_ratio": _median(
                    [item.get("scheduler_decisions_with_hook_energy_ratio") for item in items]
                ),
                "median_energy_delta": _median(
                    [item.get("median_energy_delta") for item in items]
                ),
                "median_max_energy_delta": _median(
                    [item.get("max_energy_delta") for item in items]
                ),
                "median_uopz_overhead_ratio": None,
            }
        )

    raw_mode = next((item for item in mode_summaries if item["mode"] == "PHUZZ_RAW"), None)
    raw_eps = raw_mode.get("median_requests_per_second") if raw_mode else None
    if raw_eps:
        for item in mode_summaries:
            eps = item.get("median_requests_per_second")
            item["median_uopz_overhead_ratio"] = (eps / raw_eps) if eps is not None else None

    return {
        "plugin": plugin_names[0] if len(plugin_names) == 1 else ",".join(plugin_names),
        "total_runs": len(run_summaries),
        "modes": mode_summaries,
        "runs": sorted(
            run_summaries,
            key=lambda item: (str(item.get("mode", "")), int(item.get("run", 0))),
        ),
    }


def write_run_summary(path: str | Path, summary: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(summary, indent=2), encoding="utf-8")


def write_coverage_timeline_outputs(run_dir: str | Path, summary: dict[str, Any]) -> None:
    output_path = Path(run_dir)
    timeline = summary.get("coverage_timeline", [])
    if not isinstance(timeline, list):
        timeline = []

    (output_path / "coverage_timeline.json").write_text(
        json.dumps(timeline, indent=2),
        encoding="utf-8",
    )

    fieldnames = [
        "bucket_index",
        "elapsed_start_seconds",
        "elapsed_end_seconds",
        "requests",
        "requests_per_second",
        "requests_per_minute",
        "cumulative_unique_callbacks",
        "blindspots_reduced",
        "unique_vulns",
    ]
    with (output_path / "coverage_timeline.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in timeline:
            writer.writerow({key: row.get(key) for key in fieldnames})


def write_batch_outputs(output_root: str | Path, aggregate: dict[str, Any]) -> None:
    output_path = Path(output_root)
    output_path.mkdir(parents=True, exist_ok=True)

    results_json = output_path / "benchmark_results.json"
    results_csv = output_path / "benchmark_results.csv"
    results_json.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")

    csv_rows = aggregate.get("runs", [])
    fieldnames = [
        "plugin",
        "mode",
        "run",
        "time_budget_seconds",
        "bucket_minutes",
        "total_requests",
        "requests_per_second",
        "requests_per_minute",
        "time_to_first_unique_vuln_seconds",
        "requests_to_first_unique_vuln",
        "time_to_3_unique_vulns_seconds",
        "requests_to_3_unique_vulns",
        "unique_vulns_found_within_budget",
        "unique_vulns_found_after_30min",
        "requests_per_unique_vuln",
        "unique_executed_callbacks",
        "requests_with_executed_callbacks",
        "hook_signal_request_ratio",
        "target_surface",
        "low_hook_signal",
        "scheduler_decisions",
        "scheduler_decisions_with_hook_energy",
        "scheduler_decisions_with_hook_energy_ratio",
        "median_energy_delta",
        "max_energy_delta",
        "uopz_overhead_ratio",
        "blindspots_reduced",
        "notes",
        "run_dir",
    ]
    with results_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in csv_rows:
            writer.writerow({key: row.get(key) for key in fieldnames})


def summarize_batch(benchmark_root: str | Path) -> dict[str, Any]:
    root = Path(benchmark_root)
    run_summaries = []
    for path in sorted(root.rglob("benchmark_summary.json")):
        payload = _load_json(path)
        if isinstance(payload, dict):
            run_summaries.append(payload)
    return aggregate_results(run_summaries)


def _build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Summarize PHUZZ benchmark artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("summarize-run", help="Compute one run summary.")
    run_parser.add_argument("--run-dir", required=True)
    run_parser.add_argument("--plugin", required=True)
    run_parser.add_argument("--mode-label", required=True)
    run_parser.add_argument("--mode-value", required=True, type=int)
    run_parser.add_argument("--run-id", required=True, type=int)
    run_parser.add_argument("--time-budget-seconds", type=int, default=1800)
    run_parser.add_argument("--bucket-minutes", type=int, default=5)
    run_parser.add_argument("--output", required=True)

    batch_parser = subparsers.add_parser("summarize-batch", help="Aggregate multiple run summaries.")
    batch_parser.add_argument("--benchmark-root", required=True)
    batch_parser.add_argument("--output-root", required=True)
    return parser


def main() -> int:
    parser = _build_cli()
    args = parser.parse_args()

    if args.command == "summarize-run":
        summary = analyze_run(
            args.run_dir,
            plugin=args.plugin,
            mode_label=args.mode_label,
            mode_value=args.mode_value,
            run_id=args.run_id,
            time_budget_seconds=args.time_budget_seconds,
            bucket_minutes=args.bucket_minutes,
        )
        write_run_summary(args.output, summary)
        write_coverage_timeline_outputs(args.run_dir, summary)
        return 0

    if args.command == "summarize-batch":
        aggregate = summarize_batch(args.benchmark_root)
        write_batch_outputs(args.output_root, aggregate)
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
