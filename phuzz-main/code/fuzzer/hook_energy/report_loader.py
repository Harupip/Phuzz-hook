from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LoadedRunArtifacts:
    metadata: dict
    decisions: list[dict] = field(default_factory=list)
    exception_candidates: list[dict] = field(default_factory=list)
    vulnerability_candidates: dict = field(default_factory=dict)
    requests: dict[str, dict] = field(default_factory=dict)
    coverage_summary: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _read_json_file(path: Path, default):
    if not path or not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl_file(path: Path) -> list[dict]:
    if not path or not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows


def _load_requests_dir(requests_dir: Path) -> dict[str, dict]:
    if not requests_dir or not requests_dir.exists():
        return {}
    payloads = {}
    for path in sorted(requests_dir.glob("*.json")):
        payload = _normalize_request_payload(json.loads(path.read_text(encoding="utf-8")))
        request_id = str(payload.get("request_id", path.stem))
        payloads[request_id] = payload
    return payloads


def _normalize_callbacks_section(section) -> list[dict]:
    if isinstance(section, dict):
        return [item for item in section.values() if isinstance(item, dict)]
    if isinstance(section, list):
        return [item for item in section if isinstance(item, dict)]
    return []


def _normalize_coverage_summary(payload: dict) -> dict:
    if not payload:
        return {}

    metadata = payload.get("metadata", {}) if isinstance(payload, dict) else {}
    data = payload.get("data", {}) if isinstance(payload, dict) else {}
    if metadata or data:
        registered_callbacks = _normalize_callbacks_section(data.get("registered_callbacks", {}))
        executed_callbacks = _normalize_callbacks_section(data.get("executed_callbacks", {}))
        blindspot_callbacks = _normalize_callbacks_section(data.get("blindspot_callbacks", {}))
        return {
            "registered_total": int(metadata.get("total_registered_callbacks", len(registered_callbacks))),
            "executed_total": int(metadata.get("total_executed_callbacks", len(executed_callbacks))),
            "coverage_percent": str(metadata.get("coverage_percent", payload.get("coverage_percent", "0%"))),
            "registered_callbacks": registered_callbacks,
            "executed_callbacks": executed_callbacks,
            "blindspot_callbacks": blindspot_callbacks,
        }

    normalized = dict(payload)
    normalized["blindspot_callbacks"] = _normalize_callbacks_section(normalized.get("blindspot_callbacks", []))
    return normalized


def _normalize_request_payload(payload: dict) -> dict:
    normalized = dict(payload)
    normalized["request_method"] = str(
        normalized.get("request_method") or normalized.get("http_method") or ""
    )
    if "request_time_ms" not in normalized:
        response = normalized.get("response", {}) if isinstance(normalized.get("response"), dict) else {}
        normalized["request_time_ms"] = float(response.get("time_ms", 0.0))
    return normalized


def load_run_artifacts(
    *,
    run_label: str,
    mode: str,
    decisions_path: Path,
    exceptions_path: Path,
    vulnerabilities_path: Path,
    requests_dir: Path,
    coverage_summary_path: Path,
) -> LoadedRunArtifacts:
    return LoadedRunArtifacts(
        metadata={"label": run_label, "mode": mode},
        decisions=_read_jsonl_file(decisions_path),
        exception_candidates=_read_json_file(exceptions_path, []),
        vulnerability_candidates=_read_json_file(vulnerabilities_path, {}),
        requests=_load_requests_dir(requests_dir),
        coverage_summary=_normalize_coverage_summary(_read_json_file(coverage_summary_path, {})),
        warnings=[],
    )
