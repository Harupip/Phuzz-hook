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
        payload = json.loads(path.read_text(encoding="utf-8"))
        request_id = str(payload.get("request_id", path.stem))
        payloads[request_id] = payload
    return payloads


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
        coverage_summary=_read_json_file(coverage_summary_path, {}),
        warnings=[],
    )
