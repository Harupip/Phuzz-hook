from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Optional

from scoring import calculate_hook_coverage_energy

from .models import RequestEnergyReport
from .state import HookEnergyDemoState


def apply_hook_priority_bonus(base_priority: float, hook_energy: float, weight: float) -> float:
    return float(base_priority) + (float(hook_energy) * float(weight))


def apply_hook_energy_bonus(base_energy: int, hook_energy: float, weight: float) -> int:
    base_value = max(1, int(base_energy))
    bonus = 0
    if hook_energy > 0:
        bonus = int(math.ceil(float(hook_energy) * float(weight)))
    return max(1, base_value + bonus)


def apply_candidate_hook_feedback(
    candidate,
    report: Optional[RequestEnergyReport],
    *,
    base_priority: float,
    base_energy: Optional[int],
    priority_weight: float,
    energy_weight: float,
) -> tuple[float, Optional[int]]:
    if report is None:
        candidate.hook_request_id = ""
        candidate.hook_energy = 0.0
        candidate.hook_energy_avg = 0.0
    else:
        candidate.hook_request_id = report.request_id
        candidate.hook_energy = float(report.hook_energy)
        candidate.hook_energy_avg = float(report.hook_energy_avg)

    candidate.base_priority = base_priority
    final_priority = apply_hook_priority_bonus(base_priority, candidate.hook_energy, priority_weight)
    candidate.priority = final_priority

    final_energy: Optional[int] = None
    if base_energy is not None:
        candidate.base_energy = int(base_energy)
        final_energy = apply_hook_energy_bonus(base_energy, candidate.hook_energy, energy_weight)
        candidate.final_energy = final_energy

    return final_priority, final_energy


class HookEnergyTracker:
    def __init__(self, requests_dir: str, state: Optional[HookEnergyDemoState] = None) -> None:
        self.requests_dir = Path(requests_dir)
        self.state = state or HookEnergyDemoState()
        self._indexed_request_files: set[str] = set()
        self._coverage_payloads: dict[str, tuple[dict, str]] = {}
        self._cached_reports_by_request_id: dict[str, RequestEnergyReport] = {}

    def consume_candidate(self, coverage_id: str) -> Optional[RequestEnergyReport]:
        if not coverage_id:
            return None

        self._index_request_artifacts()
        payload_info = self._coverage_payloads.get(str(coverage_id))
        if payload_info is None:
            return None

        payload, request_file = payload_info
        request_id = str(payload.get("request_id", Path(request_file).stem))
        cached = self._cached_reports_by_request_id.get(request_id)
        if cached is not None:
            return cached

        report = calculate_hook_coverage_energy(
            payload,
            state=self.state,
            update_state=request_id not in self.state.processed_request_ids,
        )
        self._cached_reports_by_request_id[request_id] = report
        return report

    def _index_request_artifacts(self) -> None:
        if not self.requests_dir.exists():
            return

        for path in sorted(self.requests_dir.glob("*.json")):
            path_str = str(path)
            if path_str in self._indexed_request_files:
                continue
            self._indexed_request_files.add(path_str)

            payload = self._read_json(path)
            if payload is None:
                continue

            coverage_id = self._extract_coverage_id(payload)
            if not coverage_id:
                continue

            self._coverage_payloads[str(coverage_id)] = (payload, path_str)

    def _extract_coverage_id(self, payload: dict) -> str:
        params = payload.get("request_params", {})
        if not isinstance(params, dict):
            return ""

        headers = params.get("headers", {})
        if not isinstance(headers, dict):
            return ""

        for key, value in headers.items():
            if str(key).lower() == "x-fuzzer-covid":
                return str(value).strip()
        return ""

    def _read_json(self, path: Path) -> Optional[dict]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return payload if isinstance(payload, dict) else None
