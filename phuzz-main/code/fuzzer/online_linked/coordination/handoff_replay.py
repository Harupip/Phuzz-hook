"""Replay metadata and rejection reasons for a worker handoff."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


def handoff_replay_row(child: Mapping[str, Any], replay_path: Path, *, config_root: Path) -> dict[str, Any]:
    return {
        "config_slug": replay_path.relative_to(config_root).with_suffix("").as_posix(),
        "hook_name": child["hook_name"],
        "callback_id": child["callback_id"],
        "entrypoint_type": child["entrypoint_type"],
        "resolved_method": child["resolved_method"],
        "seed_variant_id": child.get("seed_variant_id", ""),
    }


def replay_failure_reason(
    *, artifact_error: str, replay_report: Mapping[str, Any], replay_row: Mapping[str, Any],
    replay_result: Mapping[str, Any],
) -> str:
    if artifact_error:
        return "REPLAY_ARTIFACT_SAVE_FAILED"
    if replay_report.get("error") or replay_row.get("process_status") in {"failed", "runner_error"}:
        return "REPLAY_PROCESS_FAILED"
    if replay_row.get("validation_status") != "callback_reached":
        return str(replay_row.get("validation_reason") or "CALLBACK_NOT_REACHED")
    if replay_result.get("transport_error"):
        return "REPLAY_TRANSPORT_NOT_VERIFIED"
    if replay_result.get("unverified_parameters"):
        return "PARAMETER_REPLAY_NOT_VERIFIED"
    return "CALLBACK_BASELINE_NOT_VERIFIED"
