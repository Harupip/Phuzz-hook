"""Gate replay helpers for the online-linked coordinator."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from filesystem_paths import filesystem_path
from online_linked.evidence import correlate_runtime_pair


def gate_replay_name(
    version: Mapping[str, Any], *, resume: bool, resume_count: Any,
) -> tuple[str, bool]:
    """Return (gate_name, reactivation) for the gate replay config."""
    reactivation = resume or bool(version.get("readiness_history"))
    gate_name = "v0" if not reactivation else f"resume-{resume_count}-{version['version']}"
    if reactivation:
        gate_name += f"-activation-{len(version.get('readiness_history', []))}"
    return gate_name, reactivation


def gate_replay_row(version: Mapping[str, Any], path: Path, *, config_root: Path) -> dict[str, Any]:
    """Return the replay row describing the gate config written at `path`."""
    seed = version["seed_item"].get("seed", {})
    row = {
        "config_slug": path.relative_to(config_root).with_suffix("").as_posix(),
        "hook_name": version["hook_name"], "callback_id": version["callback_id"],
        "resolved_method": version["resolved_method"], "entrypoint_type": version["entrypoint_type"],
        "seed_variant_id": str(seed.get("seed_variant_id") or ""),
    }
    return row


def load_gate_evidence(
    version: Mapping[str, Any],
    result_row: Mapping[str, Any],
    request_dir: Path,
    zend_dir: Path,
    convergence: Mapping[str, Any],
    *,
    plugin_slug: str,
) -> dict[str, Any] | None:
    request_name = str(result_row.get("matched_artifact") or "")
    if Path(request_name).name != request_name or Path(request_name).suffix != ".json":
        return None
    request_path = request_dir / request_name
    if not filesystem_path(request_path).is_file():
        return None
    zend_name = str(result_row.get("zend_artifact") or "")
    if Path(zend_name).name != zend_name or Path(zend_name).stem != Path(request_name).stem:
        zend_paths = [path for path in filesystem_path(zend_dir).glob("*.json") if path.stem == Path(request_name).stem]
        if len(zend_paths) != 1:
            return None
        zend_name = zend_paths[0].name
    zend_path = zend_dir / zend_name
    if not filesystem_path(zend_path).is_file():
        return None
    request = json.loads(filesystem_path(request_path).read_text(encoding="utf-8-sig"))
    zend = json.loads(filesystem_path(zend_path).read_text(encoding="utf-8-sig"))
    evidence = correlate_runtime_pair(
        version,
        {
            "request_name": request_name,
            "request": request,
            "zend_name": zend_name,
            "zend": zend,
        },
        plugin_slug=plugin_slug,
    )
    if evidence is None:
        return None
    convergence_request_id = str(convergence.get("request_id") or "").strip()
    if convergence_request_id and convergence_request_id != evidence["request_id"]:
        return None
    evidence["evidence_origin"] = "v0_gate"
    return evidence


def guard_replay_summary(
    current: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    config_root: Path,
    replay_run_id: str,
) -> dict[str, Any]:
    """Return the single-run pass summary for a guard replay of `current`."""
    return {"legacy_run_id": replay_run_id, "runs": [{
        "config_slug": Path(str(current["replay_config_path"])).relative_to(config_root)
        .with_suffix("").as_posix(),
        "hook_name": current["hook_name"],
        "callback_id": current["callback_id"],
        "seed_variant_id": str(current.get("seed_variant_id") or ""),
        "callback_reached": True,
        "matched_artifact": str(evidence["request_name"]),
        "resolved_method": current["resolved_method"],
        "process_status": "replaying",
    }]}


def unsent_guard_probes(result: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return pending probes whose (source, name) the guard replay reported as unsent."""
    unsent = {
        (str(row.get("source") or "").upper(), str(row.get("name") or ""))
        for row in (result.get("observed_parameters") or [])
        if isinstance(row, Mapping) and row.get("candidate_reason") == "unsent_guard"
    }
    probes = [
        dict(row) for row in (result.get("pending_probes") or [])
        if isinstance(row, Mapping)
        and (str(row.get("source") or "").upper(), str(row.get("name") or "")) in unsent
    ]
    return probes
