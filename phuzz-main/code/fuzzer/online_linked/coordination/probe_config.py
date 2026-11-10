"""Pure probe config selection, paths and artifact correlation for the online-linked coordinator."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from filesystem_paths import filesystem_path
from online_linked.coordination.errors import OnlineLinkedError


def select_probe_item(convergence: Mapping[str, Any], probe: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """Return the exported seed item for this probe's variant, or the only item when unambiguous."""
    merged_probe_report = convergence.get("merged_suggested_seeds")
    probe_items = merged_probe_report.get("suggested_seeds", []) if isinstance(merged_probe_report, Mapping) else []
    if not isinstance(probe_items, list):
        probe_items = []
    variant = str(probe.get("seed_variant_id") or "")
    probe_item = next(
        (item for item in probe_items if isinstance(item, Mapping)
         and str((item.get("seed") or {}).get("seed_variant_id") or "") == variant),
        None,
    )
    if probe_item is None and len(probe_items) == 1 and isinstance(probe_items[0], Mapping):
        probe_item = probe_items[0]
    return probe_item


def probe_runtime_metadata(probe: Mapping[str, Any]) -> dict[str, Any]:
    """Describe the probed candidate in config metadata without its observed value."""
    return {
        "parameter": str(probe.get("name") or ""),
        "source": str(probe.get("source") or "").upper(),
        "location": str(probe.get("location") or ""),
        "helper_depth": probe.get("helper_depth"),
        "value_origin": "generated_probe",
        "candidate_value_redacted": True,
        "candidate_request_id": probe.get("request_id"),
        "candidate_run_id": probe.get("run_id"),
    }


@dataclass(frozen=True)
class ProbePaths:
    root: Path
    generated_dir: Path
    generated_summary: Path
    config: Path
    config_mirror: Path
    replay: Path
    replay_mirror: Path


def probe_paths(*, run_dir: Path, config_dir: Path, version: str, probe_id: str) -> ProbePaths:
    """Return where one probe's exported, config, replay and mirror files live."""
    probe_root = run_dir / "versions" / str(version) / "probe" / probe_id
    return ProbePaths(
        root=probe_root,
        generated_dir=config_dir / "versions" / str(version) / "probe" / probe_id / "exported",
        generated_summary=probe_root / "generated_config_summary.json",
        config=config_dir / "versions" / str(version) / "probe" / probe_id / f"{probe_id}-config.json",
        config_mirror=probe_root / f"{probe_id}-config.json",
        replay=config_dir / "versions" / str(version) / "probe" / probe_id / f"{probe_id}-replay.json",
        replay_mirror=probe_root / f"{probe_id}-replay.json",
    )


def probe_request_row(
    probe_item: Mapping[str, Any],
    parent: dict[str, Any],
    *,
    replay_path: Path,
    config_root: Path,
) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Return ``(probe_row, probe_parent, method_transition)`` for sending one probe replay."""
    probe_seed = probe_item.get("seed") if isinstance(probe_item.get("seed"), Mapping) else {}
    probe_parent = parent
    method_transition = probe_seed.get("method_transition") == {"from": "GET", "to": "POST"}
    if method_transition:
        probe_parent = {**parent, "resolved_method": "POST"}
    probe_row = {
        "config_slug": replay_path.relative_to(config_root).with_suffix("").as_posix(),
        "hook_name": str(probe_item.get("hook_name") or parent["hook_name"]),
        "callback_id": str(probe_item.get("callback_id") or parent["callback_id"]),
        "entrypoint_type": str(probe_item.get("entrypoint_type") or parent["entrypoint_type"]),
        "resolved_method": str(probe_seed.get("resolved_method") or probe_seed.get("method") or parent["resolved_method"]),
        "seed_variant_id": str(probe_seed.get("seed_variant_id") or ""),
    }
    return probe_row, probe_parent, method_transition


def load_correlated_probe_artifacts(
    request_dir: Path,
    zend_dir: Path,
    artifact_name: str,
    probe_run_id: str,
) -> tuple[Path, Mapping[str, Any], Path, Mapping[str, Any]]:
    """Load the saved request/Zend pair, requiring both to belong to this probe run."""
    request_path = request_dir / artifact_name
    zend_paths = [path for path in filesystem_path(zend_dir).glob("*.json") if path.stem == request_path.stem]
    if Path(artifact_name).name != artifact_name or not filesystem_path(request_path).is_file() or len(zend_paths) != 1:
        raise OnlineLinkedError("PROBE_ARTIFACT_CORRELATION_FAILED")
    probe_request = json.loads(filesystem_path(request_path).read_text(encoding="utf-8-sig"))
    probe_zend = json.loads(filesystem_path(zend_paths[0]).read_text(encoding="utf-8-sig"))
    if (
        not isinstance(probe_request, Mapping)
        or not isinstance(probe_zend, Mapping)
        or str(probe_request.get("request_id") or "") != request_path.stem
        or str(probe_zend.get("request_id") or "") != request_path.stem
        or str(probe_request.get("legacy_run_id") or probe_request.get("run_id") or "") != probe_run_id
        or str(probe_zend.get("run_id") or probe_zend.get("legacy_run_id") or "") != probe_run_id
    ):
        raise OnlineLinkedError("PROBE_ARTIFACT_CORRELATION_FAILED")
    return request_path, probe_request, zend_paths[0], probe_zend
