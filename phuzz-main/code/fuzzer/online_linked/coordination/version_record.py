"""Version record construction for the online-linked coordinator."""

from __future__ import annotations

import copy
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from hook_energy.seed_generation.online_common import config_hash


def new_version_record(
    name: str,
    config: Mapping[str, Any],
    config_path: Path,
    parent: Mapping[str, Any] | None,
    discovery_event: str | None,
    seed_item: Mapping[str, Any],
    *,
    plugin_slug: str,
    config_generation_seconds: float | None = None,
) -> dict[str, Any]:
    """Return the pending state record for a newly generated version config."""
    metadata = config.get("metadata") if isinstance(config.get("metadata"), Mapping) else {}
    record = {
        "version": name,
        "parent_version": parent.get("version") if isinstance(parent, Mapping) else None,
        "parent_config": parent.get("config_path") if isinstance(parent, Mapping) else None,
        "config_path": str(config_path),
        "config_type": str(config.get("config_type") or "").strip().lower(),
        "config_hash": config_hash(config),
        "discovery_event": discovery_event,
        "replay_result": None,
        "replay_config_path": None,
        "worker_status": "pending",
        "status": "pending",
        "terminal_reason": "",
        "hook_name": str(metadata.get("hook_name") or seed_item.get("hook_name") or ""),
        "callback_id": str(metadata.get("callback_id") or seed_item.get("callback_id") or ""),
        "canonical_callback": str(metadata.get("callback_repr") or seed_item.get("callback_repr") or ""),
        "plugin_slug": plugin_slug,
        "entrypoint_type": str(config.get("entrypoint_type") or ""),
        "resolved_method": str(metadata.get("resolved_method") or ""),
        "auth_context": str(metadata.get("auth_context") or "authenticated"),
        "seed_variant_id": str(metadata.get("seed_variant_id") or (seed_item.get("seed") or {}).get("seed_variant_id") or ""),
        "seed_item": copy.deepcopy(dict(seed_item)),
    }
    if config_generation_seconds is not None:
        record["config_generation_seconds"] = max(0.0, float(config_generation_seconds))
    return record
