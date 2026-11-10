"""Compatibility checks for resuming an online-linked candidate checkpoint."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from online_linked.coordination.candidate_identity import _CANDIDATE_CONTEXT_KEY_VERSION


def validate_resume_checkpoint(saved: Mapping[str, Any], *, expected: Mapping[str, Any]) -> None:
    """Raise ValueError for the first saved field that makes the checkpoint unsafe to resume."""
    if saved.get("budget_policy") != "progress_idle_v1":
        raise ValueError("resume budget policy incompatible; create a new run")
    checkpoint = saved.get("checkpoint", {})
    if (saved.get("context_key_version") != _CANDIDATE_CONTEXT_KEY_VERSION
            or checkpoint.get("context_key_version") != _CANDIDATE_CONTEXT_KEY_VERSION):
        raise ValueError("resume candidate context-key version missing or unsupported")
    if not isinstance(saved.get("queued_candidate_context_keys"), list):
        raise ValueError("resume candidate context-key checkpoint is missing")
    if saved.get("terminal_status") not in {None, "PARTIAL"}:
        raise ValueError("resume requires a PARTIAL candidate")
    for field in ("plugin_slug", "legacy_run_id", "max_seconds", "hard_seconds", "hard_versions",
                  "runtime_cookie_probes"):
        if saved.get(field) != expected[field]:
            raise ValueError(f"resume candidate context changed: {field}")
    if saved.get("initial_max_versions") != expected["initial_max_versions"]:
        raise ValueError("resume initial version budget changed")
