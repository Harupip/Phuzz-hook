from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import ImportedSeedRequest, ImportedSeedResult

ACCEPTED_AUTH_MODES = {"authenticated", "unauth-capable"}


class HookSeedImporter:
    def __init__(self, *, handoff_doc: Path, hook_gap_report: Path, suggested_seeds: Path) -> None:
        self.handoff_doc = Path(handoff_doc)
        self.hook_gap_report = Path(hook_gap_report)
        self.suggested_seeds = Path(suggested_seeds)

    def import_from_handoff(self) -> ImportedSeedResult:
        payload = json.loads(self.hook_gap_report.read_text(encoding="utf-8"))
        result = ImportedSeedResult()

        for callback in payload.get("callbacks", []):
            if not self._is_replayable(callback):
                continue

            imported_request = self._build_request(callback)
            if imported_request.auth_mode == "authenticated":
                result.authenticated_queue.append(imported_request)
            else:
                result.unauthenticated_queue.append(imported_request)

        return result

    def _build_request(self, callback: dict[str, Any]) -> ImportedSeedRequest:
        seed = callback["seed"]
        return ImportedSeedRequest(
            request_id=f"seed-import-{callback['callback_id']}",
            source="hook_gap_report.json",
            http_method=seed["method"],
            path=seed["path"],
            content_type=seed["content_type"],
            body=dict(seed["body"]),
            auth_mode=seed["auth_mode"],
            metadata={
                "hook_name": callback["hook_name"],
                "callback_id": callback["callback_id"],
                "callback_name": callback["callback_name"],
                "seed_priority": callback["seed_priority"],
                "target_family": callback["target_family"],
            },
        )

    def _is_replayable(self, callback: dict[str, Any]) -> bool:
        seed = callback.get("seed")
        return (
            callback.get("status") == "uncovered"
            and callback.get("is_active") is True
            and callback.get("direct_http_supported") is True
            and callback.get("generation_status") == "supported_http_seed"
            and isinstance(seed, Mapping)
            and isinstance(seed.get("method"), str)
            and isinstance(seed.get("path"), str)
            and isinstance(seed.get("content_type"), str)
            and isinstance(seed.get("body"), Mapping)
            and seed.get("auth_mode") in ACCEPTED_AUTH_MODES
        )
