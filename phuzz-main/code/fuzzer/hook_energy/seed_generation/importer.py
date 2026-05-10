from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .models import ImportedSeedRequest, ImportedSeedResult, ManualAnalysisEntry
from .stale_check import detect_stale_seed_artifacts

ACCEPTED_AUTH_MODES = {"authenticated", "unauth-capable"}


class HookSeedImporter:
    def __init__(
        self,
        *,
        handoff_doc: Path,
        hook_gap_report: Path,
        suggested_seeds: Path,
        source_pipeline: Path | None = None,
        source_plugin: Path | None = None,
    ) -> None:
        self.handoff_doc = Path(handoff_doc)
        self.hook_gap_report = Path(hook_gap_report)
        self.suggested_seeds = Path(suggested_seeds)
        self.source_pipeline = Path(source_pipeline) if source_pipeline is not None else None
        self.source_plugin = Path(source_plugin) if source_plugin is not None else None

    def import_from_handoff(self) -> ImportedSeedResult:
        if not self.hook_gap_report.exists():
            raise FileNotFoundError(f"Missing primary handoff file: {self.hook_gap_report}")

        payload = json.loads(self.hook_gap_report.read_text(encoding="utf-8"))
        callbacks = payload.get("callbacks")
        if not isinstance(callbacks, list):
            raise ValueError("hook_gap_report.json must contain a callbacks array")

        result = ImportedSeedResult()

        for callback in callbacks:
            if not self._is_replayable(callback):
                if self._is_manual_only(callback):
                    result.manual_analysis_queue.append(self._build_manual_entry(callback))
                continue

            imported_request = self._build_request(callback)
            if imported_request.auth_mode == "authenticated":
                result.authenticated_queue.append(imported_request)
            else:
                result.unauthenticated_queue.append(imported_request)

        if self.source_pipeline is not None and self.source_plugin is not None:
            result.warnings.extend(
                detect_stale_seed_artifacts(
                    report_direct_candidates=payload.get("summary", {}).get("direct_http_seed_candidates", 0),
                    source_pipeline=self.source_pipeline,
                    source_plugin=self.source_plugin,
                )
            )

        return result

    def write_artifacts(self, output_dir: Path) -> ImportedSeedResult:
        result = self.import_from_handoff()
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        (output_path / "imported_unauth_seeds.json").write_text(
            json.dumps([item.to_dict() for item in result.unauthenticated_queue], indent=2),
            encoding="utf-8",
        )
        (output_path / "imported_auth_seeds.json").write_text(
            json.dumps([item.to_dict() for item in result.authenticated_queue], indent=2),
            encoding="utf-8",
        )
        (output_path / "manual_analysis_queue.json").write_text(
            json.dumps(result.manual_analysis_queue, indent=2),
            encoding="utf-8",
        )
        (output_path / "import_summary.json").write_text(
            json.dumps(
                {
                    "authenticated_count": len(result.authenticated_queue),
                    "unauthenticated_count": len(result.unauthenticated_queue),
                    "manual_analysis_count": len(result.manual_analysis_queue),
                    "warnings": result.warnings,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        return result

    def _build_request(self, callback: dict[str, Any]) -> ImportedSeedRequest:
        seed = callback["seed"]
        return ImportedSeedRequest(
            request_id=f"seed-import-{callback['callback_id']}",
            source="external-hook-gap-report",
            http_method=seed["method"],
            path=seed["path"],
            content_type=seed["content_type"],
            body=dict(seed["body"]),
            auth_mode=seed["auth_mode"],
            query_params=dict(seed.get("query_params", {}))
            if isinstance(seed.get("query_params"), Mapping)
            else {},
            headers=dict(seed.get("headers", {})) if isinstance(seed.get("headers"), Mapping) else {},
            cookies=dict(seed.get("cookies", {})) if isinstance(seed.get("cookies"), Mapping) else {},
            metadata={
                "hook_name": callback["hook_name"],
                "callback_id": callback["callback_id"],
                "callback_name": callback["callback_name"],
                "seed_priority": callback["seed_priority"],
                "target_family": callback["target_family"],
                "source_file": callback.get("source_file"),
                "source_line": callback.get("source_line"),
                "priority": callback.get("priority"),
                "accepted_args": callback.get("accepted_args"),
            },
        )

    def _build_manual_entry(self, callback: dict[str, Any]) -> dict[str, Any]:
        return ManualAnalysisEntry(
            callback_id=callback["callback_id"],
            hook_name=callback["hook_name"],
            callback_name=callback["callback_name"],
            status=callback["status"],
            is_active=bool(callback["is_active"]),
            direct_http_supported=bool(callback["direct_http_supported"]),
            generation_status=callback["generation_status"],
            seed_priority=callback["seed_priority"],
            target_family=callback["target_family"],
            source_file=callback.get("source_file"),
            source_line=callback.get("source_line"),
            accepted_args=callback.get("accepted_args"),
        ).__dict__

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

    def _is_manual_only(self, callback: dict[str, Any]) -> bool:
        return (
            callback.get("status") == "uncovered"
            and callback.get("is_active") is True
            and (
                callback.get("direct_http_supported") is False
                or callback.get("generation_status") == "manual_analysis_required"
            )
        )
