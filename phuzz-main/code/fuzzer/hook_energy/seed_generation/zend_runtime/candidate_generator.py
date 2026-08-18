from __future__ import annotations

from typing import Any

from ..common_generator import SeedGeneratorBase


class ZendRuntimeSeedGenerator(SeedGeneratorBase):
    """Generate bootstrap candidates from runtime coverage, never plugin source."""

    def _extract_input_params(self, registered_entry: dict[str, Any]) -> dict[str, Any]:
        return {
            "input_params": [],
            "source_resolution": {
                "source_file": str(registered_entry.get("source_file") or ""),
                "status": "runtime_only",
                "resolved_source_file": None,
            },
        }

    def _method_decisions(
        self,
        hook_name: str,
        metadata: dict[str, Any],
        input_params: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if hook_name.startswith(("wp_ajax_nopriv_", "wp_ajax_")):
            return [{
                "method": "POST",
                "resolved_method": "POST",
                "method_status": "resolved",
                "method_confidence": "runtime_probe",
                "candidate_methods": ["POST"],
            }]
        return super()._method_decisions(hook_name, metadata, input_params)
