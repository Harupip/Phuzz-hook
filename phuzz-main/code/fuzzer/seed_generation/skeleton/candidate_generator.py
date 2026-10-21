from __future__ import annotations

from typing import Any

from discovery.entrypoints.entrypoints import seed_template_for_callback
from .common_generator import SeedGeneratorBase


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

    def _is_discovery_eligible(
        self, hook_name: str, is_active: bool, coverage_status: str, callback_metadata: dict[str, Any],
    ) -> bool:
        return is_active and (
            coverage_status == "uncovered"
            or seed_template_for_callback(hook_name, callback_metadata) is not None
        )

    @staticmethod
    def _correlated_admin_post_probe(registration: Any, observation: Any) -> bool:
        if not isinstance(registration, dict) or not isinstance(observation, dict):
            return False
        hook_name = str(registration.get("hook_name") or "")
        prefix = next(
            (value for value in ("admin_post_nopriv_", "admin_post_") if hook_name.startswith(value)),
            "",
        )
        if not prefix:
            return False
        action = hook_name[len(prefix):]
        target_plugin = str(observation.get("target_plugin") or "")
        source_file = str(registration.get("source_file") or "").replace("\\", "/")
        return bool(
            action
            and observation.get("request_id")
            and observation.get("http_method")
            and observation.get("callback_id") == registration.get("callback_id")
            and observation.get("hook_name") == hook_name
            and observation.get("fired_hook") == hook_name
            and observation.get("callback_repr") == registration.get("callback_repr")
            and observation.get("endpoint") == f"ADMIN_POST:{action}"
            and target_plugin
            and f"/wp-content/plugins/{target_plugin}/" in source_file
        )

    def _method_decisions(
        self,
        hook_name: str,
        metadata: dict[str, Any],
        input_params: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if hook_name.startswith(("admin_post_nopriv_", "admin_post_")):
            metadata = dict(metadata)
            if self._correlated_admin_post_probe(metadata, metadata.get("_executed_callback")):
                # Registration provenance is not the replay observation ID.
                metadata.pop("request_id", None)
            else:
                metadata.pop("_executed_callback", None)
        decisions = super()._method_decisions(hook_name, metadata, input_params)
        if hook_name.startswith(("wp_ajax_nopriv_", "wp_ajax_")):
            if any(item.get("method_status") == "resolved" for item in decisions):
                return decisions
            return [{
                "method": "GET",
                "resolved_method": "GET",
                "method_status": "resolved",
                "method_source": "bootstrap_probe",
                "method_confidence": "bootstrap_probe",
                "candidate_methods": ["GET"],
                "method_evidence": {"reason": "ajax_bootstrap_without_method_evidence"},
                "seed_variant_id": "get",
                "export_allowed": True,
                "replay_allowed": True,
            }]
        return decisions
