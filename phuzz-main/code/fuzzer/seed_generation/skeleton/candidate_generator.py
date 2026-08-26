from __future__ import annotations

from copy import deepcopy
from typing import Any

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

    def build_reports(self, coverage_payload: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
        payload = deepcopy(coverage_payload)
        data = payload.get("data")
        if isinstance(data, dict):
            registered = data.get("registered_callbacks")
            executed = data.get("executed_callbacks")
            if isinstance(registered, dict) and isinstance(executed, dict):
                for callback_id, observation in executed.items():
                    registration = registered.get(callback_id)
                    if self._correlated_admin_post_probe(registration, observation):
                        # Keep runtime transport evidence while admitting this explicit
                        # action probe as a bootstrap candidate for Zend replay.
                        observation["executed_count"] = 0
        return super().build_reports(payload)

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
        if hook_name.startswith(("wp_ajax_nopriv_", "wp_ajax_")):
            return [{
                "method": "POST",
                "resolved_method": "POST",
                "method_status": "resolved",
                "method_confidence": "runtime_probe",
                "candidate_methods": ["POST"],
            }]
        runtime_observation = metadata.get("_executed_callback")
        if self._correlated_admin_post_probe(metadata, runtime_observation):
            metadata = dict(metadata)
            # Registration request provenance is not the replay observation ID.
            metadata.pop("request_id", None)
        return super()._method_decisions(hook_name, metadata, input_params)
