from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .models import CallbackDescriptor, RequestCallbackExecution, RequestObservation
from .state import HookEnergyDemoState


class HookCollector:
    def __init__(self, state: Optional[HookEnergyDemoState] = None) -> None:
        self.state = state or HookEnergyDemoState()

    def read_request_file(self, filepath: str) -> Optional[dict]:
        path = Path(filepath)
        if not path.exists():
            return None

        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def list_pending_request_files(self, requests_dir: str) -> list[str]:
        base = Path(requests_dir)
        if not base.exists():
            return []

        pending_files: list[str] = []
        for path in sorted(base.glob("*.json")):
            if path.stem in self.state.processed_request_ids:
                continue
            pending_files.append(str(path))
        return pending_files

    def collect_request(self, request_data: dict, request_file: Optional[str] = None) -> RequestObservation:
        request_id = str(request_data.get("request_id", Path(request_file).stem if request_file else "unknown-request"))
        endpoint = str(request_data.get("endpoint", request_id))
        scenario_name = self._extract_scenario_name(request_data, request_id, endpoint)

        observation = RequestObservation(
            request_id=request_id,
            scenario_name=scenario_name,
            endpoint=endpoint,
            request_file=request_file,
        )

        hook_coverage = request_data.get("hook_coverage", {})
        registered_payload = hook_coverage.get("registered_callbacks", {})
        for callback_id, item in registered_payload.items():
            descriptor = self._descriptor_from_payload(str(callback_id), item)
            observation.registered_callbacks[descriptor.callback_id] = descriptor
            self._merge_descriptor_into_state(descriptor)

        executed_payload = hook_coverage.get("executed_callbacks", {})
        for callback_id, item in sorted(executed_payload.items()):
            callback_id_str = str(callback_id)
            descriptor = observation.registered_callbacks.get(callback_id_str) or self.state.callbacks.get(callback_id_str)
            if descriptor is None:
                descriptor = self._descriptor_from_payload(callback_id_str, item)

            observation.executed_callbacks.append(
                RequestCallbackExecution(
                    callback_id=callback_id_str,
                    hook_name=descriptor.hook_name,
                    callback_identity=descriptor.callback_identity,
                    priority=descriptor.priority,
                    callback_type=descriptor.callback_type,
                    request_execution_count=max(1, int(item.get("executed_count", 1))),
                )
            )

        return observation

    def finalize_request(self, report) -> None:
        for item in report.executed_callbacks:
            descriptor = self.state.callbacks.get(item.callback_id)
            if descriptor is None:
                descriptor = CallbackDescriptor(
                    callback_id=item.callback_id,
                    hook_name=item.hook_name,
                    callback_identity=item.callback_identity,
                    priority=item.priority,
                    callback_type=item.callback_type,
                )
                self.state.callbacks[item.callback_id] = descriptor

            descriptor.total_execution_count += max(0, int(item.request_execution_count))
            descriptor.total_request_count += 1
            if descriptor.total_execution_count > 0:
                descriptor.status = "covered"

        self.state.processed_request_ids.add(report.request_id)

    def _descriptor_from_payload(self, callback_id: str, payload: dict) -> CallbackDescriptor:
        callback_identity = self._resolve_callback_identity(callback_id, payload)
        return CallbackDescriptor(
            callback_id=callback_id,
            hook_name=str(payload.get("hook_name", payload.get("fired_hook", "unknown_hook"))),
            callback_identity=callback_identity,
            priority=int(payload.get("priority", 10)),
            callback_type=str(payload.get("callback_type", payload.get("type", "unknown"))),
            is_active=bool(payload.get("is_active", True)),
            status=str(payload.get("status", "registered_only")),
            source_file=payload.get("source_file"),
            source_line=payload.get("source_line"),
            callback_runtime_id=payload.get("callback_runtime_id"),
            stable_id=payload.get("stable_id"),
            runtime_id=payload.get("runtime_id"),
            total_execution_count=int(payload.get("total_execution_count", 0)),
            total_request_count=int(payload.get("total_request_count", 0)),
        )

    def _resolve_callback_identity(self, callback_id: str, payload: dict) -> str:
        for key in ("callback_repr", "stable_id", "runtime_id"):
            value = str(payload.get(key, "")).strip()
            if value:
                return value
        return callback_id

    def _merge_descriptor_into_state(self, descriptor: CallbackDescriptor) -> None:
        existing = self.state.callbacks.get(descriptor.callback_id)
        if existing is None:
            self.state.callbacks[descriptor.callback_id] = descriptor
            return

        existing.hook_name = descriptor.hook_name
        existing.callback_identity = descriptor.callback_identity
        existing.priority = descriptor.priority
        existing.callback_type = descriptor.callback_type
        existing.is_active = descriptor.is_active
        existing.status = descriptor.status
        existing.source_file = descriptor.source_file
        existing.source_line = descriptor.source_line
        existing.callback_runtime_id = descriptor.callback_runtime_id
        existing.stable_id = descriptor.stable_id
        existing.runtime_id = descriptor.runtime_id

    def _extract_scenario_name(self, request_data: dict, request_id: str, endpoint: str) -> str:
        params = request_data.get("request_params", {})
        if not isinstance(params, dict):
            params = {}

        body_params = params.get("body_params", {})
        if not isinstance(body_params, dict):
            body_params = {}

        headers = params.get("headers", {})
        if not isinstance(headers, dict):
            headers = {}

        scenario = str(body_params.get("scenario", "")).strip()
        if scenario:
            return scenario

        fuzz_id = str(headers.get("X-Uopz-Fuzz-Id", "")).strip()
        if fuzz_id:
            return fuzz_id

        if endpoint:
            return endpoint

        return request_id
