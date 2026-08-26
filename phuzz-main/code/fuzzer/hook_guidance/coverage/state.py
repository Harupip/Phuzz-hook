from __future__ import annotations

import json
from pathlib import Path

from .models import CallbackDescriptor


class HookEnergyDemoState:
    def __init__(self) -> None:
        self.callbacks: dict[str, CallbackDescriptor] = {}
        self.processed_request_ids: set[str] = set()

    def snapshot(self) -> dict:
        return {
            "schema_version": "hook-energy-demo-state-v1",
            "callbacks": {callback_id: item.to_dict() for callback_id, item in sorted(self.callbacks.items())},
            "processed_request_ids": sorted(self.processed_request_ids),
        }

    def save(self, filepath: str) -> None:
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(self.snapshot(), indent=2, ensure_ascii=False)
        path.write_text(content, encoding="utf-8")

    @classmethod
    def load(cls, filepath: str) -> "HookEnergyDemoState":
        path = Path(filepath)
        state = cls()
        if not path.exists():
            return state

        payload = json.loads(path.read_text(encoding="utf-8"))
        for callback_id, item in payload.get("callbacks", {}).items():
            state.callbacks[callback_id] = CallbackDescriptor(
                callback_id=callback_id,
                hook_name=str(item.get("hook_name", "")),
                callback_identity=str(item.get("callback_identity", item.get("callback_repr", callback_id))),
                priority=int(item.get("priority", 10)),
                callback_type=str(item.get("callback_type", item.get("type", "unknown"))),
                is_active=bool(item.get("is_active", True)),
                status=str(item.get("status", "registered_only")),
                source_file=item.get("source_file"),
                source_line=item.get("source_line"),
                callback_runtime_id=item.get("callback_runtime_id"),
                stable_id=item.get("stable_id"),
                runtime_id=item.get("runtime_id"),
                total_execution_count=int(item.get("total_execution_count", 0)),
                total_request_count=int(item.get("total_request_count", 0)),
            )

        state.processed_request_ids = {str(item) for item in payload.get("processed_request_ids", [])}
        return state


GlobalCoverageState = HookEnergyDemoState
