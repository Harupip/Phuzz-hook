from __future__ import annotations

import json
import logging
import os
import time
from typing import Dict

logger = logging.getLogger(__name__)
SNAPSHOT_SCHEMA_VERSION = "uopz-energy-state-v2"


class GlobalCoverageState:
    def __init__(self):
        self.executed_counts: Dict[str, int] = {}
        self.registered_callbacks: Dict[str, dict] = {}
        self.executed_callbacks: Dict[str, dict] = {}
        self.seen_hooks: set = set()
        self.total_requests: int = 0
        self.start_time: float = time.time()

    @property
    def blindspot_ids(self) -> set:
        return set(self.registered_callbacks.keys()) - set(self.executed_counts.keys())

    @property
    def coverage_percent(self) -> float:
        total = len(self.registered_callbacks)
        if total == 0:
            return 0.0
        covered = len(set(self.executed_counts.keys()) & set(self.registered_callbacks.keys()))
        return round(covered / total * 100, 2)

    def update_from_request(self, request_data: dict) -> None:
        self.total_requests += 1
        hook_cov = request_data.get("hook_coverage", {})

        for cb_id, info in hook_cov.get("registered_callbacks", {}).items():
            if cb_id not in self.registered_callbacks:
                self.registered_callbacks[cb_id] = info
            hook_name = info.get("hook_name", "")
            if hook_name:
                self.seen_hooks.add(hook_name)

        for cb_id, info in hook_cov.get("executed_callbacks", {}).items():
            count = int(info.get("executed_count", 1))
            self.executed_counts[cb_id] = self.executed_counts.get(cb_id, 0) + count

            if cb_id not in self.executed_callbacks:
                self.executed_callbacks[cb_id] = info.copy()
            else:
                existing = self.executed_callbacks[cb_id]
                existing["executed_count"] = self.executed_counts[cb_id]
                for field_name in ("last_seen", "fired_hook", "request_id", "endpoint"):
                    if field_name in info:
                        existing[field_name] = info[field_name]

            hook_name = info.get("hook_name", "")
            if hook_name:
                self.seen_hooks.add(hook_name)

    def get_historical_count(self, callback_id: str) -> int:
        return self.executed_counts.get(callback_id, 0)

    def is_blindspot(self, callback_id: str) -> bool:
        return callback_id in self.registered_callbacks and callback_id not in self.executed_counts

    def is_new_hook(self, hook_name: str) -> bool:
        return hook_name not in self.seen_hooks

    def snapshot(self) -> dict:
        covered_executed = {}
        blindspots = {}

        for cb_id, info in self.registered_callbacks.items():
            if cb_id in self.executed_counts:
                covered_executed[cb_id] = self.executed_callbacks.get(cb_id, info)
            else:
                blindspots[cb_id] = info

        return {
            "schema_version": SNAPSHOT_SCHEMA_VERSION,
            "metadata": {
                "total_registered_callbacks": len(self.registered_callbacks),
                "total_executed_callbacks": len(covered_executed),
                "coverage_percent": self.coverage_percent,
                "total_requests_processed": self.total_requests,
                "total_blindspots": len(blindspots),
                "uptime_seconds": round(time.time() - self.start_time, 2),
            },
            "data": {
                "registered_callbacks": self.registered_callbacks,
                "executed_callbacks": covered_executed,
                "blindspot_callbacks": blindspots,
                "seen_hooks": sorted(self.seen_hooks),
            },
        }

    def save_snapshot(self, filepath: str) -> None:
        data = self.snapshot()
        tmp = filepath + f".tmp.{os.getpid()}"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            if os.name == "nt" and os.path.exists(filepath):
                os.remove(filepath)
            os.rename(tmp, filepath)
        except OSError:
            logger.exception("Failed to save snapshot to %s", filepath)
            if os.path.exists(tmp):
                os.remove(tmp)

    def load_snapshot(self, filepath: str) -> None:
        if not os.path.exists(filepath):
            logger.warning("Snapshot file not found: %s", filepath)
            return

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            logger.exception("Failed to load snapshot from %s", filepath)
            return

        payload = data.get("data", {})

        for hook_name in payload.get("seen_hooks", []):
            if hook_name:
                self.seen_hooks.add(str(hook_name))

        for cb_id, info in payload.get("registered_callbacks", {}).items():
            if cb_id not in self.registered_callbacks:
                self.registered_callbacks[cb_id] = info
            hook_name = info.get("hook_name", "")
            if hook_name:
                self.seen_hooks.add(hook_name)

        for cb_id, info in payload.get("executed_callbacks", {}).items():
            count = int(info.get("executed_count", 0))
            self.executed_counts[cb_id] = self.executed_counts.get(cb_id, 0) + count
            if cb_id not in self.executed_callbacks:
                self.executed_callbacks[cb_id] = info.copy()
            hook_name = info.get("hook_name", "")
            if hook_name:
                self.seen_hooks.add(hook_name)
