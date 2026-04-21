from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Tuple

from .calculator import EnergyCalculator
from .config import EnergyConfig
from .models import EnergyResult
from .request_store import find_new_request_files, read_request_file, write_request_file
from .state import GlobalCoverageState


class EnergyScheduler:
    def __init__(
        self,
        requests_dir: str = "/shared-tmpfs/hook-coverage/requests",
        snapshot_path: str = "/shared-tmpfs/hook-coverage/energy_state.json",
        config: Optional[EnergyConfig] = None,
        snapshot_interval: int = 50,
        processed_ids_path: Optional[str] = None,
        enrich_request_files: bool = True,
    ):
        self.requests_dir = requests_dir
        self.snapshot_path = snapshot_path
        self.snapshot_interval = snapshot_interval
        self.processed_ids_path = processed_ids_path or f"{snapshot_path}.processed_ids.json"
        self.enrich_request_files = enrich_request_files
        self.calculator = EnergyCalculator(config)
        self.processed_ids: set = set()
        self._requests_since_snapshot = 0

    @property
    def state(self) -> GlobalCoverageState:
        return self.calculator.state

    def load_previous_state(self) -> bool:
        self._load_processed_ids()
        if os.path.exists(self.snapshot_path):
            self.calculator.state.load_snapshot(self.snapshot_path)
            return True
        return False

    def save_state(self) -> None:
        self.calculator.state.save_snapshot(self.snapshot_path)
        self._save_processed_ids()

    def _load_processed_ids(self) -> None:
        if not os.path.exists(self.processed_ids_path):
            return
        data = read_request_file(self.processed_ids_path)
        if not isinstance(data, dict):
            return
        ids = data.get("processed_ids", [])
        if isinstance(ids, list):
            self.processed_ids = {str(item) for item in ids}

    def _save_processed_ids(self) -> None:
        payload = {
            "schema_version": "uopz-processed-ids-v1",
            "processed_ids": sorted(self.processed_ids),
        }
        write_request_file(self.processed_ids_path, payload)

    def _enrich_request_payload(self, data: dict, result: EnergyResult) -> dict:
        enriched = dict(data)
        enriched["schema_version"] = enriched.get("schema_version", "uopz-request-v3")
        enriched["executed_callback_ids"] = result.executed_callback_ids
        enriched["new_callback_ids"] = result.new_callback_ids
        enriched["rare_callback_ids"] = result.rare_callback_ids
        enriched["frequent_callback_ids"] = result.frequent_callback_ids
        enriched["blindspot_callback_ids"] = result.blindspot_callback_ids
        enriched["new_hook_names"] = result.new_hook_names
        enriched["coverage_delta"] = result.coverage_delta
        enriched["score"] = result.score
        enriched["energy_feedback"] = result.to_dict()
        return enriched

    def process_request_file(self, filepath: str) -> Optional[EnergyResult]:
        data = read_request_file(filepath)
        if data is None:
            return None

        req_id = data.get("request_id", Path(filepath).stem)
        if req_id in self.processed_ids:
            return None

        result = self.calculator.process_request(data)
        self.processed_ids.add(req_id)
        self._requests_since_snapshot += 1

        if self.enrich_request_files:
            write_request_file(filepath, self._enrich_request_payload(data, result))

        if self._requests_since_snapshot >= self.snapshot_interval:
            self.save_state()
            self._requests_since_snapshot = 0

        return result

    def process_new_requests(self) -> List[Tuple[str, EnergyResult]]:
        new_files = find_new_request_files(self.requests_dir, self.processed_ids)
        results = []
        for filepath in new_files:
            req_id = Path(filepath).stem
            result = self.process_request_file(filepath)
            if result is not None:
                results.append((req_id, result))
        return results

    def get_energy_for_request(self, request_data: dict) -> EnergyResult:
        return self.calculator.process_request(request_data)
