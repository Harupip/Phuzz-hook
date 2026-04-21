from __future__ import annotations

import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from scoring import calculate_hook_coverage_energy


def build_request_payload() -> dict:
    return {
        "request_id": "req-1",
        "endpoint": "REST:/demo/hooks",
        "hook_coverage": {
            "registered_callbacks": {
                "cb-1": {"hook_name": "rest_api_init"},
                "cb-2": {"hook_name": "demo_blindspot"},
            },
            "executed_callbacks": {
                "cb-1": {
                    "callback_id": "cb-1",
                    "hook_name": "rest_api_init",
                    "callback_repr": "demo_register_routes",
                    "executed_count": 1,
                }
            },
        },
    }


class HookEnergyBridgeTests(unittest.TestCase):
    def test_bridge_calculates_energy_and_updates_state(self) -> None:
        from hook_energy import GlobalCoverageState

        state = GlobalCoverageState()
        result = calculate_hook_coverage_energy(build_request_payload(), state=state, update_state=True)

        self.assertEqual(result.new_callback_ids, ["cb-1"])
        self.assertEqual(result.score, 22)
        self.assertEqual(state.get_historical_count("cb-1"), 1)
        self.assertIn("cb-2", state.blindspot_ids)

    def test_bridge_can_calculate_without_mutating_state(self) -> None:
        from hook_energy import GlobalCoverageState

        state = GlobalCoverageState()
        result = calculate_hook_coverage_energy(build_request_payload(), state=state, update_state=False)

        self.assertEqual(result.new_callback_ids, ["cb-1"])
        self.assertEqual(result.score, 22)
        self.assertEqual(state.get_historical_count("cb-1"), 0)
        self.assertEqual(len(state.registered_callbacks), 0)


if __name__ == "__main__":
    unittest.main()
