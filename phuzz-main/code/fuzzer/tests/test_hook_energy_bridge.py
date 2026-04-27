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
        from hook_energy import HookEnergyDemoState

        state = HookEnergyDemoState()
        result = calculate_hook_coverage_energy(build_request_payload(), state=state, update_state=True)

        self.assertEqual(result.request_id, "req-1")
        self.assertEqual(result.hook_energy, 1.0)
        self.assertEqual(result.hook_energy_avg, 1.0)
        self.assertEqual(len(result.executed_callbacks), 1)
        self.assertEqual(result.executed_callbacks[0].callback_id, "cb-1")
        self.assertEqual(state.callbacks["cb-1"].total_execution_count, 1)
        self.assertEqual(state.callbacks["cb-1"].total_request_count, 1)
        self.assertIn("req-1", state.processed_request_ids)
        self.assertIn("cb-2", state.callbacks)
        self.assertEqual(state.callbacks["cb-2"].total_execution_count, 0)

    def test_bridge_can_calculate_without_mutating_state(self) -> None:
        from hook_energy import HookEnergyDemoState

        state = HookEnergyDemoState()
        result = calculate_hook_coverage_energy(build_request_payload(), state=state, update_state=False)

        self.assertEqual(result.request_id, "req-1")
        self.assertEqual(result.hook_energy, 1.0)
        self.assertEqual(len(result.executed_callbacks), 1)
        self.assertEqual(result.executed_callbacks[0].callback_id, "cb-1")
        self.assertEqual(state.callbacks, {})
        self.assertEqual(state.processed_request_ids, set())


if __name__ == "__main__":
    unittest.main()
