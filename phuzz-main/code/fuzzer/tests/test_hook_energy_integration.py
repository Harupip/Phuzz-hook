from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy import HookEnergyDemoState
from hook_energy.integration import (
    HookEnergyTracker,
    apply_hook_energy_bonus,
    apply_candidate_hook_feedback,
    apply_hook_priority_bonus,
)
from hook_energy.models import RequestEnergyReport
from candidate import Candidate


def build_request_payload(
    request_id: str,
    coverage_id: str,
    *,
    executed_callbacks,
) -> dict:
    return {
        "request_id": request_id,
        "endpoint": "ADMIN_AJAX:sac_post_type_call",
        "request_params": {
            "headers": {
                "X-FUZZER-COVID": coverage_id,
            }
        },
        "hook_coverage": {
            "registered_callbacks": {
                "cb-1": {
                    "hook_name": "wp_ajax_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "priority": 10,
                    "type": "action",
                }
            },
            "executed_callbacks": executed_callbacks,
        },
    }


class HookEnergyIntegrationTests(unittest.TestCase):
    def test_tracker_correlates_request_by_candidate_coverage_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            requests_dir = Path(tmp_dir)
            payload = build_request_payload(
                "req-1",
                "cov-1",
                executed_callbacks={
                    "cb-1": {
                        "callback_id": "cb-1",
                        "hook_name": "wp_ajax_sac_post_type_call",
                        "callback_repr": "sac_post_type_call_callback",
                        "executed_count": 1,
                    }
                },
            )
            (requests_dir / "req-1.json").write_text(json.dumps(payload), encoding="utf-8")

            tracker = HookEnergyTracker(str(requests_dir))
            report = tracker.consume_candidate("cov-1")

            self.assertIsNotNone(report)
            assert report is not None
            self.assertEqual(report.request_id, "req-1")
            self.assertEqual(report.hook_energy, 1.0)
            self.assertEqual(report.hook_energy_avg, 1.0)
            self.assertIn("req-1", tracker.state.processed_request_ids)

    def test_tracker_handles_empty_executed_callback_lists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            requests_dir = Path(tmp_dir)
            payload = build_request_payload(
                "req-empty",
                "cov-empty",
                executed_callbacks=[],
            )
            (requests_dir / "req-empty.json").write_text(json.dumps(payload), encoding="utf-8")

            tracker = HookEnergyTracker(str(requests_dir), state=HookEnergyDemoState())
            report = tracker.consume_candidate("cov-empty")

            self.assertIsNotNone(report)
            assert report is not None
            self.assertEqual(report.request_id, "req-empty")
            self.assertEqual(report.hook_energy, 0.0)
            self.assertEqual(report.hook_energy_avg, 0.0)
            self.assertEqual(report.executed_callbacks, [])
            self.assertIn("req-empty", tracker.state.processed_request_ids)

    def test_priority_stays_additive_while_energy_uses_weighted_blend(self) -> None:
        self.assertEqual(apply_hook_priority_bonus(5, 0.0, 1.0), 5.0)
        self.assertEqual(apply_hook_priority_bonus(5, 1.0, 1.5), 6.5)

        self.assertEqual(apply_hook_energy_bonus(2, 1.0, 0.8, 4), 3)
        self.assertEqual(apply_hook_energy_bonus(10, 0.1, 0.8, 4), 9)
        self.assertEqual(apply_hook_energy_bonus(2, 0.5, 0.0, 4), 2)
        self.assertEqual(apply_hook_energy_bonus(3, 1.0, 1.0, 4), 3)
        self.assertEqual(apply_hook_energy_bonus(3, -0.5, 0.8, 4), 3)
        self.assertEqual(apply_hook_energy_bonus(3, 1.7, 0.8, 4), 4)
        self.assertEqual(apply_hook_energy_bonus(0, 1.0, 0.8, 4), 2)
        self.assertEqual(apply_hook_energy_bonus(-5, 1.0, 0.8, 4), 2)

    def test_candidate_feedback_keeps_base_values_and_uses_weighted_energy_blend(self) -> None:
        candidate = Candidate()
        candidate.coverage_id = "cov-xyz"
        report = RequestEnergyReport(
            request_id="req-for-cov-xyz",
            scenario_name="ADMIN_AJAX:sac_post_type_call",
            endpoint="ADMIN_AJAX:sac_post_type_call",
            request_file=None,
            hook_energy=1.0,
            hook_energy_avg=1.0,
            executed_callbacks=[],
        )

        final_priority, final_energy = apply_candidate_hook_feedback(
            candidate,
            report,
            base_priority=3,
            base_energy=3,
            priority_weight=1.5,
            energy_weight=0.8,
            min_hook_scale=4,
        )

        self.assertEqual(candidate.hook_request_id, "req-for-cov-xyz")
        self.assertEqual(candidate.hook_energy, 1.0)
        self.assertEqual(candidate.hook_energy_avg, 1.0)
        self.assertEqual(candidate.base_priority, 3)
        self.assertEqual(candidate.base_energy, 3)
        self.assertEqual(final_priority, 4.5)
        self.assertEqual(final_energy, 4)
        self.assertEqual(candidate.priority, 4.5)
        self.assertEqual(candidate.final_energy, 4)


if __name__ == "__main__":
    unittest.main()
