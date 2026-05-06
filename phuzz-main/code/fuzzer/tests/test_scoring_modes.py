from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from candidate import Candidate
from scoring import (
    ACTIVE_SCORING_MODE,
    DefaultScoringFormula,
    SCORING_MODE_PHUZZ,
    SCORING_MODE_PHUZZ_HOOK,
)


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


def build_parent_candidate() -> Candidate:
    parent = Candidate(score=27, priority=27)
    parent.score = 27
    parent.priority = 27
    parent.base_score = 27
    parent.base_priority = 27
    parent.number_of_new_paths = 1
    parent.paths = ["plugin.php::::1_2_3"]
    parent.new_paths = {"plugin.php::::1_2_3"}
    return parent


def build_child_candidate(*, coverage_id: str) -> Candidate:
    child = Candidate(parent=build_parent_candidate(), score=0, priority=0)
    child.coverage_id = coverage_id
    child.paths = ["plugin.php::::1_2_3"]
    child.new_paths = set()
    child.number_of_new_paths = 0
    return child


class ScoringModeTests(unittest.TestCase):
    def test_default_formula_uses_hook_mode_by_default(self) -> None:
        formula = DefaultScoringFormula()
        self.assertEqual(formula.mode, ACTIVE_SCORING_MODE)
        self.assertEqual(formula.mode, SCORING_MODE_PHUZZ_HOOK)

    def test_phuzz_mode_keeps_original_priority_and_energy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = build_request_payload(
                "req-plain",
                "cov-plain",
                executed_callbacks={
                    "cb-1": {
                        "callback_id": "cb-1",
                        "hook_name": "wp_ajax_sac_post_type_call",
                        "callback_repr": "sac_post_type_call_callback",
                        "executed_count": 1,
                    }
                },
            )
            (Path(tmp_dir) / "req-plain.json").write_text(json.dumps(payload), encoding="utf-8")

            formula = DefaultScoringFormula(mode=SCORING_MODE_PHUZZ, requests_dir=tmp_dir)
            candidate = build_child_candidate(coverage_id="cov-plain")

            self.assertEqual(formula.calculate_score(candidate), 1)
            self.assertEqual(formula.calculate_priority(candidate), 1)
            self.assertEqual(formula.calculate_energy(candidate), 27)
            self.assertEqual(candidate.hook_energy, 0.0)
            self.assertEqual(candidate.hook_energy_avg, 0.0)

    def test_hook_mode_adds_hook_bonus_and_keeps_base_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            payload = build_request_payload(
                "req-hook",
                "cov-hook",
                executed_callbacks={
                    "cb-1": {
                        "callback_id": "cb-1",
                        "hook_name": "wp_ajax_sac_post_type_call",
                        "callback_repr": "sac_post_type_call_callback",
                        "executed_count": 1,
                    }
                },
            )
            (Path(tmp_dir) / "req-hook.json").write_text(json.dumps(payload), encoding="utf-8")

            formula = DefaultScoringFormula(mode=SCORING_MODE_PHUZZ_HOOK, requests_dir=tmp_dir)
            candidate = build_child_candidate(coverage_id="cov-hook")

            self.assertEqual(formula.calculate_score(candidate), 1)
            self.assertEqual(formula.calculate_priority(candidate), 2.0)
            self.assertEqual(formula.calculate_energy(candidate), 28)
            self.assertEqual(candidate.base_score, 1)
            self.assertEqual(candidate.base_priority, 1)
            self.assertEqual(candidate.base_energy, 27)
            self.assertEqual(candidate.final_energy, 28)
            self.assertEqual(candidate.hook_request_id, "req-hook")
            self.assertEqual(candidate.hook_energy, 1.0)
            self.assertEqual(candidate.hook_energy_avg, 1.0)

    def test_phuzz_mode_emits_score_debug_when_enabled(self) -> None:
        formula = DefaultScoringFormula(mode=SCORING_MODE_PHUZZ)
        candidate = build_child_candidate(coverage_id="cov-debug")
        candidate.paths = ["plugin.php::::1_2_3", "other.php::::5_9_11"]
        candidate.new_paths = {"other.php::::5_9_11"}

        with patch.dict(os.environ, {"PHUZZ_SCORE_DEBUG": "1"}, clear=False):
            with patch("sys.stdout", new_callable=StringIO) as stdout:
                score = formula.calculate_score(candidate)

        self.assertEqual(score, 4)
        debug_output = stdout.getvalue()
        self.assertIn("[score-debug] new_path file=other.php raw=5_9_11 segments=3 underscores=2", debug_output)
        self.assertIn("[score-debug] total hit_counter=2 total_paths=2 score=4", debug_output)


if __name__ == "__main__":
    unittest.main()
