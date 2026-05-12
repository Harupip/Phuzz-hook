from __future__ import annotations

import importlib
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
    DEFAULT_HOOK_ENERGY_BASE_WEIGHT,
    DEFAULT_HOOK_ENERGY_WEIGHT,
    DEFAULT_HOOK_MIN_ENERGY_SCALE,
    DEFAULT_HOOK_PRIORITY_WEIGHT,
    DEFAULT_HOOK_REQUESTS_DIR,
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


def build_parent_candidate(*, score: int = 27, number_of_new_paths: int = 1) -> Candidate:
    parent = Candidate(score=score, priority=score)
    parent.score = score
    parent.priority = score
    parent.base_score = score
    parent.base_priority = score
    parent.number_of_new_paths = number_of_new_paths
    parent.paths = ["plugin.php::::1_2_3"]
    parent.new_paths = {"plugin.php::::1_2_3"}
    return parent


def build_child_candidate(
    *,
    coverage_id: str,
    parent_score: int = 27,
    parent_number_of_new_paths: int = 1,
) -> Candidate:
    child = Candidate(
        parent=build_parent_candidate(score=parent_score, number_of_new_paths=parent_number_of_new_paths),
        score=0,
        priority=0,
    )
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
        self.assertEqual(DEFAULT_HOOK_ENERGY_BASE_WEIGHT, 0.8)
        self.assertEqual(DEFAULT_HOOK_ENERGY_WEIGHT, 0.8)
        self.assertEqual(DEFAULT_HOOK_MIN_ENERGY_SCALE, 4)

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

    def test_hook_mode_uses_weighted_energy_blend_and_keeps_base_values(self) -> None:
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
            candidate = build_child_candidate(coverage_id="cov-hook", parent_score=2)

            self.assertEqual(formula.calculate_score(candidate), 1)
            self.assertEqual(formula.calculate_priority(candidate), 2.0)
            self.assertEqual(formula.calculate_energy(candidate), 3)
            self.assertEqual(candidate.base_score, 1)
            self.assertEqual(candidate.base_priority, 1)
            self.assertEqual(candidate.base_energy, 2)
            self.assertEqual(candidate.final_energy, 3)
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

    def test_env_can_select_scoring_mode_and_new_hook_energy_constants(self) -> None:
        import scoring

        old_values = {
            "active_mode": ACTIVE_SCORING_MODE,
            "requests_dir": DEFAULT_HOOK_REQUESTS_DIR,
            "priority_weight": DEFAULT_HOOK_PRIORITY_WEIGHT,
            "energy_base_weight": DEFAULT_HOOK_ENERGY_BASE_WEIGHT,
            "energy_weight": DEFAULT_HOOK_ENERGY_WEIGHT,
            "min_hook_scale": DEFAULT_HOOK_MIN_ENERGY_SCALE,
        }
        with patch.dict(
            os.environ,
            {
                "PHUZZ_SCORING_MODE": "1",
                "FUZZER_HOOK_REQUESTS_DIR": "/tmp/hook-requests",
                "FUZZER_HOOK_PRIORITY_WEIGHT": "2.5",
                "FUZZER_HOOK_ENERGY_BASE_WEIGHT": "0.6",
                "FUZZER_HOOK_MIN_ENERGY_SCALE": "7",
            },
            clear=False,
        ):
            reloaded_scoring = importlib.reload(scoring)
            try:
                self.assertEqual(reloaded_scoring.ACTIVE_SCORING_MODE, reloaded_scoring.SCORING_MODE_PHUZZ)
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_REQUESTS_DIR, "/tmp/hook-requests")
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_PRIORITY_WEIGHT, 2.5)
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_ENERGY_BASE_WEIGHT, 0.6)
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_ENERGY_WEIGHT, 0.6)
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_MIN_ENERGY_SCALE, 7)
                self.assertEqual(reloaded_scoring.DefaultScoringFormula().mode, reloaded_scoring.SCORING_MODE_PHUZZ)
            finally:
                os.environ["PHUZZ_SCORING_MODE"] = str(old_values["active_mode"])
                os.environ["FUZZER_HOOK_REQUESTS_DIR"] = old_values["requests_dir"]
                os.environ["FUZZER_HOOK_PRIORITY_WEIGHT"] = str(old_values["priority_weight"])
                os.environ["FUZZER_HOOK_ENERGY_BASE_WEIGHT"] = str(old_values["energy_base_weight"])
                os.environ["FUZZER_HOOK_ENERGY_WEIGHT"] = str(old_values["energy_weight"])
                os.environ["FUZZER_HOOK_MIN_ENERGY_SCALE"] = str(old_values["min_hook_scale"])
                importlib.reload(scoring)

    def test_deprecated_energy_weight_env_still_falls_back_when_new_name_is_absent(self) -> None:
        import scoring

        old_values = {
            "energy_base_weight": DEFAULT_HOOK_ENERGY_BASE_WEIGHT,
            "energy_weight": DEFAULT_HOOK_ENERGY_WEIGHT,
        }
        with patch.dict(
            os.environ,
            {
                "FUZZER_HOOK_ENERGY_WEIGHT": "0.65",
            },
            clear=False,
        ):
            os.environ.pop("FUZZER_HOOK_ENERGY_BASE_WEIGHT", None)
            reloaded_scoring = importlib.reload(scoring)
            try:
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_ENERGY_BASE_WEIGHT, 0.65)
                self.assertEqual(reloaded_scoring.DEFAULT_HOOK_ENERGY_WEIGHT, 0.65)
            finally:
                os.environ["FUZZER_HOOK_ENERGY_BASE_WEIGHT"] = str(old_values["energy_base_weight"])
                os.environ["FUZZER_HOOK_ENERGY_WEIGHT"] = str(old_values["energy_weight"])
                importlib.reload(scoring)


if __name__ == "__main__":
    unittest.main()
