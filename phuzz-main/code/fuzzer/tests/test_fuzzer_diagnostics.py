from __future__ import annotations

import json
import shutil
import sys
import types
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

sys.modules.setdefault("bleach", types.SimpleNamespace(clean=lambda value, *args, **kwargs: value))
sys.modules.setdefault("esprima", types.SimpleNamespace(parseScript=lambda *args, **kwargs: None))
sys.modules.setdefault(
    "bs4",
    types.SimpleNamespace(BeautifulSoup=lambda *args, **kwargs: None, element=types.SimpleNamespace()),
)

from candidate import Candidate
from fuzzer import Fuzzer


class FuzzerDiagnosticsTests(unittest.TestCase):
    def test_write_scheduler_decision_records_hook_energy_context(self) -> None:
        fuzzer = Fuzzer("diagnostics-unit")
        try:
            candidate = Candidate(
                http_target="http://web/wp-admin/admin-ajax.php",
                http_method="POST",
                mutated_param_type="body_params",
                mutated_param_name="filter_tag",
            )
            candidate.score = 7
            candidate.base_score = 7
            candidate.priority = 8.5
            candidate.base_priority = 7
            candidate.base_energy = 2
            candidate.final_energy = 4
            candidate.hook_request_id = "req-hook"
            candidate.hook_energy = 0.75
            candidate.hook_energy_avg = 0.5

            fuzzer._write_hook_energy_decision(candidate, 4)

            path = Path(fuzzer.output_dir) / "hook-energy-decisions.jsonl"
            rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        finally:
            shutil.rmtree(fuzzer.output_dir, ignore_errors=True)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["coverage_id"], candidate.coverage_id)
        self.assertEqual(rows[0]["http_target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(rows[0]["base_energy"], 2)
        self.assertEqual(rows[0]["final_energy"], 4)
        self.assertEqual(rows[0]["scheduler_energy"], 4)
        self.assertEqual(rows[0]["hook_request_id"], "req-hook")
        self.assertEqual(rows[0]["hook_energy"], 0.75)
        self.assertEqual(rows[0]["mutated_param_type"], "body_params")
        self.assertEqual(rows[0]["hook_energy_base_weight"], 0.8)

    def test_fuzzer_loads_explicit_config_file_with_seed_requests(self) -> None:
        fuzzer = Fuzzer("seed-config-unit")
        try:
            config_path = Path(fuzzer.output_dir) / "seed-config.json"
            config_path.write_text(
                json.dumps(
                    {
                        "print_timestamps": False,
                        "seed_requests": [
                            {
                                "target": "http://web/wp-admin/admin-ajax.php",
                                "http_method": "POST",
                                "fixed_params": {
                                    "body_params": {"action": "public_hook"},
                                },
                                "fuzz_params": {
                                    "body_params": {"filter_tag": "fuzz"},
                                },
                                "fuzz_weights": {
                                    "body_params": 1,
                                },
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            fuzzer.load_config(str(config_path))
            fuzzer.load_request_data()
            candidates = list(fuzzer.generate_initial_candidates())
        finally:
            shutil.rmtree(fuzzer.output_dir, ignore_errors=True)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].http_target, "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(candidates[0].http_method, "POST")
        self.assertEqual(candidates[0].fixed_params["body_params"]["action"], "public_hook")
        self.assertEqual(candidates[0].fuzz_params["body_params"]["filter_tag"], "fuzz")


if __name__ == "__main__":
    unittest.main()
