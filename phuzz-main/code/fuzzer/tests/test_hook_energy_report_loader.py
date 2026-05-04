from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.report_loader import load_run_artifacts


class HookVisualizationLoaderTests(unittest.TestCase):
    def test_loader_reads_decisions_candidates_requests_and_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir)
            requests_dir = run_dir / "requests"
            requests_dir.mkdir()

            (run_dir / "hook-energy-decisions.jsonl").write_text(
                json.dumps(
                    {
                        "coverage_id": "cov-1",
                        "http_target": "http://web/wp-admin/admin-ajax.php",
                        "http_method": "GET",
                        "base_score": 1,
                        "score": 1,
                        "base_priority": 1,
                        "priority": 1.5,
                        "base_energy": 1,
                        "final_energy": 2,
                        "hook_request_id": "req-1",
                        "hook_energy": 0.5,
                        "hook_energy_avg": 0.5,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (run_dir / "exceptions-and-errors.json").write_text(
                json.dumps(
                    [
                        {
                            "coverage_id": "cov-1",
                            "mutated_param_name": "post_type",
                            "mutated_param_type": "query_params",
                            "base_priority": 1,
                            "priority": 1.5,
                            "base_energy": 1,
                            "final_energy": 2,
                            "hook_request_id": "req-1",
                            "hook_energy": 0.5,
                            "hook_energy_avg": 0.5,
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (run_dir / "vulnerable-candidates.json").write_text(
                json.dumps({"WebFuzzXSSVulnCheck": []}),
                encoding="utf-8",
            )
            (run_dir / "total_coverage.json").write_text(
                json.dumps(
                    {
                        "registered_total": 6,
                        "executed_total": 5,
                        "coverage_percent": "83.33%",
                        "blindspot_callbacks": [{"callback_id": "cb-blind"}],
                    }
                ),
                encoding="utf-8",
            )
            (requests_dir / "req-1.json").write_text(
                json.dumps(
                    {
                        "request_id": "req-1",
                        "endpoint": "ADMIN_AJAX:sac_post_type_call",
                        "request_method": "GET",
                        "request_params": {"headers": {"X-FUZZER-COVID": "cov-1"}},
                        "hook_coverage": {
                            "executed_callbacks": {
                                "cb-1": {
                                    "callback_id": "cb-1",
                                    "hook_name": "wp_ajax_sac_post_type_call",
                                    "callback_repr": "sac_post_type_call_callback",
                                    "executed_count": 1,
                                }
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            loaded = load_run_artifacts(
                run_label="hook-run",
                mode="hook-aware",
                decisions_path=run_dir / "hook-energy-decisions.jsonl",
                exceptions_path=run_dir / "exceptions-and-errors.json",
                vulnerabilities_path=run_dir / "vulnerable-candidates.json",
                requests_dir=requests_dir,
                coverage_summary_path=run_dir / "total_coverage.json",
            )

            self.assertEqual(loaded.metadata["label"], "hook-run")
            self.assertEqual(len(loaded.decisions), 1)
            self.assertEqual(len(loaded.exception_candidates), 1)
            self.assertEqual(loaded.coverage_summary["registered_total"], 6)
            self.assertEqual(loaded.requests["req-1"]["endpoint"], "ADMIN_AJAX:sac_post_type_call")

    def test_loader_returns_empty_sections_for_missing_optional_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir)
            loaded = load_run_artifacts(
                run_label="baseline",
                mode="baseline",
                decisions_path=run_dir / "missing-decisions.jsonl",
                exceptions_path=run_dir / "missing-exceptions.json",
                vulnerabilities_path=run_dir / "missing-vulns.json",
                requests_dir=run_dir / "missing-requests",
                coverage_summary_path=run_dir / "missing-coverage.json",
            )

            self.assertEqual(loaded.decisions, [])
            self.assertEqual(loaded.exception_candidates, [])
            self.assertEqual(loaded.vulnerability_candidates, {})
            self.assertEqual(loaded.requests, {})
            self.assertEqual(loaded.coverage_summary, {})


if __name__ == "__main__":
    unittest.main()
