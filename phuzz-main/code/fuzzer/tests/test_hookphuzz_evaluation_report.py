import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.evaluation_report import build_evaluation_report, write_evaluation_report


def write_json(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


class HookPhuzzEvaluationReportTests(unittest.TestCase):
    def test_builds_plugin_summary_from_seed_generation_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            seed_dir = root / "output" / "seed_generation"
            write_json(
                seed_dir / "hook_gap_report.json",
                {
                    "summary": {"registered_callbacks": 3, "direct_http_seed_candidates": 2},
                    "callbacks": [
                        {
                            "hook_name": "wp_ajax_demo_lookup",
                            "callback_id": "cb-ready",
                            "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
                        }
                    ],
                },
            )
            write_json(
                seed_dir / "suggested_seeds.json",
                {
                    "summary": {"direct_http_seed_candidates": 2},
                    "suggested_seeds": [
                        {
                            "hook_name": "wp_ajax_demo_lookup",
                            "callback_id": "cb-ready",
                            "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
                            "generation_status": "supported_http_seed",
                            "seed": {
                                "fuzzable_params": ["item_id"],
                                "input_params": [{"name": "item_id", "source": "POST"}],
                            },
                        },
                        {
                            "hook_name": "wp_ajax_demo_ping",
                            "callback_id": "cb-entry",
                            "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
                            "generation_status": "supported_http_seed",
                            "seed": {"fuzzable_params": [], "input_params": []},
                        },
                        {
                            "hook_name": "template_redirect",
                            "callback_id": "cb-manual",
                            "source_file": "/var/www/html/wp-content/plugins/demo/includes/front.php",
                            "generation_status": "manual_analysis_required",
                        },
                    ],
                },
            )
            write_json(
                seed_dir / "generated_config_summary.json",
                {
                    "generated": [
                        {"hook_name": "wp_ajax_demo_lookup", "callback_id": "cb-ready", "config_slug": "generated/demo"}
                    ],
                    "skipped": [
                        {"hook_name": "template_redirect", "callback_id": "cb-manual", "reason": "missing_seed"}
                    ],
                },
            )
            write_json(
                seed_dir / "validation_result.json",
                {"summary": {"callback_reached": 1}},
            )

            report = build_evaluation_report(root / "output")
            demo = report["plugins"][0]

            self.assertEqual(demo["plugin_slug"], "demo")
            self.assertEqual(demo["registered_hooks_count"], 3)
            self.assertEqual(demo["direct_http_candidates_count"], 2)
            self.assertEqual(demo["generated_configs_count"], 1)
            self.assertEqual(demo["fuzzing_ready_count"], 1)
            self.assertEqual(demo["entrypoint_only_count"], 1)
            self.assertEqual(demo["manual_analysis_count"], 1)
            self.assertEqual(demo["skipped_count"], 1)
            self.assertEqual(demo["skipped_reasons"], {"missing_seed": 1})
            self.assertEqual(demo["callback_reached_count"], 1)
            self.assertEqual(demo["classification"], "config_generated_not_fuzzed")
            self.assertEqual(demo["extracted_fuzz_params"][0]["params"], ["item_id"])

    def test_generated_config_vuln_found_counts_as_e2e_success(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            seed_dir = root / "output" / "seed_generation"
            write_json(
                seed_dir / "hook_gap_report.json",
                {
                    "summary": {"registered_callbacks": 1, "direct_http_seed_candidates": 1},
                    "callbacks": [
                        {
                            "hook_name": "wp_ajax_demo_lookup",
                            "callback_id": "cb-ready",
                            "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
                        }
                    ],
                },
            )
            write_json(
                seed_dir / "generated_config_summary.json",
                {
                    "generated": [
                        {"hook_name": "wp_ajax_demo_lookup", "callback_id": "cb-ready", "config_slug": "generated/demo"}
                    ],
                    "skipped": [],
                },
            )
            write_json(
                seed_dir / "generated_config_run_summary.json",
                {
                    "counts": {"callback_reached": 1, "vuln_found": 0},
                    "runs": [
                        {
                            "hook_name": "wp_ajax_demo_lookup",
                            "callback_reached": True,
                            "process_status": "failed",
                            "exit_code": 57,
                        }
                    ],
                },
            )

            report = build_evaluation_report(root / "output")
            demo = report["plugins"][0]

            self.assertEqual(demo["vulnerability_found_count"], 1)
            self.assertEqual(demo["callback_reached_count"], 1)
            self.assertEqual(demo["classification"], "e2e_success")

    def test_aggregates_legacy_evaluation_summary_rows_as_e2e_success(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "output"
            run_root = output / "evaluations" / "20260602-203819"
            write_json(
                run_root / "evaluation-summary.json",
                [
                    {
                        "plugin": "gamipress",
                        "hook": "wp_ajax_nopriv_gamipress_get_logs",
                        "param": "orderby",
                        "seed_generated_automatically": True,
                        "fuzzable_param_discovered_automatically": True,
                        "callback_reached": True,
                        "vulnerability_found": True,
                        "time_to_first_vulnerability_seconds": 1,
                        "requests_to_first_vulnerability": 2,
                    },
                    {
                        "plugin": "country-state-city-auto-dropdown",
                        "hook": "wp_ajax_nopriv_tc_csca_get_states",
                        "param": "cnt",
                        "seed_generated_automatically": True,
                        "fuzzable_param_discovered_automatically": True,
                        "callback_reached": True,
                        "vulnerability_found": True,
                        "time_to_first_vulnerability_seconds": 0,
                        "requests_to_first_vulnerability": 1,
                    },
                    {
                        "plugin": "country-state-city-auto-dropdown",
                        "hook": "wp_ajax_nopriv_tc_csca_get_cities",
                        "param": "sid",
                        "seed_generated_automatically": True,
                        "fuzzable_param_discovered_automatically": True,
                        "callback_reached": True,
                        "vulnerability_found": True,
                        "time_to_first_vulnerability_seconds": 0,
                        "requests_to_first_vulnerability": 2,
                    },
                ],
            )
            write_json(
                run_root / "gamipress-seeds" / "suggested_seeds.json",
                {"summary": {"direct_http_seed_candidates": 1}, "suggested_seeds": []},
            )

            report = build_evaluation_report(output)
            by_plugin = {item["plugin_slug"]: item for item in report["plugins"]}

            self.assertEqual(by_plugin["gamipress"]["classification"], "e2e_success")
            self.assertEqual(by_plugin["gamipress"]["vulnerability_found_count"], 1)
            self.assertEqual(by_plugin["gamipress"]["first_vulnerability_time"], 1)
            self.assertEqual(by_plugin["gamipress"]["first_vulnerability_request"], 2)
            self.assertEqual(by_plugin["gamipress"]["extracted_fuzz_params"][0]["params"], ["orderby"])
            self.assertEqual(
                by_plugin["country-state-city-auto-dropdown"]["dependency_plugins"],
                ["contact-form-7"],
            )
            self.assertEqual(by_plugin["country-state-city-auto-dropdown"]["generated_configs_count"], 2)
            self.assertEqual(by_plugin["country-state-city-auto-dropdown"]["fuzzing_ready_count"], 2)
            self.assertEqual(by_plugin["country-state-city-auto-dropdown"]["first_vulnerability_request"], 1)
            self.assertTrue(any(note["plugin_slug"] == "gamipress" for note in report["case_notes"]))
            self.assertTrue(
                any(note["plugin_slug"] == "country-state-city-auto-dropdown" for note in report["case_notes"])
            )

    def test_writes_json_and_markdown_reports(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output = Path(tmp_dir) / "output"
            write_json(
                output / "seed_generation" / "hook_gap_report.json",
                {"summary": {"registered_callbacks": 0, "direct_http_seed_candidates": 0}, "callbacks": []},
            )

            json_path = output / "evaluation" / "hookphuzz_evaluation_summary.json"
            markdown_path = output / "evaluation" / "hookphuzz_evaluation_summary.md"
            report = write_evaluation_report(output, json_path=json_path, markdown_path=markdown_path)

            self.assertTrue(json_path.exists())
            self.assertTrue(markdown_path.exists())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8")), report)
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertIn("# HookPhuzz Evaluation Summary", markdown)
            self.assertIn("What HookPhuzz Successfully Proves", markdown)


if __name__ == "__main__":
    unittest.main()
