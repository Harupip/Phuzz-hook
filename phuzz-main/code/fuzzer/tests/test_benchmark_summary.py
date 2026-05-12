from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from benchmarking.summary import analyze_run, aggregate_results


def build_request_payload(
    request_id: str,
    timestamp: str,
    coverage_id: str,
    *,
    executed_callbacks: dict | None = None,
) -> dict:
    return {
        "request_id": request_id,
        "timestamp": timestamp,
        "http_method": "GET",
        "http_target": "/wp-admin/admin-ajax.php?action=sac_post_type_call",
        "endpoint": "ADMIN_AJAX:sac_post_type_call",
        "request_params": {
            "headers": {
                "X-FUZZER-COVID": coverage_id,
            }
        },
        "hook_coverage": {
            "registered_callbacks": {
                "cb-auth": {
                    "callback_id": "cb-auth",
                    "hook_name": "wp_ajax_sac_post_type_call",
                },
                "cb-admin-menu": {
                    "callback_id": "cb-admin-menu",
                    "hook_name": "admin_menu",
                },
                "cb-unauth": {
                    "callback_id": "cb-unauth",
                    "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                },
            },
            "executed_callbacks": executed_callbacks or {},
        },
    }


def build_candidate(coverage_id: str, payload: str, *, errline: int = 569) -> dict:
    return {
        "coverage_id": coverage_id,
        "http_target": "http://web/wp-admin/admin-ajax.php",
        "http_method": "GET",
        "fixed_params": {
            "query_params": {
                "action": "sac_post_type_call",
            }
        },
        "fuzz_params": {
            "query_params": {
                "post_type": payload,
            }
        },
        "mutated_param_type": "query_params",
        "mutated_param_name": "post_type",
        "errors": [
            {
                "errfile": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                "errline": errline,
            }
        ],
        "exceptions": None,
        "paths": [
            "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php::::241_548_549_569"
        ],
        "vulns": ["WebFuzzXSSVulnCheck"],
    }


class BenchmarkSummaryTests(unittest.TestCase):
    def test_analyze_run_dedupes_vulns_and_computes_30m_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            run_dir = Path(tmp_dir)
            requests_dir = run_dir / "requests"
            requests_dir.mkdir()

            request_payloads = [
                build_request_payload(
                    "190000_GET_wp-admin_admin-ajax_php_0001",
                    "2026-05-12 19:00:00",
                    "1778094000-run-1",
                    executed_callbacks={
                        "cb-auth": {
                            "callback_id": "cb-auth",
                            "hook_name": "wp_ajax_sac_post_type_call",
                        }
                    },
                ),
                build_request_payload(
                    "190100_GET_wp-admin_admin-ajax_php_0002",
                    "2026-05-12 19:01:00",
                    "1778094060-run-2",
                    executed_callbacks={
                        "cb-auth": {
                            "callback_id": "cb-auth",
                            "hook_name": "wp_ajax_sac_post_type_call",
                        }
                    },
                ),
                build_request_payload(
                    "190200_GET_wp-admin_admin-ajax_php_0003",
                    "2026-05-12 19:02:00",
                    "1778094120-run-3",
                    executed_callbacks={
                        "cb-admin-menu": {
                            "callback_id": "cb-admin-menu",
                            "hook_name": "admin_menu",
                        }
                    },
                ),
                build_request_payload(
                    "190300_GET_wp-admin_admin-ajax_php_0004",
                    "2026-05-12 19:03:00",
                    "1778094180-run-4",
                    executed_callbacks={
                        "cb-unauth": {
                            "callback_id": "cb-unauth",
                            "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                        }
                    },
                ),
            ]

            for index, payload in enumerate(request_payloads, start=1):
                (requests_dir / f"req-{index}.json").write_text(json.dumps(payload), encoding="utf-8")

            fuzzer_output = run_dir / "fuzzer-output"
            fuzzer_output.mkdir()
            vulnerable = {
                "WebFuzzXSSVulnCheck": [
                    build_candidate("1778094060-run-2", "fuzz-a"),
                    build_candidate("1778094120-run-3", "fuzz-b", errline=650),
                    build_candidate("1778094120-run-3", "fuzz-c", errline=650),
                    build_candidate("1778094180-run-4", "fuzz-d", errline=777),
                ]
            }
            (fuzzer_output / "vulnerable-candidates.json").write_text(
                json.dumps(vulnerable),
                encoding="utf-8",
            )

            total_coverage = {
                "metadata": {
                    "total_registered_callbacks": 3,
                    "total_executed_callbacks": 3,
                },
                "data": {
                    "blindspot_callbacks": {
                        "cb-admin-menu": {
                            "callback_id": "cb-admin-menu",
                        }
                    }
                },
            }
            (run_dir / "total_coverage.json").write_text(json.dumps(total_coverage), encoding="utf-8")

            summary = analyze_run(
                run_dir,
                plugin="show-all-comments-in-one-page",
                mode_label="HOOK",
                mode_value=2,
                run_id=1,
                time_budget_seconds=1800,
            )

        self.assertEqual(summary["plugin"], "show-all-comments-in-one-page")
        self.assertEqual(summary["mode"], "HOOK")
        self.assertEqual(summary["run"], 1)
        self.assertEqual(summary["total_requests"], 4)
        self.assertEqual(summary["time_to_first_unique_vuln_seconds"], 60)
        self.assertEqual(summary["requests_to_first_unique_vuln"], 2)
        self.assertEqual(summary["time_to_3_unique_vulns_seconds"], 180)
        self.assertEqual(summary["requests_to_3_unique_vulns"], 4)
        self.assertEqual(summary["unique_vulns_found_after_30min"], 3)
        self.assertAlmostEqual(summary["requests_per_unique_vuln"], 4 / 3, places=4)
        self.assertEqual(summary["unique_executed_callbacks"], 3)
        self.assertEqual(summary["blindspots_reduced"], 2)

    def test_aggregate_results_uses_medians(self) -> None:
        results = [
            {
                "plugin": "show-all-comments-in-one-page",
                "mode": "PHUZZ",
                "run": 1,
                "time_to_first_unique_vuln_seconds": 420,
                "requests_to_first_unique_vuln": 930,
                "time_to_3_unique_vulns_seconds": None,
                "requests_to_3_unique_vulns": None,
                "unique_vulns_found_after_30min": 2,
                "requests_per_unique_vuln": 465.0,
                "unique_executed_callbacks": 14,
                "blindspots_reduced": 8,
            },
            {
                "plugin": "show-all-comments-in-one-page",
                "mode": "PHUZZ",
                "run": 2,
                "time_to_first_unique_vuln_seconds": 360,
                "requests_to_first_unique_vuln": 800,
                "time_to_3_unique_vulns_seconds": None,
                "requests_to_3_unique_vulns": None,
                "unique_vulns_found_after_30min": 1,
                "requests_per_unique_vuln": 800.0,
                "unique_executed_callbacks": 12,
                "blindspots_reduced": 7,
            },
            {
                "plugin": "show-all-comments-in-one-page",
                "mode": "HOOK",
                "run": 1,
                "time_to_first_unique_vuln_seconds": 180,
                "requests_to_first_unique_vuln": 410,
                "time_to_3_unique_vulns_seconds": 900,
                "requests_to_3_unique_vulns": 1200,
                "unique_vulns_found_after_30min": 4,
                "requests_per_unique_vuln": 300.0,
                "unique_executed_callbacks": 22,
                "blindspots_reduced": 15,
            },
            {
                "plugin": "show-all-comments-in-one-page",
                "mode": "HOOK",
                "run": 2,
                "time_to_first_unique_vuln_seconds": 240,
                "requests_to_first_unique_vuln": 500,
                "time_to_3_unique_vulns_seconds": 960,
                "requests_to_3_unique_vulns": 1300,
                "unique_vulns_found_after_30min": 3,
                "requests_per_unique_vuln": 320.0,
                "unique_executed_callbacks": 20,
                "blindspots_reduced": 14,
            },
        ]

        aggregated = aggregate_results(results)

        self.assertEqual(aggregated["plugin"], "show-all-comments-in-one-page")
        self.assertEqual(len(aggregated["modes"]), 2)

        phuzz = next(item for item in aggregated["modes"] if item["mode"] == "PHUZZ")
        hook = next(item for item in aggregated["modes"] if item["mode"] == "HOOK")

        self.assertEqual(phuzz["median_time_to_first_unique_vuln_seconds"], 390.0)
        self.assertEqual(phuzz["median_requests_to_first_unique_vuln"], 865.0)
        self.assertEqual(hook["median_time_to_first_unique_vuln_seconds"], 210.0)
        self.assertEqual(hook["median_requests_to_first_unique_vuln"], 455.0)
        self.assertEqual(hook["median_unique_vulns_found_after_30min"], 3.5)


if __name__ == "__main__":
    unittest.main()
