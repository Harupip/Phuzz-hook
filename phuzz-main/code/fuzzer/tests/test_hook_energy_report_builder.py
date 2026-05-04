from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.report_models import (
    CallbackRecord,
    ComparisonSummary,
    HookVisualizationReport,
    RunMetadata,
    RunSummary,
)
from hook_energy.report_loader import LoadedRunArtifacts
from hook_energy.report_builder import build_run_pair_comparison, build_single_run_report
from hook_energy.report_render import write_html_report, write_json_report, write_markdown_summary


class HookVisualizationModelTests(unittest.TestCase):
    def test_report_model_can_hold_single_run_and_comparison_sections(self) -> None:
        metadata = RunMetadata(label="hook-run", mode="hook-aware", target_plugin="demo-plugin")
        summary = RunSummary(
            requests_total=10,
            registered_callbacks_total=6,
            executed_callbacks_total=5,
            blindspots_total=1,
            coverage_ratio=0.8333,
            exceptions_count=3,
            vulnerability_counts={"WebFuzzXSSVulnCheck": 1},
            boosted_decisions_count=4,
            avg_hook_energy=0.25,
            max_hook_energy=1.0,
            avg_priority_delta=0.4,
            max_priority_delta=1.0,
            avg_energy_delta=0.3,
            max_energy_delta=1.0,
        )
        comparison = ComparisonSummary(
            baseline_label="baseline",
            hook_label="hook-run",
            metric_deltas={"coverage_ratio_delta": 0.10},
            callbacks_only_in_hook=["cb-rare"],
            callbacks_only_in_baseline=[],
            outcome_deltas={"exceptions_delta": 2},
            interpretation_flags=["hook improved rare callback exploration"],
        )

        report = HookVisualizationReport(
            metadata=metadata,
            summary=summary,
            decision_records=[],
            callback_records=[],
            request_records=[],
            comparison=comparison,
            warnings=[],
        )

        self.assertEqual(report.metadata.label, "hook-run")
        self.assertEqual(report.summary.blindspots_total, 1)
        self.assertEqual(report.comparison.metric_deltas["coverage_ratio_delta"], 0.10)

    def test_single_run_builder_computes_deltas_and_blindspots(self) -> None:
        loaded = LoadedRunArtifacts(
            metadata={"label": "hook-run", "mode": "hook-aware"},
            decisions=[
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
            ],
            exception_candidates=[
                {
                    "coverage_id": "cov-1",
                    "mutated_param_name": "post_type",
                    "mutated_param_type": "query_params",
                    "hook_request_id": "req-1",
                    "hook_energy": 0.5,
                    "hook_energy_avg": 0.5,
                }
            ],
            vulnerability_candidates={"WebFuzzXSSVulnCheck": []},
            requests={
                "req-1": {
                    "request_id": "req-1",
                    "endpoint": "ADMIN_AJAX:sac_post_type_call",
                    "request_method": "GET",
                    "hook_coverage": {
                        "registered_callbacks": {
                            "cb-1": {
                                "hook_name": "wp_ajax_sac_post_type_call",
                                "callback_repr": "sac_post_type_call_callback",
                                "priority": 10,
                            },
                            "cb-blind": {
                                "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                                "callback_repr": "sac_post_type_call_callback",
                                "priority": 10,
                            },
                        },
                        "executed_callbacks": {
                            "cb-1": {
                                "callback_id": "cb-1",
                                "hook_name": "wp_ajax_sac_post_type_call",
                                "callback_repr": "sac_post_type_call_callback",
                                "executed_count": 1,
                            }
                        },
                    },
                }
            },
            coverage_summary={
                "registered_total": 2,
                "executed_total": 1,
                "coverage_percent": "50.00%",
                "blindspot_callbacks": [{"callback_id": "cb-blind"}],
            },
            warnings=[],
        )

        report = build_single_run_report(loaded)

        self.assertEqual(report.summary.boosted_decisions_count, 1)
        self.assertAlmostEqual(report.summary.avg_priority_delta, 0.5)
        self.assertAlmostEqual(report.summary.avg_energy_delta, 1.0)
        self.assertEqual(report.summary.blindspots_total, 1)
        self.assertEqual(report.decision_records[0].mutated_param_name, "post_type")
        self.assertEqual(report.callback_records[0].status, "executed")

    def test_run_pair_builder_highlights_metric_deltas_and_interpretation(self) -> None:
        baseline = HookVisualizationReport(
            metadata=RunMetadata(label="baseline", mode="baseline"),
            summary=RunSummary(
                requests_total=10,
                registered_callbacks_total=6,
                executed_callbacks_total=4,
                blindspots_total=2,
                coverage_ratio=0.66,
                exceptions_count=1,
                vulnerability_counts={"WebFuzzXSSVulnCheck": 0},
                boosted_decisions_count=0,
                avg_hook_energy=0.0,
                max_hook_energy=0.0,
                avg_priority_delta=0.0,
                max_priority_delta=0.0,
                avg_energy_delta=0.0,
                max_energy_delta=0.0,
            ),
            decision_records=[],
            callback_records=[
                CallbackRecord("cb-common", "common_hook", "common_callback", 5, 1, 0.2, 0.16, "executed")
            ],
            request_records=[],
            warnings=[],
        )
        hook = HookVisualizationReport(
            metadata=RunMetadata(label="hook-run", mode="hook-aware"),
            summary=RunSummary(
                requests_total=11,
                registered_callbacks_total=6,
                executed_callbacks_total=5,
                blindspots_total=1,
                coverage_ratio=0.83,
                exceptions_count=3,
                vulnerability_counts={"WebFuzzXSSVulnCheck": 1},
                boosted_decisions_count=4,
                avg_hook_energy=0.2,
                max_hook_energy=1.0,
                avg_priority_delta=0.4,
                max_priority_delta=1.0,
                avg_energy_delta=0.3,
                max_energy_delta=1.0,
            ),
            decision_records=[],
            callback_records=[
                CallbackRecord("cb-common", "common_hook", "common_callback", 5, 1, 0.2, 0.16, "executed"),
                CallbackRecord("cb-rare", "rare_hook", "rare_callback", 1, 1, 1.0, 0.5, "executed"),
            ],
            request_records=[],
            warnings=[],
        )

        comparison = build_run_pair_comparison(baseline, hook)

        self.assertEqual(comparison.metric_deltas["executed_callbacks_delta"], 1)
        self.assertEqual(comparison.metric_deltas["blindspots_delta"], -1)
        self.assertIn("cb-rare", comparison.callbacks_only_in_hook)
        self.assertIn("hook improved rare callback exploration", comparison.interpretation_flags)

    def test_single_run_builder_warns_about_repeated_decisions_and_missing_request_artifacts(self) -> None:
        loaded = LoadedRunArtifacts(
            metadata={"label": "hook-run", "mode": "hook-aware"},
            decisions=[
                {
                    "coverage_id": "cov-1",
                    "http_target": "http://web/wp-admin/admin-ajax.php",
                    "http_method": "GET",
                    "base_score": 1,
                    "score": 1,
                    "base_priority": 1,
                    "priority": 2,
                    "base_energy": 1,
                    "final_energy": 2,
                    "hook_request_id": "req-missing",
                    "hook_energy": 1.0,
                    "hook_energy_avg": 1.0,
                },
                {
                    "coverage_id": "cov-1",
                    "http_target": "http://web/wp-admin/admin-ajax.php",
                    "http_method": "GET",
                    "base_score": 1,
                    "score": 1,
                    "base_priority": 1,
                    "priority": 2,
                    "base_energy": 1,
                    "final_energy": 2,
                    "hook_request_id": "req-missing",
                    "hook_energy": 1.0,
                    "hook_energy_avg": 1.0,
                },
            ],
            exception_candidates=[],
            vulnerability_candidates={},
            requests={},
            coverage_summary={},
            warnings=[],
        )

        report = build_single_run_report(loaded)

        self.assertTrue(any("Missing request artifacts" in warning for warning in report.warnings))
        self.assertTrue(any("repeated rows" in warning for warning in report.warnings))

    def test_renderers_write_json_markdown_and_html_files(self) -> None:
        report = HookVisualizationReport(
            metadata=RunMetadata(label="hook-run", mode="hook-aware"),
            summary=RunSummary(
                requests_total=1,
                registered_callbacks_total=2,
                executed_callbacks_total=1,
                blindspots_total=1,
                coverage_ratio=0.5,
                exceptions_count=1,
                vulnerability_counts={"WebFuzzXSSVulnCheck": 0},
                boosted_decisions_count=1,
                avg_hook_energy=0.5,
                max_hook_energy=0.5,
                avg_priority_delta=0.5,
                max_priority_delta=0.5,
                avg_energy_delta=1.0,
                max_energy_delta=1.0,
            ),
            decision_records=[],
            callback_records=[],
            request_records=[],
            warnings=["missing request artifact timing"],
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            json_path = Path(tmp_dir) / "report.json"
            md_path = Path(tmp_dir) / "report-summary.md"
            html_path = Path(tmp_dir) / "report.html"

            write_json_report(report, json_path)
            write_markdown_summary(report, md_path)
            write_html_report(report, html_path)

            self.assertIn("\"label\": \"hook-run\"", json_path.read_text(encoding="utf-8"))
            self.assertIn("boosted_decisions_count", md_path.read_text(encoding="utf-8"))
            self.assertIn("Concrete boosted candidate", html_path.read_text(encoding="utf-8"))
            self.assertIn("missing request artifact timing", html_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
