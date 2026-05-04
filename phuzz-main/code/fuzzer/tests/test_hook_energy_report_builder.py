from __future__ import annotations

import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.report_models import (
    ComparisonSummary,
    HookVisualizationReport,
    RunMetadata,
    RunSummary,
)


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


if __name__ == "__main__":
    unittest.main()
