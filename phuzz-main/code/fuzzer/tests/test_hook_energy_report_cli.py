from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.cli import main


class HookVisualizationCliTests(unittest.TestCase):
    def test_report_subcommand_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            requests_dir = base / "requests"
            requests_dir.mkdir()
            (base / "hook-energy-decisions.jsonl").write_text("", encoding="utf-8")
            (base / "exceptions-and-errors.json").write_text("[]", encoding="utf-8")
            (base / "vulnerable-candidates.json").write_text("{}", encoding="utf-8")
            (base / "total_coverage.json").write_text(
                json.dumps({"registered_total": 0, "executed_total": 0, "coverage_percent": "0%"}),
                encoding="utf-8",
            )

            output_dir = base / "report-output"
            argv = [
                "hook_energy_cli",
                "report",
                "--run-label",
                "hook-run",
                "--mode",
                "hook-aware",
                "--decisions",
                str(base / "hook-energy-decisions.jsonl"),
                "--exceptions",
                str(base / "exceptions-and-errors.json"),
                "--vulnerabilities",
                str(base / "vulnerable-candidates.json"),
                "--requests-dir",
                str(requests_dir),
                "--coverage-summary",
                str(base / "total_coverage.json"),
                "--output-dir",
                str(output_dir),
            ]

            with mock.patch.object(sys, "argv", argv):
                rc = main()

            self.assertEqual(rc, 0)
            self.assertTrue((output_dir / "report.json").exists())
            self.assertTrue((output_dir / "report-summary.md").exists())
            self.assertTrue((output_dir / "report.html").exists())


if __name__ == "__main__":
    unittest.main()
