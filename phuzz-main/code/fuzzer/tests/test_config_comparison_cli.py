from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))


def cli_config(action: str = "demo") -> dict:
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "body_params": {
            "data": [{"name": "action", "value": action}],
            "fixed": ["action"],
            "fuzz": [],
        },
    }


def write_json(path: Path, value: object, *, bom: bool = False) -> None:
    text = json.dumps(value)
    path.write_text(("\ufeff" if bom else "") + text, encoding="utf-8")


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "config_comparison.cli", *args],
        cwd=FUZZER_DIR,
        capture_output=True,
        text=True,
        timeout=15,
        env=os.environ.copy(),
    )


class ConfigComparisonCliTests(unittest.TestCase):
    def test_direct_file_match_emits_json_and_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual = root / "generated.json"
            write_json(expected, cli_config())
            write_json(actual, cli_config())

            result = run_cli("--expected", str(expected), "--actual", str(actual), "--format", "json")

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"]["MATCH"], 1)
            self.assertEqual(report["counts"]["MISMATCH"], 0)
            self.assertEqual(report["input_errors"], [])

    def test_direct_wrong_method_is_mismatch_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual = root / "generated.json"
            write_json(expected, cli_config())
            wrong = cli_config()
            wrong["methods"] = ["GET"]
            write_json(actual, wrong)

            result = run_cli("--expected", str(expected), "--actual", str(actual))

            self.assertEqual(result.returncode, 1)
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"]["MISMATCH"], 1)

    def test_folder_lookup_ignores_filenames_and_reports_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected_dir = root / "refs"
            actual_dir = root / "actuals"
            expected_dir.mkdir()
            actual_dir.mkdir()
            write_json(expected_dir / "z-reference-name.json", cli_config())
            write_json(actual_dir / "a-generated-name.json", cli_config())

            result = run_cli("--expected", str(expected_dir), "--actual", str(actual_dir), "--format", "json")

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report["counts"]["MATCH"], 1)
            self.assertIn("actual_path", report["results"][0])
            self.assertIn("reference_paths", report["results"][0])

    def test_bom_and_duplicate_object_key_are_structured_input_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual = root / "bom.json"
            write_json(expected, cli_config())
            write_json(actual, cli_config(), bom=True)
            bom_result = run_cli("--expected", str(expected), "--actual", str(actual))
            self.assertEqual(bom_result.returncode, 0, bom_result.stderr)

            duplicate = root / "duplicate.json"
            duplicate.write_text('{"target":"http://web","target":"http://other","methods":["GET"]}', encoding="utf-8")
            duplicate_result = run_cli("--expected", str(expected), "--actual", str(duplicate))
            self.assertEqual(duplicate_result.returncode, 2)
            report = json.loads(duplicate_result.stdout)
            self.assertTrue(report["input_errors"])
            self.assertIn("duplicate", report["input_errors"][0]["message"])

    def test_empty_or_mixed_folder_is_input_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            write_json(expected, cli_config())
            empty = root / "empty"
            empty.mkdir()
            empty_result = run_cli("--expected", str(expected), "--actual", str(empty))
            self.assertEqual(empty_result.returncode, 2)
            self.assertIn("empty", json.loads(empty_result.stdout)["input_errors"][0]["message"])

            mixed = root / "mixed"
            mixed.mkdir()
            write_json(mixed / "generated_config_summary.json", {"generated": []})
            mixed_result = run_cli("--expected", str(expected), "--actual", str(mixed))
            self.assertEqual(mixed_result.returncode, 2)
            self.assertTrue(json.loads(mixed_result.stdout)["input_errors"])

    def test_output_cannot_overwrite_or_live_inside_input_tree(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual_dir = root / "actuals"
            actual_dir.mkdir()
            actual = actual_dir / "generated.json"
            write_json(expected, cli_config())
            write_json(actual, cli_config())

            same_result = run_cli("--expected", str(expected), "--actual", str(actual), "--output", str(actual))
            self.assertEqual(same_result.returncode, 2)
            self.assertEqual(json.loads(actual.read_text(encoding="utf-8")), cli_config())

            inside_result = run_cli(
                "--expected", str(expected), "--actual", str(actual_dir), "--output", str(actual_dir / "report.json")
            )
            self.assertEqual(inside_result.returncode, 2)
            self.assertFalse((actual_dir / "report.json").exists())

    def test_report_output_file_is_written_only_after_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual = root / "generated.json"
            report_path = root / "report.json"
            write_json(expected, cli_config())
            write_json(actual, cli_config())

            result = run_cli("--expected", str(expected), "--actual", str(actual), "--output", str(report_path))

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(json.loads(report_path.read_text(encoding="utf-8"))["counts"]["MATCH"], 1)

    def test_invalid_policy_is_rejected_without_traceback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            expected = root / "reference.json"
            actual = root / "generated.json"
            write_json(expected, cli_config())
            write_json(actual, cli_config())

            result = run_cli("--expected", str(expected), "--actual", str(actual), "--policy", "effective")

            self.assertEqual(result.returncode, 2)
            self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
