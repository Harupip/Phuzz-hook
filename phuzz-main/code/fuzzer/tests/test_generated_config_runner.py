import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.generated_config_runner import (
    load_config_slugs,
    main,
    run_generated_configs,
)


class FakeRunner:
    def __init__(self, results):
        self.results = list(results)
        self.commands = []
        self.calls = []

    def __call__(self, command, **kwargs):
        self.commands.append(list(command))
        self.calls.append((list(command), kwargs))
        if command[:3] == ["docker", "rm", "-f"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        result = self.results.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def completed(returncode):
    return subprocess.CompletedProcess(["docker"], returncode, "", "")


class GeneratedConfigRunnerTests(unittest.TestCase):
    def test_load_config_slugs_preserves_generated_order(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary_path = Path(tmp_dir) / "generated_config_summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "generated": [
                            {"config_slug": "generated-hooks/one"},
                            {"config_slug": "generated-hooks/two"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                load_config_slugs(summary_path),
                ["generated-hooks/one", "generated-hooks/two"],
            )

    def test_load_config_slugs_rejects_malformed_generated_item(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary_path = Path(tmp_dir) / "generated_config_summary.json"
            summary_path.write_text(json.dumps({"generated": [{}]}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, r"generated\[0\].config_slug"):
                load_config_slugs(summary_path)

    def test_nonzero_exit_is_recorded_and_later_config_still_runs(self):
        runner = FakeRunner([completed(3), completed(0)])

        report = run_generated_configs(
            ["generated-hooks/one", "generated-hooks/two"],
            timeout_seconds=5,
            run_command=runner,
        )

        self.assertEqual([row["status"] for row in report["runs"]], ["failed", "passed"])
        self.assertEqual(report["counts"], {"total": 2, "passed": 1, "failed": 1, "timed_out": 0})
        self.assertEqual(report["runs"][0]["exit_code"], 3)
        self.assertIn("FUZZER_CONFIG=generated-hooks/two", runner.commands[1])
        self.assertNotIn("capture_output", runner.calls[0][1])
        self.assertNotIn("text", runner.calls[0][1])

    def test_timeout_cleans_named_container_and_continues(self):
        runner = FakeRunner([subprocess.TimeoutExpired(["docker"], 5), completed(0)])

        report = run_generated_configs(
            ["generated-hooks/one", "generated-hooks/two"],
            timeout_seconds=5,
            run_command=runner,
        )

        self.assertEqual([row["status"] for row in report["runs"]], ["timed_out", "passed"])
        container_name = report["runs"][0]["container_name"]
        cleanup_command = ["docker", "rm", "-f", container_name]
        self.assertIn(cleanup_command, runner.commands)
        cleanup_call = runner.calls[runner.commands.index(cleanup_command)]
        self.assertEqual(cleanup_call[1]["timeout"], 30)
        self.assertEqual(report["counts"], {"total": 2, "passed": 1, "failed": 0, "timed_out": 1})

    def test_main_writes_empty_success_summary(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            source = root / "generated_config_summary.json"
            output = root / "generated_config_run_summary.json"
            source.write_text(json.dumps({"generated": []}), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                result = main(
                    [
                        "--generated-config-summary",
                        str(source),
                        "--output-file",
                        str(output),
                        "--timeout-seconds",
                        "5",
                    ]
                )

            self.assertEqual(result, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["generated_config_summary"], str(source))
            self.assertEqual(report["counts"]["total"], 0)

    def test_main_returns_two_for_malformed_summary(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "generated_config_summary.json"
            source.write_text(json.dumps({"generated": [{}]}), encoding="utf-8")

            with contextlib.redirect_stderr(io.StringIO()):
                result = main(
                    [
                        "--generated-config-summary",
                        str(source),
                        "--output-file",
                        str(Path(tmp_dir) / "run-summary.json"),
                    ]
                )

            self.assertEqual(result, 2)


class GeneratedConfigPowerShellContractTests(unittest.TestCase):
    def test_wordpress_runner_exposes_and_wires_opt_in_batch_mode(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[switch]$RunGeneratedConfigs", script)
        self.assertIn("$GeneratedConfigTimeoutSeconds", script)
        self.assertIn("if ($RunGeneratedConfigs)", script)
        self.assertIn("docker compose stop --timeout 30 $fuzzerService", script)
        self.assertIn("generated_config_runner.py", script)
        self.assertIn("--generated-config-summary", script)
        self.assertIn("--output-file", script)
        self.assertIn("--timeout-seconds", script)


if __name__ == "__main__":
    unittest.main()
