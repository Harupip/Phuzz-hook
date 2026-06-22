import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.generated_config_runner import (
    load_generated_configs,
    list_request_artifacts,
    load_request_artifact,
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


def generated_config(slug="generated-hooks/one", hook_name="wp_ajax_nopriv_demo", callback_id="cb-one"):
    return {"config_slug": slug, "hook_name": hook_name, "callback_id": callback_id}


class FakeArtifacts:
    def __init__(self, snapshots, payloads):
        self.snapshots = list(snapshots)
        self.payloads = payloads
        self.loaded = []

    def list(self):
        return set(self.snapshots.pop(0))

    def load(self, name):
        self.loaded.append(name)
        return self.payloads[name]


class GeneratedConfigRunnerTests(unittest.TestCase):
    @patch("hook_energy.seed_generation.generated_config_runner.subprocess.run")
    def test_list_request_artifacts_uses_web_shared_tmpfs(self, run_command):
        run_command.return_value = subprocess.CompletedProcess([], 0, "b.json\na.json\n", "")

        self.assertEqual(list_request_artifacts(), {"a.json", "b.json"})
        command = run_command.call_args.args[0]
        self.assertEqual(command[:6], ["docker", "compose", "exec", "-T", "web", "sh"])
        self.assertIn("/shared-tmpfs/hook-coverage/requests", command[-1])
        self.assertEqual(run_command.call_args.kwargs["timeout"], 30)

    @patch("hook_energy.seed_generation.generated_config_runner.subprocess.run")
    def test_load_request_artifact_reads_json_from_web(self, run_command):
        run_command.return_value = subprocess.CompletedProcess([], 0, '{"request_id":"one"}', "")

        self.assertEqual(load_request_artifact("one.json"), {"request_id": "one"})
        self.assertEqual(
            run_command.call_args.args[0],
            ["docker", "compose", "exec", "-T", "web", "cat", "/shared-tmpfs/hook-coverage/requests/one.json"],
        )

    def test_load_generated_configs_preserves_entries_and_order(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary_path = Path(tmp_dir) / "generated_config_summary.json"
            summary_path.write_text(
                json.dumps(
                    {
                        "generated": [
                            {"config_slug": "generated-hooks/one", "hook_name": "hook-one", "callback_id": "cb-one"},
                            {"config_slug": "generated-hooks/two", "hook_name": "hook-two", "callback_id": "cb-two"},
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                load_generated_configs(summary_path),
                [
                    {"config_slug": "generated-hooks/one", "hook_name": "hook-one", "callback_id": "cb-one"},
                    {"config_slug": "generated-hooks/two", "hook_name": "hook-two", "callback_id": "cb-two"},
                ],
            )

    def test_load_config_slugs_rejects_malformed_generated_item(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            summary_path = Path(tmp_dir) / "generated_config_summary.json"
            summary_path.write_text(json.dumps({"generated": [{"config_slug": "one"}]}), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, r"generated\[0\].hook_name"):
                load_generated_configs(summary_path)

    def test_nonzero_exit_is_recorded_and_later_config_still_runs(self):
        runner = FakeRunner([completed(3), completed(0)])
        artifacts = FakeArtifacts([set(), set(), set(), set()], {})

        report = run_generated_configs(
            [generated_config(), generated_config("generated-hooks/two", "hook-two", "cb-two")],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual([row["process_status"] for row in report["runs"]], ["failed", "exited"])
        self.assertEqual([row["validation_status"] for row in report["runs"]], ["no_artifact", "no_artifact"])
        self.assertEqual(report["counts"]["process_failed"], 1)
        self.assertEqual(report["runs"][0]["exit_code"], 3)
        self.assertIn("FUZZER_CONFIG=generated-hooks/two", runner.commands[1])
        self.assertNotIn("capture_output", runner.calls[0][1])
        self.assertNotIn("text", runner.calls[0][1])

    def test_timeout_cleans_named_container_and_continues(self):
        runner = FakeRunner([subprocess.TimeoutExpired(["docker"], 5), completed(0)])
        artifact = {
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {"cb-one": {"callback_id": "cb-one", "fired_hook": "wp_ajax_nopriv_demo"}},
                "blindspot_callbacks": {},
            }
        }
        artifacts = FakeArtifacts([set(), {"request-one.json"}, {"request-one.json"}, {"request-one.json"}], {"request-one.json": artifact})

        report = run_generated_configs(
            [generated_config(), generated_config("generated-hooks/two", "hook-two", "cb-two")],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual(report["runs"][0]["process_status"], "window_elapsed")
        self.assertEqual(report["runs"][0]["validation_status"], "callback_reached")
        self.assertEqual(report["runs"][0]["requests_created"], 1)
        self.assertEqual(report["runs"][1]["validation_status"], "no_artifact")
        self.assertEqual(artifacts.loaded, ["request-one.json"])
        container_name = report["runs"][0]["container_name"]
        cleanup_command = ["docker", "rm", "-f", container_name]
        self.assertIn(cleanup_command, runner.commands)
        cleanup_call = runner.calls[runner.commands.index(cleanup_command)]
        self.assertEqual(cleanup_call[1]["timeout"], 30)
        self.assertEqual(report["counts"]["callback_reached"], 1)
        self.assertEqual(report["counts"]["no_artifact"], 1)

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
