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
    classify_expected_auth_skips,
    format_recursive_summary,
    load_generated_configs,
    list_request_artifacts,
    list_zend_artifacts,
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


class FakeProcess:
    def __init__(self):
        self.returncode = None
        self.wait_calls = []

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        self.returncode = 0
        return self.returncode


def completed(returncode):
    return subprocess.CompletedProcess(["docker"], returncode, "", "")


def generated_config(slug="generated-hooks/one", hook_name="wp_ajax_nopriv_demo", callback_id="cb-one", entrypoint_type=None):
    row = {"config_slug": slug, "hook_name": hook_name, "callback_id": callback_id}
    if entrypoint_type:
        row["entrypoint_type"] = entrypoint_type
    return row


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
    def test_zend_callback_mode_stops_when_callback_and_zend_artifact_match(self):
        process = FakeProcess()
        runner = FakeRunner([])
        request_payload = {
            "response": {"status_code": 200},
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "blindspot_callbacks": {},
            },
        }
        request_artifacts = FakeArtifacts(
            [set(), {"request-one.json"}, {"request-one.json"}, {"request-one.json"}],
            {"request-one.json": request_payload},
        )
        zend_artifacts = FakeArtifacts(
            [set(), {"request-one.json"}],
            {},
        )

        report = run_generated_configs(
            [generated_config()],
            timeout_seconds=30,
            stop_on_callback=True,
            process_factory=lambda *args, **kwargs: process,
            list_artifacts=request_artifacts.list,
            load_artifact=request_artifacts.load,
            list_zend_artifacts=zend_artifacts.list,
            poll_interval_seconds=0,
            run_command=runner,
        )

        row = report["runs"][0]
        self.assertEqual(row["process_status"], "stopped_on_callback")
        self.assertEqual(row["validation_status"], "callback_reached")
        self.assertEqual(row["matched_artifact"], "request-one.json")
        self.assertEqual(runner.commands[0][:3], ["docker", "rm", "-f"])
        self.assertEqual(process.wait_calls, [30])

    def test_zend_callback_mode_does_not_stop_without_matching_zend_artifact(self):
        process = FakeProcess()
        process.returncode = 0
        runner = FakeRunner([])
        request_payload = {
            "response": {"status_code": 200},
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "blindspot_callbacks": {},
            },
        }
        request_artifacts = FakeArtifacts(
            [set(), {"request-one.json"}, {"request-one.json"}],
            {"request-one.json": request_payload},
        )
        zend_artifacts = FakeArtifacts([set(), set()], {})

        report = run_generated_configs(
            [generated_config()],
            timeout_seconds=30,
            stop_on_callback=True,
            process_factory=lambda *args, **kwargs: process,
            list_artifacts=request_artifacts.list,
            load_artifact=request_artifacts.load,
            list_zend_artifacts=zend_artifacts.list,
            poll_interval_seconds=0,
            run_command=runner,
        )

        self.assertEqual(report["runs"][0]["process_status"], "exited")
        self.assertEqual(process.wait_calls, [])

    def test_final_replay_uses_default_full_length_runner(self):
        runner = FakeRunner([completed(0)])
        request_payload = {
            "response": {"status_code": 200},
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "blindspot_callbacks": {},
            },
        }
        request_artifacts = FakeArtifacts(
            [set(), {"request-one.json"}],
            {"request-one.json": request_payload},
        )

        report = run_generated_configs(
            [generated_config()],
            timeout_seconds=30,
            process_factory=lambda *args, **kwargs: self.fail("final replay must not poll for callbacks"),
            list_artifacts=request_artifacts.list,
            load_artifact=request_artifacts.load,
            run_command=runner,
        )

        row = report["runs"][0]
        self.assertFalse(report["stop_on_callback"])
        self.assertEqual(row["process_status"], "exited")
        self.assertIsNone(row["stop_reason"])
        self.assertEqual(row["validation_status"], "callback_reached")
        self.assertFalse(any(command[:3] == ["docker", "rm", "-f"] for command in runner.commands))

    def test_stop_on_callback_stops_after_completed_200_without_expected_callback(self):
        process = FakeProcess()
        runner = FakeRunner([])
        request_payload = {
            "response": {"status_code": 200},
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {},
                "blindspot_callbacks": {},
            },
        }
        request_names = [set(), {"request-one.json"}]

        def list_requests():
            return request_names.pop(0) if request_names else {"request-one.json"}

        report = run_generated_configs(
            [generated_config()],
            timeout_seconds=0.001,
            stop_on_callback=True,
            process_factory=lambda *args, **kwargs: process,
            list_artifacts=list_requests,
            load_artifact=lambda name: request_payload,
            list_zend_artifacts=lambda: set(),
            poll_interval_seconds=0,
            run_command=runner,
        )

        row = report["runs"][0]
        self.assertEqual(row["process_status"], "stopped_on_request")
        self.assertEqual(row["stop_reason"], "request_completed")
        self.assertEqual(row["validation_status"], "registered_not_executed")
        self.assertEqual(row["requests_created"], 1)

    def test_expected_auth_skip_requires_reached_authenticated_counterpart(self):
        runs = [
            {
                "hook_name": "wp_ajax_nopriv_demo",
                "entrypoint_type": "ajax_unauthenticated",
                "process_status": "window_elapsed",
                "validation_status": "registered_not_executed",
                "callback_reached": False,
                "failure_category": "E. callback registered but not HTTP reachable",
            },
            {
                "hook_name": "wp_ajax_demo",
                "entrypoint_type": "ajax_authenticated",
                "process_status": "window_elapsed",
                "validation_status": "callback_reached",
                "callback_reached": True,
            },
        ]

        self.assertEqual(classify_expected_auth_skips(runs), 1)
        self.assertTrue(runs[0]["expected_auth_skip"])
        self.assertEqual(runs[0]["expected_auth_reason"], "authenticated_counterpart_reached")
        self.assertIsNone(runs[0]["failure_category"])

    def test_expected_auth_skip_does_not_mask_unpaired_or_failed_auth(self):
        runs = [
            {
                "hook_name": "wp_ajax_nopriv_unpaired",
                "entrypoint_type": "ajax_unauthenticated",
                "process_status": "window_elapsed",
                "validation_status": "registered_not_executed",
                "callback_reached": False,
            },
            {
                "hook_name": "wp_ajax_nopriv_failed",
                "entrypoint_type": "ajax_unauthenticated",
                "process_status": "window_elapsed",
                "validation_status": "registered_not_executed",
                "callback_reached": False,
            },
            {
                "hook_name": "wp_ajax_failed",
                "entrypoint_type": "ajax_authenticated",
                "process_status": "failed",
                "validation_status": "no_artifact",
                "callback_reached": False,
            },
        ]

        self.assertEqual(classify_expected_auth_skips(runs), 0)
        self.assertFalse(runs[0].get("expected_auth_skip", False))
        self.assertFalse(runs[1].get("expected_auth_skip", False))

    def test_expected_auth_skip_makes_generated_batch_success(self):
        runner = FakeRunner([completed(0), completed(0)])
        nopriv_artifact = {
            "hook_coverage": {
                "registered_callbacks": {"cb-nopriv": {"callback_id": "cb-nopriv"}},
                "executed_callbacks": {},
                "blindspot_callbacks": {},
            }
        }
        auth_artifact = {
            "hook_coverage": {
                "registered_callbacks": {"cb-auth": {"callback_id": "cb-auth"}},
                "executed_callbacks": {"cb-auth": {"callback_id": "cb-auth"}},
                "blindspot_callbacks": {},
            }
        }
        artifacts = FakeArtifacts(
            [set(), {"nopriv.json"}, {"nopriv.json"}, {"nopriv.json", "auth.json"}],
            {"nopriv.json": nopriv_artifact, "auth.json": auth_artifact},
        )

        report = run_generated_configs(
            [
                generated_config(
                    "generated-hooks/nopriv",
                    "wp_ajax_nopriv_demo",
                    "cb-nopriv",
                    "ajax_unauthenticated",
                ),
                generated_config(
                    "generated-hooks/auth",
                    "wp_ajax_demo",
                    "cb-auth",
                    "ajax_authenticated",
                ),
            ],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual(report["counts"]["callback_reached"], 1)
        self.assertEqual(report["counts"]["expected_auth_skip"], 1)
        self.assertEqual(report["runs"][0]["validation_status"], "registered_not_executed")
        self.assertTrue(report["runs"][0]["expected_auth_skip"])

    @patch("hook_energy.seed_generation.generated_config_runner.run_generated_configs")
    def test_main_returns_success_for_expected_auth_skip(self, run_configs):
        run_configs.return_value = {
            "runs": [{"callback_reached": False, "expected_auth_skip": True}],
            "counts": {
                "total": 1,
                "callback_reached": 0,
                "expected_auth_skip": 1,
                "process_failed": 0,
                "runner_error": 0,
                "vuln_found": 0,
            },
        }
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
                    ]
                )

        self.assertEqual(result, 0)

    @patch("hook_energy.seed_generation.generated_config_runner.subprocess.run")
    def test_list_request_artifacts_uses_web_shared_tmpfs(self, run_command):
        run_command.return_value = subprocess.CompletedProcess([], 0, "b.json\na.json\n", "")

        self.assertEqual(list_request_artifacts(), {"a.json", "b.json"})
        command = run_command.call_args.args[0]
        self.assertEqual(command[:6], ["docker", "compose", "exec", "-T", "web", "sh"])
        self.assertIn("/shared-tmpfs/hook-coverage/requests", command[-1])
        self.assertEqual(run_command.call_args.kwargs["timeout"], 30)

    @patch("hook_energy.seed_generation.generated_config_runner.subprocess.run")
    def test_list_zend_artifacts_uses_web_shared_tmpfs(self, run_command):
        run_command.return_value = subprocess.CompletedProcess([], 0, "b.json\na.json\n", "")

        self.assertEqual(list_zend_artifacts(), {"a.json", "b.json"})
        command = run_command.call_args.args[0]
        self.assertEqual(command[:6], ["docker", "compose", "exec", "-T", "web", "sh"])
        self.assertIn("/shared/opcode-events", command[-1])

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
                            {
                                "config_slug": "generated-hooks/two",
                                "hook_name": "hook-two",
                                "callback_id": "cb-two",
                                "entrypoint_type": "rest_route",
                                "resolved_method": "PATCH",
                                "candidate_methods": ["PATCH"],
                                "method_status": "resolved",
                                "method_confidence": "route_declared",
                                "route_declared_methods": ["PATCH"],
                                "seed_variant_id": "rest-patch",
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )

            self.assertEqual(
                load_generated_configs(summary_path),
                [
                    {"config_slug": "generated-hooks/one", "hook_name": "hook-one", "callback_id": "cb-one"},
                    {
                        "config_slug": "generated-hooks/two",
                        "hook_name": "hook-two",
                        "callback_id": "cb-two",
                        "entrypoint_type": "rest_route",
                        "resolved_method": "PATCH",
                        "candidate_methods": ["PATCH"],
                        "method_status": "resolved",
                        "method_confidence": "route_declared",
                        "route_declared_methods": ["PATCH"],
                        "seed_variant_id": "rest-patch",
                    },
                ],
            )

    def test_config_path_runs_relative_to_fuzzer_configs_dir(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            config_path = Path(tmp_dir) / "fuzzer" / "output" / "recursive-child-hooks" / "configs" / "child.json"
            config_path.parent.mkdir(parents=True)
            runner = FakeRunner([completed(0)])
            artifacts = FakeArtifacts([set(), set()], {})

            run_generated_configs(
                [{**generated_config(), "config_path": str(config_path)}],
                timeout_seconds=5,
                run_command=runner,
                list_artifacts=artifacts.list,
                load_artifact=artifacts.load,
            )

        self.assertIn("FUZZER_CONFIG=../output/recursive-child-hooks/configs/child", runner.commands[0])

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
        self.assertEqual(report['runs'][0]['failure_category'], 'C. request mapping wrong')
        self.assertEqual(report["counts"]["process_failed"], 1)
        self.assertEqual(report["runs"][0]["exit_code"], 3)
        self.assertIn("FUZZER_CONFIG=generated-hooks/two", runner.commands[1])
        self.assertNotIn("capture_output", runner.calls[0][1])
        self.assertNotIn("text", runner.calls[0][1])

    def test_legacy_run_id_is_passed_to_each_generated_request(self):
        runner = FakeRunner([completed(0), completed(0)])
        artifacts = FakeArtifacts([set(), set(), set(), set()], {})

        report = run_generated_configs(
            [generated_config(), generated_config("generated-hooks/two", "hook-two", "cb-two")],
            timeout_seconds=5,
            legacy_run_id="legacy-123",
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual(report["legacy_run_id"], "legacy-123")
        for command in runner.commands:
            self.assertIn("-e", command)
            self.assertIn("HOOKPHUZZ_LEGACY_RUN_ID=legacy-123", command)

    def test_stop_on_vuln_exit_is_recorded_as_vuln_found_not_failed(self):
        runner = FakeRunner([completed(57)])
        artifact = {
            "hook_coverage": {
                "registered_callbacks": {"cb-one": {"callback_id": "cb-one"}},
                "executed_callbacks": {"cb-one": {"callback_id": "cb-one", "fired_hook": "wp_ajax_nopriv_demo"}},
                "blindspot_callbacks": {},
            }
        }
        artifacts = FakeArtifacts([set(), {"request-one.json"}], {"request-one.json": artifact})

        report = run_generated_configs(
            [generated_config()],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual(report["runs"][0]["process_status"], "vuln_found")
        self.assertEqual(report["runs"][0]["exit_code"], 57)
        self.assertEqual(report["runs"][0]["validation_status"], "callback_reached")
        self.assertEqual(report["counts"]["vuln_found"], 1)
        self.assertEqual(report["counts"]["process_failed"], 0)

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
        self.assertEqual(report["runs"][0]["matched_artifact"], "request-one.json")
        self.assertEqual(artifacts.loaded, ["request-one.json"])
        container_name = report["runs"][0]["container_name"]
        cleanup_command = ["docker", "rm", "-f", container_name]
        self.assertIn(cleanup_command, runner.commands)
        cleanup_call = runner.calls[runner.commands.index(cleanup_command)]
        self.assertEqual(cleanup_call[1]["timeout"], 30)
        self.assertEqual(report["counts"]["callback_reached"], 1)
        self.assertEqual(report["counts"]["no_artifact"], 1)

    def test_rest_config_preserves_entrypoint_type_and_validates_callback_id(self):
        runner = FakeRunner([completed(0)])
        artifact = {
            "hook_coverage": {
                "registered_callbacks": {"cb-rest": {"callback_id": "cb-rest"}},
                "executed_callbacks": {
                    "cb-rest": {
                        "callback_id": "cb-rest",
                        "hook_name": "rest_route:demo/v1/items",
                        "entrypoint_type": "rest_route",
                    }
                },
                "blindspot_callbacks": {},
            }
        }
        artifacts = FakeArtifacts([set(), {"request-rest.json"}], {"request-rest.json": artifact})

        report = run_generated_configs(
            [generated_config("generated-hooks/rest", "rest_route:demo/v1/items", "cb-rest", "rest_route")],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual(report["runs"][0]["entrypoint_type"], "rest_route")
        self.assertEqual(report["runs"][0]["validation_status"], "callback_reached")

    def test_runner_error_is_recorded_and_later_config_still_runs(self):
        runner = FakeRunner([RuntimeError("boom"), completed(0)])
        artifacts = FakeArtifacts([set(), set(), set()], {})

        report = run_generated_configs(
            [generated_config(), generated_config("generated-hooks/two", "hook-two", "cb-two")],
            timeout_seconds=5,
            run_command=runner,
            list_artifacts=artifacts.list,
            load_artifact=artifacts.load,
        )

        self.assertEqual([row["process_status"] for row in report["runs"]], ["runner_error", "exited"])
        self.assertEqual(report["runs"][0]["validation_reason"], "boom")
        self.assertEqual(report["counts"]["runner_error"], 1)

    def test_recursive_summary_statuses_and_matched_artifact(self):
        reached = {
            "config_slug": "generated-hooks/one",
            "config_path": "fuzzer/output/recursive-child-hooks/configs/one.json",
            "hook_name": "hook-one",
            "callback_id": "cb-one",
            "process_status": "window_elapsed",
            "validation_status": "callback_reached",
            "validation_reason": "hit",
            "callback_reached": True,
            "request_artifacts": ["hit.json"],
            "matched_artifact": "hit.json",
            "duration_seconds": 1.2,
        }
        timed_out = {
            **reached,
            "config_slug": "generated-hooks/two",
            "hook_name": "hook-two",
            "callback_id": "cb-two",
            "process_status": "window_elapsed",
            "validation_status": "no_artifact",
            "validation_reason": "none",
            "callback_reached": False,
            "request_artifacts": [],
            "matched_artifact": None,
            "duration_seconds": 5.0,
        }
        failed = {**timed_out, "config_slug": "generated-hooks/three", "process_status": "failed"}
        errored = {**timed_out, "config_slug": "generated-hooks/four", "process_status": "runner_error"}

        summary = format_recursive_summary({"runs": [reached, timed_out, failed, errored]})

        self.assertEqual(summary["total_configs"], 4)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["timed_out"], 1)
        self.assertEqual(summary["failed"], 2)
        self.assertEqual(
            [row["status"] for row in summary["results"]],
            ["callback_reached", "timed_out", "failed", "runner_error"],
        )
        self.assertEqual(summary["results"][0]["matched_artifact"], "hit.json")
        self.assertEqual(summary["results"][0]["config"], "fuzzer/output/recursive-child-hooks/configs/one.json")

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
            validation_result = root / 'validation_result.json'
            self.assertTrue(validation_result.exists())
            validation = json.loads(validation_result.read_text(encoding='utf-8'))
            self.assertEqual(validation['summary']['total'], 0)
            self.assertEqual(validation['validations'], [])

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
    def test_wordpress_bootstrap_installs_country_state_city_dependency_before_target(self):
        script_path = FUZZER_DIR.parent / "web" / "applications" / "wordpress" / "init.sh"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("${WP_TARGET_PLUGIN} == 'country-state-city-auto-dropdown'", script)
        self.assertIn("./wp-cli.phar plugin install ./_plugins/contact-form-7.zip --activate", script)
        self.assertLess(
            script.index("./wp-cli.phar plugin install ./_plugins/contact-form-7.zip --activate"),
            script.index("./wp-cli.phar plugin install ./_plugins/${WP_TARGET_PLUGIN}.zip --activate"),
        )

    def test_wordpress_runner_exposes_and_wires_opt_in_batch_mode(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[switch]$RunGeneratedConfigs", script)
        self.assertIn("[switch]$UseZendDiscovery", script)
        self.assertIn("-UseZendDiscovery requires -RunGeneratedConfigs.", script)
        self.assertIn("HOOKPHUZZ_LEGACY_RUN_ID: $LegacyRunId", script)
        self.assertIn("[string]$PluginSlug = \"show-all-comments-in-one-page\"", script)
        self.assertIn('$safePluginSlug = ($PluginSlug -replace "[^A-Za-z0-9._-]", "-").Trim("-")', script)
        self.assertIn('$legacyRunId = $safePluginSlug + "-" + (Get-Date -Format "yyyyMMddTHHmmssZ")', script)
        self.assertNotIn('$legacyRunId = "legacy-" +', script)
        self.assertIn("[ValidateRange(1, 30)]", script)
        self.assertIn("[int]$GeneratedConfigTimeoutSeconds = 30", script)
        self.assertIn("[int]$ZendMaxIterations = 5", script)
        self.assertIn("$GeneratedConfigTimeoutSeconds", script)
        self.assertIn("fuzzer\\configs\\{0}.json", script)
        self.assertIn("fuzzer\\configs\\generated-config\\$PluginSlug", script)
        self.assertIn("Convert-LiveSeedSuggestionsToConfigs -ScriptRoot $scriptRoot -PluginSlug $PluginSlug", script)
        self.assertIn("-RuntimeParametersOnly:$UseZendDiscovery", script)
        self.assertIn('"--runtime-parameters-only"', script)
        self.assertIn("wordpress/$PluginSlug", script)
        self.assertIn("wordpress/bootstrap-generated", script)
        self.assertIn("web\\applications\\wordpress\\_plugins\\$PluginSlug.zip", script)
        self.assertIn("WP_TARGET_PLUGIN: $PluginSlug", script)
        self.assertIn("FUZZER_CONFIG: $BootstrapConfigSlug", script)
        self.assertIn("if ($RunGeneratedConfigs)", script)
        self.assertIn("Invoke-Compose -ComposeArgs $composeArgs -AdditionalArgs @(\"stop\", \"--timeout\", \"30\", $fuzzerService)", script)
        self.assertIn("generated_config_runner.py", script)
        self.assertIn("--generated-config-summary", script)
        self.assertIn("--output-file", script)
        self.assertIn("--timeout-seconds", script)
        self.assertIn("--legacy-run-id", script)
        self.assertIn("--stop-on-callback", script)

    def test_wordpress_runner_wires_success_only_artifact_retention(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")
        wrapper = (FUZZER_DIR.parent / "phuzz.ps1").read_text(encoding="utf-8-sig")

        self.assertIn("[switch]$KeepDebugArtifacts", script)
        self.assertIn("artifact_retention.py", script)
        self.assertIn("seed_generation\\zend_runtime\\bridge_cli.py", script)
        self.assertIn("seed_generation\\zend_runtime\\artifact_retention.py", script)
        self.assertIn("--terminal-status", script)
        self.assertIn("--final-config-summary", script)
        self.assertIn("--final-run-summary", script)
        self.assertIn("--zend-discovery-run-dir", script)
        self.assertIn("--keep-debug-artifacts", script)
        self.assertIn("Invoke-ZendArtifactRetention", script)
        self.assertLess(
            script.index("Invoke-ZendArtifactRetention"),
            script.index('Write-Host "Generated config run summary:'),
        )
        self.assertIn("[switch]$KeepDebugArtifacts", wrapper)
        self.assertIn('$runnerParams["KeepDebugArtifacts"] = $true', wrapper)

    def test_wordpress_runner_has_zend_owned_two_pass_bridge(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("Invoke-ZendDiscoveryBridge", script)
        self.assertIn("pass1-generated_config_run_summary.json", script)
        self.assertIn("zend_enriched_seeds.json", script)
        self.assertIn("zend_merged_suggested_seeds.json", script)
        self.assertIn("--operation\", \"combine-final\"", script)
        self.assertIn("Move-Item -LiteralPath $combinedTemp -Destination $finalMergedSuggestedSeeds -Force", script)
        self.assertIn("pass2-generated_config_run_summary.json", script)
        self.assertIn("mkdir -p /shared/opcode-events && chown www-data:www-data /shared/opcode-events", script)
        self.assertNotIn("zend-runner-summary", script)

    def test_zend_discovery_bootstraps_rest_routes_before_seed_export(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("Invoke-ZendRestRouteBootstrap", script)
        self.assertIn("http://localhost:8080/?rest_route=/", script)
        self.assertLess(
            script.index("Invoke-ZendRestRouteBootstrap"),
            script.index("Export-LiveSeedSuggestions"),
        )

    def test_zend_discovery_replay_uses_rest_route_fallback_configs(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("[switch]$RestRouteFallback", script)
        self.assertIn("--rest-route-fallback", script)
        self.assertIn("-ReplayOnly `\n                -RestRouteFallback", script)
        self.assertIn("-SummaryPath $finalConfigSummary `\n            -RestRouteFallback", script)

    def test_zend_convergence_uses_short_filesystem_target_dirs_without_shortening_identity(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("function Get-ZendTargetDirectoryName", script)
        self.assertIn('$CandidateKey.Substring(0, 16)', script)
        self.assertIn("$targetDirectoryName = Get-ZendTargetDirectoryName -CandidateKey $targetCandidateKey", script)
        self.assertIn("$targetDir = Join-Path $targetsDir $targetDirectoryName", script)
        self.assertIn('$targetIterationsDir = Join-Path $targetDir "i"', script)
        self.assertIn('$replayConfigDir = Join-Path $iterationDir "cfg"', script)
        self.assertIn('$replayConfigSummary = Join-Path $iterationDir "cfg.json"', script)
        self.assertIn('$finalSeedReports += (Join-Path $targetFinalDir "seeds.json")', script)
        self.assertNotIn('Join-Path $targetFinalDir "merged_suggested_seeds.json"', script)
        self.assertIn('$currentRunSummary = Join-Path $iterationDir "run.json"', script)
        self.assertIn("target_directory = $targetDirectoryName", script)
        self.assertIn("--candidate-key $targetCandidateKey", script)
        self.assertIn("candidate_key = $targetCandidateKey", script)
        self.assertIn('$tempDir = "$TargetDir.t"', script)
        self.assertIn('$oldDir = "$TargetDir.o"', script)
        self.assertIn('("$SnapshotName-t")', script)
        self.assertNotIn('$TargetDir.tmp.$([guid]', script)
        self.assertNotIn('$SnapshotName.tmp.$([guid]', script)

    def test_wordpress_runner_converges_zend_candidates_independently_and_preserves_stage1_fallback(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("function Invoke-ZendConvergence", script)
        self.assertIn("foreach ($candidate in @($targets))", script)
        self.assertIn("--operation list-targets", script)
        self.assertIn("--pass1-run-summary $InitialRunSummary", script)
        self.assertIn("--candidate-key $targetCandidateKey", script)
        self.assertIn("$targetCurrentDir", script)
        self.assertIn("$targetFinalDir", script)
        self.assertNotIn("$zendCandidateCount -eq 1", script)
        self.assertIn("Invoke-ZendConvergence", script)
        self.assertIn("Invoke-ZendDiscoveryBridge", script)
        self.assertIn("Invoke-ZendPass2Verification", script)
        self.assertIn("candidate_key", script)
        self.assertIn("REPLAY_FAILED", script)
        self.assertIn("REPEATED_CONFIG", script)
        self.assertIn("PASS_PARTIAL_AUTH_EXPECTED", script)

    def test_zend_artifact_copy_uses_only_callback_matched_request(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")
        zend_copy = script[
            script.index("function Copy-ZendOpcodeArtifacts"):
            script.index("function Initialize-ZendCallbackRegistry")
        ]

        self.assertIn("if ($row.matched_artifact)", zend_copy)
        self.assertNotIn("request_artifacts", zend_copy)

    def test_wordpress_runner_uses_shared_bootstrap_config_for_generated_mode(self):
        runner_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        runner = runner_path.read_text(encoding="utf-8-sig")
        config_path = FUZZER_DIR / "configs" / "wordpress" / "bootstrap-generated.json"
        self.assertTrue(config_path.exists())
        config = json.loads(config_path.read_text(encoding="utf-8-sig"))

        self.assertIn('"wordpress/bootstrap-generated"', runner)
        self.assertIn("$BootstrapConfigSlug", runner)
        self.assertIn("fuzzer\\configs\\{0}.json", runner)
        self.assertIn('$BootstrapConfigSlug.Replace("/", [System.IO.Path]::DirectorySeparatorChar)', runner)
        self.assertEqual(config["target"], "http://web/")
        self.assertEqual(config["methods"], ["GET"])
        self.assertEqual(config["query_params"]["fuzz"], ["hookphuzz_probe"])

    def test_wordpress_runner_maps_copied_plugin_source_into_seed_export(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("docker cp", script)
        self.assertIn("--container-source-root", script)
        self.assertIn("/var/www/html/wp-content/plugins/$PluginSlug", script)
        self.assertIn("--host-source-root", script)
        self.assertIn("--source-root", script)
        self.assertIn("--unresolved-source-reason", script)
        self.assertIn("source_copy_failed", script)
        self.assertIn("no_php_files", script)

    def test_wordpress_runner_source_temp_cleanup_is_best_effort(self):
        script_path = FUZZER_DIR.parent / "scripts" / "wordpress" / "run-wordpress-phuzz.ps1"
        script = script_path.read_text(encoding="utf-8-sig")

        self.assertIn("Plugin source temp cleanup failed", script)
        self.assertIn("Remove-Item -LiteralPath $pluginSourceTempRoot -Recurse -Force -ErrorAction Stop", script)



if __name__ == "__main__":
    unittest.main()
