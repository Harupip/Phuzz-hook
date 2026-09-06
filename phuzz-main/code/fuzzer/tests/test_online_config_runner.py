from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_config_runner import (
    build_child_config,
    build_replay_config,
    classify_cmplog_events,
    classify_runtime_parameter_events,
    OnlineCoordinator,
    OnlineConfigError,
    validate_v0_config,
)


def online_config() -> dict:
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "config_type": "fuzzing_ready",
        "body_params": {
            "data": [{"name": "action", "value": "hookphuzz_stage1_direct"}, {"name": "name", "value": "Alice"}],
            "fixed": ["action"],
            "fuzz": ["name"],
        },
        "metadata": {
            "hook_name": "wp_ajax_nopriv_hookphuzz_stage1_direct",
            "callback_id": "fixture-callback",
            "callback_repr": "HookPhuzzFixture::stage1",
            "resolved_method": "POST",
            "entrypoint_type": "ajax_unauthenticated",
        },
    }


def callback_artifact(*, source: str = "POST", name: str = "age", value: str = "21") -> dict:
    return {
        "request_id": "request-1",
        "request_method": "POST",
        "request_params": {"body_params": {name: value}},
        "callback_summaries": [{
            "callback": "HookPhuzzFixture::stage1",
            "unique_parameters": [{
                "name": name,
                "source": source,
                "path": [name],
                "observed_value": value,
                "helper_depth": 0,
                "observed_count": 1,
            }],
        }],
    }


class OnlineConfigRunnerContractTests(unittest.TestCase):
    def test_v0_requires_target_method_callback_and_fuzzable_config(self) -> None:
        config = online_config()
        self.assertEqual(validate_v0_config(config), (True, ""))

        for field in ("target", "methods"):
            candidate = copy.deepcopy(config)
            candidate.pop(field)
            self.assertFalse(validate_v0_config(candidate)[0], field)

        candidate = copy.deepcopy(config)
        candidate["metadata"].pop("callback_repr")
        candidate["metadata"].pop("callback_id")
        self.assertEqual(validate_v0_config(candidate), (False, "MISSING_CALLBACK"))

        candidate = copy.deepcopy(config)
        candidate["config_type"] = "replay_only"
        candidate["body_params"]["fuzz"] = []
        self.assertEqual(validate_v0_config(candidate), (False, "NOT_FUZZING_READY"))
        self.assertEqual(validate_v0_config(candidate, require_fuzzing_ready=False), (True, ""))

    def test_direct_ajax_provenance_supports_get_post_request_and_cookie(self) -> None:
        expected = {
            "GET": "query_params",
            "POST": "body_params",
            "COOKIE": "cookies",
        }
        for source, placement in expected.items():
            with self.subTest(source=source):
                artifact = callback_artifact(source=source)
                if source == "GET":
                    artifact["request_params"] = {"query_params": {"age": "21"}}
                elif source == "COOKIE":
                    artifact["request_params"] = {"cookies": {"age": "21"}}
                events = classify_runtime_parameter_events(artifact, online_config(), "v0")
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["status"], "ACCEPTED")
                self.assertEqual(events[0]["parameter"]["placement"], placement)

        request_artifact = callback_artifact(source="REQUEST")
        request_artifact["request_params"] = {"query_params": {"age": "21"}}
        events = classify_runtime_parameter_events(request_artifact, online_config(), "v0")
        self.assertEqual(events[0]["status"], "ACCEPTED")
        self.assertEqual(events[0]["parameter"]["placement"], "query_params")

        ambiguous = callback_artifact(source="REQUEST")
        ambiguous["request_params"] = {
            "query_params": {"age": "21"},
            "body_params": {"age": "21"},
        }
        self.assertEqual(
            classify_runtime_parameter_events(ambiguous, online_config(), "v0")[0]["status"],
            "REJECTED",
        )

    def test_rest_request_provenance_retains_all_buckets(self) -> None:
        for bucket in ("URL", "GET", "POST", "JSON"):
            with self.subTest(bucket=bucket):
                config = online_config()
                config["target"] = "http://web/?rest_route=/hookphuzz/v1/probe"
                config["methods"] = ["GET" if bucket in {"URL", "GET"} else "POST"]
                config["metadata"].update({
                    "entrypoint_type": "rest_route",
                    "resolved_method": config["methods"][0],
                    "callback_repr": "HookPhuzzFixture::rest_probe",
                })
                artifact = {
                    "request_id": "rest-request",
                    "request_method": config["methods"][0],
                    "rest_parameter_events": [{
                        "accessor": "WP_REST_Request::get_param",
                        "callback": "HookPhuzzFixture::rest_probe",
                        "source": "REST",
                        "bucket": bucket,
                        "path": [bucket, "search"],
                        "parameter": "search",
                        "observed_value": "needle",
                        "observed_count": 1,
                    }],
                    "callback_summaries": [{"callback": "HookPhuzzFixture::rest_probe"}],
                }
                events = classify_runtime_parameter_events(artifact, config, "v0")
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["status"], "ACCEPTED")
                self.assertEqual(events[0]["parameter"]["source"], f"REST_{bucket}")

        with self.assertRaisesRegex(OnlineConfigError, "REST_URL_CONFIG_PLACEMENT_UNSUPPORTED"):
            build_child_config(online_config(), {
                "status": "ACCEPTED",
                "parameter": {
                    "name": "id",
                    "source": "REST_URL",
                    "placement": "url_params",
                    "value": "1",
                },
            })
        with self.assertRaisesRegex(OnlineConfigError, "REST_JSON_CONFIG_PLACEMENT_UNSUPPORTED"):
            build_child_config(online_config(), {
                "status": "ACCEPTED",
                "parameter": {
                    "name": "payload",
                    "source": "REST_JSON",
                    "placement": "body_params",
                    "value": "1",
                    "materializable": False,
                },
            })

        existing = online_config()
        existing["target"] = "http://web/?rest_route=/hookphuzz/v1/probe"
        existing["methods"] = ["GET"]
        existing["body_params"] = {"data": [], "fixed": [], "fuzz": []}
        existing["query_params"] = {
            "data": [{"name": "search", "value": "hello"}],
            "fixed": [],
            "fuzz": ["search"],
        }
        existing["metadata"].update({
            "entrypoint_type": "rest_route",
            "resolved_method": "GET",
            "callback_repr": "HookPhuzzFixture::rest_probe",
        })
        artifact = {
            "request_id": "rest-existing",
            "request_method": "GET",
            "request_params": {"query_params": {"search": "needle"}},
            "rest_parameter_events": [{
                "accessor": "WP_REST_Request::get_param",
                "callback": "HookPhuzzFixture::rest_probe",
                "source": "REST",
                "bucket": "GET",
                "path": ["GET", "search"],
                "parameter": "search",
                "observed_value": "needle",
                "observed_count": 1,
            }],
            "callback_summaries": [{"callback": "HookPhuzzFixture::rest_probe"}],
        }
        events = classify_runtime_parameter_events(artifact, existing, "v0")
        self.assertEqual(events[0]["status"], "IGNORED")
        self.assertEqual(events[0]["reason"], "PARAMETER_ALREADY_PRESENT")

    def test_new_callback_is_rejected_as_separate_action_event(self) -> None:
        artifact = callback_artifact()
        artifact["callback_summaries"].append({
            "callback": "HookPhuzzFixture::new_action",
            "unique_parameters": [{
                "name": "ignored",
                "source": "POST",
                "path": ["ignored"],
                "observed_value": "x",
                "helper_depth": 0,
                "observed_count": 1,
            }],
        })
        events = classify_runtime_parameter_events(artifact, online_config(), "v0")
        action_events = [event for event in events if event["kind"] == "ACTION_DISCOVERY"]
        self.assertEqual(len(action_events), 1)
        self.assertEqual(action_events[0]["status"], "REJECTED")
        self.assertEqual(action_events[0]["reason"], "ACTION_EXPANSION_NOT_IMPLEMENTED")

    def test_missing_callback_method_or_provenance_is_rejected(self) -> None:
        artifact = callback_artifact()
        artifact["callback_summaries"][0]["callback"] = "Other::callback"
        events = classify_runtime_parameter_events(artifact, online_config(), "v0")
        self.assertTrue(all(event["status"] == "REJECTED" for event in events))
        self.assertIn("ACTION_EXPANSION_NOT_IMPLEMENTED", {event["reason"] for event in events})

        artifact = callback_artifact()
        artifact["request_method"] = "GET"
        events = classify_runtime_parameter_events(artifact, online_config(), "v0")
        self.assertEqual(events[0]["reason"], "METHOD_EVIDENCE_MISMATCH")

        artifact = callback_artifact()
        artifact["callback_summaries"][0]["unique_parameters"][0].pop("source")
        events = classify_runtime_parameter_events(artifact, online_config(), "v0")
        self.assertEqual(events[0]["reason"], "PROVENANCE_MISSING")

    def test_existing_parameter_cmplog_value_is_mutation_only(self) -> None:
        artifact = {
            "request_id": "request-cmplog",
            "comparison_events": [{
                "callback": "HookPhuzzFixture::stage1",
                "opcode": "IS_IDENTICAL",
                "source": "POST",
                "path": ["name"],
                "runtime_value": "Alice",
                "comparison_value": "Admin",
            }],
        }
        events = classify_cmplog_events(artifact, online_config(), "v0")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["kind"], "CMPLOG_VALUE")
        self.assertEqual(events[0]["parameter"]["name"], "name")
        self.assertEqual(events[0]["candidate_value"], "Admin")
        self.assertNotIn("discovery", events[0]["kind"].lower())

    def test_child_and_replay_configs_are_separate_and_immutable(self) -> None:
        parent = online_config()
        event = {
            "event_id": "event-1",
            "status": "ACCEPTED",
            "parameter": {
                "name": "age",
                "source": "POST",
                "placement": "body_params",
                "value": "21",
            },
        }
        child = build_child_config(parent, event)
        self.assertEqual(parent["body_params"]["fuzz"], ["name"])
        self.assertIn("age", child["body_params"]["fuzz"])
        self.assertNotEqual(child, parent)

        replay = build_replay_config(child, {"body_params": {"age": "21"}})
        self.assertEqual(replay["config_type"], "replay_only")
        self.assertEqual(replay["body_params"]["fuzz"], [])
        self.assertIn("age", replay["body_params"]["fixed"])
        self.assertEqual(
            next(item["value"] for item in replay["body_params"]["data"] if item["name"] == "age"),
            "21",
        )

    def test_v0_gate_writes_lineage_without_starting_empty_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({"suggested_seeds": [{
                "hook_name": "wp_ajax_nopriv_empty",
                "callback_id": "empty-callback",
                "seed": {
                    "auth_mode": "unauth-capable",
                    "method": "POST",
                    "resolved_method": "POST",
                    "method_status": "resolved",
                    "path": "/wp-admin/admin-ajax.php",
                    "body": {},
                    "query_params": {},
                    "fixed_params": [],
                    "fuzzable_params": [],
                },
            }]}), encoding="utf-8")
            commands = []

            def run_command(command, **kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            coordinator = OnlineCoordinator(
                suggested_seeds=suggested,
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-gate",
                max_seconds=1,
                max_versions=2,
                run_command=run_command,
            )

            self.assertEqual(coordinator.run(), 2)
            self.assertEqual(commands, [])
            self.assertEqual(coordinator.lineage["versions"], [])
            self.assertEqual(coordinator.lineage["terminal_reason"], "V0_PREREQUISITE_GATE_FAILED")
            self.assertFalse((root / "configs").exists())

    def test_bootstrap_config_fallback_keeps_callback_evidence_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({"suggested_seeds": [{
                "hook_name": "wp_ajax_nopriv_hookphuzz_stage1_direct",
                "callback_id": "fixture-callback",
                "callback_repr": "HookPhuzzFixture::stage1",
                "seed": {
                    "method": "POST",
                    "resolved_method": "POST",
                    "path": "/wp-admin/admin-ajax.php",
                    "fuzzable_params": [],
                },
            }]}), encoding="utf-8")
            bootstrap = root / "bootstrap.json"
            bootstrap.write_text(json.dumps(online_config()), encoding="utf-8")
            coordinator = OnlineCoordinator(
                suggested_seeds=suggested,
                bootstrap_config=bootstrap,
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-bootstrap",
                max_seconds=1,
                max_versions=2,
            )

            selected = coordinator._select_v0()

            self.assertIsNotNone(selected)
            _, config = selected
            self.assertEqual(config["metadata"]["callback_id"], "fixture-callback")
            self.assertIn("name", config["body_params"]["fuzz"])

    def test_replay_pass_starts_separate_child_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            commands = []
            replay_kwargs = []

            def run_command(command, **kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            def replay_runner(*args, **kwargs):
                replay_kwargs.append(kwargs)
                return {"runs": [{
                    "validation_status": "callback_reached",
                    "process_status": "exited",
                    "matched_artifact": "replay.json",
                }]}

            coordinator = OnlineCoordinator(
                suggested_seeds=root / "unused.json",
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-pass",
                max_seconds=1,
                max_versions=2,
                run_command=run_command,
                replay_runner=replay_runner,
            )
            coordinator.run_dir.mkdir(parents=True)
            parent_path = coordinator._write_config("v0", online_config())
            parent = coordinator._new_version("v0", online_config(), parent_path, None, None)
            self.assertTrue(coordinator._start_worker(parent))
            event = {
                "event_id": "event-pass",
                "status": "ACCEPTED",
                "parameter": {
                    "name": "age",
                    "source": "POST",
                    "placement": "body_params",
                    "value": "21",
                },
            }

            coordinator._expand_parameter(parent, event)

            self.assertEqual(len(coordinator.lineage["versions"]), 2)
            child = coordinator.lineage["versions"][1]
            self.assertEqual(child["parent_config"], str(parent_path))
            self.assertEqual(child["status"], "fuzzing")
            self.assertEqual(child["replay_result"]["passed"], True)
            for version in coordinator.lineage["versions"]:
                self.assertIn(version["status"], {"pending", "replaying", "replay_pass", "replay_failed", "fuzzing"})
                self.assertTrue(version["config_hash"])
                self.assertIn("terminal_reason", version)
                self.assertIn("parent_config", version)
                self.assertIn("discovery_event", version)
                self.assertIn("replay_result", version)
                self.assertIn("worker_status", version)

            self.assertEqual(len(coordinator.lineage["workers"]), 2)
            self.assertEqual(len([item for item in commands if "-d" in item]), 2)
            self.assertIn("FUZZER_NODE_ID=1", commands[0])
            self.assertIn("FUZZER_NODE_ID=2", commands[-1])
            self.assertEqual(replay_kwargs[0]["fuzzer_node_id"], 101)
            self.assertTrue(all("compose up" not in " ".join(item) for item in commands))

    def test_replay_only_worker_is_marked_replaying(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            suggested = root / "suggested.json"
            suggested.write_text(json.dumps({"suggested_seeds": []}), encoding="utf-8")
            coordinator = OnlineCoordinator(
                suggested_seeds=suggested,
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-replaying",
                max_seconds=1,
                max_versions=2,
                run_command=lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "", ""),
            )
            coordinator.run_dir.mkdir(parents=True)
            replay = online_config()
            replay["config_type"] = "replay_only"
            replay["body_params"]["fuzz"] = []
            config_path = coordinator._write_config("v0", replay)
            version = coordinator._new_version("v0", replay, config_path, None, None)

            self.assertTrue(coordinator._start_worker(version))
            self.assertEqual(version["status"], "replaying")

    def test_replay_failure_does_not_start_child_worker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            commands = []

            def run_command(command, **kwargs):
                commands.append(command)
                return subprocess.CompletedProcess(command, 0, "", "")

            coordinator = OnlineCoordinator(
                suggested_seeds=root / "unused.json",
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-fail",
                max_seconds=1,
                max_versions=2,
                run_command=run_command,
                replay_runner=lambda *args, **kwargs: {"runs": [{
                    "validation_status": "registered_not_executed",
                    "validation_reason": "CALLBACK_NOT_REACHED",
                    "process_status": "exited",
                }]},
            )
            coordinator.run_dir.mkdir(parents=True)
            parent_path = coordinator._write_config("v0", online_config())
            parent = coordinator._new_version("v0", online_config(), parent_path, None, None)
            self.assertTrue(coordinator._start_worker(parent))
            coordinator._expand_parameter(parent, {
                "event_id": "event-fail",
                "status": "ACCEPTED",
                "parameter": {
                    "name": "age",
                    "source": "POST",
                    "placement": "body_params",
                    "value": "21",
                },
            })

            child = coordinator.lineage["versions"][1]
            self.assertEqual(child["status"], "replay_failed")
            self.assertEqual(len(coordinator.lineage["workers"]), 1)
            self.assertEqual(len([item for item in commands if "-d" in item]), 1)

    def test_artifact_retention_failure_does_not_drop_runtime_event(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            coordinator = OnlineCoordinator(
                suggested_seeds=root / "unused.json",
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-retention",
                max_seconds=1,
                max_versions=2,
            )
            coordinator.run_dir.mkdir(parents=True)
            parent_config = online_config()
            parent_path = coordinator._write_config("v0", parent_config)
            parent = coordinator._new_version("v0", parent_config, parent_path, None, None)
            coordinator._active_version = "v0"
            accepted = []
            coordinator._expand_parameter = lambda version, event, deadline=None: accepted.append(event)

            def fail_retention(*args, **kwargs):
                raise OSError("request artifact disappeared during cleanup")

            coordinator._copy_artifact = fail_retention
            coordinator._process_artifact_pair(
                "request.json",
                callback_artifact(),
                "zend.json",
                {},
            )

            self.assertEqual(len(accepted), 1)
            self.assertEqual(accepted[0]["status"], "ACCEPTED")
            self.assertEqual(len(coordinator.lineage["artifact_copy_errors"]), 2)

    def test_artifact_retention_writes_a_run_local_copy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            coordinator = OnlineCoordinator(
                suggested_seeds=root / "unused.json",
                config_root=root / "configs",
                output_root=root / "output",
                plugin_slug="fixture",
                legacy_run_id="run-copy",
                max_seconds=1,
                max_versions=2,
            )
            coordinator._copy_artifact("v0", "request", "request.json", {"request_id": "request-1"})

            self.assertEqual(
                json.loads((coordinator.artifact_dir / "v0" / "request" / "request.json").read_text()),
                {"request_id": "request-1"},
            )


if __name__ == "__main__":
    unittest.main()
