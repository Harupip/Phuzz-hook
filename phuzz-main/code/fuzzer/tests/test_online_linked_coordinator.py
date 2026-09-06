import copy
import json
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_linked_coordinator import OnlineLinkedCoordinator, run_online_linked
from seed_generation.config.config_exporter import SeedConfigSkip, export_seed_configs


def seed_item() -> dict:
    return {
        "hook_name": "wp_ajax_nopriv_fixture",
        "callback_id": "cb-fixture",
        "callback_repr": "fixture_callback",
        "seed": {
            "auth_mode": "unauth-capable",
            "method": "POST",
            "resolved_method": "POST",
            "method_status": "resolved",
            "path": "/wp-admin/admin-ajax.php",
            "body": {"action": "fixture", "seed": "base"},
            "query_params": {},
            "headers": {},
            "fixed_params": ["action"],
            "fuzzable_params": ["seed"],
        },
    }


def config_for(item: dict, *, include_new: bool = False) -> dict:
    names = ["action", "seed"] + (["new_param"] if include_new else [])
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST"],
        "body_params": {
            "data": [{"name": name, "value": "base" if name == "seed" else "fixture"} for name in names],
            "fixed": ["action"],
            "fuzz": ["seed"] + (["new_param"] if include_new else []),
            "weight": 1,
        },
        "metadata": {
            "callback_id": item["callback_id"],
            "callback_repr": item["callback_repr"],
            "hook_name": item["hook_name"],
            "resolved_method": "POST",
        },
        "config_type": "fuzzing_ready",
    }


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class OnlineLinkedCoordinatorTests(unittest.TestCase):
    def test_online_linked_batch_continues_after_candidate_vulnerability(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            suggested = root / "suggested_seeds.json"
            suggested.write_text(json.dumps({
                "plugin_slug": "fixture",
                "suggested_seeds": [
                    {"hook_name": "wp_ajax_first", "callback_id": "cb-first", "seed": {}},
                    {"hook_name": "wp_ajax_second", "callback_id": "cb-second", "seed": {}},
                ],
            }), encoding="utf-8")
            registry = root / "registry.json"
            registry.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            calls = []

            class FakeCoordinator:
                def __init__(self, **kwargs):
                    calls.append(kwargs)
                    self.state_path = Path(kwargs["output_root"]) / "online-linked" / kwargs["legacy_run_id"] / "state.json"
                    self.state = {
                        "terminal_status": "VULN_FOUND" if len(calls) == 1 else "BOUNDED_ONLINE_COMPLETE",
                        "terminal_reason": "VULN_FOUND" if len(calls) == 1 else "BUDGET_EXPIRED",
                        "versions": [],
                    }

                def run(self):
                    return 0

            args = SimpleNamespace(
                suggested_seeds=str(suggested),
                bootstrap_config="",
                config_root=str(root / "configs"),
                output_root=str(root / "output"),
                plugin_slug="fixture",
                legacy_run_id="run",
                max_seconds=1,
                max_versions=2,
                callback_registry=str(registry),
                service="fuzzer-wordpress-plugin",
            )
            with patch("hook_energy.seed_generation.online_linked_coordinator.OnlineLinkedCoordinator", FakeCoordinator):
                self.assertEqual(run_online_linked(args), 0)

            self.assertEqual(len(calls), 2)
            batch_state = json.loads(
                (root / "output" / "online-linked" / "run" / "batch-state.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(batch_state["candidates"]), 2)
            self.assertEqual(batch_state["candidates"][0]["terminal_status"], "VULN_FOUND")
            self.assertEqual(batch_state["candidates"][1]["terminal_status"], "BOUNDED_ONLINE_COMPLETE")

    def test_worker_vulnerability_exit_stops_current_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)

            def run_command(command, **kwargs):
                if command[:2] == ["docker", "inspect"]:
                    return subprocess.CompletedProcess(command, 0, "57\n", "")
                if command[:3] == ["docker", "compose", "run"]:
                    log.append("worker_start")
                elif command[:3] == ["docker", "rm", "-f"]:
                    log.append("worker_stop")
                return subprocess.CompletedProcess(command, 0, "", "")

            coordinator.run_command = run_command
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(coordinator.state["terminal_status"], "VULN_FOUND")
            self.assertEqual(coordinator.state["versions"][-1]["status"], "vuln_found")
            self.assertIn("worker_stop", log)

    def make_coordinator(
        self,
        root: Path,
        log: list[str],
        *,
        replay_passes: bool = True,
        discovers_parameter: bool = True,
        incomplete_parameter: bool = False,
        convergence_error: bool = False,
        replay_error: bool = False,
        request_callback_id: str | None = None,
        max_versions: int = 3,
        request_names: set[str] | None = None,
        zend_names: set[str] | None = None,
        legacy_run_id: str = "run",
    ) -> OnlineLinkedCoordinator:
        item = seed_item()
        raw_report = {"plugin_slug": "fixture", "suggested_seeds": [item]}
        suggested = root / "suggested_seeds.json"
        suggested.write_text(json.dumps(raw_report), encoding="utf-8")
        registry = root / "registry.json"
        registry.write_text(json.dumps({"schema_version": 1, "callback_map": {}}), encoding="utf-8")
        clock = Clock()
        request_names = request_names if request_names is not None else {"req-v0.json"}
        zend_names = zend_names if zend_names is not None else {"req-v0.json"}
        request_id = Path(sorted(request_names)[0]).stem

        def build_config(*args, **kwargs):
            log.append("build_config")
            return "fixture", config_for(item)

        def list_targets(*args, **kwargs):
            log.append("list_targets")
            return [{
                "candidate_key": "candidate-fixture",
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
                "entrypoint_type": "ajax",
                "method": "POST",
                "route": "/wp-admin/admin-ajax.php",
            }]

        def list_artifacts():
            log.append("list_request_artifacts")
            return set(request_names)

        def load_artifact(name):
            log.append("load_request_artifact")
            payload = {
                "request_id": Path(name).stem,
                "legacy_run_id": f"{legacy_run_id}-v0",
                "target_plugin": "fixture",
                "http_method": "POST",
                "request_params": {"body_params": {"action": "fixture", "seed": "base"}},
            }
            if request_callback_id is not None:
                payload["callback_id"] = request_callback_id
            return payload

        def list_zend():
            log.append("list_zend_artifacts")
            return set(zend_names)

        def load_zend(name):
            log.append("load_zend_artifact")
            return {"request_id": Path(name).stem, "run_id": f"{legacy_run_id}-v0"}

        def converge(**kwargs):
            log.append("converge_iteration")
            if convergence_error:
                raise RuntimeError("REPLAY_FAILED: exact candidate correlation failed")
            if not discovers_parameter:
                return {
                    "status": "CONVERGED",
                    "request_id": request_id,
                    "known_parameters": [],
                    "new_parameters": [],
                    "merged_suggested_seeds": copy.deepcopy(raw_report),
                }
            parameter = {
                "name": "new_param",
                "path": ["new_param"],
                "source": "POST",
                "location": "form",
                "helper_depth": 0,
                "observed_count": 1,
                "evidence_kind": "zend_runtime",
                "run_id": f"{legacy_run_id}-v0",
                "plugin_slug": "fixture",
                "request_id": request_id,
                "canonical_callback": "fixture_callback",
                "request_method": "POST",
            }
            if incomplete_parameter:
                parameter.pop("request_id")
            self.assertEqual(kwargs["legacy_run_id"], f"{legacy_run_id}-v0")
            self.assertEqual(kwargs["candidate_key"], "candidate-fixture")
            return {
                "status": "CONTINUE",
                "request_id": request_id,
                "known_parameters": [parameter],
                "new_parameters": [parameter],
                "merged_suggested_seeds": copy.deepcopy(raw_report),
            }

        def materialize(*args, **kwargs):
            log.append("materialize_convergence_seeds")
            return copy.deepcopy(raw_report)

        def export_configs(report, *, output_config_dir, summary_path, **kwargs):
            log.append("export_seed_configs")
            output_config_dir = Path(output_config_dir)
            path = output_config_dir / "exported.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(config_for(item, include_new=True)), encoding="utf-8")
            summary = {"generated": [{
                "config_slug": "online-linked/exported",
                "config_path": str(path),
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
            }]}
            Path(summary_path).write_text(json.dumps(summary), encoding="utf-8")
            return summary

        def force_replay(config):
            log.append("force_replay_only")
            for section in (config.get("body_params"), config.get("query_params")):
                if isinstance(section, dict):
                    section["fuzz"] = []
            config["config_type"] = "replay_only"

        def replay_runner(*args, **kwargs):
            log.append("run_generated_configs")
            if replay_error:
                raise RuntimeError("REPLAY_FAILED: replay runner failed")
            return {"legacy_run_id": kwargs["legacy_run_id"], "runs": [{
                "hook_name": item["hook_name"],
                "callback_id": item["callback_id"],
                "callback_reached": replay_passes,
                "validation_status": "callback_reached" if replay_passes else "registered_not_executed",
                "validation_reason": "" if replay_passes else "CALLBACK_NOT_REACHED",
                "process_status": "exited",
                "matched_artifact": "replay-v1.json",
                "request_artifacts": ["replay-v1.json"],
                "resolved_method": "POST",
            }]}

        def verify_pass2(*args, **kwargs):
            log.append("verify_pass2_contract")
            return {"accepted": 1, "total": 1} if replay_passes else {"accepted": 0, "total": 0}

        def run_command(command, **kwargs):
            if command[:3] == ["docker", "compose", "run"]:
                log.append("worker_start")
            elif command[:3] == ["docker", "rm", "-f"]:
                log.append("worker_stop")
            return subprocess.CompletedProcess(command, 0, "", "")

        return OnlineLinkedCoordinator(
            suggested_seeds=suggested,
            config_root=root / "configs",
            output_root=root / "output",
            plugin_slug="fixture",
            legacy_run_id=legacy_run_id,
            max_seconds=2,
            max_versions=max_versions,
            registry_path=registry,
            build_config_fn=build_config,
            list_targets_fn=list_targets,
            list_artifacts=list_artifacts,
            load_artifact=load_artifact,
            list_zend_artifacts=list_zend,
            load_zend_artifact=load_zend,
            converge_fn=converge,
            materialize_fn=materialize,
            export_configs_fn=export_configs,
            force_replay_only_fn=force_replay,
            replay_runner=replay_runner,
            verify_pass2_fn=verify_pass2,
            run_command=run_command,
            clock=clock,
            sleeper=clock.sleep,
        )

    def test_online_linked_calls_legacy_pipeline_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            positions = {name: log.index(name) for name in {
                "build_config", "list_targets", "worker_start", "list_request_artifacts",
                "load_request_artifact", "list_zend_artifacts", "load_zend_artifact",
                "converge_iteration", "materialize_convergence_seeds", "export_seed_configs",
                "force_replay_only", "run_generated_configs", "verify_pass2_contract",
            }}
            self.assertLess(positions["build_config"], positions["list_targets"])
            self.assertLess(positions["list_targets"], positions["worker_start"])
            self.assertLess(positions["worker_start"], positions["converge_iteration"])
            self.assertLess(positions["converge_iteration"], positions["materialize_convergence_seeds"])
            self.assertLess(positions["materialize_convergence_seeds"], positions["export_seed_configs"])
            self.assertLess(positions["export_seed_configs"], positions["force_replay_only"])
            self.assertLess(positions["force_replay_only"], positions["run_generated_configs"])
            self.assertLess(positions["run_generated_configs"], positions["verify_pass2_contract"])

    def test_v0_selection_allows_replay_only_seed_without_fuzz_params(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)

            def build_replay_config(*args, **kwargs):
                config = config_for(seed_item())
                config["config_type"] = "replay_only"
                config["body_params"]["fuzz"] = []
                return "fixture", config

            coordinator.build_config_fn = build_replay_config

            selected = coordinator._select_v0()

            self.assertIsNotNone(selected)
            _, config, _ = selected
            self.assertEqual(config["config_type"], "replay_only")
            self.assertEqual(config["body_params"]["fuzz"], [])

    def test_v0_selection_falls_back_to_replay_builder_for_blocked_seed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)

            def build_blocked_then_replay(*args, **kwargs):
                if not kwargs.get("replay_only"):
                    raise SeedConfigSkip("blocked_http_method")
                config = config_for(seed_item())
                config["config_type"] = "replay_only"
                config["body_params"]["fuzz"] = []
                return "fixture", config

            coordinator.build_config_fn = build_blocked_then_replay
            selected = coordinator._select_v0()

            self.assertIsNotNone(selected)
            _, config, _ = selected
            self.assertEqual(config["config_type"], "replay_only")

    def test_replay_only_worker_is_marked_replaying(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            log: list[str] = []
            coordinator = self.make_coordinator(root, log)
            config = config_for(seed_item())
            config["config_type"] = "replay_only"
            config["body_params"]["fuzz"] = []
            coordinator.run_dir.mkdir(parents=True)
            config_path = coordinator._write_config("v0", config)
            version = coordinator._new_version("v0", config, config_path, None, None, seed_item())

            self.assertTrue(coordinator._start_worker(version))
            self.assertEqual(version["status"], "replaying")

    def test_cmp_log_only_does_not_create_child_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, discovers_parameter=False)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertNotIn("materialize_convergence_seeds", log)
            self.assertNotIn("run_generated_configs", log)

    def test_zend_parameter_creates_child_after_exact_correlation(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            versions = coordinator.state["versions"]
            self.assertEqual([version["version"] for version in versions], ["v0", "v1"])
            self.assertEqual(versions[1]["parent_version"], "v0")
            self.assertEqual(versions[1]["replay_result"]["passed"], True)
            self.assertEqual(versions[1]["status"], "fuzzing")
            self.assertIn("new_param", json.dumps(json.loads(Path(versions[1]["config_path"]).read_text())))

    def test_missing_correlation_does_not_create_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(
                Path(tmp), log, request_names={"req-v0.json"}, zend_names={"prefix-req-v0.json"}
            )
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 1)
            self.assertNotIn("converge_iteration", log)

    def test_parameter_missing_correlation_is_rejected_without_child_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, incomplete_parameter=True)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("CORRELATION_OR_PROVENANCE_INCOMPLETE", json.dumps(coordinator.state["events"]))
            self.assertNotIn("export_seed_configs", log)

    def test_new_action_or_callback_is_recorded_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, request_callback_id="new-callback")
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("ACTION_EXPANSION_NOT_IMPLEMENTED", json.dumps(coordinator.state["events"]))
            self.assertNotIn("converge_iteration", log)

    def test_convergence_exception_is_rejected_and_parent_continues(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, convergence_error=True)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("CORRELATION_OR_PROVENANCE_INCOMPLETE", json.dumps(coordinator.state["events"]))

    def test_replay_exception_restarts_parent_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_error=True)
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 2)

    def test_replay_failure_restarts_parent_without_child_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, replay_passes=False)
            self.assertNotEqual(coordinator.run(), 0)
            self.assertEqual(len(coordinator.state["versions"]), 2)
            self.assertEqual(coordinator.state["versions"][1]["status"], "replay_failed")
            self.assertEqual([item for item in coordinator.state["workers"] if item["version"] == "v1"], [])
            self.assertEqual(log.count("worker_start"), 2)

    def test_replay_pass_starts_child_only_after_parent_stops(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            stop_index = log.index("worker_stop")
            replay_index = log.index("run_generated_configs")
            child_start_index = log.index("worker_start", log.index("worker_start") + 1)
            self.assertLess(stop_index, replay_index)
            self.assertLess(replay_index, child_start_index)

    def test_online_max_versions_includes_v0(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log, max_versions=1)
            self.assertEqual(coordinator.run(), 0)
            self.assertEqual([version["version"] for version in coordinator.state["versions"]], ["v0"])
            self.assertIn("VERSION_LIMIT_REACHED", json.dumps(coordinator.state["events"]))
            self.assertNotIn("run_generated_configs", log)

    def test_no_worker_versions_run_concurrently(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            starts = [index for index, value in enumerate(log) if value == "worker_start"]
            stops = [index for index, value in enumerate(log) if value == "worker_stop"]
            self.assertEqual(len(starts), 2)
            self.assertEqual(len(stops), 2)
            self.assertLess(starts[0], stops[0])
            self.assertLess(stops[0], starts[1])

    def test_config_files_are_immutable_and_hashed_per_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            for version in coordinator.state["versions"]:
                config_path = Path(version["config_path"])
                self.assertTrue(config_path.is_file())
                self.assertEqual(version["config_hash"], coordinator.config_hash(config_path))
                self.assertNotEqual(version["config_path"], version.get("replay_config_path"))

    def test_runtime_evidence_is_saved_under_run_specific_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            log: list[str] = []
            coordinator = self.make_coordinator(Path(tmp), log)
            self.assertEqual(coordinator.run(), 0)
            run_dir = coordinator.run_dir
            self.assertTrue((run_dir / "state.json").is_file())
            self.assertTrue((run_dir / "events.jsonl").is_file())
            self.assertTrue((run_dir / "versions" / "v0").is_dir())

    def test_long_run_id_preserves_evidence_and_resolvable_worker_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / ("workspace-" + "x" * 45)
            root.mkdir()
            run_id = "plugin-20260906T121044Z-candidate-001-wp_ajax_nopriv_" + "upload_file_" * 5
            coordinator = self.make_coordinator(
                root, [], legacy_run_id=run_id,
                request_names={"1788671490-f70d334e-44a4-46f8-85e6-95b571434eec.json"},
                zend_names={"1788671490-f70d334e-44a4-46f8-85e6-95b571434eec.json"},
            )
            coordinator.export_configs_fn = export_seed_configs
            replay_runner = coordinator.replay_runner

            def replay_with_existing_config(rows, **kwargs):
                config = coordinator.config_root / (rows[0]["config_slug"] + ".json")
                self.assertTrue(config.is_file(), config)
                self.assertEqual(json.loads(config.read_text())["config_type"], "replay_only")
                return replay_runner(rows, **kwargs)

            coordinator.replay_runner = replay_with_existing_config
            self.assertEqual(coordinator.run(), 0, coordinator.state["terminal_reason"])
            self.assertEqual([v["version"] for v in coordinator.state["versions"]], ["v0", "v1"])
            self.assertTrue(coordinator.state["versions"][1]["replay_result"]["passed"])
            state = json.loads(coordinator.state_path.read_text())
            self.assertEqual(state["legacy_run_id"], run_id)
            evidence = next((coordinator.run_dir / "versions/v0/observation/request").glob("*.json"))
            self.assertEqual(json.loads(evidence.read_text())["legacy_run_id"], run_id + "-v0")
            for worker in state["workers"]:
                slug = next(arg.split("=", 1)[1] for arg in worker["command"] if arg.startswith("FUZZER_CONFIG="))
                self.assertTrue((coordinator.config_root / (slug + ".json")).is_file())
            for path in root.rglob("*.json"):
                self.assertLess(len(str(path.resolve())), 260, path)


if __name__ == "__main__":
    unittest.main()
