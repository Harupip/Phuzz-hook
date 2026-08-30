import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_linked_coordinator import OnlineLinkedCoordinator


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
                "legacy_run_id": "run-v0",
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
            return {"request_id": Path(name).stem, "run_id": "run-v0"}

        def converge(**kwargs):
            log.append("converge_iteration")
            if convergence_error:
                raise RuntimeError("REPLAY_FAILED: exact candidate correlation failed")
            if not discovers_parameter:
                return {
                    "status": "CONVERGED",
                    "request_id": "req-v0",
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
                "run_id": "run-v0",
                "plugin_slug": "fixture",
                "request_id": "req-v0",
                "canonical_callback": "fixture_callback",
                "request_method": "POST",
            }
            if incomplete_parameter:
                parameter.pop("request_id")
            self.assertEqual(kwargs["legacy_run_id"], "run-v0")
            self.assertEqual(kwargs["candidate_key"], "candidate-fixture")
            return {
                "status": "CONTINUE",
                "request_id": "req-v0",
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
            legacy_run_id="run",
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
            run_dir = Path(tmp) / "output" / "online-linked" / "run"
            self.assertTrue((run_dir / "state.json").is_file())
            self.assertTrue((run_dir / "events.jsonl").is_file())
            self.assertTrue((run_dir / "versions" / "v0").is_dir())


if __name__ == "__main__":
    unittest.main()
