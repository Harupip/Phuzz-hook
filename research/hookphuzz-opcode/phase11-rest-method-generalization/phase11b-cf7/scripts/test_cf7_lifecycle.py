#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("cf7_lifecycle.py")
SPEC = importlib.util.spec_from_file_location("cf7_lifecycle", SCRIPT)
assert SPEC and SPEC.loader
LIFECYCLE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LIFECYCLE)
PHASE = SCRIPT.parents[1]
ROOT = Path(__file__).resolve().parents[5]


class LifecycleTests(unittest.TestCase):
    def test_relative_and_absolute_phase_paths_resolve_same_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            results = Path(temporary)
            relative = LIFECYCLE.resolve_paths(PHASE.relative_to(ROOT), results, "run", "project", "test")
            absolute = LIFECYCLE.resolve_paths(PHASE, results, "run", "project", "test")
        self.assertEqual(ROOT, relative["repo_root"])
        self.assertEqual(ROOT, absolute["repo_root"])

    def test_resolution_is_independent_of_caller_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            previous = Path.cwd()
            try:
                os.chdir(temporary)
                paths = LIFECYCLE.resolve_paths(PHASE, Path(temporary), "run", "project", "test")
            finally:
                os.chdir(previous)
        self.assertEqual(ROOT, paths["repo_root"])

    def test_build_context_is_repository_root_and_copy_sources_exist(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = LIFECYCLE.resolve_paths(PHASE, Path(temporary), "run", "project", "test")
            LIFECYCLE.validate_build_context(paths, "run", "test")
            value = json.loads((Path(temporary) / "docker-build-context.json").read_text())
        self.assertEqual(str(ROOT), value["build_context"])
        self.assertEqual([], value["missing_copy_sources"])

    def test_compose_command_is_explicit_and_scoped(self) -> None:
        paths = {"project": "hookphuzz-phase12-run", "compose_file": PHASE / "docker-compose.yml"}
        command = LIFECYCLE.compose(paths, "down", "--volumes", "--remove-orphans")
        self.assertEqual(command[:2], ["docker", "compose"])
        self.assertEqual(command[command.index("--project-name") + 1], "hookphuzz-phase12-run")
        self.assertEqual(Path(command[command.index("--file") + 1]), PHASE / "docker-compose.yml")
        self.assertEqual(command[-3:], ["down", "--volumes", "--remove-orphans"])

    def test_zero_multiple_and_non_running_containers_are_rejected(self) -> None:
        paths = {"project": "project"}
        with self.assertRaisesRegex(LIFECYCLE.LifecycleError, "found 0"):
            LIFECYCLE.select_single_container(paths, "web", [], [])
        with self.assertRaisesRegex(LIFECYCLE.LifecycleError, "found 2"):
            LIFECYCLE.select_single_container(paths, "web", ["a", "b"], [{"State": {"Running": True}}] * 2)
        with self.assertRaisesRegex(LIFECYCLE.LifecycleError, "not running"):
            LIFECYCLE.select_single_container(paths, "web", ["a"], [{"State": {"Running": False}}])

    def test_wrong_compose_labels_are_rejected(self) -> None:
        paths = {"project": "project"}
        state = {"State": {"Running": True}, "Config": {"Labels": {"com.docker.compose.project": "other", "com.docker.compose.service": "web"}}}
        with self.assertRaisesRegex(LIFECYCLE.LifecycleError, "labels"):
            LIFECYCLE.select_single_container(paths, "web", ["a"], [state])

    def test_dynamic_container_id_with_matching_labels_is_accepted(self) -> None:
        paths = {"project": "project"}
        state = {"State": {"Running": True}, "Config": {"Labels": {"com.docker.compose.project": "project", "com.docker.compose.service": "web"}}}
        self.assertEqual("dynamic-id", LIFECYCLE.select_single_container(paths, "web", ["dynamic-id"], [state]))

    def test_json_write_is_atomic_and_machine_readable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "artifact.json"
            LIFECYCLE.write_json(path, {"run_id": "current"})
            self.assertEqual({"run_id": "current"}, json.loads(path.read_text(encoding="utf-8")))
            self.assertFalse(path.with_suffix(".json.tmp").exists())

    def test_phase_runners_use_shared_helper_and_no_literal_container(self) -> None:
        phase12 = ROOT / "research/hookphuzz-opcode/phase12/run.sh"
        phase11 = PHASE / "run.sh"
        self.assertIn("cf7_lifecycle.py", phase11.read_text(encoding="utf-8"))
        self.assertIn("cf7_lifecycle.py", phase12.read_text(encoding="utf-8"))
        self.assertNotIn("phase11b-cf7-web-1", phase12.read_text(encoding="utf-8"))

    def test_replay_artifact_redacts_authentication_material(self) -> None:
        replay = ROOT / "research/hookphuzz-opcode/phase12/scripts/run_cf7_current.py"
        text = replay.read_text(encoding="utf-8")
        self.assertIn("authentication_material':'redacted", text)
        self.assertNotIn("'nonce':nonce", text)

    def test_readiness_does_not_store_login_html(self) -> None:
        text = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"wordpress_http_ready": ["exec", "-T", "web", "curl", "-fsS", "-o", "/dev/null"', text)


if __name__ == "__main__":
    unittest.main()
