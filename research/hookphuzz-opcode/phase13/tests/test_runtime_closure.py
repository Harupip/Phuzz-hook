from __future__ import annotations
import importlib.util
import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("phase13_runner", ROOT / "scripts" / "phase13.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RuntimeClosureTests(unittest.TestCase):
    def _env(self, **updates):
        keys = {"PHASE13_SELECTED_PLUGINS", "PHASE13_MATRIX_PATH", "PHASE13_RUN_MODE"} | set(updates)
        old = {key: os.environ.get(key) for key in keys}
        for key in keys:
            if key in updates:
                os.environ[key] = updates[key]
            else:
                os.environ.pop(key, None)
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) if v is not None else os.environ.pop(k, None) for k, v in old.items()])

    def test_default_matrix_loads_canonical_gate_set(self):
        self._env(PHASE13_RUN_MODE="exploratory")
        mode, matrix, source = RUNNER.load_plugin_matrix()
        self.assertEqual(mode, "canonical")
        self.assertEqual(source, "plugin-matrix.json")
        self.assertGreaterEqual(len(matrix), 3)
        self.assertIn("plugin_matrix_has_at_least_3_real_plugins", RUNNER.phase13_required_gates(mode))

    def test_selected_plugin_builds_exploratory_matrix(self):
        self._env(PHASE13_SELECTED_PLUGINS="gamipress")
        mode, matrix, source = RUNNER.load_plugin_matrix()
        self.assertEqual(mode, "exploratory")
        self.assertEqual(source, "PHASE13_SELECTED_PLUGINS")
        self.assertEqual([plugin["slug"] for plugin in matrix], ["gamipress"])
        self.assertEqual(matrix[0]["zip"], "gamipress.zip")

    def test_custom_matrix_path_uses_local_zip_defaults(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "matrix.json"
            path.write_text(json.dumps({"plugins": [{"slug": "gamipress"}]}), encoding="utf-8")
            self._env(PHASE13_MATRIX_PATH=str(path), PHASE13_RUN_MODE="exploratory")
            mode, matrix, source = RUNNER.load_plugin_matrix()
            self.assertEqual(mode, "exploratory")
            self.assertEqual(source, str(path))
            self.assertEqual(matrix[0]["slug"], "gamipress")

    def test_missing_selected_plugin_zip_fails_closed(self):
        self._env(PHASE13_SELECTED_PLUGINS="definitely-missing-phase13-plugin")
        with self.assertRaisesRegex(RuntimeError, "plugin_zip_missing"):
            RUNNER.load_plugin_matrix()

    def test_zip_version_reads_plugin_header_without_matrix_version(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "demo.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("demo/demo.php", "<?php\n/*\nPlugin Name: Demo\nVersion: 1.2.3\n*/\n")
            self.assertEqual(RUNNER.zip_version(path, "demo"), "1.2.3")

    def test_zip_metadata_reads_main_file_when_name_differs_from_slug(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "demo.zip"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr("demo/bt-comments.php", "<?php\n/*\nPlugin Name: Demo\nVersion: 7.0.0\n*/\n")
            self.assertEqual(RUNNER.zip_metadata(path, "demo"), {"version": "7.0.0", "plugin_main_file": "demo/bt-comments.php"})

    def test_exploratory_gates_do_not_require_canonical_matrix_or_cf7(self):
        gates = RUNNER.phase13_required_gates("exploratory")
        self.assertNotIn("plugin_matrix_has_at_least_3_real_plugins", gates)
        self.assertNotIn("authenticated_replay_confirmed", gates)
        self.assertNotIn("phase9_regression_passed", gates)
        self.assertIn("public_replay_confirmed", gates)

    def test_public_selection_prefers_replayable_public_get(self):
        catalog = {"records": [
            {"ownership": "plugin", "authentication": "public", "methods": ["POST"], "limitations": [], "route": "/b", "callback": "b", "schema_parameters": []},
            {"ownership": "plugin", "authentication": "public", "methods": ["GET"], "limitations": [], "route": "/x/(?P<bad>[a-z]+)", "callback": "x", "schema_parameters": []},
            {"ownership": "plugin", "authentication": "public", "methods": ["GET"], "limitations": [], "route": "/a", "callback": "a", "schema_parameters": []},
        ]}
        self.assertEqual(RUNNER.select_public_target(catalog)["route"], "/a")

    def test_public_selection_allows_runtime_classified_unresolved(self):
        catalog = {"records": [
            {"ownership": "plugin", "authentication": "unresolved", "methods": ["GET"], "limitations": [], "route": "/wp/v2/items", "callback": "Items::get", "schema_parameters": []},
        ]}
        self.assertEqual(RUNNER.select_public_target(catalog)["route"], "/wp/v2/items")

    def test_request_id_is_fresh_and_scoped(self):
        one = RUNNER.fresh_request_id("run", "plugin", "public")
        two = RUNNER.fresh_request_id("run", "plugin", "public")
        self.assertNotEqual(one, two)
        self.assertTrue(one.startswith("run-plugin-public-"))

    def _record(self, root: Path, *, run_id: str = "run", plugin: str = "plugin", request_id: str = "req", method: str = "GET", route: str = "/plugin/v1/item", callback: str = "Plugin::items") -> dict:
        config = root / "config.json"
        config.write_text(json.dumps({"metadata": {"plugin": plugin, "plugin_version": "1.0", "route": route, "method": method, "callback": callback, "request_id": request_id, "replay_run_id": run_id}}), encoding="utf-8")
        runtime = root / "plugins" / plugin / "runtime" / f"{request_id}.json"
        runtime.parent.mkdir(parents=True)
        runtime.write_text(json.dumps({"request_id": request_id, "method": method, "route_callback_invocations": [{"route": route, "callable": callback}]}), encoding="utf-8")
        return {"phase13_run_id": run_id, "plugin_slug": plugin, "plugin_version": "1.0", "config_path": str(config), "config_sha256": RUNNER.sha(config), "route": route, "http_method": method, "request_id": request_id, "entrypoint_callback": callback, "authentication_mode": "public", "runtime_artifact_path": str(runtime), "runtime_artifact_sha256": RUNNER.sha(runtime), "request_marker": None, "timestamp": "2026-08-05T00:00:00Z"}

    def test_valid_correlation_passes(self):
        with tempfile.TemporaryDirectory() as temp:
            ok, errors = RUNNER.validate_correlations([self._record(Path(temp))], "run", int(time.time()) - 10)
            self.assertTrue(ok, errors)

    def test_wrong_plugin_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            row = self._record(Path(temp))
            row["plugin_slug"] = "other"
            ok, errors = RUNNER.validate_correlations([row], "run", int(time.time()) - 10)
            self.assertFalse(ok)
            self.assertTrue(any("artifact_from_another_plugin" in error or "config_plugin_mismatch" in error for error in errors))

    def test_wrong_request_id_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            row = self._record(Path(temp))
            row["request_id"] = "wrong"
            ok, errors = RUNNER.validate_correlations([row], "run", int(time.time()) - 10)
            self.assertFalse(ok)
            self.assertTrue(any("wrong_request_id" in error for error in errors))

    def test_wrong_method_or_route_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            row = self._record(Path(temp))
            row["http_method"] = "POST"
            ok, errors = RUNNER.validate_correlations([row], "run", int(time.time()) - 10)
            self.assertFalse(ok)
            self.assertTrue(any("wrong_method" in error or "config_method_mismatch" in error for error in errors))

    def test_after_callbacks_dispatch_counts_as_runtime_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            row = self._record(root)
            runtime = Path(row["runtime_artifact_path"])
            runtime.write_text(json.dumps({"request_id": "req", "method": "GET", "route_callback_invocations": [], "rest_dispatch": [{"route": "/plugin/v1/item", "callback": "Plugin::items", "stage": "after_callbacks"}]}), encoding="utf-8")
            row["runtime_artifact_sha256"] = RUNNER.sha(runtime)
            ok, errors = RUNNER.validate_correlations([row], "run", int(time.time()) - 10)
            self.assertTrue(ok, errors)

    def test_stale_artifact_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            row = self._record(Path(temp))
            os.utime(row["runtime_artifact_path"], (1, 1))
            ok, errors = RUNNER.validate_correlations([row], "run", int(time.time()) - 10)
            self.assertFalse(ok)
            self.assertTrue(any("stale_runtime_artifact" in error for error in errors))

    def test_negative_suite_rejects_partial_aggregate(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            row = self._record(root)
            result = RUNNER.negative_correlation_tests([row], "run", int(time.time()) - 10, root)
            self.assertTrue(result["passed"])
            self.assertTrue(result["tests"]["missing_runtime_evidence"])


if __name__ == "__main__":
    unittest.main()
