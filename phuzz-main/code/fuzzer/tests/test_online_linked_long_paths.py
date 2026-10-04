"""Real filesystem regressions for deep online config and evidence paths."""

import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.online_common import _write_exclusive_json, _write_json, config_hash
from hook_energy.seed_generation.generated_config_runner import read_correlated_artifact_pair
from hook_energy.seed_generation.zend_runtime.bridge_cli import _read_json
from online_linked.coordinator import OnlineLinkedCoordinator
from online_linked.export import export_online_linked_batch
from seed_generation.config.config_exporter import export_seed_configs
from test_seed_to_config_exporter import build_seed_item


def test_native(path):
    # Independent setup/assertion path: do not use the production conversion.
    return Path("\\\\?\\" + os.path.abspath(path)) if os.name == "nt" else Path(path)


class OnlineLinkedLongPathTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="hp-path-"))
        self.addCleanup(shutil.rmtree, test_native(self.root))

    def directory(self, length, *, unicode=False):
        path = self.root / ("thư mục" if unicode else "paths")
        while len(str(path)) < length:
            remaining = length - len(str(path)) - 1
            if remaining <= 0:
                break
            path /= "d" * min(60, remaining)
        self.assertEqual(len(str(path)), length)
        return path

    def test_exclusive_and_atomic_json_at_windows_boundaries(self):
        for length in (240, 259, 260, 261, 286, 350, 512, 1024):
            with self.subTest(length=length):
                path = self.directory(length - len("/state.json"), unicode=True) / "state.json"
                self.assertEqual(len(str(path)), length)
                _write_exclusive_json(path, {"value": "Tiếng Việt", "count": 0})
                with self.assertRaises(FileExistsError):
                    _write_exclusive_json(path, {"value": "overwrite"})
                self.assertEqual(json.loads(test_native(path).read_text(encoding="utf-8")), {"value": "Tiếng Việt", "count": 0})
                _write_json(path, {"replacement": False})
                self.assertEqual(_read_json(path), {"replacement": False})
                self.assertFalse(test_native(path.with_name(path.name + ".tmp")).exists())

    def test_export_and_param_summary_with_deep_roots(self):
        for length in (220, 259, 260, 286, 350, 512):
            with self.subTest(length=length):
                output = self.directory(length) / "configs" / "online-linked" / "fixture"
                summary_path = output.parent / "generated_config_summary.json"
                summary = export_seed_configs(
                    {"suggested_seeds": [build_seed_item()]},
                    output_config_dir=output, summary_path=summary_path,
                )
                row = summary["generated"][0]
                path = Path(row["config_path"])
                self.assertFalse(str(path).startswith("\\\\?\\"))
                self.assertEqual(json.loads(test_native(path).read_text(encoding="utf-8"))["body_params"]["fuzz"], ["item_id"])
                params = json.loads(test_native(summary_path.with_name("generated_param_summary.json")).read_text(encoding="utf-8"))
                self.assertTrue(params["configs"][0]["has_fuzz_params"])
                self.assertEqual(json.loads(test_native(summary_path).read_text(encoding="utf-8")), summary)

    def test_final_export_reads_deep_state_and_preserves_bytes(self):
        for length in (259, 286, 350, 512):
            with self.subTest(length=length):
                root = self.directory(length)
                config_path = root / "versions" / "v1" / "v1-config.json"
                from seed_generation.config.config_exporter import build_config_for_seed_item
                config = build_config_for_seed_item(build_seed_item())[1]
                content = (json.dumps(config, ensure_ascii=False, indent=2) + "\n").encode()
                test_native(config_path.parent).mkdir(parents=True, exist_ok=True)
                test_native(config_path).write_bytes(content)
                state_path = root / "state.json"
                _write_json(state_path, {
                    "legacy_run_id": "candidate-1", "plugin_slug": "fixture",
                    "versions": [{
                        "version": "v1", "config_path": str(config_path),
                        "config_type": "fuzzing_ready", "config_hash": config_hash(config),
                        "replay_result": {"passed": True, "pass2_verification": {"accepted": 1, "total": 1}},
                    }],
                })
                batch = root / "batch-state.json"
                _write_json(batch, {"plugin_slug": "fixture", "candidates": [{
                    "identity": "fixture|callback|POST", "run_id": "candidate-1",
                    "hook_name": "wp_ajax_fixture", "state_path": str(state_path),
                }]})
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(export_online_linked_batch(batch), 1)
                files = list(test_native(root / "final-configs").glob("*.json"))
                self.assertEqual(len(files), 1)
                self.assertEqual(files[0].read_bytes(), content)
                with self.assertRaises(FileExistsError):
                    export_online_linked_batch(batch)

    def test_coordinator_mirror_and_registry_read_with_deep_root(self):
        root = self.directory(350, unicode=True)
        registry = root / "registry.json"
        test_native(registry.parent).mkdir(parents=True)
        test_native(registry).write_text('{"callback_map": {}}')
        coordinator = OnlineLinkedCoordinator(
            suggested_seeds=root / "suggested.json", registry_path=registry,
            config_root=root / "configs", output_root=root / "output",
            plugin_slug="all-in-one-wp-security-and-firewall", legacy_run_id="run-" + "x" * 120,
            max_seconds=60, max_versions=5,
        )
        payload = {"metadata": {"callback_repr": "fixture"}, "value": "Tiếng Việt"}
        path = coordinator._write_config("v0", payload)
        self.assertFalse(str(path).startswith("\\\\?\\"))
        self.assertEqual(_read_json(path), payload)
        self.assertEqual(_read_json(coordinator.run_dir / "versions/v0/v0-config.json"), payload)
        coordinator._record_event({"kind": "PATH_TEST", "status": "PASS"})
        self.assertEqual(_read_json(coordinator.state_path)["events"][0]["kind"], "PATH_TEST")

    def test_compact_export_names_keep_identity_and_do_not_collide(self):
        items = [build_seed_item(hook_name="wp_ajax_" + "x" * 180) for _ in range(2)]
        items[1]["seed"]["seed_variant_id"] = "post-other"
        original = copy.deepcopy(items)
        output = self.root / "configs"
        summary = export_seed_configs({"suggested_seeds": items}, output_config_dir=output, compact_names=True)
        paths = [Path(row["config_path"]) for row in summary["generated"]]
        self.assertEqual(len({path.name for path in paths}), 2)
        for path, item in zip(paths, items):
            self.assertLessEqual(len(path.name), 32)
            self.assertEqual(json.loads(test_native(path).read_text())["metadata"]["hook_name"], item["hook_name"])
        self.assertEqual(items, original)

    def test_request_ids_are_short_stable_and_distinct_across_phases(self):
        from online_linked.coordinator import _request_id
        for length in (30, 120, 260, 512, 1024):
            with self.subTest(length=length):
                run = "r" * length
                phases = [run + suffix for suffix in ("-probe-p1", "-probe-p2", "-replay", "-trial-t0")]
                ids = [_request_id(phase) for phase in phases]
                self.assertEqual(len(set(ids)), 4)
                for phase, request_id in zip(phases, ids):
                    self.assertLessEqual(len(request_id + ".json"), 32)
                    self.assertEqual(_request_id(phase), request_id)
                    self.assertRegex(request_id, r"^[A-Za-z0-9_-]+$")

    def test_preflight_checks_deep_directory_and_explains_invalid_root(self):
        from filesystem_paths import check_directory_io
        root = self.directory(512, unicode=True)
        check_directory_io(root)
        self.assertEqual(list(test_native(root).iterdir()), [])
        blocked = self.root / "a-file"
        blocked.write_text("keep", encoding="utf-8")
        with self.assertRaisesRegex(OSError, "FILESYSTEM_PATH_UNSUPPORTED.*operation=mkdir.*path_length="):
            check_directory_io(blocked / "child")
        self.assertEqual(blocked.read_text(encoding="utf-8"), "keep")

    def test_deep_request_zend_pair_keeps_strict_correlation(self):
        from online_linked.coordinator import _request_id
        run_id = "all-in-one-wp-security-and-firewall-" + "x" * 260
        request_id = _request_id(run_id + "-probe-p1")
        for length in (259, 260, 286, 350, 512):
            with self.subTest(length=length):
                root = self.directory(length)
                request_dir, zend_dir = root / "request", root / "zend"
                request = {
                    "request_id": request_id, "run_id": run_id,
                    "target_plugin": "fixture", "http_method": "POST", "auth_context": "guest",
                    "hook_name": "wp_ajax_fixture", "callback_id": "cb-fixture",
                    "response": {"status_code": 200},
                }
                zend = {"request_id": request_id, "run_id": run_id}
                _write_json(request_dir / (request_id + ".json"), request)
                _write_json(zend_dir / (request_id + ".json"), zend)
                expected = {"plugin_slug": "fixture", "method": "POST", "auth_context": "guest",
                            "hook_name": "wp_ajax_fixture", "callback_id": "cb-fixture"}
                pair = read_correlated_artifact_pair(
                    request_dir, zend_dir, request_id=request_id, run_id=run_id, expected=expected,
                )
                self.assertIsNotNone(pair)
                self.assertEqual(pair["request"], request)
                self.assertEqual(pair["zend"], zend)
                self.assertEqual(pair["request_name"], request_id + ".json")
                zend["run_id"] = "other-run"
                _write_json(zend_dir / (request_id + ".json"), zend)
                self.assertIsNone(read_correlated_artifact_pair(
                    request_dir, zend_dir, request_id=request_id, run_id=run_id, expected=expected,
                ))

    def test_preflight_failure_stops_before_docker(self):
        blocked = self.root / "config-file"
        blocked.write_text("keep", encoding="utf-8")
        def unexpected_docker(*args, **kwargs):
            self.fail("Docker must not start after a filesystem preflight failure")
        coordinator = OnlineLinkedCoordinator(
            suggested_seeds=self.root / "missing.json", registry={},
            config_root=blocked / "child", output_root=self.root / "output",
            plugin_slug="fixture", legacy_run_id="preflight", max_seconds=60, max_versions=2,
            run_command=unexpected_docker,
        )
        from contextlib import redirect_stderr
        with redirect_stderr(io.StringIO()):
            self.assertEqual(coordinator.run(), 2)
        self.assertEqual(coordinator.state["terminal_status"], "NOT_VERIFIED")
        self.assertIn("FILESYSTEM_PATH_UNSUPPORTED", coordinator.state["terminal_reason"])
        self.assertEqual(blocked.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(os.name == "nt", "Windows path syntax")
    def test_windows_conversion_handles_unc_relative_and_existing_prefix(self):
        from filesystem_paths import filesystem_path
        relative = Path("relative") / ".." / "thư mục" / "state.json"
        expected = Path("\\\\?\\" + str(Path.cwd() / "thư mục" / "state.json"))
        self.assertEqual(filesystem_path(relative), expected)
        self.assertEqual(filesystem_path(expected), expected)
        self.assertEqual(filesystem_path("\\\\server\\share\\folder\\state.json"),
                         Path("\\\\?\\UNC\\server\\share\\folder\\state.json"))


if __name__ == "__main__":
    unittest.main()
