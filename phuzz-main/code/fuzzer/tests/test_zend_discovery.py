from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from zend_discovery.engine import (
    BLOCKED_NEEDS_RECIPE,
    BLOCKED_UNSAFE_AUTO_PROBE,
    build_catalog,
    correlate_artifact,
    read_plugin_metadata,
    run_discovery,
    select_auto_probes,
)
from zend_discovery.source_materializer import materialize_plugin_source
from zend_discovery.parameter_seeds import build_parameter_seed
from hook_energy.seed_generation.input_extractor import InputSignatureExtractor


class StaticExtractor:
    def __init__(self, input_params: list[dict]) -> None:
        self.input_params = input_params

    def extract(self, callback: dict) -> dict:
        return {"input_params": self.input_params}


class ZendDiscoveryTests(unittest.TestCase):
    def make_plugin_zip(self, root: Path) -> Path:
        plugin = root / "demo-plugin.zip"
        with zipfile.ZipFile(plugin, "w") as archive:
            archive.writestr(
                "demo-plugin/demo-plugin.php",
                "<?php\n/*\n * Plugin Name: Demo Plugin\n * Version: 1.2.3\n */\n",
            )
            archive.writestr(
                "demo-plugin/ajax.php",
                "<?php\nfunction demo_fetch_items() {\n    $term = $_POST['term'];\n}\n",
            )
        return plugin

    def registry(self) -> dict:
        return {
            "hook_coverage": {
                "registered_callbacks": {
                    "ajax-public": {
                        "callback_id": "ajax-public",
                        "hook_name": "wp_ajax_nopriv_demo_fetch_items",
                        "callback_repr": "Demo::fetch",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/ajax.php",
                        "input_params": [{"name": "term", "source": "POST"}],
                    },
                    "rest-get": {
                        "callback_id": "rest-get",
                        "entrypoint_type": "rest_route",
                        "namespace": "demo/v1",
                        "route": "/items",
                        "methods": ["GET", "POST"],
                        "callback_repr": "Demo::items",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/rest.php",
                    },
                    "ajax-write": {
                        "callback_id": "ajax-write",
                        "hook_name": "wp_ajax_nopriv_demo_save",
                        "callback_repr": "Demo::save",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/ajax.php",
                    },
                    "core": {
                        "callback_id": "core",
                        "hook_name": "wp_ajax_nopriv_core_fetch",
                        "callback_repr": "Core::fetch",
                        "source_file": "/var/www/html/wp-includes/core.php",
                    },
                }
            }
        }

    def test_zip_metadata_requires_selected_slug_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin = self.make_plugin_zip(Path(tmp_dir))
            metadata = read_plugin_metadata(plugin, "demo-plugin")

            self.assertEqual(metadata["slug"], "demo-plugin")
            self.assertEqual(metadata["version"], "1.2.3")
            self.assertEqual(metadata["main_file"], "demo-plugin/demo-plugin.php")
            self.assertEqual(metadata["sha256"], hashlib.sha256(plugin.read_bytes()).hexdigest())

    def test_materialize_plugin_source_rejects_zip_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = root / "demo-plugin.zip"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr("demo-plugin/../../escape.php", "<?php")

            with self.assertRaisesRegex(ValueError, "PLUGIN_ZIP_UNSAFE_MEMBER"):
                materialize_plugin_source(plugin, "demo-plugin", root / "source")

    def test_materialize_plugin_source_maps_container_callback_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = root / "demo-plugin.zip"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr("demo-plugin/ajax.php", "<?php\n")

            source_root = materialize_plugin_source(plugin, "demo-plugin", root / "source")

            self.assertEqual(source_root / "ajax.php", root / "source" / "demo-plugin" / "ajax.php")
            self.assertTrue((source_root / "ajax.php").is_file())

    def test_ajax_seed_merges_literal_post_read_into_body_fuzz_parameter(self) -> None:
        endpoint = {"callback_id": "ajax-public", "kind": "ajax", "method": "POST"}
        callback = {
            "callback_id": "ajax-public",
            "source_file": "unused.php",
        }
        artifact = {"request_params": {}}
        extractor = StaticExtractor([{"name": "term", "source": "POST", "location": "body"}])

        seed = build_parameter_seed(endpoint, callback, artifact, extractor)

        self.assertEqual(
            seed["parameters"],
            [{"name": "term", "location": "body", "fuzzable": True, "evidence": ["static:POST"]}],
        )

    def test_rest_get_seed_uses_declared_route_method_and_query_location(self) -> None:
        endpoint = {"callback_id": "rest-get", "kind": "rest", "methods": ["GET", "POST"]}
        callback = {
            "callback_id": "rest-get",
            "argument_definitions": {"page": {"required": False}},
        }
        artifact = {"request_params": {"query_params": {"page": "redacted"}}}

        seed = build_parameter_seed(endpoint, callback, artifact, StaticExtractor([]))

        self.assertEqual(seed["method"], "GET")
        self.assertEqual(seed["parameters"][0]["name"], "page")
        self.assertEqual(seed["parameters"][0]["location"], "query")

    def test_nonce_cookie_and_secret_names_are_blocked_not_fuzzed(self) -> None:
        endpoint = {"callback_id": "ajax-public", "kind": "ajax", "method": "POST"}
        callback = {"callback_id": "ajax-public"}
        extractor = StaticExtractor(
            [
                {"name": "nonce", "source": "POST", "location": "body", "role": "security_nonce"},
                {"name": "session_token", "source": "COOKIE", "location": "cookie"},
            ]
        )

        seed = build_parameter_seed(endpoint, callback, {"request_params": {}}, extractor)

        self.assertEqual(seed["parameters"], [])
        self.assertEqual({row["name"] for row in seed["blocked_parameters"]}, {"nonce", "session_token"})

    def test_catalog_keeps_only_selected_plugin_and_normalizes_ajax_rest(self) -> None:
        catalog = build_catalog(self.registry(), "demo-plugin")

        self.assertEqual([item["callback_id"] for item in catalog], ["ajax-public", "rest-get", "ajax-write"])
        self.assertEqual(catalog[0]["kind"], "ajax")
        self.assertEqual(catalog[0]["action"], "demo_fetch_items")
        self.assertEqual(catalog[1]["route"], "/wp-json/demo/v1/items")
        self.assertEqual(catalog[1]["methods"], ["GET", "POST"])
        self.assertEqual(catalog[2]["ownership"], "target")

    def test_auto_probe_selects_safe_read_operations_and_blocks_others(self) -> None:
        catalog = build_catalog(self.registry(), "demo-plugin")
        selected = select_auto_probes(catalog)

        self.assertEqual([(item["callback_id"], item["method"]) for item in selected], [("ajax-public", "POST"), ("rest-get", "GET")])
        blocked = next(item for item in catalog if item["callback_id"] == "ajax-write")
        self.assertEqual(blocked["status"], BLOCKED_UNSAFE_AUTO_PROBE)

    def test_correlation_rejects_cross_plugin_and_accepts_exact_runtime_proof(self) -> None:
        endpoint = build_catalog(self.registry(), "demo-plugin")[0]
        artifact = {
            "run_id": "run-1",
            "request_id": "request-1",
            "target_plugin": "demo-plugin",
            "http_method": "POST",
            "http_target": "/wp-admin/admin-ajax.php?action=demo_fetch_items",
            "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
        }

        self.assertEqual(correlate_artifact(endpoint, artifact, "run-1", "demo-plugin")["request_id"], "request-1")
        artifact["target_plugin"] = "other-plugin"
        self.assertIsNone(correlate_artifact(endpoint, artifact, "run-1", "demo-plugin"))

    def test_run_writes_immutable_outputs_and_generates_config_only_from_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            request = self.registry()
            request.update(
                {
                    "run_id": "run-1",
                    "request_id": "request-1",
                    "target_plugin": "demo-plugin",
                    "http_method": "POST",
                    "http_target": "/wp-admin/admin-ajax.php?action=demo_fetch_items",
                    "hook_coverage": {
                        **request["hook_coverage"],
                        "executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}},
                    },
                }
            )
            summary = run_discovery(
                plugin_zip=plugin,
                plugin_slug="demo-plugin",
                run_id="run-1",
                registry=self.registry(),
                request_artifacts=[request],
                output_root=root / "output",
            )

            output = root / "output" / "run-1"
            self.assertEqual(summary["stages"]["integrity"], "PASS")
            self.assertEqual(summary["stages"]["replay"], "PASS")
            self.assertTrue((output / "run-summary.json").exists())
            self.assertTrue((output / "endpoint-catalog.json").exists())
            self.assertTrue((output / "runtime" / "request-1.json").exists())
            self.assertTrue((output / "configs" / "ajax-public.json").exists())
            self.assertTrue((output / "generated_config_summary.json").exists())
            config = json.loads((output / "configs" / "ajax-public.json").read_text(encoding="utf-8"))
            self.assertEqual(config["body_params"]["fixed"], ["action"])
            self.assertEqual(config["body_params"]["fuzz"], ["term"])

    def test_run_writes_seed_before_config_and_preserves_parameter_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            artifact = {
                "run_id": "run-1",
                "request_id": "request-1",
                "target_plugin": "demo-plugin",
                "http_method": "POST",
                "http_target": "/wp-admin/admin-ajax.php?action=demo_fetch_items",
                "request_params": {"body_params": {"term": "redacted"}},
                "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
            }

            run_discovery(plugin, "demo-plugin", "run-1", self.registry(), [artifact], root / "output")

            output = root / "output" / "run-1"
            seed = json.loads((output / "seeds" / "ajax-public.json").read_text(encoding="utf-8"))
            config = json.loads((output / "configs" / "ajax-public.json").read_text(encoding="utf-8"))
            self.assertEqual(seed["parameters"][0]["name"], "term")
            self.assertIn("static:POST", seed["parameters"][0]["evidence"])
            self.assertEqual(config["body_params"]["fuzz"], ["term"])

    def test_run_blocks_proven_callback_with_no_fuzzable_parameter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = root / "demo-plugin.zip"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr("demo-plugin/demo-plugin.php", "<?php\n/*\nPlugin Name: Demo Plugin\nVersion: 1.2.3\n*/\n")
                archive.writestr("demo-plugin/ajax.php", "<?php\ncheck_ajax_referer('demo', 'nonce');\n")
            artifact = {
                "run_id": "run-1",
                "request_id": "request-1",
                "target_plugin": "demo-plugin",
                "http_method": "POST",
                "http_target": "/wp-admin/admin-ajax.php?action=demo_fetch_items",
                "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
            }

            summary = run_discovery(plugin, "demo-plugin", "run-1", self.registry(), [artifact], root / "output")

            output = root / "output" / "run-1"
            endpoint = next(row for row in summary["endpoints"] if row["callback_id"] == "ajax-public")
            self.assertEqual(endpoint["status"], BLOCKED_NEEDS_RECIPE)
            self.assertFalse((output / "configs" / "ajax-public.json").exists())

    def test_recipe_rejects_secrets_and_unknown_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            recipe = root / "recipe.json"
            recipe.write_text(json.dumps({"selector": {"callback_id": "ajax-public"}, "password": "nope"}), encoding="utf-8")

            summary = run_discovery(plugin, "demo-plugin", "run-1", self.registry(), [], root / "output", recipe)

            self.assertEqual(summary["stages"]["recipe"], "FAILED")
            self.assertIn(BLOCKED_NEEDS_RECIPE, {item["status"] for item in summary["endpoints"]})

    def test_uopz_captures_zend_run_id_from_request_header(self) -> None:
        instrumentation = (
            FUZZER_DIR.parent / "web" / "instrumentation" / "hook_coverage" / "uopz_hook_wp.php"
        ).read_text(encoding="utf-8")

        self.assertIn("HTTP_X_ZEND_DISCOVERY_RUN_ID", instrumentation)
        self.assertIn("'run_id' =>", instrumentation)

    def test_engine_cli_runs_as_direct_script(self) -> None:
        result = subprocess.run(
            [sys.executable, str(FUZZER_DIR / "zend_discovery" / "engine.py"), "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Build Zend discovery artifacts", result.stdout)

    def test_engine_cli_accepts_powershell_utf8_bom_registry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            registry_path = root / "registry.json"
            probe_plan = root / "probe-plan.json"
            registry_path.write_text(json.dumps(self.registry()), encoding="utf-8-sig")

            result = subprocess.run(
                [
                    sys.executable,
                    str(FUZZER_DIR / "zend_discovery" / "engine.py"),
                    "--plugin-zip",
                    str(self.make_plugin_zip(root)),
                    "--plugin-slug",
                    "demo-plugin",
                    "--run-id",
                    "run-1",
                    "--registry",
                    str(registry_path),
                    "--write-probe-plan",
                    str(probe_plan),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(probe_plan.exists())


if __name__ == "__main__":
    unittest.main()
