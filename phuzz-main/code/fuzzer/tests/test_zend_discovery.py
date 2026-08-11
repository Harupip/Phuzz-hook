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
    canonical_identity,
    canonical_identity_id,
    correlate_artifact,
    correlate_pass1_artifact,
    enrich_current_run,
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
    def pass1_candidate(self) -> dict:
        return {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "ajax",
            "action": "demo_fetch_items",
            "callback_id": "ajax-public",
            "method": "post",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "pass1-1",
        }

    def pass1_artifact(self, candidate: dict, **updates: object) -> dict:
        artifact = {
            "legacy_run_id": candidate["legacy_run_id"],
            "request_id": candidate["pass1_request_id"],
            "target_plugin": candidate["plugin_slug"],
            "canonical_identity_id": canonical_identity_id(candidate),
            "callback_id": candidate["callback_id"],
            "http_method": candidate["method"].upper(),
            "auth_variant": "unauthenticated",
            "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
        }
        artifact.update(updates)
        return artifact

    def test_canonical_identity_is_deterministic_and_excludes_callback_display(self) -> None:
        candidate = self.pass1_candidate()
        candidate["callback_repr"] = "Demo::fetch"

        self.assertEqual(
            canonical_identity(candidate),
            {
                "plugin_slug": "demo-plugin",
                "entrypoint_type": "ajax",
                "dispatch_identity": {"dispatcher": "ajax", "action": "demo_fetch_items"},
                "callback_identity": "ajax-public",
                "resolved_method": "POST",
                "auth_variant": "unauthenticated",
            },
        )
        candidate["callback_repr"] = "Renamed::display_only"
        self.assertEqual(canonical_identity_id(candidate), canonical_identity_id(self.pass1_candidate()))
        self.assertEqual(
            canonical_identity(
                {
                    "plugin_slug": "demo-plugin",
                    "entrypoint_type": "rest",
                    "namespace": "demo/v1",
                    "route_pattern": "/items/(?P<id>\\d+)",
                    "endpoint_definition_index": 2,
                    "materialized_route": "/wp-json/demo/v1/items/7",
                    "callback_id": "rest-items",
                    "resolved_method": "get",
                    "auth_variant": "authenticated",
                }
            )["dispatch_identity"],
            {
                "namespace": "demo/v1",
                "route_pattern": "/items/(?P<id>\\d+)",
                "endpoint_definition_index": 2,
                "materialized_route": "/wp-json/demo/v1/items/7",
            },
        )

    def test_pass1_correlation_requires_exact_identity_fields_and_callback_proof(self) -> None:
        candidate = self.pass1_candidate()
        identity_id = canonical_identity_id(candidate)
        artifact = {
            "legacy_run_id": "legacy-1",
            "request_id": "pass1-1",
            "target_plugin": "demo-plugin",
            "canonical_identity_id": identity_id,
            "callback_id": "ajax-public",
            "http_method": "POST",
            "auth_variant": "unauthenticated",
            "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
        }

        self.assertIs(
            correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            ),
            artifact,
        )
        for field, wrong_value in (
            ("legacy_run_id", "other-run"),
            ("request_id", "other-request"),
            ("target_plugin", "other-plugin"),
            ("canonical_identity_id", "0" * 64),
            ("callback_id", "other-callback"),
            ("http_method", "GET"),
            ("auth_variant", "authenticated"),
        ):
            rejected = dict(artifact)
            rejected[field] = wrong_value
            self.assertIsNone(
                correlate_pass1_artifact(
                    candidate,
                    rejected,
                    legacy_run_id="legacy-1",
                    pass1_request_id="pass1-1",
                    plugin_slug="demo-plugin",
                ),
                field,
            )
        rejected = dict(artifact)
        rejected["hook_coverage"] = {"executed_callbacks": {}}
        self.assertIsNone(
            correlate_pass1_artifact(
                candidate,
                rejected,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )
        legacy_artifact = dict(artifact)
        legacy_artifact.pop("legacy_run_id")
        legacy_artifact["run_id"] = "legacy-1"
        self.assertIsNotNone(
            correlate_pass1_artifact(
                candidate,
                legacy_artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )

    def test_pass1_rejects_unknown_auth_but_normalizes_unauth_capable(self) -> None:
        candidate = self.pass1_candidate()
        candidate.pop("auth_mode")
        self.assertEqual(canonical_identity(candidate)["auth_variant"], "unresolved")
        artifact = self.pass1_artifact(candidate)
        artifact["auth_variant"] = "unresolved"
        self.assertIsNone(
            correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )
        candidate["auth_mode"] = "unauth-capable"
        self.assertEqual(canonical_identity(candidate)["auth_variant"], "unauthenticated")

    def test_enrichment_ignores_runtime_fields_from_rejected_artifact(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(
            candidate,
            target_plugin="other-plugin",
            request_params={"query_params": {"untrusted_runtime_field": "must-not-import"}},
        )

        seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertNotIn("untrusted_runtime_field", {row["name"] for row in seed["parameters"]})

    def test_enrichment_requires_callback_identity_before_extraction(self) -> None:
        candidate = self.pass1_candidate()

        seed = enrich_current_run(
            candidate,
            {"callback_id": "wrong-callback"},
            self.pass1_artifact(candidate),
            StaticExtractor([{"name": "term", "source": "POST"}]),
        )

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertEqual(seed["parameters"], [])

    def test_enrichment_blocks_body_params_without_explicit_transport_type(self) -> None:
        candidate = self.pass1_candidate()
        absent_type = self.pass1_artifact(
            candidate,
            request_params={"body_params": {"unknown_body": "value"}},
        )
        unsupported_type = self.pass1_artifact(
            candidate,
            request_content_type="text/plain",
            request_params={"body_params": {"plain_body": "value"}},
        )

        absent_seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, absent_type, StaticExtractor([]))
        unsupported_seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, unsupported_type, StaticExtractor([]))

        for seed in (absent_seed, unsupported_seed):
            self.assertFalse(seed["final_fuzz_export_allowed"])
            self.assertEqual(seed["parameters"][0]["location"], "unknown")
            self.assertTrue(seed["parameters"][0]["blocked"])
            self.assertEqual(seed["parameters"][0]["blocked_reason"], "unresolved_location")

    def test_enrichment_rejects_body_content_type_substring_matches(self) -> None:
        candidate = self.pass1_candidate()
        json_like = self.pass1_artifact(
            candidate,
            request_content_type="text/plain; profile=json",
            request_params={"body_params": {"json_like": "value"}},
        )
        form_like = self.pass1_artifact(
            candidate,
            request_content_type="text/plain; note=multipart/form-data",
            request_params={"body_params": {"form_like": "value"}},
        )

        for artifact in (json_like, form_like):
            seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))
            self.assertFalse(seed["final_fuzz_export_allowed"])
            self.assertEqual(seed["parameters"][0]["location"], "unknown")
            self.assertTrue(seed["parameters"][0]["blocked"])
            self.assertEqual(seed["parameters"][0]["blocked_reason"], "unresolved_location")

    def test_enrichment_resolves_direct_current_run_get_and_post_only(self) -> None:
        get_candidate = self.pass1_candidate()
        get_candidate["method"] = "GET"
        get_artifact = self.pass1_artifact(get_candidate)
        callback = {"callback_id": "ajax-public"}
        extractor = StaticExtractor([{"name": "search", "source": "GET"}, {"name": "term", "source": "POST"}])

        get_seed = enrich_current_run(get_candidate, callback, get_artifact, extractor)

        self.assertTrue(get_seed["probe_replay_allowed"])
        self.assertTrue(get_seed["final_fuzz_export_allowed"])
        self.assertEqual(get_seed["parameters"][0]["location"], "query")
        post = next(row for row in get_seed["parameters"] if row["name"] == "term")
        self.assertEqual(post["location"], "unknown")
        self.assertTrue(post["blocked"])
        self.assertEqual(post["blocked_reason"], "unresolved_location")

        post_candidate = self.pass1_candidate()
        post_seed = enrich_current_run(
            post_candidate,
            callback,
            self.pass1_artifact(post_candidate),
            StaticExtractor([{"name": "term", "source": "POST"}]),
        )
        self.assertEqual(post_seed["parameters"][0]["location"], "form")
        self.assertFalse(post_seed["parameters"][0]["blocked"])

    def test_enrichment_uses_runtime_query_form_and_json_without_values(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(
            candidate,
            request_params={
                "query_params": {"page": "this-value-must-not-persist"},
                "form_params": {"term": "also-secret-submitted-value"},
                "json_params": {"payload": {"nested": "private"}},
            },
        )

        seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))

        by_name = {row["name"]: row for row in seed["parameters"]}
        self.assertEqual(by_name["page"]["location"], "query")
        self.assertEqual(by_name["term"]["location"], "form")
        self.assertEqual(by_name["payload"]["location"], "json")
        self.assertEqual(by_name["payload"]["safe_observed_type"], "object")
        self.assertTrue(by_name["term"]["redacted_value_metadata"]["redacted"])
        encoded = json.dumps(seed, sort_keys=True)
        self.assertNotIn("this-value-must-not-persist", encoded)
        self.assertNotIn("also-secret-submitted-value", encoded)
        self.assertNotIn("private", encoded)

    def test_enrichment_blocks_schema_get_param_request_and_method_only_evidence(self) -> None:
        candidate = self.pass1_candidate()
        callback = {
            "callback_id": "ajax-public",
            "argument_definitions": {"schema_only": {"required": False}},
        }
        extractor = StaticExtractor(
            [
                {"name": "via_get_param", "source": "REST_GET_PARAM"},
                {"name": "via_request", "source": "REQUEST"},
                {"name": "method_only", "source": "METHOD"},
            ]
        )

        seed = enrich_current_run(candidate, callback, self.pass1_artifact(candidate), extractor)

        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertEqual({row["location"] for row in seed["parameters"]}, {"unknown"})
        self.assertTrue(all(row["blocked"] for row in seed["parameters"]))
        evidence_kinds = {
            evidence["kind"]
            for row in seed["parameters"]
            for evidence in row["evidence"]
        }
        self.assertEqual(
            evidence_kinds,
            {"rest_schema_declared", "rest_get_param_name_only", "static_candidate", "zend_superglobal_read"},
        )

    def test_enrichment_blocks_sensitive_names_and_invalid_pass1_proof(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(candidate)
        artifact["hook_coverage"] = {"executed_callbacks": {}}

        seed = enrich_current_run(
            candidate,
            {"callback_id": "ajax-public"},
            artifact,
            StaticExtractor([{"name": "session_token", "source": "POST"}]),
        )

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        parameter = seed["parameters"][0]
        self.assertTrue(parameter["blocked"])
        self.assertEqual(parameter["blocked_reason"], "security_field")
        self.assertEqual(seed["blocked_parameters"], [parameter])

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
