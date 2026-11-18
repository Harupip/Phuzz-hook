from __future__ import annotations

import base64
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy import bootstrap_entry_discovery as bootstrap
from hook_energy.seed_generation.generated_config_runner import load_request_artifact
from seed_generation.verification.seed_validator import _collect_observed_payloads, evaluate_artifact_payloads


def legacy_request():
    child = {
        "callback_id": "child", "hook_name": "wp_ajax_child", "callback_repr": "child_handler",
        "registered_inside_callback": True, "parent_callback_id": "parent", "hook_level": 2,
        "is_active": True, "status": "registered_only", "methods": ["POST"],
        "argument_definitions": {"id": {"type": "integer"}},
    }
    return {
        "schema_version": "uopz-request-v3", "request_id": "req-compact", "run_id": "run-compact",
        "http_method": "POST", "target_plugin": "fixture", "request_params": {"body_params": {"id": 0}},
        "hook_coverage": {
            "registered_callbacks": {
                "parent": {"callback_id": "parent", "hook_name": "wp_ajax_parent"},
                "child": child,
                "removed": {"callback_id": "removed", "is_active": False},
            },
            "executed_callbacks": {"parent": {"callback_id": "parent", "hook_name": "wp_ajax_parent"}},
            "blindspot_callbacks": {"child": copy.deepcopy(child)},
        },
        "blindspot_callback_ids": ["child"],
    }


def compact_request(payload):
    compact = copy.deepcopy(payload)
    compact["schema_version"] = "uopz-request-v4"
    del compact["hook_coverage"]["blindspot_callbacks"]
    return compact


class CompactReaderTests(unittest.TestCase):
    def test_validation_observations_are_identical_for_legacy_and_compact_requests(self):
        legacy = legacy_request()
        candidate = {"callback_id": "child", "hook_name": "wp_ajax_child"}
        self.assertEqual(_collect_observed_payloads([legacy]), _collect_observed_payloads([compact_request(legacy)]))
        self.assertEqual(
            evaluate_artifact_payloads(candidate, [legacy]),
            evaluate_artifact_payloads(candidate, [compact_request(legacy)]),
        )

    def test_fallback_registry_restores_full_blindspot_metadata(self):
        results = []
        for payload in (legacy_request(), compact_request(legacy_request())):
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "requests").mkdir()
                (root / "requests" / "req-compact.json").write_text(json.dumps(payload), encoding="utf-8")
                result = bootstrap._registry_from_request_artifacts(root)
                result.pop("generated_at")
                results.append(result)
        self.assertEqual(results[0], results[1])
        self.assertEqual(set(results[1]["data"]["blindspot_callbacks"]), {"child"})

    def test_missing_compact_reference_reports_request_and_callback(self):
        payload = compact_request(legacy_request())
        payload["blindspot_callback_ids"].append("missing")
        with self.assertRaisesRegex(ValueError, "req-compact.*missing"):
            evaluate_artifact_payloads({"callback_id": "child"}, [payload])

    def test_fallback_registry_preserves_legacy_callback_id_normalization(self):
        for alias, explicit_id in (("map-alias", "child"), ("child", None)):
            payload = legacy_request()
            descriptor = payload["hook_coverage"]["registered_callbacks"].pop("child")
            if explicit_id is None:
                descriptor.pop("callback_id")
            payload["hook_coverage"]["registered_callbacks"][alias] = descriptor
            payload["hook_coverage"]["blindspot_callbacks"] = {alias: copy.deepcopy(descriptor)}
            payload["blindspot_callback_ids"] = [alias]
            for artifact in (payload, compact_request(payload)):
                with self.subTest(alias=alias, schema=artifact["schema_version"]):
                    with tempfile.TemporaryDirectory() as tmp:
                        root = Path(tmp)
                        (root / "requests").mkdir()
                        (root / "requests/r.json").write_text(json.dumps(artifact), encoding="utf-8")
                        blindspots = bootstrap._registry_from_request_artifacts(root)["data"]["blindspot_callbacks"]
                    self.assertEqual(set(blindspots), {"child"})
                    self.assertEqual(blindspots["child"]["callback_id"], "child")

    def test_compact_ids_must_be_an_explicit_list(self):
        for identifiers in (None, "child", {"child": True}):
            payload = compact_request(legacy_request())
            payload["blindspot_callback_ids"] = identifiers
            with self.subTest(identifiers=identifiers):
                with self.assertRaisesRegex(ValueError, "REQUEST_BLINDSPOT_IDS_INVALID.*req-compact"):
                    evaluate_artifact_payloads({"callback_id": "child"}, [payload])
        del payload["blindspot_callback_ids"]
        with self.assertRaisesRegex(ValueError, "REQUEST_BLINDSPOT_IDS_INVALID.*req-compact"):
            evaluate_artifact_payloads({"callback_id": "child"}, [payload])

    @patch("hook_energy.seed_generation.generated_config_runner.subprocess.run")
    def test_malformed_json_error_identifies_the_artifact(self, run):
        run.return_value = subprocess.CompletedProcess([], 0, "", "")
        with self.assertRaisesRegex(RuntimeError, r"REQUEST_JSON_INVALID.*broken.json.*bytes=0"):
            load_request_artifact("broken.json")


@unittest.skipUnless(shutil.which("php") or os.environ.get("HOOKPHUZZ_REQUEST_TEST_CONTAINER"),
                     "requires PHP CLI or HOOKPHUZZ_REQUEST_TEST_CONTAINER")
class CompactPhpProducerTests(unittest.TestCase):
    def php(self, script):
        source = (FUZZER_DIR.parent / "web/instrumentation/hook_coverage/uopz_hook_wp.php").read_text(encoding="utf-8")
        start = source.index("function __uopz_write_json_atomic(")
        functions = source[start:source.index("// AGGREGATION", start)]
        command = [shutil.which("php"), "-n"] if shutil.which("php") else [
            "docker", "exec", "-i", os.environ["HOOKPHUZZ_REQUEST_TEST_CONTAINER"], "php", "-n",
        ]
        command += ["-d", "display_errors=0", "-d", "log_errors=1"]
        result = subprocess.run(command, input="<?php\n" + functions + "\n" + script,
                                capture_output=True, text=True, encoding="utf-8", timeout=20)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout), result.stderr

    def test_producer_compacts_only_blindspot_duplicates(self):
        payload = legacy_request()
        payload["schema_version"] = "uopz-request-v4"
        source = (FUZZER_DIR.parent / "web/instrumentation/hook_coverage/uopz_hook_wp.php").read_text(encoding="utf-8")
        self.assertIn("'schema_version' => 'uopz-request-v4'", source)
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        actual, _ = self.php(
            f"$GLOBALS['__uopz_request'] = json_decode(base64_decode('{encoded}'), true);\n"
            "echo json_encode(__uopz_build_request_export());"
        )
        self.assertEqual(actual["schema_version"], "uopz-request-v4")
        self.assertNotIn("blindspot_callbacks", actual["hook_coverage"])
        self.assertEqual(actual["blindspot_callback_ids"], ["child"])
        for field in ("registered_callbacks", "executed_callbacks"):
            self.assertEqual(actual["hook_coverage"][field], payload["hook_coverage"][field])
        self.assertEqual(actual["request_params"], payload["request_params"])
        self.assertEqual(actual["hook_coverage_summary"]["blindspot_callbacks"], 1)

    def test_writer_uses_compact_json_without_changing_values(self):
        actual, _ = self.php(
            "$path = tempnam(sys_get_temp_dir(), 'phuzz-compact-');\n"
            "__uopz_write_json_atomic($path, ['value' => [false, 0, null, 'Tiếng Việt']]);\n"
            "$raw = file_get_contents($path); unlink($path);\n"
            "echo json_encode(['raw' => $raw, 'decoded' => json_decode($raw, true)]);"
        )
        self.assertNotIn("\n", actual["raw"])
        self.assertEqual(actual["decoded"], {"value": [False, 0, None, "Tiếng Việt"]})

    def test_encoding_failure_preserves_existing_file_and_reports_path(self):
        actual, stderr = self.php(
            "$path = tempnam(sys_get_temp_dir(), 'phuzz-compact-'); file_put_contents($path, '{}');\n"
            "__uopz_write_json_atomic($path, ['bad' => \"\\xFF\"]);\n"
            "$raw = file_get_contents($path); unlink($path);\n"
            "echo json_encode(['raw' => $raw, 'path' => $path]);"
        )
        self.assertEqual(actual["raw"], "{}")
        self.assertIn("HOOKPHUZZ_ARTIFACT_JSON_ENCODE_FAILED", stderr)
        self.assertIn(actual["path"], stderr)

    def test_write_failure_reports_path_and_does_not_publish(self):
        actual, stderr = self.php(
            "$path = sys_get_temp_dir() . '/phuzz-missing-' . bin2hex(random_bytes(8)) . '/request.json';\n"
            "__uopz_write_json_atomic($path, ['ok' => true]);\n"
            "echo json_encode(['exists' => file_exists($path), 'path' => $path]);"
        )
        self.assertFalse(actual["exists"])
        self.assertIn("HOOKPHUZZ_ARTIFACT_WRITE_FAILED", stderr)
        self.assertIn(actual["path"], stderr)

    def test_rename_failure_reports_path_and_removes_temporary_file(self):
        actual, stderr = self.php(
            "$path = sys_get_temp_dir() . '/phuzz-rename-' . bin2hex(random_bytes(8)); mkdir($path);\n"
            "__uopz_write_json_atomic($path, ['ok' => true]);\n"
            "$temporary = glob($path . '.tmp.*'); $intact = is_dir($path); rmdir($path);\n"
            "echo json_encode(['intact' => $intact, 'temporary' => $temporary, 'path' => $path]);"
        )
        self.assertTrue(actual["intact"])
        self.assertEqual(actual["temporary"], [])
        self.assertIn("HOOKPHUZZ_ARTIFACT_RENAME_FAILED", stderr)
        self.assertIn(actual["path"], stderr)


def static_heavy_request():
    """Static callbacks repeat in every request and filled the 1 GB tmpfs (2026-11-18 run)."""
    payload = legacy_request()
    payload["schema_version"] = "uopz-request-v4"
    del payload["hook_coverage"]["blindspot_callbacks"]
    heavy = {
        "source_file": "/var/www/html/wp-content/plugins/fixture/fixture.php", "source_line": 10,
        "registered_from": "fixture.php:10", "registered_at": "2026-11-18T02:27:47+00:00",
        "endpoint": "ADMIN_AJAX:" + "x" * 200, "input_signature": "a" * 40, "request_id": "req-compact",
        "stable_id": "s" * 40, "runtime_id": "r" * 40, "callback_runtime_id": "c" * 40,
        "formal_parameters": [{"name": "arg", "position": 0, "optional": False}],
        "start_line": 10, "end_line": 40, "class_name": "Fixture", "method_name": "handler",
    }
    registered = payload["hook_coverage"]["registered_callbacks"]
    registered["parent"].update(heavy, type="action", priority=10, is_active=True, status="covered",
                                registered_inside_callback=False, hook_level=0, callback_repr="Fixture->parent")
    registered["static_blind"] = {
        **heavy, "callback_id": "static_blind", "hook_name": "wp_ajax_static", "type": "action", "priority": 5,
        "callback_repr": "Fixture->blind", "is_active": True, "status": "registered_only",
        "registered_inside_callback": False, "hook_level": 0,
    }
    registered["nested_level"] = {
        **heavy, "callback_id": "nested_level", "hook_name": "wp_ajax_nested", "is_active": True,
        "status": "registered_only", "registered_inside_callback": False, "hook_level": 1,
        "parent_callback_id": "parent",
    }
    payload["blindspot_callback_ids"] = ["child", "static_blind", "nested_level"]
    return payload


@unittest.skipUnless(shutil.which("php") or os.environ.get("HOOKPHUZZ_REQUEST_TEST_CONTAINER"),
                     "requires PHP CLI or HOOKPHUZZ_REQUEST_TEST_CONTAINER")
class CompactRegisteredCallbackTests(unittest.TestCase):
    """FUZZER_COMPACT_REQUEST_ARTIFACTS trims static descriptors without changing any decision."""

    php = CompactPhpProducerTests.php

    def export(self, payload, flag):
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        setenv = "" if flag is None else f"putenv('FUZZER_COMPACT_REQUEST_ARTIFACTS={flag}');\n"
        actual, _ = self.php(
            setenv + f"$GLOBALS['__uopz_request'] = json_decode(base64_decode('{encoded}'), true);\n"
            "echo json_encode(__uopz_build_request_export());"
        )
        return actual

    def test_static_descriptors_shrink_but_runtime_children_stay_full(self):
        payload = static_heavy_request()
        compact = self.export(payload, "1")["hook_coverage"]["registered_callbacks"]
        full = payload["hook_coverage"]["registered_callbacks"]
        # Runtime A->B discovery and child-hook summaries read every field of these entries.
        self.assertEqual(compact["child"], full["child"])
        self.assertEqual(compact["nested_level"], full["nested_level"])
        self.assertEqual(set(compact["static_blind"]), {
            "callback_id", "hook_name", "type", "priority", "callback_repr", "is_active", "status",
            "registered_inside_callback", "hook_level",
        })
        for callback_id in ("static_blind", "parent"):
            for field in compact[callback_id]:
                self.assertEqual(compact[callback_id][field], full[callback_id][field])
        self.assertEqual(compact["removed"], full["removed"])  # no heavy fields to drop
        self.assertLess(len(json.dumps(compact["static_blind"])), len(json.dumps(full["static_blind"])) / 3)

    def test_gate_observations_and_diagnostics_are_unchanged(self):
        payload = static_heavy_request()
        full = self.export(payload, None)
        compact = self.export(payload, "1")
        self.assertEqual(_collect_observed_payloads([full]), _collect_observed_payloads([compact]))
        # A static callback that was registered but not executed must keep that diagnosis.
        for candidate in (
            {"callback_id": "static_blind", "hook_name": "wp_ajax_static"},
            {"callback_id": "parent", "hook_name": "wp_ajax_parent"},
            {"callback_id": "child", "hook_name": "wp_ajax_child"},
        ):
            with self.subTest(candidate=candidate["callback_id"]):
                self.assertEqual(evaluate_artifact_payloads(candidate, [full]),
                                 evaluate_artifact_payloads(candidate, [compact]))
        self.assertEqual(
            evaluate_artifact_payloads({"callback_id": "static_blind", "hook_name": "wp_ajax_static"},
                                       [compact])["status"],
            "registered_not_executed",
        )

    def test_runtime_discovery_and_callback_identity_match_full_artifact(self):
        from hook_energy.seed_generation.generated_config_runner import _artifact_matches_callback
        from online_linked.coordination.runtime_discovery import registered_child_callback

        payload = static_heavy_request()
        full = self.export(payload, None)
        compact = self.export(payload, "1")

        def children(artifact):
            return [
                registered_child_callback(key, value, parent_callback_id="parent", parent_hook_name="wp_ajax_parent",
                                          request_id="req-compact", plugin_slug="fixture")
                for key, value in artifact["hook_coverage"]["registered_callbacks"].items()
            ]

        self.assertEqual(children(full), children(compact))
        for hook_name, callback_id in (("wp_ajax_parent", "parent"), ("wp_ajax_static", "static_blind")):
            self.assertEqual(
                _artifact_matches_callback(full, full["hook_coverage"], hook_name=hook_name, callback_id=callback_id),
                _artifact_matches_callback(compact, compact["hook_coverage"], hook_name=hook_name,
                                           callback_id=callback_id),
            )

    def test_flag_off_keeps_full_descriptors_and_reports_detail_level(self):
        payload = static_heavy_request()
        for flag in (None, "0", "false"):
            with self.subTest(flag=flag):
                actual = self.export(payload, flag)
                self.assertEqual(actual["hook_coverage"]["registered_callbacks"],
                                 payload["hook_coverage"]["registered_callbacks"])
                self.assertEqual(actual["hook_coverage_summary"]["registered_callbacks_detail"], "full")
        self.assertEqual(self.export(payload, "1")["hook_coverage_summary"]["registered_callbacks_detail"], "compact")


if __name__ == "__main__":
    unittest.main()
