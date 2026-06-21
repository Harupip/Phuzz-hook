from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.entry_classifier import (
    classify_callbacks,
    load_registry,
    write_classification_artifacts,
)


def build_registered_callback(hook_name: str, callback_id: str | None = None) -> dict:
    return {
        "callback_id": callback_id or f"cb-{hook_name}",
        "hook_name": hook_name,
        "callback_repr": f"{hook_name}_handler",
        "callback_type": "action",
        "function_name": f"{hook_name}_handler",
        "priority": 10,
        "accepted_args": 1,
        "source_file": "/var/www/html/wp-content/plugins/demo/plugin.php",
        "source_line": 42,
        "status": "registered_only",
    }


def build_child_registered_callback() -> dict:
    child = build_registered_callback("wp_ajax_nopriv_hookphuzz_level2", "cb-level2")
    child.update(
        {
            "registered_inside_callback": True,
            "hook_level": 1,
            "parent_hook_name": "wp_ajax_nopriv_hookphuzz_level1",
            "parent_callback_id": "cb-level1",
            "parent_callback_repr": "hookphuzz_level1",
            "registration_stack_depth": 1,
            "parent_callback": {
                "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
                "callback_id": "cb-level1",
                "stable_id": "stable-level1",
                "runtime_id": "runtime-level1",
                "callback_repr": "hookphuzz_level1",
                "function_name": "hookphuzz_level1",
                "class_name": None,
                "method_name": None,
                "source_file": "/var/www/html/wp-content/plugins/demo/plugin.php",
                "source_line": 10,
                "hook_level": 0,
            },
        }
    )
    return child


def build_total_coverage(*hooks: str) -> dict:
    registered = {}
    executed = {}
    for index, hook_name in enumerate(hooks, start=1):
        callback_id = f"cb-{index}"
        registered[callback_id] = build_registered_callback(hook_name, callback_id)
        if hook_name == "wp_ajax_abc":
            executed[callback_id] = {"executed_count": 3}
    return {
        "schema_version": "uopz-total-coverage-v3",
        "data": {
            "registered_callbacks": registered,
            "executed_callbacks": executed,
        },
    }


class EntryClassifierTests(unittest.TestCase):
    def test_total_coverage_direct_http_hooks_are_classified_with_http_templates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_file = Path(tmp_dir) / "total_coverage.json"
            input_file.write_text(
                json.dumps(
                    build_total_coverage(
                        "wp_ajax_abc",
                        "wp_ajax_nopriv_abc",
                        "admin_post_abc",
                        "admin_post_nopriv_abc",
                        "admin_action_abc",
                        "login_form_lostpassword",
                        "heartbeat_received",
                        "heartbeat_nopriv_received",
                    )
                ),
                encoding="utf-8",
            )

            callbacks, detected_format = load_registry(input_file, "auto")
            report = classify_callbacks(callbacks, str(input_file))

        self.assertEqual(detected_format, "total_coverage")
        by_hook = {item["hook_name"]: item for item in report["candidates"]}
        self.assertEqual(report["counts"]["direct_http"], 8)

        self.assertEqual(by_hook["wp_ajax_abc"]["entry_type"], "ajax_authenticated")
        self.assertEqual(by_hook["wp_ajax_abc"]["http_template"]["method"], "POST")
        self.assertEqual(by_hook["wp_ajax_abc"]["http_template"]["path"], "/wp-admin/admin-ajax.php")
        self.assertEqual(by_hook["wp_ajax_abc"]["http_template"]["body_params"], {"action": "abc"})
        self.assertTrue(by_hook["wp_ajax_abc"]["auth_required"])
        self.assertEqual(by_hook["wp_ajax_abc"]["executed_count"], 3)

        self.assertEqual(by_hook["wp_ajax_nopriv_abc"]["entry_type"], "ajax_unauthenticated")
        self.assertFalse(by_hook["wp_ajax_nopriv_abc"]["auth_required"])
        self.assertEqual(by_hook["admin_post_abc"]["entry_type"], "admin_post_authenticated")
        self.assertEqual(by_hook["admin_post_abc"]["http_template"]["path"], "/wp-admin/admin-post.php")
        self.assertEqual(by_hook["admin_post_nopriv_abc"]["entry_type"], "admin_post_unauthenticated")
        self.assertFalse(by_hook["admin_post_nopriv_abc"]["auth_required"])
        self.assertEqual(by_hook["admin_action_abc"]["entry_type"], "admin_action")
        self.assertEqual(by_hook["admin_action_abc"]["http_template"]["method"], "GET")
        self.assertEqual(by_hook["admin_action_abc"]["http_template"]["query_params"], {"action": "abc"})
        self.assertEqual(by_hook["login_form_lostpassword"]["entry_type"], "login_form")
        self.assertEqual(by_hook["login_form_lostpassword"]["http_template"]["path"], "/wp-login.php")
        self.assertFalse(by_hook["login_form_lostpassword"]["auth_required"])
        self.assertEqual(by_hook["heartbeat_received"]["entry_type"], "heartbeat_authenticated")
        self.assertEqual(by_hook["heartbeat_received"]["http_template"]["body_params"], {"action": "heartbeat"})
        self.assertEqual(by_hook["heartbeat_nopriv_received"]["entry_type"], "heartbeat_unauthenticated")
        self.assertFalse(by_hook["heartbeat_nopriv_received"]["auth_required"])

    def test_lifecycle_enqueue_and_generic_hooks_are_non_entry(self) -> None:
        callbacks, _ = load_registry_from_payload(
            {
                "callbacks": [
                    build_registered_callback("init"),
                    build_registered_callback("admin_menu"),
                    build_registered_callback("wp_enqueue_scripts"),
                    build_registered_callback("custom_filter"),
                ]
            }
        )

        report = classify_callbacks(callbacks, "hook_gap_report.json")

        self.assertEqual(report["counts"]["non_entry"], 4)
        self.assertTrue(all(item["classification"] == "non_entry" for item in report["candidates"]))
        self.assertTrue(all(item["http_template"] is None for item in report["candidates"]))

    def test_shortcode_rewrite_rest_and_xmlrpc_records_are_setup_required(self) -> None:
        callbacks, _ = load_registry_from_payload(
            {
                "callbacks": [
                    build_registered_callback("shortcode_demo"),
                    build_registered_callback("rewrite_endpoint_demo"),
                    {"hook_name": "rest_api_init", "callback_id": "cb-rest", "rest_route": "/demo/v1/items"},
                    {"hook_name": "xmlrpc_methods", "callback_id": "cb-xmlrpc", "method_map": True},
                ]
            }
        )

        report = classify_callbacks(callbacks, "hook_gap_report.json")

        self.assertEqual(report["counts"]["setup_required"], 4)
        self.assertEqual(
            {item["entry_type"] for item in report["candidates"]},
            {"shortcode", "rewrite", "rest_route", "xmlrpc_method_map"},
        )

    def test_missing_optional_fields_normalize_to_none(self) -> None:
        callbacks, _ = load_registry_from_payload({"callbacks": [{"hook_name": "init"}]})

        report = classify_callbacks(callbacks, "hook_gap_report.json")
        candidate = report["candidates"][0]

        self.assertEqual(candidate["hook_name"], "init")
        self.assertIsNone(candidate["callback_id"])
        self.assertIsNone(candidate["callback_repr"])
        self.assertIsNone(candidate["source_file"])
        self.assertIsNone(candidate["source_line"])
        self.assertIsNone(candidate["accepted_args"])
        self.assertIsNone(candidate["priority"])
        self.assertIsNone(candidate["executed_count"])

    def test_entry_classifier_preserves_multistage_hook_metadata(self) -> None:
        callbacks, _ = load_registry_from_payload({"callbacks": [build_child_registered_callback()]})

        report = classify_callbacks(callbacks, "hook_gap_report.json")
        candidate = report["candidates"][0]

        self.assertEqual(candidate["classification"], "direct_http")
        self.assertTrue(candidate["registered_inside_callback"])
        self.assertEqual(candidate["hook_level"], 1)
        self.assertEqual(candidate["parent_hook_name"], "wp_ajax_nopriv_hookphuzz_level1")
        self.assertEqual(candidate["parent_callback_id"], "cb-level1")
        self.assertEqual(candidate["parent_callback_repr"], "hookphuzz_level1")
        self.assertEqual(candidate["registration_stack_depth"], 1)
        self.assertEqual(candidate["parent_callback"]["callback_id"], "cb-level1")
        self.assertEqual(candidate["parent_callback"]["hook_level"], 0)

    def test_artifact_writer_splits_candidates_and_recalculates_counts(self) -> None:
        callbacks, _ = load_registry_from_payload(
            {
                "callbacks": [
                    build_registered_callback("wp_ajax_nopriv_abc"),
                    build_registered_callback("shortcode_demo"),
                    build_registered_callback("init"),
                ]
            }
        )
        report = classify_callbacks(callbacks, "hook_gap_report.json")

        with tempfile.TemporaryDirectory() as tmp_dir:
            paths = write_classification_artifacts(report, Path(tmp_dir), pretty=True)

            self.assertEqual(
                set(paths),
                {
                    "entrypoint_candidates",
                    "direct_http_candidates",
                    "setup_required_candidates",
                    "non_entry_hooks",
                },
            )
            all_payload = json.loads((Path(tmp_dir) / "entrypoint_candidates.json").read_text(encoding="utf-8"))
            direct_payload = json.loads((Path(tmp_dir) / "direct_http_candidates.json").read_text(encoding="utf-8"))
            setup_payload = json.loads((Path(tmp_dir) / "setup_required_candidates.json").read_text(encoding="utf-8"))
            non_entry_payload = json.loads((Path(tmp_dir) / "non_entry_hooks.json").read_text(encoding="utf-8"))

            self.assertIn("\n  ", (Path(tmp_dir) / "entrypoint_candidates.json").read_text(encoding="utf-8"))
            self.assertEqual(all_payload["counts"], {"direct_http": 1, "setup_required": 1, "non_entry": 1})
            self.assertEqual(direct_payload["counts"], {"direct_http": 1, "setup_required": 0, "non_entry": 0})
            self.assertEqual(setup_payload["counts"], {"direct_http": 0, "setup_required": 1, "non_entry": 0})
            self.assertEqual(non_entry_payload["counts"], {"direct_http": 0, "setup_required": 0, "non_entry": 1})

    def test_cli_writes_all_candidate_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            input_file = root / "hook_gap_report.json"
            output_dir = root / "out"
            input_file.write_text(
                json.dumps(
                    {
                        "callbacks": [
                            build_registered_callback("wp_ajax_nopriv_abc"),
                            build_registered_callback("shortcode_demo"),
                            build_registered_callback("init"),
                        ]
                    }
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(FUZZER_DIR / "hook_energy" / "entry_classifier.py"),
                    "--input-file",
                    str(input_file),
                    "--output-dir",
                    str(output_dir),
                    "--format",
                    "auto",
                    "--pretty",
                ],
                cwd=FUZZER_DIR,
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Entry classifier summary: direct_http=1 setup_required=1 non_entry=1", result.stdout)
            self.assertTrue((output_dir / "entrypoint_candidates.json").exists())
            self.assertTrue((output_dir / "direct_http_candidates.json").exists())
            self.assertTrue((output_dir / "setup_required_candidates.json").exists())
            self.assertTrue((output_dir / "non_entry_hooks.json").exists())


def load_registry_from_payload(payload: dict) -> tuple[list, str]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        input_file = Path(tmp_dir) / "registry.json"
        input_file.write_text(json.dumps(payload), encoding="utf-8")
        return load_registry(input_file, "auto")


if __name__ == "__main__":
    unittest.main()
