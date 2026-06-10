from __future__ import annotations

import json
import shutil
import sys
import textwrap
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))
TEST_TMP_ROOT = FUZZER_DIR / "tmp_static_seed_tests"

from hook_energy.static_seed_generation.config_writer import StaticSeedConfigWriter
from hook_energy.static_seed_generation.scanner import StaticSeedScanner
from hook_energy.static_seed_generation.validation import validate_static_report


class StaticSeedGenerationTests(unittest.TestCase):
    def test_scan_maps_wordpress_entrypoints_params_rest_and_configs(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        root = TEST_TMP_ROOT / "scan_maps"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        plugin = root / "plugin"
        output = root / "out"
        plugin.mkdir()
        (plugin / "plugin.php").write_text(
            textwrap.dedent(
                """\
                <?php
                define('STATIC_ACTION', 'const_action');
                $literal_action = 'concat_action';

                add_action('wp_ajax_save_item', 'save_item');
                add_action('wp_ajax_nopriv_public_item', [$this, 'public_item']);
                add_action('admin_post_nopriv_submit_item', 'submit_item');
                add_action('wp_ajax_' . 'literal_concat', 'literal_concat');
                add_action('wp_ajax_' . $literal_action, 'concat_item');
                add_action('wp_ajax_' . $unknown_action, 'unknown_item');

                add_action('rest_api_init', function () {
                    register_rest_route('demo/v1', '/thing', [
                        'methods' => 'POST',
                        'callback' => 'rest_item',
                        'permission_callback' => '__return_true',
                    ]);
                });

                function save_item() {
                    global $wpdb;
                    $id = $_POST['id'];
                    $page = $_GET['page'];
                    $mixed = $_REQUEST['mixed'];
                    $wpdb->query('SELECT 1');
                }

                class Demo_Handler {
                    public function public_item() {
                        $name = filter_input(INPUT_POST, 'name');
                    }
                }

                function submit_item() {
                    $token = $_COOKIE['token'];
                }

                function literal_concat() {}
                function concat_item() {}
                function unknown_item() {}

                function rest_item(WP_REST_Request $request) {
                    $rest_id = $request->get_param('rest_id');
                    $alt = $request['alt'];
                    shell_exec($request->get_param('cmd'));
                }
                """
            ),
            encoding="utf-8",
        )
        (plugin / "vendor").mkdir()
        (plugin / "vendor" / "ignored.php").write_text(
            "<?php add_action('wp_ajax_ignored', 'ignored');",
            encoding="utf-8",
        )

        report = StaticSeedScanner(base_url="http://web").scan(
            plugin_path=plugin,
            plugin_slug="demo",
            output_dir=output,
            write_configs=True,
            include_rest=True,
            include_unresolved=True,
        )

        self.assertEqual(report["summary"]["php_files_scanned"], 1)
        self.assertEqual(report["summary"]["resolved_http_endpoints"], 5)
        self.assertEqual(report["summary"]["rest_routes_found"], 1)
        self.assertTrue((output / "static_seed_report.json").exists())

        endpoints = {item.get("hook_name") or item.get("route"): item for item in report["endpoints"]}
        ajax = endpoints["wp_ajax_save_item"]
        self.assertEqual(ajax["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(ajax["fixed_params"], {"action": "save_item"})
        self.assertEqual({item["name"] for item in ajax["params"]}, {"id", "page", "mixed"})
        self.assertEqual(set(ajax["fuzz_params"]), {"id", "page", "mixed"})
        self.assertIn("SQLi:$wpdb->query", ajax["sink_hints"])

        public = endpoints["wp_ajax_nopriv_public_item"]
        self.assertEqual(public["auth_mode"], "unauthenticated")
        self.assertEqual(public["params"][0]["name"], "name")

        admin = endpoints["admin_post_nopriv_submit_item"]
        self.assertEqual(admin["target"], "http://web/wp-admin/admin-post.php")
        self.assertEqual(admin["auth_mode"], "unauthenticated")
        self.assertEqual(admin["params"][0]["source"], "COOKIE")

        self.assertEqual(endpoints["wp_ajax_literal_concat"]["confidence"], "medium")
        self.assertEqual(endpoints["wp_ajax_concat_action"]["confidence"], "medium")

        unresolved = next(item for item in report["endpoints"] if item.get("unresolved"))
        self.assertEqual(unresolved["confidence"], "low")
        self.assertNotIn("action", unresolved)

        rest = endpoints["/demo/v1/thing"]
        self.assertEqual(rest["target"], "http://web/wp-json/demo/v1/thing")
        self.assertEqual(rest["method"], "POST")
        self.assertEqual(rest["auth_mode"], "unauthenticated")
        self.assertEqual(set(rest["fuzz_params"]), {"rest_id", "alt", "cmd"})
        self.assertIn("RCE:shell_exec", rest["sink_hints"])

        config = json.loads((output / "configs" / "demo_wp_ajax_save_item.json").read_text(encoding="utf-8"))
        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["methods"], ["POST"])
        body = config["body_params"]
        self.assertIn({"name": "action", "value": "save_item"}, body["data"])
        self.assertIn("action", body["fixed"])
        self.assertEqual(set(body["fuzz"]), {"id", "page", "mixed"})
        self.assertFalse((output / "configs" / "demo_wp_ajax_unknown_item.json").exists())

    def test_validation_merge_classifies_static_and_dynamic_runtime_status(self) -> None:
        static_report = {
            "endpoints": [
                {"hook_name": "wp_ajax_seen", "callback": "seen_cb"},
                {"hook_name": "wp_ajax_static_only", "callback": "static_cb"},
            ]
        }
        hook_report = {
            "callbacks": [
                {"hook_name": "wp_ajax_seen", "callback_name": "seen_cb", "status": "uncovered"},
                {"hook_name": "wp_ajax_executed", "callback_name": "exec_cb", "status": "covered"},
            ]
        }

        result = validate_static_report(static_report, hook_report)

        statuses = {item["hook_name"]: item["validation_status"] for item in result["endpoints"]}
        self.assertEqual(statuses["wp_ajax_seen"], "registered_runtime")
        self.assertEqual(statuses["wp_ajax_static_only"], "static_only")
        self.assertEqual(statuses["wp_ajax_executed"], "dynamic_only")
        self.assertEqual(result["summary"]["registered_runtime"], 1)
        self.assertEqual(result["summary"]["executed_runtime"], 1)
        self.assertEqual(result["summary"]["static_only"], 1)
        self.assertEqual(result["summary"]["dynamic_only"], 1)

    def test_config_writer_skips_low_confidence_or_unresolved_entries(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        root = TEST_TMP_ROOT / "config_writer"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        writer = StaticSeedConfigWriter(root)
        written = writer.write_configs(
            "demo",
            [
                {
                    "kind": "wp_ajax",
                    "action": "ok",
                    "target": "http://web/wp-admin/admin-ajax.php",
                    "method": "POST",
                    "confidence": "medium",
                    "fixed_params": {"action": "ok"},
                    "fuzz_params": ["name"],
                },
                {
                    "kind": "wp_ajax",
                    "target": "http://web/wp-admin/admin-ajax.php",
                    "method": "POST",
                    "confidence": "low",
                    "unresolved": True,
                    "fuzz_params": ["name"],
                },
            ],
        )

        self.assertEqual(len(written), 1)
        self.assertTrue((root / "configs" / "demo_wp_ajax_ok.json").exists())


if __name__ == "__main__":
    unittest.main()
