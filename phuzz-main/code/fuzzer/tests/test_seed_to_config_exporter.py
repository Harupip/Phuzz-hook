import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.entrypoints import seed_template_for_callback
from hook_energy.seed_generation.config_exporter import (
    SeedConfigSkip,
    build_generated_param_summary,
    build_config_for_seed_item,
    export_seed_configs,
)


def build_seed_item(*, hook_name="wp_ajax_nopriv_example_lookup", auth_mode="unauth-capable"):
    return {
        "hook_name": hook_name,
        "callback_id": "cb-public",
        "callback_name": "example_lookup_handler",
        "callback_repr": "example_lookup_handler",
        "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
        "source_line": 42,
        "start_line": 42,
        "source_resolution": {
            "source_file": "/var/www/html/wp-content/plugins/demo/includes/ajax.php",
            "status": "zip_mapped",
            "resolved_source_file": "/tmp/demo/includes/ajax.php",
        },
        "generation_status": "supported_http_seed",
        "seed": {
            "method": "POST",
            "path": "/wp-admin/admin-ajax.php",
            "content_type": "application/x-www-form-urlencoded",
            "body": {"action": "example_lookup", "item_id": "FUZZ"},
            "query_params": {"page": "FUZZ"},
            "headers": {"X-Seed": "fixed"},
            "cookies": {"wordpress_test_cookie": "WP Cookie check"},
            "auth_mode": auth_mode,
            "fixed_params": ["action"],
            "fuzzable_params": ["item_id", "page"],
            "input_params": [
                {"name": "item_id", "source": "POST", "confidence": "static_regex"},
                {"name": "page", "source": "GET", "confidence": "static_regex"},
            ],
        },
    }


def build_rest_seed_item(*, method="GET", fuzzable_params=None):
    fuzzable_params = ["term"] if fuzzable_params is None else fuzzable_params
    seed = {
        "methods": [method],
        "path": "/wp-json/demo/v1/items",
        "content_type": "application/json",
        "body": {},
        "query_params": {"term": "FUZZ"} if "term" in fuzzable_params else {},
        "auth_mode": "unauth-capable",
        "fixed_params": [],
        "fuzzable_params": fuzzable_params,
        "entrypoint_type": "rest_route",
    }
    if method != "GET":
        seed["query_params"] = {}
        seed["body"] = {"title": "FUZZ"} if "title" in fuzzable_params else {}
    return {
        "hook_name": "rest_route:demo/v1/items",
        "callback_id": "cb-rest",
        "callback_name": "rest_lookup",
        "entrypoint_type": "rest_route",
        "generation_status": "supported_http_seed",
        "seed": seed,
    }


class SeedToConfigExporterTests(unittest.TestCase):
    def test_unauth_seed_becomes_phuzz_config_with_fixed_action_and_fuzzed_params(self):
        slug, config = build_config_for_seed_item(build_seed_item(), target_base="http://web")

        self.assertEqual(slug, "wp_ajax_nopriv_example_lookup-cb-public")
        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["methods"], ["POST"])
        self.assertEqual(config["config_type"], "fuzzing_ready")
        self.assertEqual(
            config["body_params"],
            {
                "data": [
                    {"name": "action", "value": "example_lookup"},
                    {"name": "item_id", "value": "fuzz"},
                ],
                "fixed": ["action"],
                "fuzz": ["item_id"],
                "weight": 1,
            },
        )
        self.assertEqual(
            config["query_params"],
            {
                "data": [{"name": "page", "value": "fuzz"}],
                "fixed": [],
                "fuzz": ["page"],
                "weight": 1,
            },
        )
        self.assertEqual(config["headers"]["fixed"], ["X\\-Seed"])
        self.assertEqual(config["cookies"]["fixed"], ["wordpress_test_cookie"])

    def test_generated_config_includes_entrypoint_metadata(self):
        _, config = build_config_for_seed_item(build_seed_item(), target_base='http://web')

        self.assertEqual(config['entrypoint_type'], 'ajax_unauthenticated')
        self.assertEqual(
            config['metadata'],
            {
                'entrypoint_type': 'ajax_unauthenticated',
                'hook_name': 'wp_ajax_nopriv_example_lookup',
                'callback_repr': 'example_lookup_handler',
                'callback_source_file': '/var/www/html/wp-content/plugins/demo/includes/ajax.php',
                'callback_start_line': 42,
                'auth_mode': 'unauth-capable',
                'generated_reason': 'supported_http_seed',
                'fuzzing_ready': True,
                'setup_required': False,
                'manual_analysis': False,
            },
        )

    def test_action_only_seed_becomes_replay_only_config(self):
        item = build_seed_item()
        item["seed"].update({"body": {"action": "example_lookup"}, "query_params": {}, "fuzzable_params": []})

        _, config = build_config_for_seed_item(item, target_base="http://web")

        self.assertEqual(config["config_type"], "replay_only")
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertEqual(config["body_params"]["fuzz"], [])

    def test_discovered_file_params_are_metadata_not_fuzz_params(self):
        item = build_seed_item()
        item["seed"].update(
            {
                "body": {"action": "example_lookup"},
                "query_params": {},
                "fuzzable_params": [],
                "discovered_file_params": [{"name": "upload", "source": "FILES"}],
            }
        )

        _, config = build_config_for_seed_item(item, target_base="http://web")

        self.assertEqual(config["config_type"], "replay_only")
        self.assertEqual(config["metadata"]["discovered_file_params"], [{"name": "upload", "source": "FILES"}])
        self.assertNotIn("upload", config["body_params"]["fuzz"])
        self.assertNotIn({"name": "upload", "value": "fuzz"}, config["body_params"]["data"])

    def test_authenticated_ajax_seed_becomes_config_with_fixed_action(self):
        slug, config = build_config_for_seed_item(
            build_seed_item(hook_name="wp_ajax_example_lookup", auth_mode="authenticated")
        )

        self.assertEqual(slug, "wp_ajax_example_lookup-cb-public")
        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertEqual(config["body_params"]["fuzz"], ["item_id"])

    def test_authenticated_admin_post_seed_becomes_config_with_fixed_action(self):
        item = build_seed_item(hook_name="admin_post_export_orders", auth_mode="authenticated")
        item["seed"].update(
            {
                "path": "/wp-admin/admin-post.php",
                "body": {"action": "export_orders", "order_id": "FUZZ"},
                "query_params": {},
                "fuzzable_params": ["order_id"],
            }
        )

        slug, config = build_config_for_seed_item(item)

        self.assertEqual(slug, "admin_post_export_orders-cb-public")
        self.assertEqual(config["target"], "http://web/wp-admin/admin-post.php")
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertEqual(config["body_params"]["fuzz"], ["order_id"])

    def test_login_form_seed_becomes_config_with_fixed_query_action(self):
        item = build_seed_item(hook_name="login_form_lostpassword")
        item["seed"].update(
            {
                "path": "/wp-login.php",
                "body": {},
                "query_params": {"action": "lostpassword"},
                "auth_mode": "unauth-capable",
                "fuzzable_params": [],
            }
        )

        _, config = build_config_for_seed_item(item)

        self.assertEqual(config["target"], "http://web/wp-login.php")
        self.assertEqual(config["entrypoint_type"], "login_form")
        self.assertEqual(config["metadata"]["auth_mode"], "unauth-capable")
        self.assertEqual(config["query_params"]["fixed"], ["action"])
        self.assertEqual(config["query_params"]["data"], [{"name": "action", "value": "lostpassword"}])

    def test_exported_heartbeat_template_stays_replay_only_with_fixed_probe_body(self):
        heartbeat_body = {
            "action": "heartbeat",
            "_nonce": "hookphuzz",
            "screen_id": "front",
            "data[hookphuzz_probe]": "1",
        }
        for hook_name, auth_mode in (
            ("heartbeat_received", "authenticated"),
            ("heartbeat_nopriv_received", "unauth-capable"),
        ):
            with self.subTest(hook_name=hook_name):
                item = build_seed_item(hook_name=hook_name, auth_mode=auth_mode)
                item["seed"] = seed_template_for_callback(hook_name)

                _, config = build_config_for_seed_item(item)

                self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
                self.assertEqual(config["entrypoint_type"], "heartbeat")
                self.assertEqual(config["config_type"], "replay_only")
                self.assertEqual(config["metadata"]["auth_mode"], auth_mode)
                self.assertFalse(config["metadata"]["fuzzing_ready"])
                self.assertFalse(config["metadata"]["setup_required"])
                self.assertFalse(config["metadata"]["manual_analysis"])
                self.assertEqual(config["body_params"]["fixed"], ["action", "_nonce", "screen_id", "data\\[hookphuzz_probe\\]"])
                self.assertEqual(config["body_params"]["fuzz"], [])
                self.assertEqual(
                    config["body_params"]["data"],
                    [
                        {"name": "action", "value": "heartbeat"},
                        {"name": "_nonce", "value": "hookphuzz"},
                        {"name": "screen_id", "value": "front"},
                        {"name": "data[hookphuzz_probe]", "value": "1"},
                    ],
                )
                self.assertEqual(item["seed"]["body"], heartbeat_body)

    def test_bracket_param_data_name_stays_raw_and_fuzz_selector_is_escaped(self):
        item = build_seed_item(hook_name="wp_ajax_vx_form_save_api_settings", auth_mode="authenticated")
        item["seed"].update(
            {
                "body": {
                    "action": "vx_form_save_api_settings",
                    "vx_nonce": "fuzz",
                    "cfx_settings[alert_emails]": "FUZZ",
                },
                "query_params": {},
                "fixed_params": ["action", "vx_nonce"],
                "fuzzable_params": ["cfx_settings[alert_emails]"],
            }
        )

        _, config = build_config_for_seed_item(item)

        self.assertIn({"name": "cfx_settings[alert_emails]", "value": "fuzz"}, config["body_params"]["data"])
        self.assertEqual(config["body_params"]["fixed"], ["action", "vx_nonce"])
        self.assertEqual(config["body_params"]["fuzz"], ["cfx_settings\\[alert_emails\\]"])

    def test_fixed_bracket_selector_is_escaped(self):
        item = build_seed_item()
        item["seed"].update(
            {
                "body": {"action": "example_lookup", "token[field]": "fuzz"},
                "query_params": {},
                "fixed_params": ["action", "token[field]"],
                "fuzzable_params": [],
            }
        )

        _, config = build_config_for_seed_item(item)

        self.assertEqual(config["body_params"]["fixed"], ["action", "token\\[field\\]"])

    def test_legacy_regex_selector_is_not_escaped(self):
        item = build_seed_item()
        item["seed"].update(
            {
                "body": {"action": "example_lookup", ".*": "FUZZ"},
                "query_params": {},
                "fixed_params": ["action"],
                "fuzzable_params": [".*"],
            }
        )

        _, config = build_config_for_seed_item(item)

        self.assertEqual(config["body_params"]["fuzz"], [".*"])

    def test_rest_seed_becomes_wp_json_config_without_action(self):
        slug, config = build_config_for_seed_item(build_rest_seed_item(), target_base="http://web")

        self.assertEqual(slug, "rest_route_demo_v1_items-cb-rest")
        self.assertEqual(config["target"], "http://web/wp-json/demo/v1/items")
        self.assertEqual(config["methods"], ["GET"])
        self.assertEqual(config["entrypoint_type"], "rest_route")
        self.assertEqual(config["config_type"], "fuzzing_ready")
        self.assertEqual(config["query_params"]["fuzz"], ["term"])
        self.assertNotIn("body_params", config)
        self.assertNotIn("action", json.dumps(config))

    def test_post_rest_seed_fuzzes_body_params(self):
        _, config = build_config_for_seed_item(build_rest_seed_item(method="POST", fuzzable_params=["title"]))

        self.assertEqual(config["methods"], ["POST"])
        self.assertEqual(config["body_params"]["fuzz"], ["title"])
        self.assertNotIn("query_params", config)
        self.assertNotIn("action", json.dumps(config))

    def test_rest_seed_without_fuzz_params_is_replay_only(self):
        _, config = build_config_for_seed_item(build_rest_seed_item(fuzzable_params=[]))

        self.assertEqual(config["config_type"], "replay_only")
        self.assertEqual(config["entrypoint_type"], "rest_route")

    def test_manual_or_malformed_seed_is_skipped_with_clear_reason(self):
        with self.assertRaises(SeedConfigSkip) as raised:
            build_config_for_seed_item({"hook_name": "template_redirect", "callback_id": "cb-manual"})

        self.assertEqual(raised.exception.reason, "missing_seed")

    def test_export_writes_config_file_and_summary(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_dir = root / "configs" / "generated-hooks"
            summary_path = root / "generated_config_summary.json"
            seed_report = {
                "suggested_seeds": [
                    build_seed_item(),
                    build_rest_seed_item(),
                    build_seed_item(hook_name="wp_ajax_example_lookup", auth_mode="authenticated"),
                    {"hook_name": "template_redirect", "callback_id": "cb-manual"},
                ]
            }

            summary = export_seed_configs(
                seed_report,
                output_config_dir=output_dir,
                summary_path=summary_path,
                target_base="http://web",
            )

            config_path = output_dir / "wp_ajax_nopriv_example_lookup-cb-public.json"
            self.assertTrue(config_path.exists())
            self.assertTrue((output_dir / "rest_route_demo_v1_items-cb-rest.json").exists())
            self.assertTrue((output_dir / "wp_ajax_example_lookup-cb-public.json").exists())
            self.assertEqual(summary["generated"][0]["config_slug"], "generated-hooks/wp_ajax_nopriv_example_lookup-cb-public")
            self.assertTrue(summary['generated'][0]['fuzzing_ready'])
            self.assertEqual(summary['generated'][0]['generated_reason'], 'supported_http_seed')
            self.assertEqual(summary["generated"][1]["entrypoint_type"], "rest_route")
            self.assertEqual(summary["generated"][2]["config_slug"], "generated-hooks/wp_ajax_example_lookup-cb-public")
            self.assertEqual(summary["skipped"][0]["reason"], "missing_seed")
            self.assertEqual(json.loads(summary_path.read_text(encoding="utf-8")), summary)
            self.assertTrue((root / "generated_param_summary.json").exists())

    def test_builds_param_summary_for_generated_configs(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_dir = root / "configs" / "generated-hooks"
            seed_item = build_seed_item()
            action_only = build_seed_item(hook_name="wp_ajax_example_action_only")
            action_only["source_resolution"] = {"status": "zip_mapped", "resolved_source_file": "/tmp/demo/ajax.php"}
            action_only["seed"].update(
                {"body": {"action": "example_action_only"}, "query_params": {}, "fuzzable_params": [], "input_params": []}
            )
            unresolved = build_seed_item(hook_name="wp_ajax_example_unresolved")
            unresolved["source_resolution"] = {"status": "unresolved", "resolved_source_file": None}
            unresolved["seed"].update(
                {"body": {"action": "example_unresolved"}, "query_params": {}, "fuzzable_params": [], "input_params": []}
            )
            seed_report = {"suggested_seeds": [seed_item, action_only, unresolved]}
            summary = export_seed_configs(seed_report, output_config_dir=output_dir)

            param_summary = build_generated_param_summary(
                seed_report,
                summary,
                output_config_dir=output_dir,
            )

            self.assertEqual(
                param_summary["summary"],
                {"total": 3, "fuzzing_ready": 1, "entrypoint_only": 1, "manual_analysis": 1},
            )
            ready = param_summary["configs"][0]
            self.assertEqual(ready["hook_name"], "wp_ajax_nopriv_example_lookup")
            self.assertEqual(ready["callback_repr"], "example_lookup_handler")
            self.assertTrue(ready["config_path"].endswith("wp_ajax_nopriv_example_lookup-cb-public.json"))
            self.assertEqual(ready["endpoint_type"], "ajax")
            self.assertEqual(ready["callback_source_file"], "/var/www/html/wp-content/plugins/demo/includes/ajax.php")
            self.assertTrue(ready["callback_source_found"])
            self.assertEqual(ready["extracted_params"], ["item_id", "page"])
            self.assertEqual(ready["param_sources"], ["$_POST", "$_GET"])
            self.assertTrue(ready["has_fuzz_params"])
            self.assertEqual(ready["status"], "fuzzing_ready")
            self.assertEqual(param_summary["configs"][1]["status"], "entrypoint_only")
            self.assertEqual(param_summary["configs"][2]["status"], "manual_analysis")

    def test_cli_writes_config_and_summary_from_suggested_seeds_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            suggested = root / "suggested_seeds.json"
            output_dir = root / "configs" / "generated-hooks"
            summary_path = root / "generated_config_summary.json"
            suggested.write_text(json.dumps({"suggested_seeds": [build_seed_item()]}), encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(FUZZER_DIR / "hook_energy" / "seed_generation" / "seed_to_config_cli.py"),
                    "--suggested-seeds",
                    str(suggested),
                    "--output-config-dir",
                    str(output_dir),
                    "--summary",
                    str(summary_path),
                ],
                cwd=FUZZER_DIR,
                text=True,
                capture_output=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("generated=1 skipped=0", result.stdout)
            self.assertTrue((output_dir / "wp_ajax_nopriv_example_lookup-cb-public.json").exists())
            self.assertTrue(summary_path.exists())


if __name__ == "__main__":
    unittest.main()
