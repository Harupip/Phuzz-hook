from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.generator import LiveHookSeedGenerator


def build_live_coverage_payload() -> dict:
    return {
        "schema_version": "uopz-total-coverage-v3",
        "metadata": {
            "total_registered_callbacks": 4,
            "total_executed_callbacks": 2,
            "coverage_percent": "50%",
        },
        "data": {
            "registered_callbacks": {
                "cb-admin-menu": {
                    "callback_id": "cb-admin-menu",
                    "hook_name": "admin_menu",
                    "callback_repr": "bt_comments_create_menu",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 11,
                    "is_active": True,
                    "status": "registered_only",
                },
                "cb-auth": {
                    "callback_id": "cb-auth",
                    "hook_name": "wp_ajax_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 551,
                    "is_active": True,
                    "status": "covered",
                },
                "cb-unauth": {
                    "callback_id": "cb-unauth",
                    "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 551,
                    "is_active": True,
                    "status": "registered_only",
                },
                "cb-enqueue": {
                    "callback_id": "cb-enqueue",
                    "hook_name": "wp_enqueue_scripts",
                    "callback_repr": "sac_wp_enqueue_styles_and_scripts",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 603,
                    "is_active": True,
                    "status": "covered",
                },
            },
            "executed_callbacks": {
                "cb-auth": {
                    "callback_id": "cb-auth",
                    "hook_name": "wp_ajax_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "executed_count": 5,
                },
                "cb-enqueue": {
                    "callback_id": "cb-enqueue",
                    "hook_name": "wp_enqueue_scripts",
                    "callback_repr": "sac_wp_enqueue_styles_and_scripts",
                    "executed_count": 1,
                },
            },
            "blindspot_callbacks": {
                "cb-admin-menu": {
                    "callback_id": "cb-admin-menu",
                    "hook_name": "admin_menu",
                },
                "cb-unauth": {
                    "callback_id": "cb-unauth",
                    "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                },
            },
        },
    }


class LiveHookSeedGeneratorTests(unittest.TestCase):
    def test_generator_derives_direct_http_seed_and_manual_only_entries(self) -> None:
        generator = LiveHookSeedGenerator()

        gap_report, seed_report = generator.build_reports(build_live_coverage_payload())

        self.assertEqual(gap_report["summary"]["registered_callbacks"], 4)
        self.assertEqual(gap_report["summary"]["uncovered_callbacks"], 2)
        self.assertEqual(gap_report["summary"]["direct_http_seed_candidates"], 1)
        self.assertEqual(seed_report["summary"]["suggested_entries"], 2)
        self.assertEqual(seed_report["summary"]["direct_http_seed_candidates"], 1)
        self.assertEqual(seed_report["summary"]["manual_only_entries"], 1)

        direct_seed = next(
            item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call"
        )
        self.assertEqual(direct_seed["generation_status"], "supported_http_seed")
        self.assertEqual(direct_seed["seed"]["method"], "POST")
        self.assertEqual(direct_seed["seed"]["path"], "/wp-admin/admin-ajax.php")
        self.assertEqual(direct_seed["seed"]["body"], {"action": "sac_post_type_call"})
        self.assertEqual(direct_seed["seed"]["auth_mode"], "unauth-capable")

        manual_only = next(item for item in seed_report["suggested_seeds"] if item["hook_name"] == "admin_menu")
        self.assertEqual(manual_only["generation_status"], "manual_analysis_required")
        self.assertNotIn("seed", manual_only)

    def test_generator_writes_seed_artifacts_without_import_queues(self) -> None:
        generator = LiveHookSeedGenerator()

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            generator.write_artifacts(build_live_coverage_payload(), output_dir)

            self.assertTrue((output_dir / "hook_gap_report.json").exists())
            self.assertTrue((output_dir / "suggested_seeds.json").exists())
            self.assertTrue((output_dir / "suggested_seeds.md").exists())
            self.assertFalse((output_dir / "imported_auth_seeds.json").exists())
            self.assertFalse((output_dir / "imported_unauth_seeds.json").exists())
            self.assertFalse((output_dir / "manual_analysis_queue.json").exists())

            suggested = json.loads((output_dir / "suggested_seeds.json").read_text(encoding="utf-8"))
            self.assertEqual(suggested["summary"]["direct_http_seed_candidates"], 1)

    def test_generator_adds_extracted_fuzzable_params_to_direct_seed(self) -> None:
        source = "\n".join(
            [
                "<?php",
                "function sac_post_type_call_callback() {",
                "    $action = $_REQUEST['action'];",
                "    $orderby = sanitize_text_field($_REQUEST['orderby']);",
                "    $page = absint($_GET['page']);",
                "}",
                "",
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "bt-comments.php"
            source_file.write_text(source, encoding="utf-8")

            payload = build_live_coverage_payload()
            callback = payload["data"]["registered_callbacks"]["cb-unauth"]
            callback["source_file"] = str(source_file)
            callback["source_line"] = 2
            callback["start_line"] = 2
            callback["end_line"] = 6

            gap_report, seed_report = LiveHookSeedGenerator().build_reports(payload)

        callback_row = next(
            item for item in gap_report["callbacks"] if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call"
        )
        direct_seed = next(
            item["seed"]
            for item in seed_report["suggested_seeds"]
            if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call" and item["seed"]["method"] == "POST"
        )

        self.assertIn({"source": "REQUEST", "name": "orderby"}, [
            {"source": item["source"], "name": item["name"]} for item in callback_row["input_params"]
        ])
        self.assertEqual(direct_seed["body"]["action"], "sac_post_type_call")
        self.assertEqual(direct_seed["body"]["orderby"], "FUZZ")
        self.assertEqual(direct_seed["query_params"]["page"], "FUZZ")
        self.assertEqual(direct_seed["fixed_params"], ["action"])
        self.assertIn("orderby", direct_seed["fuzzable_params"])
        self.assertIn("page", direct_seed["fuzzable_params"])
        self.assertNotIn("action", direct_seed["fuzzable_params"])

    def test_generator_keeps_nonce_fixed_and_prunes_nested_parent_param(self) -> None:
        source = "\n".join(
            [
                "<?php",
                "function save_api_settings() {",
                "    check_ajax_referer('vx_nonce','vx_nonce');",
                "    if (isset($_POST['cfx_settings'])) {",
                "        if (!empty($_POST['cfx_settings']['alert_emails'])) {",
                "            $info_form['alert_emails'] = $_POST['cfx_settings']['alert_emails'];",
                "        }",
                "    }",
                "}",
                "",
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "crm.php"
            source_file.write_text(source, encoding="utf-8")

            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-crm": {
                            "callback_id": "cb-crm",
                            "hook_name": "wp_ajax_vx_form_save_api_settings",
                            "callback_repr": "cfx_form_admin_pages->save_api_settings",
                            "source_file": str(source_file),
                            "source_line": 2,
                            "start_line": 2,
                            "end_line": 9,
                            "is_active": True,
                            "status": "registered_only",
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            _, seed_report = LiveHookSeedGenerator().build_reports(payload)

        seed = next(item["seed"] for item in seed_report["suggested_seeds"] if item["seed"]["method"] == "POST")
        self.assertEqual(seed["body"]["action"], "vx_form_save_api_settings")
        self.assertEqual(seed["body"]["vx_nonce"], "fuzz")
        self.assertEqual(seed["body"]["cfx_settings[alert_emails]"], "FUZZ")
        self.assertNotIn("cfx_settings", seed["body"])
        self.assertIn("vx_nonce", seed["fixed_params"])
        self.assertNotIn("vx_nonce", seed["fuzzable_params"])
        self.assertEqual(seed["fuzzable_params"], ["cfx_settings[alert_emails]"])

    def test_generator_prioritizes_nopriv_over_authenticated_hooks(self) -> None:
        generator = LiveHookSeedGenerator()

        auth_priority, auth_rank, _ = generator._classify_seed_priority("wp_ajax_demo", True)
        nopriv_priority, nopriv_rank, _ = generator._classify_seed_priority("wp_ajax_nopriv_demo", True)

        self.assertEqual(nopriv_priority, "highest")
        self.assertEqual(auth_priority, "high")
        self.assertGreater(nopriv_rank, auth_rank)


if __name__ == "__main__":
    unittest.main()
