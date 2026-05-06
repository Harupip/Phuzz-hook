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


if __name__ == "__main__":
    unittest.main()
