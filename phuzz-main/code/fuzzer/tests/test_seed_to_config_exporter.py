import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.config_exporter import (
    SeedConfigSkip,
    build_config_for_seed_item,
    export_seed_configs,
)


def build_seed_item(*, hook_name="wp_ajax_nopriv_example_lookup", auth_mode="unauth-capable"):
    return {
        "hook_name": hook_name,
        "callback_id": "cb-public",
        "callback_name": "example_lookup_handler",
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
        },
    }


class SeedToConfigExporterTests(unittest.TestCase):
    def test_unauth_seed_becomes_phuzz_config_with_fixed_action_and_fuzzed_params(self):
        slug, config = build_config_for_seed_item(build_seed_item(), target_base="http://web")

        self.assertEqual(slug, "wp_ajax_nopriv_example_lookup-cb-public")
        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["methods"], ["POST"])
        self.assertEqual(
            config["body_params"],
            {
                "data": [
                    {"name": "action", "value": "example_lookup"},
                    {"name": "item_id", "value": "FUZZ"},
                ],
                "fixed": ["action"],
                "fuzz": ["item_id"],
                "weight": 1,
            },
        )
        self.assertEqual(
            config["query_params"],
            {
                "data": [{"name": "page", "value": "FUZZ"}],
                "fixed": [],
                "fuzz": ["page"],
                "weight": 1,
            },
        )
        self.assertEqual(config["headers"]["fixed"], ["X-Seed"])
        self.assertEqual(config["cookies"]["fixed"], ["wordpress_test_cookie"])

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
            self.assertTrue((output_dir / "wp_ajax_example_lookup-cb-public.json").exists())
            self.assertEqual(summary["generated"][0]["config_slug"], "generated-hooks/wp_ajax_nopriv_example_lookup-cb-public")
            self.assertEqual(summary["generated"][1]["config_slug"], "generated-hooks/wp_ajax_example_lookup-cb-public")
            self.assertEqual(summary["skipped"][0]["reason"], "missing_seed")
            self.assertEqual(json.loads(summary_path.read_text(encoding="utf-8")), summary)

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
