from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.phuzz_config_writer import build_config_for_candidate, write_candidate_configs


def build_candidate(**overrides):
    candidate = {
        "candidate_id": "cb-public",
        "classification": "direct_http",
        "hook_name": "wp_ajax_nopriv_abc",
        "callback_id": "cb-public",
        "callback_repr": "abc_handler",
        "entry_type": "ajax_unauthenticated",
        "http_template": {
            "method": "POST",
            "path": "/wp-admin/admin-ajax.php",
            "query_params": {"page": "1"},
            "body_params": {"action": "abc", "item_id": "FUZZ"},
            "headers": {"X-Demo": "fixed"},
            "cookies": {"wordpress_test_cookie": "WP Cookie check"},
        },
    }
    candidate.update(overrides)
    return candidate


class PhuzzConfigWriterTests(unittest.TestCase):
    def test_wp_ajax_nopriv_candidate_becomes_admin_ajax_config_with_fixed_action_and_metadata(self) -> None:
        slug, config = build_config_for_candidate(build_candidate(), target_base="http://web")

        self.assertEqual(slug, "cb-public")
        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["methods"], ["POST"])
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertIn("item_id", config["body_params"]["fuzz"])
        self.assertEqual(
            config["body_params"]["data"],
            [{"name": "action", "value": "abc"}, {"name": "item_id", "value": "FUZZ"}],
        )
        self.assertEqual(config["query_params"]["fuzz"], ["page"])
        self.assertEqual(config["headers"]["fixed"], ["X\\-Demo"])
        self.assertEqual(config["cookies"]["fixed"], ["wordpress_test_cookie"])
        self.assertEqual(
            config["metadata"],
            {
                "candidate_id": "cb-public",
                "hook_name": "wp_ajax_nopriv_abc",
                "callback_id": "cb-public",
                "callback_repr": "abc_handler",
                "entry_type": "ajax_unauthenticated",
                "generated_by": "hookphuzz_bootstrap_entry_discovery",
            },
        )

    def test_placeholder_fuzz_param_is_added_when_candidate_has_only_action(self) -> None:
        candidate = build_candidate(
            http_template={
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "body_params": {"action": "abc"},
            }
        )

        _, config = build_config_for_candidate(candidate, target_base="http://web")

        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertIn("hookphuzz_probe", config["body_params"]["fuzz"])
        self.assertIn({"name": "hookphuzz_probe", "value": "fuzz"}, config["body_params"]["data"])

    def test_bracket_param_selectors_are_escaped_but_legacy_regex_stays_raw(self) -> None:
        candidate = build_candidate(
            http_template={
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "body_params": {
                    "action": "abc",
                    "cfx_settings[alert_emails]": "FUZZ",
                    ".*": "FUZZ",
                },
            }
        )

        _, config = build_config_for_candidate(candidate, target_base="http://web")

        self.assertIn({"name": "cfx_settings[alert_emails]", "value": "FUZZ"}, config["body_params"]["data"])
        self.assertEqual(config["body_params"]["fixed"], ["action"])
        self.assertEqual(config["body_params"]["fuzz"], ["cfx_settings\\[alert_emails\\]", ".*"])

    def test_write_candidate_configs_only_writes_direct_http_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            direct_file = Path(tmp_dir) / "direct_http_candidates.json"
            output_dir = Path(tmp_dir) / "generated_phuzz_configs"
            direct_file.write_text(
                json.dumps(
                    {
                        "candidates": [
                            build_candidate(),
                            build_candidate(candidate_id="setup", classification="setup_required"),
                        ]
                    }
                ),
                encoding="utf-8",
            )

            written = write_candidate_configs(direct_file, output_dir=output_dir, target_base="http://web", pretty=True)

            self.assertEqual(len(written), 1)
            self.assertEqual(written[0]["candidate_id"], "cb-public")
            self.assertTrue((output_dir / "cb-public.json").exists())
            self.assertFalse((output_dir / "setup.json").exists())


if __name__ == "__main__":
    unittest.main()
