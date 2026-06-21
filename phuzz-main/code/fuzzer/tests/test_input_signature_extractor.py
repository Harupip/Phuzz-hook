from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.input_extractor import InputSignatureExtractor


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "hook_input_callbacks.php"


class InputSignatureExtractorContractTests(unittest.TestCase):
    def test_maps_container_source_path_to_host_plugin_source_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            host_root = Path(tmp_dir) / "gamipress"
            source_file = host_root / "includes" / "ajax-functions.php"
            source_file.parent.mkdir(parents=True)
            source_file.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function gamipress_ajax_get_logs() {",
                        "    $orderby = $_REQUEST['orderby'];",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            extractor = InputSignatureExtractor(
                container_source_root="/var/www/html/wp-content/plugins/gamipress",
                host_source_root=host_root,
            )
            result = extractor.extract(
                {
                    "callback_repr": "gamipress_ajax_get_logs",
                    "source_file": "/var/www/html/wp-content/plugins/gamipress/includes/ajax-functions.php",
                    "start_line": 2,
                    "end_line": 4,
                }
            )

        self.assertEqual(result["source_resolution"]["status"], "zip_mapped")
        self.assertEqual(result["source_resolution"]["resolved_source_file"], str(source_file.resolve()))
        self.assertEqual({item["name"] for item in result["input_params"]}, {"orderby"})

    def test_reports_callback_and_static_request_inputs_without_action(self) -> None:
        result = InputSignatureExtractor().extract(
            {
                "callback_repr": "hookphuzz_fixture_callback",
                "source_file": str(FIXTURE),
                "start_line": 2,
                "end_line": 9,
            }
        )

        self.assertEqual(result["callback"], "hookphuzz_fixture_callback")
        names = {item["name"] for item in result["input_params"]}
        self.assertEqual(names, {"orderby", "sid", "cnt", "avatar", "theme"})
        self.assertNotIn("action", names)

    def test_extracts_shortcode_default_keys_from_shallow_same_tree_helper(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin_root = Path(tmp_dir) / "gamipress"
            ajax_file = plugin_root / "includes" / "ajax-functions.php"
            helper_file = plugin_root / "includes" / "shortcodes" / "gamipress_logs.php"
            ajax_file.parent.mkdir(parents=True)
            helper_file.parent.mkdir(parents=True)
            ajax_file.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function gamipress_ajax_get_logs() {",
                        "    if( isset( $_REQUEST['page'] ) ) {",
                        "        set_query_var( 'paged', absint( $_REQUEST['page'] ) );",
                        "    }",
                        "    $atts = $_REQUEST;",
                        "    unset( $atts['action'] );",
                        "    $atts = shortcode_atts( gamipress_logs_shortcode_defaults(), $atts, 'gamipress_logs' );",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            helper_file.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function gamipress_logs_shortcode_defaults() {",
                        "    return apply_filters( 'gamipress_logs_shortcode_defaults', array(",
                        "        'orderby' => 'date',",
                        "        'order' => 'ASC',",
                        "    ) );",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            result = InputSignatureExtractor(source_root=plugin_root).extract(
                {
                    "callback_repr": "gamipress_ajax_get_logs",
                    "source_file": str(ajax_file),
                    "start_line": 2,
                    "end_line": 9,
                }
            )

        by_name = {item["name"]: item for item in result["input_params"]}
        self.assertEqual(result["source_resolution"]["status"], "resolved")
        self.assertEqual(by_name["page"]["confidence"], "static_regex")
        self.assertEqual(by_name["orderby"]["confidence"], "shallow_helper_shortcode_defaults")
        self.assertIn("order", by_name)

    def test_extracts_json_body_key_access_near_php_input_decode(self) -> None:
        result = InputSignatureExtractor().extract(
            {
                "callback_repr": "hookphuzz_json_callback",
                "source_file": str(FIXTURE),
                "start_line": 11,
                "end_line": 14,
            }
        )

        self.assertIn(
            {
                "name": "token",
                "source": "BODY_JSON",
                "location": "body",
                "confidence": "static_regex",
            },
            [
                {
                    "name": item["name"],
                    "source": item["source"],
                    "location": item["location"],
                    "confidence": item["confidence"],
                }
                for item in result["input_params"]
            ],
        )


if __name__ == "__main__":
    unittest.main()
