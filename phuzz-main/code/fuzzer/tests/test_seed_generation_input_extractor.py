from __future__ import annotations

import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.input_extractor import InputSignatureExtractor


class InputSignatureExtractorTests(unittest.TestCase):
    def test_extracts_superglobals_and_wrapper_accesses(self) -> None:
        source = textwrap.dedent(
            """\
            <?php
            function ajax_handler() {
                $orderby = sanitize_text_field($_REQUEST['orderby']);
                $page = absint($_GET["page"]);
                $title = wp_unslash($_POST['title']);
                $avatar = $_FILES["avatar"];
                $session = intval($_COOKIE['session_id']);
            }
            """
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "plugin.php"
            source_file.write_text(source, encoding="utf-8")

            result = InputSignatureExtractor().extract(
                {
                    "source_file": str(source_file),
                    "start_line": 2,
                    "end_line": 8,
                    "function_name": "ajax_handler",
                }
            )

        extracted = {(item["source"], item["name"]) for item in result["input_params"]}
        self.assertEqual(
            extracted,
            {
                ("REQUEST", "orderby"),
                ("GET", "page"),
                ("POST", "title"),
                ("FILES", "avatar"),
                ("COOKIE", "session_id"),
            },
        )
        self.assertTrue(all(item["confidence"] == "static_regex" for item in result["input_params"]))

    def test_extracts_filter_input_and_deduplicates_repeated_params(self) -> None:
        source = textwrap.dedent(
            """\
            <?php
            function admin_post_handler() {
                $id = filter_input(INPUT_POST, 'id');
                $id_again = $_POST["id"];
                $preview = filter_input(INPUT_GET, "preview");
                $theme = filter_input(INPUT_COOKIE, 'theme');
            }
            """
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "plugin.php"
            source_file.write_text(source, encoding="utf-8")

            result = InputSignatureExtractor().extract(
                {
                    "source_file": str(source_file),
                    "source_line": 2,
                    "end_line": 7,
                }
            )

        extracted = [(item["source"], item["name"]) for item in result["input_params"]]
        self.assertEqual(extracted.count(("POST", "id")), 1)
        self.assertIn(("GET", "preview"), extracted)
        self.assertIn(("COOKIE", "theme"), extracted)


if __name__ == "__main__":
    unittest.main()
