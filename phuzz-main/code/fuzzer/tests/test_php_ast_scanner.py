from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
SCAN_SCRIPT = REPO_ROOT / "code" / "fuzzer" / "static_analysis" / "php_ast" / "scan.php"
TEST_TMP_ROOT = REPO_ROOT / "code" / "fuzzer" / "output" / "test_tmp"


class PhpAstScannerTests(unittest.TestCase):
    def test_scanner_writes_artifacts_and_keeps_scanning_after_parse_errors(self) -> None:
        TEST_TMP_ROOT.mkdir(exist_ok=True)
        base_dir = TEST_TMP_ROOT / "hookphuzz_php_ast_test"
        if base_dir.exists():
            shutil.rmtree(base_dir, ignore_errors=True)
        source_dir = base_dir / "plugin"
        output_dir = base_dir / "ast"
        source_dir.mkdir(parents=True)

        (source_dir / "plugin.php").write_text(
            textwrap.dedent(
                """\
                <?php
                add_action('wp_ajax_test_action', 'test_callback');

                class Demo_Handler {
                    private $action_name = 'dynamic_action';

                    public function register() {
                        add_action('wp_ajax_' . $this->action_name, [$this, 'handle'], 20, 2);
                    }

                    public function handle() {
                        global $wpdb;
                        $id = $_POST['id'];
                        $q = $_REQUEST['q'];
                        $wpdb->query("SELECT * FROM table WHERE id = " . $_POST['id']);
                    }
                }
                """
            ),
            encoding="utf-8",
        )
        (source_dir / "broken.php").write_text("<?php function broken( {", encoding="utf-8")

        result = subprocess.run(
            [
                "php",
                str(SCAN_SCRIPT),
                "--source",
                str(source_dir),
                "--out",
                str(output_dir),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((output_dir / "ast_summary.json").exists())
        self.assertTrue((output_dir / "ast_files.jsonl").exists())

        summary = json.loads((output_dir / "ast_summary.json").read_text(encoding="utf-8"))
        self.assertEqual(summary["total_files_scanned"], 2)
        self.assertEqual(summary["successfully_parsed_files"], 1)
        self.assertEqual(summary["failed_files"], 1)
        self.assertGreater(summary["total_ast_nodes"], 0)

        ast_rows = [
            json.loads(line)
            for line in (output_dir / "ast_files.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        self.assertEqual(len(ast_rows), 2)
        self.assertEqual({row["status"] for row in ast_rows}, {"parsed", "parse_error"})
        self.assertTrue(any(row["error"] for row in ast_rows if row["status"] == "parse_error"))

        hooks = json.loads((output_dir / "hook_candidates.json").read_text(encoding="utf-8"))
        static_hook = next(item for item in hooks if item["function_name"] == "add_action" and item["hook_name"])
        self.assertEqual(static_hook["hook_name"], "wp_ajax_test_action")
        self.assertFalse(static_hook["is_dynamic"])

        dynamic_hook = next(item for item in hooks if item["function_name"] == "add_action" and item["is_dynamic"])
        self.assertIsNone(dynamic_hook["hook_name"])
        self.assertIn("wp_ajax_", dynamic_hook["hook_expression"])
        self.assertEqual(dynamic_hook["callback"], "[$this, 'handle']")
        self.assertEqual(dynamic_hook["priority"], 20)
        self.assertEqual(dynamic_hook["accepted_args"], 2)

        inputs = json.loads((output_dir / "input_candidates.json").read_text(encoding="utf-8"))
        extracted_inputs = {(item["source"], item["parameter_name"]) for item in inputs}
        self.assertIn(("POST", "id"), extracted_inputs)
        self.assertIn(("REQUEST", "q"), extracted_inputs)

        sinks = json.loads((output_dir / "sink_candidates.json").read_text(encoding="utf-8"))
        self.assertIn("$wpdb->query", {item["sink_name"] for item in sinks})


if __name__ == "__main__":
    unittest.main()
