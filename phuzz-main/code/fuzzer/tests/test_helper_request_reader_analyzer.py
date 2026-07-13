from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.helper_request_reader_analyzer import HelperRequestReaderAnalyzer


class HelperRequestReaderAnalyzerTests(unittest.TestCase):
    def test_registers_only_static_helper_with_direct_formal_superglobal_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "helpers.php").write_text(
                """<?php
class cfx_form {
 public static function post($key, $arr='') {
  if (is_array($arr)) return $arr[$key];
  return isset($_REQUEST[$key]) ? self::clean($_REQUEST[$key]) : '';
 }
 public static function named_post($key) { return $_POST['fixed']; }
 public function instance($key) { return $_POST[$key]; }
}
""",
                encoding="utf-8",
            )
            registry = HelperRequestReaderAnalyzer().analyze(root, display_root="/plugin")

        self.assertEqual(len(registry["readers"]), 1)
        reader = registry["readers"][0]
        self.assertEqual(reader["symbol"], "cfx_form::post")
        self.assertEqual(reader["formal_key_argument_index"], 0)
        self.assertEqual(reader["http_source"], "REQUEST")
        self.assertEqual(reader["evidence"]["source_expression"], "$_REQUEST[$key]")
        self.assertEqual(reader["definition_file"], "/plugin/helpers.php")


if __name__ == "__main__":
    unittest.main()
