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
    def analyze_php(self, php: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            (root / "helpers.php").write_text("<?php\n" + php, encoding="utf-8")
            return HelperRequestReaderAnalyzer().analyze(root, display_root="/plugin")

    def test_positive_supported_reader_forms(self) -> None:
        registry = self.analyze_php(
            """
class StaticPost { public static function post($key) { return $_POST[$key] ?? null; } }
class InstanceGet { public function get($name) { return $_GET[$name] ?? null; } }
function request_value($key) { return isset($_REQUEST[$key]) ? $_REQUEST[$key] : null; }
function input_value($key) { return filter_input(INPUT_POST, $key); }
function input_get_value($key) { return filter_input(INPUT_GET, $key); }
function rest_value($request, $key) { return $request->get_param($key); }
"""
        )
        by_symbol = {reader["symbol"]: reader for reader in registry["readers"]}
        self.assertEqual(by_symbol["StaticPost::post"]["symbol_type"], "static_method")
        self.assertEqual(by_symbol["StaticPost::post"]["http_source"], "POST")
        self.assertEqual(by_symbol["InstanceGet::get"]["symbol_type"], "instance_method")
        self.assertEqual(by_symbol["InstanceGet::get"]["http_source"], "GET")
        self.assertEqual(by_symbol["request_value"]["http_source"], "REQUEST")
        self.assertEqual(by_symbol["input_value"]["http_source"], "FILTER_INPUT_POST")
        self.assertEqual(by_symbol["input_get_value"]["http_source"], "FILTER_INPUT_GET")
        self.assertEqual(by_symbol["rest_value"]["http_source"], "REST_GET_PARAM")
        self.assertEqual(by_symbol["rest_value"]["formal_key_argument_index"], 1)

    def test_phase3_crm_style_static_request_helper_still_proves(self) -> None:
        registry = self.analyze_php(
            """
class cfx_form {
 public static function post($key, $arr='') {
  if (is_array($arr)) return $arr[$key];
  return isset($_REQUEST[$key]) ? self::clean($_REQUEST[$key]) : '';
 }
 public static function named_post($key) { return $_POST['fixed']; }
}
"""
        )
        readers = registry["readers"]
        self.assertEqual(len(readers), 1)
        self.assertEqual(readers[0]["symbol"], "cfx_form::post")
        self.assertEqual(readers[0]["http_source"], "REQUEST")

    def test_negative_cases_reject_with_reasons(self) -> None:
        registry = self.analyze_php(
            """
class BadName { public static function post($key) { return $key; } }
class BadComputed { public static function post($key) { return $_POST[strtolower($key)]; } }
function wrong_arg($value) { return $_GET['fixed']; }
function sanitize_only($value) { return sanitize_text_field($value); }
function constant_reader($key) { return 'x'; }
function hardcoded($key) { return $_POST['fixed']; }
function bulk($key) { return $_POST; }
"""
        )
        self.assertEqual(registry["readers"], [])
        reasons = {row["symbol"]: row["reason"] for row in registry["rejections"]}
        self.assertEqual(reasons["BadComputed::post"], "unsupported_computed_superglobal_key")
        self.assertEqual(reasons["sanitize_only"], "sanitizes_argument_without_http_read")
        self.assertEqual(reasons["constant_reader"], "returns_constant_without_http_read")
        self.assertEqual(reasons["bulk"], "unsupported_bulk_superglobal_read")
        self.assertIn(reasons["wrong_arg"], {"missing_source_evidence", "unsupported_computed_superglobal_key"})

    def test_ambiguous_symbol_rejected(self) -> None:
        registry = self.analyze_php(
            """
function dup($key) { return $_GET[$key]; }
function dup($key) { return $_POST[$key]; }
"""
        )
        self.assertEqual(registry["readers"], [])
        self.assertTrue(all(row["reason"] == "ambiguous_symbol_multiple_incompatible_definitions" for row in registry["rejections"]))


if __name__ == "__main__":
    unittest.main()

