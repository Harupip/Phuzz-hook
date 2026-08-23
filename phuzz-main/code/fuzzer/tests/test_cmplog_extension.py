import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
EXTENSION_SOURCE = FUZZER_DIR / "zend_discovery" / "extension" / "hookphuzz_opcode.c"
FIXTURE_SOURCE = FUZZER_DIR / "tests" / "fixtures" / "hookphuzz-cmplog-fixture.php"


class CmpLogExtensionContractTests(unittest.TestCase):
    def test_extension_has_additive_comparison_event_contract(self) -> None:
        source = EXTENSION_SOURCE.read_text(encoding="utf-8")

        self.assertIn("comparison_events", source)
        self.assertIn("ZEND_IS_EQUAL", source)
        self.assertIn("ZEND_IS_NOT_EQUAL", source)
        self.assertIn("ZEND_IS_IDENTICAL", source)
        self.assertIn("ZEND_IS_NOT_IDENTICAL", source)
        self.assertIn("ZEND_SWITCH_STRING", source)
        self.assertIn("ZEND_COALESCE", source)
        self.assertIn("ZEND_QM_ASSIGN", source)
        self.assertIn("ZEND_CAST", source)

    def test_fixture_contains_all_required_runtime_shapes(self) -> None:
        source = FIXTURE_SOURCE.read_text(encoding="utf-8")

        for expression in (
            "===",
            "==",
            "!==",
            "!=",
            "'reverse_target' === $copied",
            "switch ($copied)",
            "'constant_left' === 'constant_right'",
            "getenv('HOOKPHUZZ_UNLINKED')",
        ):
            self.assertIn(expression, source)


if __name__ == "__main__":
    unittest.main()
