from __future__ import annotations

import re
import unittest
from pathlib import Path


UOPZ_HOOK_FILE = (
    Path(__file__).resolve().parents[2]
    / "web"
    / "instrumentation"
    / "hook_coverage"
    / "uopz_hook_wp.php"
)


class UopzMultistageMetadataContractTests(unittest.TestCase):
    def test_uopz_runtime_declares_callback_stack_helpers(self) -> None:
        source = UOPZ_HOOK_FILE.read_text(encoding="utf-8")

        self.assertIn("$GLOBALS['__hookphuzz_callback_stack'] = [];", source)
        self.assertIn("function __uopz_current_parent_callback_metadata(): ?array", source)
        self.assertIn("function __uopz_push_callback_stack(", source)
        self.assertIn("function __uopz_pop_callback_stack(): void", source)

    def test_registered_callback_records_multistage_metadata(self) -> None:
        source = UOPZ_HOOK_FILE.read_text(encoding="utf-8")

        register_body = re.search(
            r"function __uopz_register_callback\([\s\S]+?\n}\n\nfunction __uopz_unregister_callback",
            source,
        )
        self.assertIsNotNone(register_body)
        body = register_body.group(0)

        self.assertIn("'registered_inside_callback' =>", body)
        self.assertIn("'parent_callback' =>", body)
        self.assertIn("'hook_level' =>", body)
        self.assertIn("'parent_hook_name' =>", body)
        self.assertIn("'parent_callback_id' =>", body)
        self.assertIn("'parent_callback_repr' =>", body)
        self.assertIn("'registration_stack_depth' =>", body)

    def test_actual_invocation_pushes_and_pops_callback_stack(self) -> None:
        source = UOPZ_HOOK_FILE.read_text(encoding="utf-8")

        invocation_body = re.search(
            r"function __uopz_record_actual_callback_invocation\([\s\S]+?\n}\n\n// Duyet",
            source,
        )
        self.assertIsNotNone(invocation_body)
        body = invocation_body.group(0)

        self.assertIn("__uopz_push_callback_stack(", body)
        self.assertIn("try {", body)
        self.assertIn("__uopz_pop_callback_stack();", body)
        self.assertIn("finally {", body)


if __name__ == "__main__":
    unittest.main()
