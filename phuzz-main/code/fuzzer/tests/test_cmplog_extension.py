import json
import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qsl, urlsplit


FUZZER_DIR = Path(__file__).resolve().parents[1]
EXTENSION_SOURCE = FUZZER_DIR / "zend_discovery" / "extension" / "hookphuzz_opcode.c"
FIXTURE_SOURCE = FUZZER_DIR / "tests" / "fixtures" / "hookphuzz-cmplog-fixture.php"
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from fuzz_guidance.cmplog.hints import apply_cmplog_hint, normalize_comparison_events
from core.candidate import Candidate
from fuzzer import Fuzzer


class CmpLogExtensionContractTests(unittest.TestCase):
    def test_null_type_check_handler_is_registered_and_unregistered(self):
        source = EXTENSION_SOURCE.read_text(encoding="utf-8")
        for expression in (
            "zend_get_user_opcode_handler(ZEND_TYPE_CHECK)",
            "zend_set_user_opcode_handler(ZEND_TYPE_CHECK, hookphuzz_null_check_handler)",
            "zend_set_user_opcode_handler(ZEND_TYPE_CHECK, NULL)",
        ):
            self.assertTrue(expression in source, expression)

    def test_bool_not_handler_is_registered_and_unregistered(self) -> None:
        source = EXTENSION_SOURCE.read_text(encoding="utf-8")
        for expression in (
            "zend_get_user_opcode_handler(ZEND_BOOL_NOT)",
            "zend_set_user_opcode_handler(ZEND_BOOL_NOT, hookphuzz_bool_not_handler)",
            "zend_set_user_opcode_handler(ZEND_BOOL_NOT, NULL)",
        ):
            self.assertTrue(expression in source, expression)

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
            "if (!$copied)",
            "if ($copied == false)",
        ):
            self.assertIn(expression, source)


@unittest.skipUnless(os.environ.get("HOOKPHUZZ_OPCODE_TEST_CONTAINER"), "requires a Zend test container")
class BoolNotRuntimeTests(unittest.TestCase):
    def run_fixture(self, params, opcache=False, fixture=FIXTURE_SOURCE, callback="hookphuzz_cmplog_fixture"):
        container = os.environ["HOOKPHUZZ_OPCODE_TEST_CONTAINER"]
        extension = os.environ.get("HOOKPHUZZ_OPCODE_TEST_EXTENSION", "hookphuzz_opcode")
        request_id = "bool-not-test-" + uuid.uuid4().hex
        path = "/shared/opcode-events/" + request_id + ".json"
        script_path = "/tmp/" + request_id + ".php"
        source = "<?php $_GET = json_decode(getenv('HOOKPHUZZ_TEST_PARAMS'), true); ?>"
        source += fixture.read_text(encoding="utf-8")
        try:
            if opcache:
                subprocess.run(["docker", "exec", "-i", container, "sh", "-c", 'cat > "$1"', "sh", script_path],
                               input=source, text=True, capture_output=True, timeout=15, check=True)
            options = (["-d", "zend_extension=opcache", "-d", "opcache.enable_cli=1",
                        "-d", "opcache.file_update_protection=0"] if opcache else [])
            result = subprocess.run([
                "docker", "exec", "-i", "-e", "HTTP_X_FUZZER_COVID=" + request_id,
                "-e", "HOOKPHUZZ_TEST_PARAMS=" + json.dumps(params), container,
                "php", "-n", *options, "-d", "extension=" + extension,
                "-d", "hookphuzz_opcode.target_callbacks=" + callback,
                *([script_path] if opcache else []),
            ], input="" if opcache else source, text=True, capture_output=True, timeout=15, check=True)
            artifact = subprocess.run(["docker", "exec", container, "cat", path],
                                      capture_output=True, timeout=15, check=True)
            return json.loads(result.stdout), json.loads(artifact.stdout)
        finally:
            subprocess.run(["docker", "exec", container, "rm", "-f", "--", path, script_path],
                           capture_output=True, timeout=15, check=True)

    def test_local_copy_bool_not_hints_open_both_falsey_branches(self):
        self.check_falsey_branches(opcache=False)

    def test_optimized_bool_not_hints_open_both_falsey_branches(self):
        self.check_falsey_branches(opcache=True)

    def check_falsey_branches(self, opcache):
        params = {"mode": "fuzz", "other": "fuzz", "nonce": "fuzz"}
        before, artifact = self.run_fixture(params, opcache=opcache)
        self.assertNotIn("bool_not", before)
        self.assertNotIn("equals_false", before)
        hints = [hint for hint in normalize_comparison_events(artifact, {"query_params": params})
                 if hint["opcode"] in {"BOOL_NOT", "JMPZ", "JMPNZ"}]
        self.assertEqual([hint["candidate_value"] for hint in hints], ["", "0"])
        self.assertEqual({hint["parameter"] for hint in hints}, {"mode"})
        for hint in hints:
            with self.subTest(value=hint["candidate_value"]):
                child = apply_cmplog_hint({"query_params": params}, hint)
                after, artifact = self.run_fixture(child["fuzz_params"]["query_params"], opcache=opcache)
                self.assertIn("bool_not", after)
                self.assertIn("equals_false", after)
                self.assertFalse(any(e["opcode"] in {"BOOL_NOT", "JMPZ", "JMPNZ"}
                                     for e in artifact.get("comparison_events", [])))

    def test_typed_json_null_and_query_omission_reach_null_branches(self):
        fixture = FUZZER_DIR / "tests" / "fixtures" / "hookphuzz-null-check-fixture.php"
        for opcache in (False, True):
            with self.subTest(opcache=opcache):
                params = {"query": {"mode": "null", "keep": "query"},
                          "body": {"mode": "null", "keep": "body", "nonce": "fuzz"}}
                before, artifact = self.run_fixture(params, opcache, fixture, "hookphuzz_null_check_fixture")
                self.assertNotIn("json_null", before)
                self.assertNotIn("query_null", before)
                parent = Candidate(http_target="http://web/?mode=fuzz", http_method="POST",
                    fixed_params={"headers": {"Content-Type": "application/json"}},
                    fuzz_params={"query_params": params["query"], "body_params": params["body"]})
                hints = [h for h in normalize_comparison_events(artifact, parent.fuzz_params)
                         if h["opcode"] == "TYPE_CHECK"]
                self.assertEqual({h["source"] for h in hints}, {"GET", "REST_JSON"})
                self.assertEqual(len(hints), 2)
                for hint in hints:
                    worker = object.__new__(Fuzzer)
                    worker.config = {}
                    worker.fuzzer_id = 1
                    worker.scoring_formula = SimpleNamespace(calculate_priority=lambda c: 1)
                    worker.cmplog_hints = [hint]
                    child = worker.ff_mutate(parent)
                    prepared = worker.prepare_request(child)
                    sent = {"query": dict(parse_qsl(urlsplit(prepared.url).query)),
                            "body": json.loads(prepared.body)}
                    after, _ = self.run_fixture(sent, opcache, fixture, "hookphuzz_null_check_fixture")
                    if hint["source"] == "REST_JSON":
                        self.assertIn("mode", sent["body"])
                        self.assertIsNone(sent["body"]["mode"])
                        self.assertEqual(after["json_null"], "new-json-path")
                        self.assertTrue(after["is_null"])
                        self.assertNotIn("query_null", after)
                    else:
                        self.assertNotIn("mode", sent["query"])
                        self.assertEqual(after["query_null"], "new-query-path")
                        self.assertNotIn("json_null", after)


if __name__ == "__main__":
    unittest.main()
