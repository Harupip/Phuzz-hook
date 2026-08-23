import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.zend_runtime.cmplog import (
    apply_cmplog_hint,
    normalize_comparison_events,
)


class CmpLogNormalizationTests(unittest.TestCase):
    def test_active_zend_extension_contract_mentions_comparison_artifacts(self) -> None:
        source = (
            FUZZER_DIR / "zend_discovery" / "extension" / "hookphuzz_opcode.c"
        ).read_text(encoding="utf-8")

        self.assertIn("comparison_events", source)
        self.assertIn("ZEND_IS_EQUAL", source)
        self.assertIn("ZEND_IS_NOT_EQUAL", source)
        self.assertIn("ZEND_IS_IDENTICAL", source)
        self.assertIn("ZEND_IS_NOT_IDENTICAL", source)
        self.assertIn("ZEND_SWITCH_STRING", source)

    def test_normalizes_rest_string_comparison_to_the_same_parameter(self) -> None:
        artifact = {
            "request_id": "request-1",
            "comparison_events": [
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "REST",
                    "path": ["GET", "mode"],
                    "runtime_value": "INVALID_VALUE",
                    "comparison_value": "special_operation",
                }
            ],
        }

        hints = normalize_comparison_events(
            artifact,
            {"query_params": {"mode": "INVALID_VALUE"}},
        )

        self.assertEqual(len(hints), 1)
        self.assertEqual(hints[0]["parameter"], "mode")
        self.assertEqual(hints[0]["placement"], "query_params")
        self.assertEqual(hints[0]["candidate_value"], "special_operation")
        self.assertEqual(hints[0]["request_id"], "request-1")
        self.assertEqual(hints[0]["callback"], "Demo::handle")

    def test_rejects_unlinked_and_constant_comparisons(self) -> None:
        artifact = {
            "request_id": "request-2",
            "comparison_events": [
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "NONE",
                    "path": [],
                    "runtime_value": "AAAA",
                    "comparison_value": "special_operation",
                }
            ],
        }

        self.assertEqual(
            normalize_comparison_events(
                artifact,
                {"query_params": {"mode": "AAAA"}},
            ),
            [],
        )

    def test_deduplicates_and_does_not_cross_parameters(self) -> None:
        event = {
            "callback": "Demo::handle",
            "opcode": "IS_EQUAL",
            "source": "REST",
            "path": ["POST", "mode"],
            "runtime_value": "INVALID_MODE",
            "comparison_value": "special_mode",
        }
        artifact = {
            "request_id": "request-3",
            "comparison_events": [event, dict(event), {
                "callback": "Demo::handle",
                "opcode": "IS_IDENTICAL",
                "source": "REST",
                "path": ["POST", "other"],
                "runtime_value": "INVALID_OTHER",
                "comparison_value": "special_other",
            }],
        }

        hints = normalize_comparison_events(
            artifact,
            {"body_params": {"mode": "INVALID_MODE", "other": "INVALID_OTHER"}},
        )

        self.assertEqual(
            {(item["parameter"], item["candidate_value"]) for item in hints},
            {("mode", "special_mode"), ("other", "special_other")},
        )

    def test_rejects_sensitive_parameter_and_non_scalar_target(self) -> None:
        artifact = {
            "request_id": "request-4",
            "comparison_events": [
                {
                    "callback": "Demo::auth",
                    "opcode": "IS_IDENTICAL",
                    "source": "POST",
                    "path": ["nonce"],
                    "runtime_value": "AAAA",
                    "comparison_value": "BBBB",
                },
                {
                    "callback": "Demo::handle",
                    "opcode": "IS_IDENTICAL",
                    "source": "POST",
                    "path": ["mode"],
                    "runtime_value": "AAAA",
                    "comparison_value": ["not", "scalar"],
                },
            ],
        }

        self.assertEqual(
            normalize_comparison_events(
                artifact,
                {"body_params": {"nonce": "AAAA", "mode": "AAAA"}},
            ),
            [],
        )


class CmpLogMutationTests(unittest.TestCase):
    def test_applies_normalized_hint_to_the_matching_parameter(self) -> None:
        hint = {
            "request_id": "request-1",
            "callback": "Demo::handle",
            "opcode": "IS_IDENTICAL",
            "source": "REST_QUERY",
            "path": ["mode"],
            "parameter": "mode",
            "placement": "query_params",
            "observed_value": "INVALID_VALUE",
            "candidate_value": "special_operation",
            "reason": "cmplog",
        }

        result = apply_cmplog_hint(
            {"query_params": {"mode": "INVALID_VALUE"}},
            hint,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["fuzz_params"]["query_params"]["mode"], "special_operation")
        self.assertEqual(result["mutated_param_type"], "query_params")
        self.assertEqual(result["mutated_param_name"], "mode")
        self.assertEqual(result["mutation_source"], "cmplog")

    def test_ff_mutate_consumes_normalized_hints_without_artifact_io(self) -> None:
        source = (FUZZER_DIR / "fuzzer.py").read_text(encoding="utf-8")
        mutate_body = source.split("    def ff_mutate(self, c):", 1)[1].split(
            "    def ff_send_request", 1
        )[0]

        self.assertIn("self.cmplog_hints", mutate_body)
        self.assertIn("apply_cmplog_hint", mutate_body)
        self.assertNotIn("opcode-events", mutate_body)
        self.assertNotIn("json.load", mutate_body)


if __name__ == "__main__":
    unittest.main()
