from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison.models import DifferenceKind
from config_comparison.normalizer import normalize_config
from config_comparison.policy import ComparisonPolicy


def base_config() -> dict:
    return {
        "target": "HTTP://Web:80/admin-ajax.php?z=last&blank=",
        "methods": [" post ", "POST"],
        "headers": {
            "data": [{"name": "Content-Type", "value": "application/json"}],
            "fixed": ["Content-Type"],
            "fuzz": [],
            "weight": 2,
        },
        "cookies": {
            "data": [{"name": "wordpress_test_cookie", "value": "cookie"}],
            "fixed": ["wordpress_test_cookie"],
            "fuzz": [],
        },
        "body_params": {
            "data": [
                {"name": "action", "value": "gamipress_get_logs"},
                {"name": "product_id", "seeds": [1, {"b": 2, "a": True}, ["x", "y"]]},
            ],
            "fixed": ["action", "product_id"],
            "fuzz": [],
            "weight": 1,
        },
        "metadata": {"hook_name": "wp_ajax_demo", "run_id": "run-1"},
    }


class ConfigNormalizerTests(unittest.TestCase):
    def test_normalizes_sections_methods_selectors_and_detaches_input(self) -> None:
        config = base_config()
        original = copy.deepcopy(config)

        normalized = normalize_config(config, ComparisonPolicy(mode="strict"))

        self.assertEqual(normalized.errors, [])
        self.assertIsNotNone(normalized.config)
        self.assertEqual(normalized.config.target, "http://web/admin-ajax.php")
        self.assertEqual(normalized.config.methods, ("POST",))
        self.assertEqual(normalized.config.parameters["body_params"]["action"]["value"], "gamipress_get_logs")
        self.assertIn("query_params", normalized.config.parameters)
        self.assertEqual(normalized.config.parameters["query_params"]["blank"]["value"], "")
        self.assertEqual(config, original)

        config["body_params"]["data"][0]["value"] = "changed_after_normalize"
        self.assertEqual(normalized.config.parameters["body_params"]["action"]["value"], "gamipress_get_logs")

    def test_absent_sections_are_empty_and_data_order_is_not_semantic(self) -> None:
        config = {"target": "http://web/", "methods": ["GET"]}
        normalized = normalize_config(config, ComparisonPolicy())

        self.assertEqual(normalized.errors, [])
        self.assertEqual(normalized.config.parameters, {
            "headers": {},
            "cookies": {},
            "query_params": {},
            "body_params": {},
        })
        self.assertEqual(normalized.config.selectors["body_params"], {"fixed": frozenset(), "fuzz": frozenset()})

    def test_query_url_preserves_blank_value_and_rejects_duplicate_or_conflict(self) -> None:
        valid = {"target": "http://web/?b=2&a=&b2=1", "methods": ["GET"]}
        result = normalize_config(valid, ComparisonPolicy())
        self.assertEqual(result.errors, [])
        self.assertEqual(result.config.parameters["query_params"]["a"]["value"], "")

        duplicate = {"target": "http://web/?a=1&a=1", "methods": ["GET"]}
        duplicate_result = normalize_config(duplicate, ComparisonPolicy())
        self.assertEqual(duplicate_result.config, None)
        self.assertTrue(any(error.kind == DifferenceKind.DUPLICATE_PARAMETER for error in duplicate_result.errors))

        conflict = {
            "target": "http://web/?a=1",
            "methods": ["GET"],
            "query_params": {"data": [{"name": "a", "value": "1"}]},
        }
        conflict_result = normalize_config(conflict, ComparisonPolicy())
        self.assertEqual(conflict_result.config, None)
        self.assertTrue(any(error.message == "conflicting_query_definition" for error in conflict_result.errors))

    def test_typed_values_and_seed_declarations_are_retained(self) -> None:
        config = {
            "target": "https://web/path",
            "methods": ["GET", "POST"],
            "body_params": {
                "data": [
                    {"name": "bool_value", "value": True},
                    {"name": "int_value", "value": 1},
                    {"name": "null_value", "value": None},
                    {"name": "seed_value", "seeds": ["b", "a", "a"]},
                    {"name": "both", "value": "value", "seeds": ["seed"]},
                ],
                "fixed": ["bool_value", "int_value", "null_value", "seed_value", "both"],
                "fuzz": [],
            },
        }
        result = normalize_config(config, ComparisonPolicy())
        self.assertEqual(result.errors, [])
        self.assertIs(result.config.parameters["body_params"]["bool_value"]["value"], True)
        self.assertEqual(result.config.parameters["body_params"]["seed_value"]["seeds"], ["b", "a", "a"])
        self.assertEqual(result.config.parameters["body_params"]["both"]["value"], "value")

    def test_duplicate_names_and_malformed_entries_accumulate_errors(self) -> None:
        config = {
            "target": "http://web",
            "methods": ["GET"],
            "body_params": {
                "data": [
                    {"name": "same", "value": 1},
                    {"name": "same", "value": 1},
                    {"name": "no_value"},
                    "not-an-entry",
                ],
                "fixed": ["same", 3, "["],
                "fuzz": "not-a-list",
            },
        }
        result = normalize_config(config, ComparisonPolicy())

        self.assertIsNone(result.config)
        self.assertGreaterEqual(len(result.errors), 4)
        kinds = {error.kind for error in result.errors}
        self.assertIn(DifferenceKind.DUPLICATE_PARAMETER, kinds)
        self.assertIn(DifferenceKind.INVALID_CONFIG, kinds)

    def test_invalid_url_and_methods_do_not_leak_exceptions(self) -> None:
        cases = [
            {"target": "", "methods": ["GET"]},
            {"target": "ftp://web", "methods": ["GET"]},
            {"target": "http://user:pass@web", "methods": ["GET"]},
            {"target": "http://web/#fragment", "methods": ["GET"]},
            {"target": "http://web/#", "methods": ["GET"]},
            {"target": "http://web", "methods": []},
            {"target": "http://web", "methods": "GET"},
        ]
        for config in cases:
            with self.subTest(config=config):
                result = normalize_config(config, ComparisonPolicy())
                self.assertIsNone(result.config)
                self.assertTrue(result.errors)

    def test_null_selector_is_invalid_but_missing_selector_is_empty(self) -> None:
        missing = {
            "target": "http://web",
            "methods": ["GET"],
            "body_params": {"data": [{"name": "x", "value": "1"}]},
        }
        self.assertEqual(normalize_config(missing, ComparisonPolicy()).errors, [])

        explicit_null = copy.deepcopy(missing)
        explicit_null["body_params"]["fixed"] = None
        result = normalize_config(explicit_null, ComparisonPolicy())
        self.assertIsNone(result.config)
        self.assertTrue(any(error.path == "/body_params/fixed" for error in result.errors))

    def test_selector_without_data_does_not_create_parameter(self) -> None:
        config = {
            "target": "http://web",
            "methods": ["POST"],
            "body_params": {
                "data": [{"name": "action", "value": "demo"}],
                "fixed": ["action", "product_id"],
                "fuzz": ["page", "product_id"],
            },
        }
        result = normalize_config(config, ComparisonPolicy())
        self.assertEqual(result.errors, [])
        self.assertEqual(set(result.config.parameters["body_params"]), {"action"})
        self.assertEqual(result.config.selectors["body_params"]["fixed"], {"action", "product_id"})

    def test_policy_validation_and_reserved_effective_mode(self) -> None:
        self.assertEqual(ComparisonPolicy().mode, "strict")
        self.assertEqual(ComparisonPolicy(mode="semantic").mode, "semantic")
        with self.assertRaisesRegex(ValueError, "effective policy is not supported in V1"):
            ComparisonPolicy(mode="effective")
        with self.assertRaises(ValueError):
            ComparisonPolicy(mode="unknown")
        with self.assertRaises(ValueError):
            ComparisonPolicy(mode=[])
        with self.assertRaises(ValueError):
            ComparisonPolicy(allowed_extra_parameters={("not_a_source", "x")})
        with self.assertRaises(ValueError):
            ComparisonPolicy(allowed_extra_parameters=[[['body_params'], "x"]])
        with self.assertRaises(ValueError):
            ComparisonPolicy(ignored_metadata_paths={"/body_params/x"})


if __name__ == "__main__":
    unittest.main()
