from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison.comparator import compare_configs
from config_comparison.models import DifferenceKind, Status
from config_comparison.policy import ComparisonPolicy


def comparison_config() -> dict:
    return {
        "target": "http://web/wp-admin/admin-ajax.php",
        "methods": ["POST", "GET"],
        "query_params": {
            "data": [
                {"name": "page", "value": "1"},
                {"name": "blank", "value": ""},
            ],
            "fixed": ["page", "blank"],
            "fuzz": ["page_id", "post_id"],
            "weight": 1,
        },
        "body_params": {
            "data": [
                {"name": "action", "value": "demo"},
                {"name": "product_id", "value": 7},
                {"name": "profile[name]", "seeds": [{"b": 2, "a": True}, ["x", "y"]]},
            ],
            "fixed": ["action", "product_id"],
            "fuzz": [r"profile\[name\]"],
            "weight": 1,
        },
        "metadata": {
            "hook_name": "wp_ajax_demo",
            "resolved_method": "POST",
            "run_id": "original-run",
        },
        "print_timestamps": False,
    }


def kinds_and_paths(result):
    return {(difference.kind, difference.path) for difference in result.differences}


class ConfigComparatorTests(unittest.TestCase):
    def test_same_config_and_declaration_order_match(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"].reverse()
        actual["body_params"]["fixed"].reverse()
        actual["body_params"]["fuzz"].reverse()
        actual = dict(reversed(list(actual.items())))

        result = compare_configs(expected, actual, ComparisonPolicy(mode="strict"))

        self.assertEqual(result.status, Status.MATCH)
        self.assertTrue(result.matched)
        self.assertEqual(result.differences, [])

    def test_missing_parameter_reports_named_pointer(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"] = [
            item for item in actual["body_params"]["data"] if item["name"] != "product_id"
        ]

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.MISSING_PARAMETER, "/body_params/product_id"), kinds_and_paths(result))

    def test_missing_cookie_is_mismatch(self) -> None:
        expected = comparison_config()
        expected["cookies"] = {
            "data": [{"name": "session_id", "value": "fixture-session"}],
            "fixed": ["session_id"],
            "fuzz": [],
        }
        actual = copy.deepcopy(expected)
        del actual["cookies"]

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.MISSING_PARAMETER, "/cookies/session_id"), kinds_and_paths(result))

    def test_selector_move_from_fuzz_to_fixed_is_classification_mismatch(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["fixed"].append(r"profile\[name\]")
        actual["body_params"]["fuzz"].remove(r"profile\[name\]")

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.CLASSIFICATION_MISMATCH, "/body_params/fixed"), kinds_and_paths(result))
        self.assertIn((DifferenceKind.CLASSIFICATION_MISMATCH, "/body_params/fuzz"), kinds_and_paths(result))

    def test_wrong_method_and_target_are_typed_differences(self) -> None:
        expected = comparison_config()
        wrong_method = copy.deepcopy(expected)
        wrong_method["methods"] = ["PUT"]
        wrong_target = copy.deepcopy(expected)
        wrong_target["target"] = "http://web/wp-admin/admin-post.php"

        method_result = compare_configs(expected, wrong_method, ComparisonPolicy())
        target_result = compare_configs(expected, wrong_target, ComparisonPolicy())

        self.assertEqual(method_result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.METHOD_MISMATCH, "/methods"), kinds_and_paths(method_result))
        self.assertEqual(target_result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.TARGET_MISMATCH, "/target"), kinds_and_paths(target_result))

    def test_parameter_moved_between_query_and_body_is_one_source_difference(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        page = actual["query_params"]["data"].pop(0)
        actual["body_params"]["data"].append(page)

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertEqual(result.status, Status.MISMATCH)
        source_differences = [d for d in result.differences if d.kind == DifferenceKind.SOURCE_MISMATCH]
        self.assertEqual(len(source_differences), 1)
        self.assertEqual(source_differences[0].expected["source"], "query_params")
        self.assertEqual(source_differences[0].actual["source"], "body_params")

    def test_unexpected_parameter_and_source_scoped_allowlist(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"].append({"name": "nonce", "value": "secret"})
        actual["body_params"]["fixed"].append("nonce")

        rejected = compare_configs(expected, actual, ComparisonPolicy())
        allowed = compare_configs(
            expected,
            actual,
            ComparisonPolicy(allowed_extra_parameters={("body_params", "nonce")}),
        )

        self.assertIn((DifferenceKind.UNEXPECTED_PARAMETER, "/body_params/nonce"), kinds_and_paths(rejected))
        self.assertEqual(allowed.status, Status.MATCH)

    def test_allowlist_does_not_hide_missing_required_parameter(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"].append({"name": "nonce", "value": "secret"})
        actual["body_params"]["fixed"].append("nonce")
        actual["body_params"]["data"] = [
            item for item in actual["body_params"]["data"] if item["name"] != "product_id"
        ]

        result = compare_configs(
            expected,
            actual,
            ComparisonPolicy(allowed_extra_parameters={("body_params", "nonce")}),
        )

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertIn((DifferenceKind.MISSING_PARAMETER, "/body_params/product_id"), kinds_and_paths(result))

    def test_values_and_seeds_use_typed_order_rules(self) -> None:
        expected = comparison_config()
        reordered = copy.deepcopy(expected)
        reordered["body_params"]["data"][2]["seeds"] = [["x", "y"], {"a": True, "b": 2}]
        self.assertEqual(compare_configs(expected, reordered, ComparisonPolicy()).status, Status.MATCH)

        changed_value = copy.deepcopy(expected)
        changed_value["body_params"]["data"][1]["value"] = "7"
        value_result = compare_configs(expected, changed_value, ComparisonPolicy())
        self.assertIn((DifferenceKind.VALUE_MISMATCH, "/body_params/product_id/value"), kinds_and_paths(value_result))

        changed_seed = copy.deepcopy(expected)
        changed_seed["body_params"]["data"][2]["seeds"] = [["y", "x"], {"a": True, "b": 2}]
        seed_result = compare_configs(expected, changed_seed, ComparisonPolicy())
        self.assertIn((DifferenceKind.SEED_MISMATCH, "/body_params/profile[name]/seeds"), kinds_and_paths(seed_result))

    def test_missing_field_differs_from_explicit_null_and_value_vs_seeds(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"][1] = {"name": "product_id", "value": None}
        result = compare_configs(expected, actual, ComparisonPolicy())
        self.assertIn((DifferenceKind.VALUE_MISMATCH, "/body_params/product_id/value"), kinds_and_paths(result))

        seeds_actual = copy.deepcopy(expected)
        seeds_actual["body_params"]["data"][1] = {"name": "product_id", "seeds": [7]}
        seeds_result = compare_configs(expected, seeds_actual, ComparisonPolicy())
        self.assertTrue(any(d.reason == "missing_field" for d in seeds_result.differences))

    def test_strict_checks_transient_and_semantic_ignores_only_allowlist(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["print_timestamps"] = True
        actual["metadata"]["run_id"] = "new-run"
        actual["metadata"]["hook_name"] = "changed-hook"

        strict = compare_configs(expected, actual, ComparisonPolicy(mode="strict"))
        semantic = compare_configs(expected, actual, ComparisonPolicy(mode="semantic"))

        self.assertEqual(strict.status, Status.MISMATCH)
        self.assertEqual(semantic.status, Status.MISMATCH)
        self.assertTrue(any(d.path == "/metadata/hook_name" for d in semantic.differences))
        self.assertFalse(any(d.path in {"/print_timestamps", "/metadata/run_id"} for d in semantic.differences))

        only_ignored = copy.deepcopy(expected)
        only_ignored["print_timestamps"] = True
        only_ignored["metadata"]["run_id"] = "new-run"
        self.assertEqual(compare_configs(expected, only_ignored, ComparisonPolicy(mode="semantic")).status, Status.MATCH)

    def test_auth_and_unknown_metadata_are_not_ignored(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["metadata"]["auth_mode"] = "authenticated"
        actual["metadata"]["unknown_annotation"] = "different"

        result = compare_configs(expected, actual, ComparisonPolicy(mode="semantic"))

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.path == "/metadata/auth_mode" for d in result.differences))
        self.assertTrue(any(d.path == "/metadata/unknown_annotation" for d in result.differences))

    def test_invalid_input_is_invalid_not_mismatch(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"].append({"name": "action", "value": "duplicate"})

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertEqual(result.status, Status.INVALID)
        self.assertFalse(result.matched)
        self.assertTrue(result.errors)
        self.assertTrue(any(d.kind == DifferenceKind.DUPLICATE_PARAMETER for d in result.differences))

    def test_broad_extra_selector_is_not_silently_allowed(self) -> None:
        expected = comparison_config()
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"].append({"name": "nonce", "value": "secret"})
        actual["body_params"]["fixed"].append(".*")

        result = compare_configs(
            expected,
            actual,
            ComparisonPolicy(allowed_extra_parameters={("body_params", "nonce")}),
        )

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.kind == DifferenceKind.CLASSIFICATION_MISMATCH for d in result.differences))

    def test_names_are_escaped_as_json_pointers(self) -> None:
        expected = comparison_config()
        expected["body_params"]["data"][2]["name"] = "profile/name~field[0]"
        actual = copy.deepcopy(expected)
        actual["body_params"]["data"][2]["seeds"] = [["changed"]]

        result = compare_configs(expected, actual, ComparisonPolicy())

        self.assertTrue(any(d.path == "/body_params/profile~1name~0field[0]/seeds" for d in result.differences))


if __name__ == "__main__":
    unittest.main()
