from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison.identity import request_identity
from config_comparison.models import ConfigError, DifferenceKind, Status
from config_comparison.normalizer import normalize_config
from config_comparison.policy import ComparisonPolicy
from config_comparison.reference_index import compare_many, prepare_references


def ajax_config(*, action_location: str = "body_params", action: object = "demo", methods=None) -> dict:
    config = {"target": "http://web/wp-admin/admin-ajax.php", "methods": methods or ["POST"]}
    config[action_location] = {"data": [{"name": "action", "value": action}], "fixed": ["action"], "fuzz": []}
    return config


def rest_config(path: str = "/wp-json/demo/v1/items", *, fallback: bool = False) -> dict:
    target = "http://web" + path
    if fallback:
        target = "http://web/?rest_route=/demo/v1/items"
    return {"target": target, "methods": ["GET"], "query_params": {"data": [{"name": "term", "value": "fuzz"}]}}


class ReferenceIndexTests(unittest.TestCase):
    def test_identity_covers_ajax_admin_post_rest_and_http(self) -> None:
        policy = ComparisonPolicy()
        ajax = normalize_config(ajax_config(), policy).config
        admin_post = normalize_config(
            {"target": "http://web/wp-admin/admin-post.php", "methods": ["POST"], "body_params": {"data": [{"name": "action", "value": "export"}]}},
            policy,
        ).config
        rest = normalize_config(rest_config(), policy).config
        http = normalize_config({"target": "http://web/other", "methods": ["GET"]}, policy).config

        self.assertEqual(request_identity(ajax).family, "ajax")
        self.assertEqual(request_identity(ajax).action, "demo")
        self.assertEqual(request_identity(admin_post).family, "admin_post")
        self.assertEqual(request_identity(admin_post).action, "export")
        self.assertEqual(request_identity(rest).family, "rest")
        self.assertEqual(request_identity(rest).endpoint, "http://web/wp-json/demo/v1/items")
        self.assertEqual(request_identity(http).family, "http")

    def test_prepared_references_have_zero_one_or_many_exact_candidates(self) -> None:
        policy = ComparisonPolicy()
        expected = ajax_config()

        self.assertEqual(compare_many([expected], prepare_references([], policy))[0].status, Status.NO_REFERENCE)
        one = compare_many([expected], prepare_references([expected], policy))[0]
        self.assertEqual(one.status, Status.MATCH)
        many = compare_many([expected], prepare_references([expected, copy.deepcopy(expected)], policy))[0]
        self.assertEqual(many.status, Status.AMBIGUOUS)
        self.assertEqual(many.reference_indices, [0, 1])

    def test_lookup_is_exact_for_method_target_and_method_sets(self) -> None:
        policy = ComparisonPolicy()
        reference = ajax_config(methods=["GET", "POST", "POST"])
        self.assertEqual(compare_many([reference], prepare_references([reference], policy))[0].status, Status.MATCH)
        self.assertEqual(compare_many([ajax_config(methods=["POST"])], prepare_references([reference], policy))[0].status, Status.NO_REFERENCE)
        wrong_target = ajax_config()
        wrong_target["target"] = "http://web/wp-admin/admin-post.php"
        self.assertEqual(compare_many([wrong_target], prepare_references([reference], policy))[0].status, Status.NO_REFERENCE)

    def test_action_source_change_finds_reference_then_reports_source_mismatch(self) -> None:
        expected = ajax_config(action_location="query_params")
        actual = ajax_config(action_location="body_params")

        result = compare_many([actual], prepare_references([expected], ComparisonPolicy()))[0]

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.kind == DifferenceKind.SOURCE_MISMATCH for d in result.differences))

    def test_action_must_be_concrete_and_unambiguous(self) -> None:
        policy = ComparisonPolicy()
        for config in (
            {"target": "http://web/wp-admin/admin-ajax.php", "methods": ["POST"]},
            ajax_config(action=None),
            ajax_config(action=["demo"]),
            {"target": "http://web/wp-admin/admin-ajax.php", "methods": ["POST"], "body_params": {"data": [{"name": "action", "seeds": ["one", "two"]}]}},
        ):
            with self.subTest(config=config):
                normalized = normalize_config(config, policy)
                self.assertEqual(normalized.errors, [])
                with self.assertRaisesRegex(ValueError, "missing_or_ambiguous_action"):
                    request_identity(normalized.config)

        duplicate_sources = {
            "target": "http://web/wp-admin/admin-ajax.php",
            "methods": ["POST"],
            "query_params": {"data": [{"name": "action", "value": "demo"}]},
            "body_params": {"data": [{"name": "action", "value": "demo"}]},
        }
        normalized = normalize_config(duplicate_sources, policy)
        self.assertEqual(normalized.errors, [])
        with self.assertRaisesRegex(ValueError, "missing_or_ambiguous_action"):
            request_identity(normalized.config)

    def test_rest_pretty_and_fallback_are_not_equivalent_and_route_change_misses(self) -> None:
        policy = ComparisonPolicy()
        pretty = rest_config()
        fallback = rest_config(fallback=True)
        self.assertNotEqual(
            request_identity(normalize_config(pretty, policy).config),
            request_identity(normalize_config(fallback, policy).config),
        )
        changed = rest_config(path="/wp-json/demo/v1/other")
        self.assertEqual(compare_many([changed], prepare_references([pretty], policy))[0].status, Status.NO_REFERENCE)

    def test_invalid_reference_set_fails_closed_for_every_actual(self) -> None:
        policy = ComparisonPolicy()
        invalid_reference = {"target": "http://web", "methods": ["GET"], "body_params": {"data": [{"name": "x"}, {"name": "x", "value": 1}]}}
        prepared = prepare_references([invalid_reference], policy)
        results = compare_many([ajax_config(), ajax_config(action="second")], prepared)

        self.assertFalse(prepared.valid)
        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.status is Status.INVALID for result in results))
        self.assertTrue(all(any(error.message == "invalid_reference_set" for error in result.errors) for result in results))
        self.assertTrue(any(error.input_index == 0 for error in prepared.reference_errors))

    def test_invalid_actual_isolated_and_empty_actual_is_empty(self) -> None:
        policy = ComparisonPolicy()
        invalid_actual = {"target": "http://web", "methods": []}
        valid_actual = ajax_config()
        results = compare_many([invalid_actual, valid_actual], prepare_references([valid_actual], policy))

        self.assertEqual(results[0].status, Status.INVALID)
        self.assertEqual(results[1].status, Status.MATCH)
        self.assertEqual(compare_many([], prepare_references([valid_actual], policy)), [])

    def test_prepare_normalizes_each_reference_once_and_bulk_reuses_it(self) -> None:
        policy = ComparisonPolicy()
        references = [ajax_config(), ajax_config(action="second")]
        originals = copy.deepcopy(references)
        with patch("config_comparison.reference_index.normalize_config", wraps=normalize_config) as normalize:
            prepared = prepare_references(references, policy)
            self.assertEqual(normalize.call_count, 2)
            compare_many([references[0], references[1], references[0]], prepared)
            self.assertEqual(normalize.call_count, 5)
        self.assertEqual(references, originals)

    def test_prepared_reference_does_not_alias_input(self) -> None:
        policy = ComparisonPolicy()
        reference = ajax_config()
        prepared = prepare_references([reference], policy)
        reference["body_params"]["data"][0]["value"] = "changed"
        self.assertEqual(compare_many([ajax_config()], prepared)[0].status, Status.MATCH)


if __name__ == "__main__":
    unittest.main()
