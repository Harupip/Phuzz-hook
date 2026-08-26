from __future__ import annotations

import sys
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from discovery.entrypoints.method_resolution import normalize_http_methods, resolve_http_methods
from discovery.wordpress.rest_routes import materialize_rest_route
from seed_generation.config.config_exporter import SeedConfigSkip, build_config_for_seed_item


class RestMethodGeneralizationTests(unittest.TestCase):
    def test_normalizes_nested_comma_separated_methods_once_in_order(self) -> None:
        self.assertEqual(
            normalize_http_methods([" get,POST ", ["PUT|PATCH", "DELETE", "POST"]]),
            ["GET", "POST", "PUT", "PATCH", "DELETE"],
        )

    def test_no_evidence_is_not_a_get_or_post_fallback(self) -> None:
        decision = resolve_http_methods()[0]
        self.assertEqual(decision["method_status"], "ambiguous")
        self.assertEqual(decision["candidate_methods"], [])
        self.assertFalse(decision["export_allowed"])
        self.assertFalse(decision["replay_allowed"])

    def test_correlated_method_outside_route_is_blocked_conflict(self) -> None:
        expected = {"callback_id": "cb", "hook_name": "rest_route:fixture/v1/items", "callback_repr": "cb"}
        observed = {**expected, "request_id": "current", "http_method": "POST", "target_plugin": "fixture"}
        decision = resolve_http_methods(
            route_declared_methods=["GET"], runtime_observation=observed, expected_callback=expected
        )[0]
        self.assertEqual(decision["method_status"], "conflict")
        self.assertFalse(decision["export_allowed"])
        self.assertEqual(decision["block_reason"], "observed_request_method_not_declared_by_route")

    def test_materializes_only_named_numeric_group(self) -> None:
        materialized = materialize_rest_route(r"/items/(?P<id>\d+)")
        self.assertEqual(materialized["materialized"], "/items/1")
        self.assertEqual(materialized["substitutions"]["id"]["value"], "1")
        self.assertEqual(materialize_rest_route(r"/items/(?P<slug>[a-z]+)")["route_materialization_status"], "unsupported")

    def test_exporter_blocks_conflict(self) -> None:
        with self.assertRaisesRegex(SeedConfigSkip, "observed_request_method_not_declared_by_route"):
            build_config_for_seed_item(
                {
                    "seed": {
                        "auth_mode": "unauth-capable",
                        "method_status": "conflict",
                        "export_allowed": False,
                        "block_reason": "observed_request_method_not_declared_by_route",
                    }
                }
            )

if __name__ == "__main__":
    unittest.main()
