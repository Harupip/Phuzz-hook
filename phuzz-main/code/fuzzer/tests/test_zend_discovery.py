from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import zipfile
import unittest
import zipfile
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from zend_discovery.engine import (
    BLOCKED_NEEDS_RECIPE,
    BLOCKED_UNSAFE_AUTO_PROBE,
    build_catalog,
    canonical_identity,
    canonical_identity_id,
    candidate_from_seed_item,
    correlate_pass1_artifact,
    enrich_current_run,
    normalize_runtime_evidence,
    prepare_callback_registry,
    read_plugin_metadata,
    run_enrichment,
    select_auto_probes,
)
from zend_discovery.convergence import (
    advance_convergence_state,
    canonical_runtime_parameter_identity,
    materialize_convergence_seeds,
)
from hook_energy.seed_generation.zend_bridge_cli import combine_final_seed_reports, converge_iteration, verify_pass2_contract
from zend_discovery.source_materializer import materialize_plugin_source
from zend_discovery.parameter_seeds import build_parameter_seed
from hook_energy.seed_generation.input_extractor import InputSignatureExtractor


class StaticExtractor:
    def __init__(self, input_params: list[dict]) -> None:
        self.input_params = input_params

    def extract(self, callback: dict) -> dict:
        return {"input_params": self.input_params}


class ZendDiscoveryTests(unittest.TestCase):
    def test_normalize_runtime_evidence_maps_direct_get_and_post_independently_of_request_method(self) -> None:
        candidate = self.pass1_candidate()
        uopz = self.pass1_artifact(candidate)
        registry = {
            "schema_version": 1,
            "callback_map": {"ajax-public": "Demo::fetch"},
            "registrations": [{"callback": "Demo::fetch", "canonical_callback": "Demo::fetch", "callback_type": "object_method"}],
        }
        zend = {
            "schema_version": 3,
            "run_id": "legacy-1",
            "request_id": "pass1-1",
            "request_method": "POST",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "callback_summaries": [{
                "callback": "Demo::fetch",
                "unique_parameters": [
                    {"source": "GET", "path": ["x"], "helper_depth": 0, "observed_count": 1},
                    {"source": "POST", "path": ["y"], "helper_depth": 0, "observed_count": 2},
                    {"source": "REQUEST", "path": ["ignored"], "helper_depth": 0, "observed_count": 1},
                    {"source": "GET", "path": ["nested", "leaf"], "helper_depth": 0, "observed_count": 1},
                    {"source": "POST", "path": ["helper"], "helper_depth": 1, "observed_count": 1},
                ],
            }],
        }

        evidence = normalize_runtime_evidence(candidate, uopz, zend, registry)

        self.assertEqual(
            evidence,
            [
                {
                    "name": "x", "path": ["x"], "source": "GET", "location": "query",
                    "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "run_id": "legacy-1", "request_id": "pass1-1",
                    "plugin_slug": "demo-plugin", "callback_id": "ajax-public",
                    "canonical_callback": "Demo::fetch", "request_method": "POST",
                },
                {
                    "name": "y", "path": ["y"], "source": "POST", "location": "form",
                    "helper_depth": 0, "observed_count": 2, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "run_id": "legacy-1", "request_id": "pass1-1",
                    "plugin_slug": "demo-plugin", "callback_id": "ajax-public",
                    "canonical_callback": "Demo::fetch", "request_method": "POST",
                },
            ],
        )
        for row in evidence:
            self.assertEqual(row["run_id"], "legacy-1")
            self.assertEqual(row["request_id"], "pass1-1")
            self.assertEqual(row["plugin_slug"], "demo-plugin")
            self.assertEqual(row["callback_id"], "ajax-public")
            self.assertEqual(row["canonical_callback"], "Demo::fetch")
            self.assertEqual(row["request_method"], "POST")

    def test_normalize_runtime_evidence_exports_rest_parameter_only_with_exact_runtime_transport_proof(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "GET",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-1",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        )
        registry = {
            "schema_version": 1,
            "callback_map": {"rest-items": "Demo::list_items"},
            "registrations": [{"callback": "Demo::list_items", "canonical_callback": "Demo::list_items", "callback_type": "static_method"}],
        }
        zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-request-1",
            "request_method": "GET",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [{
                "callback": "Demo::list_items",
                "namespace": "demo/v1",
                "route_pattern": "/items",
                "endpoint_definition_index": 0,
                "materialized_route": "/wp-json/demo/v1/items",
                "method": "GET",
                "name": "search",
                "location": "query",
                "observed_count": 1,
            }],
        }

        evidence = normalize_runtime_evidence(candidate, uopz, zend, registry)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["name"], "search")
        self.assertEqual(evidence[0]["location"], "query")
        self.assertEqual(evidence[0]["source"], "REST_QUERY")
        self.assertEqual(evidence[0]["canonical_callback"], "Demo::list_items")

    def test_normalize_runtime_evidence_accepts_zend_rest_params_fetch_event(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "GET",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-zend-fetch",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        )
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-request-zend-fetch",
            "request_method": "GET",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [{
                "source": "REST",
                "bucket": "GET",
                "parameter": "search",
                "path": ["GET", "search"],
                "callback": "Demo::list_items",
                "observed_count": 1,
            }],
        }

        evidence = normalize_runtime_evidence(candidate, uopz, zend, registry)

        self.assertEqual([(row["name"], row["source"], row["location"]) for row in evidence], [("search", "REST_QUERY", "query")])

    def test_normalize_runtime_evidence_rejects_non_rest_fetch_event_shape(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "GET",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-zend-control",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        )
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        base_zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-request-zend-control",
            "request_method": "GET",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
        }
        controls = [
            {"source": "GET", "bucket": "GET", "parameter": "search", "callback": "Demo::list_items", "observed_count": 1},
            {"source": "REST", "bucket": "GET", "parameter": "search", "observed_count": 1},
            {"source": "REST", "bucket": "POST", "parameter": "search", "callback": "Demo::list_items", "observed_count": 1},
        ]

        for event in controls:
            with self.subTest(event=event):
                self.assertEqual(
                    normalize_runtime_evidence(candidate, uopz, {**base_zend, "rest_parameter_events": [event]}, registry),
                    [],
                )

    def test_normalize_runtime_evidence_exports_only_uopz_observed_rest_query_parameter(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "GET",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-uopz-1",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
            request_params={"query_params": {"search": "hello", "page": "1", "debug": "0"}},
            rest_parameter_events=[{"accessor": "WP_REST_Request::get_param", "name": "search"}],
        )
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-request-uopz-1",
            "request_method": "GET",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [],
        }

        evidence = normalize_runtime_evidence(candidate, uopz, zend, registry)

        self.assertEqual(
            evidence,
            [{
                "name": "search", "path": ["search"], "source": "REST_QUERY", "location": "query",
                "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_rest_runtime",
                "fuzzable": True, "run_id": "legacy-1", "request_id": "rest-request-uopz-1",
                "plugin_slug": "demo-plugin", "callback_id": "rest-items",
                "canonical_callback": "Demo::list_items", "namespace": "demo/v1",
                "route_pattern": "/items", "materialized_route": "/wp-json/demo/v1/items",
                "endpoint_definition_index": 0, "request_method": "GET",
            }],
        )

    def test_normalize_runtime_evidence_rejects_unproven_uopz_rest_query_events(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "GET",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-uopz-reject",
        }
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        zend = {
            "schema_version": 4, "run_id": "legacy-1", "request_id": "rest-request-uopz-reject",
            "request_method": "GET", "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [],
        }
        cases = [
            ([], {"search": "hello"}),
            ([{"accessor": "WP_REST_Request::get_param", "name": "missing"}], {"search": "hello"}),
            ([
                {"accessor": "WP_REST_Request::get_param", "name": "search"},
                {"accessor": "WP_REST_Request::get_param", "name": "search"},
            ], {"search": "hello"}),
            ([{"accessor": "WP_REST_Request::get_param", "name": "access_token"}], {"access_token": "secret"}),
            ([{"accessor": "WP_REST_Request::get_param", "name": "filters[name]"}], {"filters[name]": "value"}),
            ([{"accessor": "WP_REST_Request::get_param", "name": "search"}], {}),
            ([{"accessor": "other", "name": "search"}], {"search": "hello"}),
        ]

        for events, query_params in cases:
            with self.subTest(events=events, query_params=query_params):
                uopz = self.pass1_artifact(
                    candidate,
                    hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
                    request_params={"query_params": query_params},
                    rest_parameter_events=events,
                )
                self.assertEqual(normalize_runtime_evidence(candidate, uopz, zend, registry), [])

        unsupported_candidate = {**candidate, "method": "POST"}
        unsupported_zend = {**zend, "request_method": "POST"}
        uopz = self.pass1_artifact(
            unsupported_candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
            request_params={"body_params": {"search": "hello"}, "json_params": {"search": "hello"}},
            rest_parameter_events=[{"accessor": "WP_REST_Request::get_param", "name": "search"}],
        )
        self.assertEqual(normalize_runtime_evidence(unsupported_candidate, uopz, unsupported_zend, registry), [])

    def test_normalize_runtime_evidence_rejects_ambiguous_or_mismatched_rest_event(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "POST",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-2",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        )
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        zend = {
            "run_id": "legacy-1", "request_id": "rest-request-2", "request_method": "POST",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [
                {"callback": "Demo::list_items", "namespace": "demo/v1", "route_pattern": "/items", "endpoint_definition_index": 0, "materialized_route": "/wp-json/demo/v1/items", "method": "POST", "name": "both", "location": "ambiguous", "observed_count": 1},
                {"callback": "Demo::list_items", "namespace": "demo/v1", "route_pattern": "/other", "endpoint_definition_index": 0, "materialized_route": "/wp-json/demo/v1/other", "method": "POST", "name": "wrong", "location": "form", "observed_count": 1},
            ],
        }

        self.assertEqual(normalize_runtime_evidence(candidate, uopz, zend, registry), [])

    def test_normalize_runtime_evidence_rejects_rest_key_seen_in_multiple_locations(self) -> None:
        candidate = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "method": "POST",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "rest-request-3",
        }
        uopz = self.pass1_artifact(
            candidate,
            hook_coverage={"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        )
        registry = {"schema_version": 1, "callback_map": {"rest-items": "Demo::list_items"}}
        base = {
            "callback": "Demo::list_items",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "method": "POST",
            "name": "term",
            "observed_count": 1,
        }
        zend = {
            "run_id": "legacy-1",
            "request_id": "rest-request-3",
            "request_method": "POST",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [
                {**base, "location": "query"},
                {**base, "location": "form"},
            ],
        }

        self.assertEqual(normalize_runtime_evidence(candidate, uopz, zend, registry), [])

    def test_callback_registry_uses_php_callable_type_for_zend_extension(self) -> None:
        registry = {
            "data": {
                "registered_callbacks": {
                    "cb": {
                        "callback_id": "cb",
                        "hook_name": "wp_ajax_demo",
                        "callback_repr": "demo_ajax",
                        "type": "action",
                        "target_plugin": "demo-plugin",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/demo.php",
                    }
                }
            }
        }

        prepared = prepare_callback_registry(registry, "demo-plugin")

        self.assertEqual(prepared["registrations"][0]["callback_type"], "function")
        self.assertEqual(prepared["registrations"][0]["wordpress_callback_type"], "action")

    def test_callback_registry_canonicalizes_object_method_for_zend_extension(self) -> None:
        registry = {
            "data": {
                "registered_callbacks": {
                    "cb-crm": {
                        "callback_id": "cb-crm",
                        "hook_name": "wp_ajax_vx_form_save_api_settings",
                        "callback_repr": "cfx_form_admin_pages->save_api_settings",
                        "class_name": "cfx_form_admin_pages",
                        "method_name": "save_api_settings",
                        "type": "action",
                        "target_plugin": "crm-perks-forms",
                        "source_file": "/var/www/html/wp-content/plugins/crm-perks-forms/includes/admin-pages.php",
                    }
                }
            }
        }

        prepared = prepare_callback_registry(registry, "crm-perks-forms")

        self.assertEqual(prepared["callback_map"]["cb-crm"], "cfx_form_admin_pages::save_api_settings")
        self.assertEqual(prepared["registrations"][0]["callback"], "cfx_form_admin_pages->save_api_settings")
        self.assertEqual(prepared["registrations"][0]["callback_type"], "object_method")
        self.assertNotIn("->", prepared["registrations"][0]["canonical_callback"])

    def test_pass1_correlation_accepts_raw_uopz_artifact_without_optional_identity_fields(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(candidate)
        artifact.pop("canonical_identity_id", None)
        artifact.pop("callback_id", None)
        artifact.pop("auth_variant", None)

        proof = correlate_pass1_artifact(
            candidate,
            artifact,
            legacy_run_id="legacy-1",
            pass1_request_id="pass1-1",
            plugin_slug="demo-plugin",
        )

        self.assertIsNotNone(proof)

    def pass1_candidate(self) -> dict:
        return {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "ajax",
            "action": "demo_fetch_items",
            "callback_id": "ajax-public",
            "method": "post",
            "auth_mode": "nopriv",
            "legacy_run_id": "legacy-1",
            "pass1_request_id": "pass1-1",
        }

    def pass1_artifact(self, candidate: dict, **updates: object) -> dict:
        artifact = {
            "legacy_run_id": candidate["legacy_run_id"],
            "request_id": candidate["pass1_request_id"],
            "target_plugin": candidate["plugin_slug"],
            "canonical_identity_id": canonical_identity_id(candidate),
            "callback_id": candidate["callback_id"],
            "http_method": candidate["method"].upper(),
            "auth_variant": "unauthenticated",
            "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
        }
        artifact.update(updates)
        return artifact

    def test_canonical_identity_is_deterministic_and_excludes_callback_display(self) -> None:
        candidate = self.pass1_candidate()
        candidate["callback_repr"] = "Demo::fetch"

        self.assertEqual(
            canonical_identity(candidate),
            {
                "plugin_slug": "demo-plugin",
                "entrypoint_type": "ajax",
                "dispatch_identity": {"dispatcher": "ajax", "action": "demo_fetch_items"},
                "callback_identity": "ajax-public",
                "resolved_method": "POST",
                "auth_variant": "unauthenticated",
            },
        )
        candidate["callback_repr"] = "Renamed::display_only"
        self.assertEqual(canonical_identity_id(candidate), canonical_identity_id(self.pass1_candidate()))
        self.assertEqual(
            canonical_identity(
                {
                    "plugin_slug": "demo-plugin",
                    "entrypoint_type": "rest",
                    "namespace": "demo/v1",
                    "route_pattern": "/items/(?P<id>\\d+)",
                    "endpoint_definition_index": 2,
                    "materialized_route": "/wp-json/demo/v1/items/7",
                    "callback_id": "rest-items",
                    "resolved_method": "get",
                    "auth_variant": "authenticated",
                }
            )["dispatch_identity"],
            {
                "namespace": "demo/v1",
                "route_pattern": "/items/(?P<id>\\d+)",
                "endpoint_definition_index": 2,
                "materialized_route": "/wp-json/demo/v1/items/7",
            },
        )

    def test_pass1_correlation_requires_exact_identity_fields_and_callback_proof(self) -> None:
        candidate = self.pass1_candidate()
        identity_id = canonical_identity_id(candidate)
        artifact = {
            "legacy_run_id": "legacy-1",
            "request_id": "pass1-1",
            "target_plugin": "demo-plugin",
            "canonical_identity_id": identity_id,
            "callback_id": "ajax-public",
            "http_method": "POST",
            "auth_variant": "unauthenticated",
            "hook_coverage": {"executed_callbacks": {"ajax-public": {"callback_id": "ajax-public"}}},
        }

        self.assertIs(
            correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            ),
            artifact,
        )
        for field, wrong_value in (
            ("legacy_run_id", "other-run"),
            ("request_id", "other-request"),
            ("target_plugin", "other-plugin"),
            ("canonical_identity_id", "0" * 64),
            ("callback_id", "other-callback"),
            ("http_method", "GET"),
            ("auth_variant", "authenticated"),
            ):
            rejected = dict(artifact)
            rejected[field] = wrong_value
            self.assertIsNone(
                correlate_pass1_artifact(
                    candidate,
                    rejected,
                    legacy_run_id="legacy-1",
                    pass1_request_id="pass1-1",
                    plugin_slug="demo-plugin",
                ),
                field,
            )
        rejected = dict(artifact)
        rejected["hook_coverage"] = {"executed_callbacks": {}}
        self.assertIsNone(
            correlate_pass1_artifact(
                candidate,
                rejected,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )
        legacy_artifact = dict(artifact)
        legacy_artifact.pop("legacy_run_id")
        legacy_artifact["run_id"] = "legacy-1"
        self.assertIsNotNone(
            correlate_pass1_artifact(
                candidate,
                legacy_artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )

    def test_pass1_rejects_unknown_auth_but_normalizes_unauth_capable(self) -> None:
        candidate = self.pass1_candidate()
        candidate.pop("auth_mode")
        self.assertEqual(canonical_identity(candidate)["auth_variant"], "unresolved")
        artifact = self.pass1_artifact(candidate)
        artifact["auth_variant"] = "unresolved"
        self.assertIsNone(
            correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )
        candidate["auth_mode"] = "unauth-capable"
        self.assertEqual(canonical_identity(candidate)["auth_variant"], "unauthenticated")

    def test_enrichment_ignores_runtime_fields_from_rejected_artifact(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(
            candidate,
            target_plugin="other-plugin",
            request_params={"query_params": {"untrusted_runtime_field": "must-not-import"}},
        )

        seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertNotIn("untrusted_runtime_field", {row["name"] for row in seed["parameters"]})

    def test_enrichment_requires_callback_identity_before_extraction(self) -> None:
        candidate = self.pass1_candidate()

        seed = enrich_current_run(
            candidate,
            {"callback_id": "wrong-callback"},
            self.pass1_artifact(candidate),
            StaticExtractor([{"name": "term", "source": "POST"}]),
        )

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertEqual(seed["parameters"], [])

    def test_enrichment_blocks_body_params_without_explicit_transport_type(self) -> None:
        candidate = self.pass1_candidate()
        absent_type = self.pass1_artifact(
            candidate,
            request_params={"body_params": {"unknown_body": "value"}},
        )
        unsupported_type = self.pass1_artifact(
            candidate,
            request_content_type="text/plain",
            request_params={"body_params": {"plain_body": "value"}},
        )

        absent_seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, absent_type, StaticExtractor([]))
        unsupported_seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, unsupported_type, StaticExtractor([]))

        for seed in (absent_seed, unsupported_seed):
            self.assertFalse(seed["final_fuzz_export_allowed"])
            self.assertEqual(seed["parameters"][0]["location"], "unknown")
            self.assertTrue(seed["parameters"][0]["blocked"])
            self.assertEqual(seed["parameters"][0]["blocked_reason"], "unresolved_location")

    def test_enrichment_rejects_body_content_type_substring_matches(self) -> None:
        candidate = self.pass1_candidate()
        json_like = self.pass1_artifact(
            candidate,
            request_content_type="text/plain; profile=json",
            request_params={"body_params": {"json_like": "value"}},
        )
        form_like = self.pass1_artifact(
            candidate,
            request_content_type="text/plain; note=multipart/form-data",
            request_params={"body_params": {"form_like": "value"}},
        )

        for artifact in (json_like, form_like):
            seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))
            self.assertFalse(seed["final_fuzz_export_allowed"])
            self.assertEqual(seed["parameters"][0]["location"], "unknown")
            self.assertTrue(seed["parameters"][0]["blocked"])
            self.assertEqual(seed["parameters"][0]["blocked_reason"], "unresolved_location")

    def test_enrichment_resolves_direct_current_run_get_and_post_only(self) -> None:
        get_candidate = self.pass1_candidate()
        get_candidate["method"] = "GET"
        get_artifact = self.pass1_artifact(get_candidate)
        callback = {"callback_id": "ajax-public"}
        extractor = StaticExtractor([{"name": "search", "source": "GET"}, {"name": "term", "source": "POST"}])

        get_seed = enrich_current_run(get_candidate, callback, get_artifact, extractor)

        self.assertTrue(get_seed["probe_replay_allowed"])
        self.assertTrue(get_seed["final_fuzz_export_allowed"])
        self.assertEqual(get_seed["parameters"][0]["location"], "query")
        post = next(row for row in get_seed["parameters"] if row["name"] == "term")
        self.assertEqual(post["location"], "unknown")
        self.assertTrue(post["blocked"])
        self.assertEqual(post["blocked_reason"], "unresolved_location")

        post_candidate = self.pass1_candidate()
        post_seed = enrich_current_run(
            post_candidate,
            callback,
            self.pass1_artifact(post_candidate),
            StaticExtractor([{"name": "term", "source": "POST"}]),
        )
        self.assertEqual(post_seed["parameters"][0]["location"], "form")
        self.assertFalse(post_seed["parameters"][0]["blocked"])

    def test_enrichment_uses_runtime_query_form_and_json_without_values(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(
            candidate,
            request_params={
                "query_params": {"page": "this-value-must-not-persist"},
                "form_params": {"term": "also-secret-submitted-value"},
                "json_params": {"payload": {"nested": "private"}},
            },
        )

        seed = enrich_current_run(candidate, {"callback_id": "ajax-public"}, artifact, StaticExtractor([]))

        by_name = {row["name"]: row for row in seed["parameters"]}
        self.assertEqual(by_name["page"]["location"], "query")
        self.assertEqual(by_name["term"]["location"], "form")
        self.assertEqual(by_name["payload"]["location"], "json")
        self.assertEqual(by_name["payload"]["safe_observed_type"], "object")
        self.assertTrue(by_name["term"]["redacted_value_metadata"]["redacted"])
        encoded = json.dumps(seed, sort_keys=True)
        self.assertNotIn("this-value-must-not-persist", encoded)
        self.assertNotIn("also-secret-submitted-value", encoded)
        self.assertNotIn("private", encoded)

    def test_enrichment_blocks_schema_get_param_request_and_method_only_evidence(self) -> None:
        candidate = self.pass1_candidate()
        callback = {
            "callback_id": "ajax-public",
            "argument_definitions": {"schema_only": {"required": False}},
        }
        extractor = StaticExtractor(
            [
                {"name": "via_get_param", "source": "REST_GET_PARAM"},
                {"name": "via_request", "source": "REQUEST"},
                {"name": "method_only", "source": "METHOD"},
            ]
        )

        seed = enrich_current_run(candidate, callback, self.pass1_artifact(candidate), extractor)

        self.assertFalse(seed["final_fuzz_export_allowed"])
        self.assertEqual({row["location"] for row in seed["parameters"]}, {"unknown"})
        self.assertTrue(all(row["blocked"] for row in seed["parameters"]))
        evidence_kinds = {
            evidence["kind"]
            for row in seed["parameters"]
            for evidence in row["evidence"]
        }
        self.assertEqual(
            evidence_kinds,
            {"rest_schema_declared", "rest_get_param_name_only", "static_candidate", "zend_superglobal_read"},
        )

    def test_enrichment_blocks_sensitive_names_and_invalid_pass1_proof(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(candidate)
        artifact["hook_coverage"] = {"executed_callbacks": {}}

        seed = enrich_current_run(
            candidate,
            {"callback_id": "ajax-public"},
            artifact,
            StaticExtractor([{"name": "session_token", "source": "POST"}]),
        )

        self.assertFalse(seed["probe_replay_allowed"])
        self.assertFalse(seed["final_fuzz_export_allowed"])
        parameter = seed["parameters"][0]
        self.assertTrue(parameter["blocked"])
        self.assertEqual(parameter["blocked_reason"], "security_field")
        self.assertEqual(seed["blocked_parameters"], [parameter])

    def make_plugin_zip(self, root: Path) -> Path:
        plugin = root / "demo-plugin.zip"
        with zipfile.ZipFile(plugin, "w") as archive:
            archive.writestr(
                "demo-plugin/demo-plugin.php",
                "<?php\n/*\n * Plugin Name: Demo Plugin\n * Version: 1.2.3\n */\n",
            )
            archive.writestr(
                "demo-plugin/ajax.php",
                "<?php\nfunction demo_fetch_items() {\n    $term = $_POST['term'];\n}\n",
            )
        return plugin

    def registry(self) -> dict:
        return {
            "hook_coverage": {
                "registered_callbacks": {
                    "ajax-public": {
                        "callback_id": "ajax-public",
                        "hook_name": "wp_ajax_nopriv_demo_fetch_items",
                        "callback_repr": "Demo::fetch",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/ajax.php",
                        "input_params": [{"name": "term", "source": "POST"}],
                    },
                    "rest-get": {
                        "callback_id": "rest-get",
                        "entrypoint_type": "rest_route",
                        "namespace": "demo/v1",
                        "route": "/items",
                        "methods": ["GET", "POST"],
                        "callback_repr": "Demo::items",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/rest.php",
                    },
                    "ajax-write": {
                        "callback_id": "ajax-write",
                        "hook_name": "wp_ajax_nopriv_demo_save",
                        "callback_repr": "Demo::save",
                        "source_file": "/var/www/html/wp-content/plugins/demo-plugin/ajax.php",
                    },
                    "core": {
                        "callback_id": "core",
                        "hook_name": "wp_ajax_nopriv_core_fetch",
                        "callback_repr": "Core::fetch",
                        "source_file": "/var/www/html/wp-includes/core.php",
                    },
                }
            }
        }

    def test_zip_metadata_requires_selected_slug_and_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            plugin = self.make_plugin_zip(Path(tmp_dir))
            metadata = read_plugin_metadata(plugin, "demo-plugin")

            self.assertEqual(metadata["slug"], "demo-plugin")
            self.assertEqual(metadata["version"], "1.2.3")
            self.assertEqual(metadata["main_file"], "demo-plugin/demo-plugin.php")
            self.assertEqual(metadata["sha256"], hashlib.sha256(plugin.read_bytes()).hexdigest())

    def test_materialize_plugin_source_rejects_zip_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = root / "demo-plugin.zip"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr("demo-plugin/../../escape.php", "<?php")

            with self.assertRaisesRegex(ValueError, "PLUGIN_ZIP_UNSAFE_MEMBER"):
                materialize_plugin_source(plugin, "demo-plugin", root / "source")

    def test_materialize_plugin_source_maps_container_callback_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = root / "demo-plugin.zip"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr("demo-plugin/ajax.php", "<?php\n")

            source_root = materialize_plugin_source(plugin, "demo-plugin", root / "source")

            self.assertEqual(source_root / "ajax.php", root / "source" / "demo-plugin" / "ajax.php")
            self.assertTrue((source_root / "ajax.php").is_file())

    def test_ajax_seed_merges_literal_post_read_into_body_fuzz_parameter(self) -> None:
        endpoint = {"callback_id": "ajax-public", "kind": "ajax", "method": "POST"}
        callback = {
            "callback_id": "ajax-public",
            "source_file": "unused.php",
        }
        artifact = {"request_params": {}}
        extractor = StaticExtractor([{"name": "term", "source": "POST", "location": "body"}])

        seed = build_parameter_seed(endpoint, callback, artifact, extractor)

        self.assertEqual(
            seed["parameters"],
            [{"name": "term", "location": "body", "fuzzable": True, "evidence": ["static:POST"]}],
        )

    def test_rest_get_seed_uses_declared_route_method_and_query_location(self) -> None:
        endpoint = {"callback_id": "rest-get", "kind": "rest", "methods": ["GET", "POST"]}
        callback = {
            "callback_id": "rest-get",
            "argument_definitions": {"page": {"required": False}},
        }
        artifact = {"request_params": {"query_params": {"page": "redacted"}}}

        seed = build_parameter_seed(endpoint, callback, artifact, StaticExtractor([]))

        self.assertEqual(seed["method"], "GET")
        self.assertEqual(seed["parameters"][0]["name"], "page")
        self.assertEqual(seed["parameters"][0]["location"], "query")

    def test_nonce_cookie_and_secret_names_are_blocked_not_fuzzed(self) -> None:
        endpoint = {"callback_id": "ajax-public", "kind": "ajax", "method": "POST"}
        callback = {"callback_id": "ajax-public"}
        extractor = StaticExtractor(
            [
                {"name": "nonce", "source": "POST", "location": "body", "role": "security_nonce"},
                {"name": "session_token", "source": "COOKIE", "location": "cookie"},
            ]
        )

        seed = build_parameter_seed(endpoint, callback, {"request_params": {}}, extractor)

        self.assertEqual(seed["parameters"], [])
        self.assertEqual({row["name"] for row in seed["blocked_parameters"]}, {"nonce", "session_token"})

    def test_catalog_keeps_only_selected_plugin_and_normalizes_ajax_rest(self) -> None:
        catalog = build_catalog(self.registry(), "demo-plugin")

        self.assertEqual([item["callback_id"] for item in catalog], ["ajax-public", "rest-get", "ajax-write"])
        self.assertEqual(catalog[0]["kind"], "ajax")
        self.assertEqual(catalog[0]["action"], "demo_fetch_items")
        self.assertEqual(catalog[1]["route"], "/wp-json/demo/v1/items")
        self.assertEqual(catalog[1]["methods"], ["GET", "POST"])
        self.assertEqual(catalog[2]["ownership"], "target")

    def test_auto_probe_selects_safe_read_operations_and_blocks_others(self) -> None:
        catalog = build_catalog(self.registry(), "demo-plugin")
        selected = select_auto_probes(catalog)

        self.assertEqual([(item["callback_id"], item["method"]) for item in selected], [("ajax-public", "POST"), ("rest-get", "GET")])
        blocked = next(item for item in catalog if item["callback_id"] == "ajax-write")
        self.assertEqual(blocked["status"], BLOCKED_UNSAFE_AUTO_PROBE)

    def raw_seed_item(self, *, callback_id: str = "ajax-public", action: str = "demo_fetch_items") -> dict:
        return {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "ajax",
            "hook_name": f"wp_ajax_nopriv_{action}",
            "callback_id": callback_id,
            "pass1_request_id": f"pass1-{callback_id}",
            "seed": {
                "method": "POST",
                "resolved_method": "POST",
                "method_status": "resolved",
                "path": "/wp-admin/admin-ajax.php",
                "body": {"action": action, "bootstrap": "preserve"},
                "query_params": {},
                "fixed_params": ["action", "bootstrap"],
                "fuzzable_params": [],
                "auth_mode": "unauth-capable",
            },
        }

    def pass1_artifact_for_raw(
        self, item: dict, *, raw_value: str = "never-write-this", include_param: bool = True
    ) -> dict:
        candidate = candidate_from_seed_item(item, plugin_slug="demo-plugin", legacy_run_id="legacy-1")
        artifact = {
            "legacy_run_id": "legacy-1",
            "request_id": item["pass1_request_id"],
            "target_plugin": "demo-plugin",
            "canonical_identity_id": canonical_identity_id(candidate),
            "callback_id": candidate["callback_id"],
            "http_method": candidate["method"],
            "auth_variant": canonical_identity(candidate)["auth_variant"],
            "content_type": "application/x-www-form-urlencoded",
            "hook_coverage": {"executed_callbacks": {item["callback_id"]: {"callback_id": item["callback_id"]}}},
        }
        if include_param:
            artifact["request_params"] = {"body_params": {"term": raw_value}}
        return artifact

    def zend_artifact_for_raw(self, item: dict, *, source: str = "POST", name: str = "term") -> dict:
        callback = {
            "ajax-public": "Demo::fetch",
            "ajax-write": "Demo::save",
        }.get(item["callback_id"], str(item["callback_id"]))
        return {
            "schema_version": 3,
            "run_id": "legacy-1",
            "request_id": item["pass1_request_id"],
            "request_method": "POST",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "callback_summaries": [
                {
                    "callback": callback,
                    "unique_parameters": [
                        {
                            "source": source,
                            "path": [name],
                            "helper_depth": 0,
                            "observed_count": 1,
                        }
                    ],
                }
            ],
        }

    def test_run_enrichment_writes_only_value_free_zend_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            item = self.raw_seed_item()
            summary = run_enrichment(
                plugin_zip=plugin,
                plugin_slug="demo-plugin",
                legacy_run_id="legacy-1",
                registry=self.registry(),
                raw_seed_report={"suggested_seeds": [item]},
                pass1_artifacts=[self.pass1_artifact_for_raw(item)],
                zend_artifacts=[self.zend_artifact_for_raw(item)],
                output_root=root / "output",
            )

            output = root / "output" / "legacy-1"
            identity_id = canonical_identity_id(
                {
                    "plugin_slug": "demo-plugin",
                    "entrypoint_type": "ajax",
                    "action": "demo_fetch_items",
                    "callback_id": "ajax-public",
                    "method": "POST",
                    "auth_mode": "unauth-capable",
                }
            )
            self.assertEqual(
                {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()},
                {
                    f"seeds/{identity_id}--POST.json",
                    "zend_enriched_seeds.json",
                    "zend-enrichment-summary.json",
                    "endpoint-catalog.json",
                },
            )
            seed = json.loads((output / "seeds" / f"{identity_id}--POST.json").read_text(encoding="utf-8"))
            self.assertTrue(seed["accepted_pass1_proof"])
            self.assertTrue(seed["probe_replay_allowed"])
            self.assertTrue(seed["final_fuzz_export_allowed"])
            self.assertEqual(seed["fuzzable_params"], ["term"])
            self.assertEqual(
                seed["seed_patch"]["fixed_bootstrap"],
                [
                    {"name": "action", "provenance": "legacy_fixed_param"},
                    {"name": "bootstrap", "provenance": "legacy_fixed_param"},
                ],
            )
            self.assertNotIn("pass2_request_id", json.dumps(seed))
            self.assertNotIn("never-write-this", json.dumps(seed))
            self.assertEqual(summary["final_fuzz_export_allowed"], 1)

    def test_run_enrichment_blocks_zero_fuzz_but_continues_independent_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            blocked = self.raw_seed_item(callback_id="ajax-write", action="demo_save")
            accepted = self.raw_seed_item()
            registry = self.registry()
            registry["hook_coverage"]["registered_callbacks"]["ajax-write"]["source_file"] = None
            summary = run_enrichment(
                plugin,
                "demo-plugin",
                "legacy-1",
                registry,
                {"suggested_seeds": [blocked, accepted]},
                [
                    self.pass1_artifact_for_raw(blocked, include_param=False),
                    self.pass1_artifact_for_raw(accepted),
                ],
                root / "output",
                zend_artifacts=[self.zend_artifact_for_raw(accepted)],
            )

            rows = {row["canonical_identity_id"]: row for row in summary["enriched_seeds"]}
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(row["final_fuzz_export_allowed"] for row in rows.values()), 1)
            self.assertEqual(summary["final_fuzz_export_allowed"], 1)

    def test_legacy_entrypoint_variants_keep_distinct_actions_and_seed_files(self) -> None:
        first = self.raw_seed_item()
        first["entrypoint_type"] = "ajax_unauthenticated"
        second = self.raw_seed_item(action="demo_fetch_other")
        second["entrypoint_type"] = "wp_ajax_nopriv"
        first_candidate = candidate_from_seed_item(first, plugin_slug="demo-plugin", legacy_run_id="legacy-1")
        second_candidate = candidate_from_seed_item(second, plugin_slug="demo-plugin", legacy_run_id="legacy-1")

        self.assertEqual(first_candidate["entrypoint_type"], "ajax")
        self.assertEqual(second_candidate["entrypoint_type"], "ajax")
        admin_post = self.raw_seed_item(action="demo_export")
        admin_post["entrypoint_type"] = "admin_post_authenticated"
        admin_post["hook_name"] = "admin_post_demo_export"
        admin_post["seed"]["auth_mode"] = "authenticated"
        rest = self.raw_seed_item(action="")
        rest["entrypoint_type"] = "wp_rest_route"
        rest["hook_name"] = "rest_route:demo/v1/items"
        self.assertEqual(candidate_from_seed_item(admin_post)["entrypoint_type"], "admin-post")
        self.assertEqual(candidate_from_seed_item(rest)["entrypoint_type"], "rest")
        self.assertNotEqual(canonical_identity_id(first_candidate), canonical_identity_id(second_candidate))

        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            summary = run_enrichment(
                plugin,
                "demo-plugin",
                "legacy-1",
                self.registry(),
                {"suggested_seeds": [first, second]},
                [self.pass1_artifact_for_raw(first), self.pass1_artifact_for_raw(second)],
                root / "output",
                zend_artifacts=[self.zend_artifact_for_raw(first), self.zend_artifact_for_raw(second)],
            )

            identities = {row["canonical_identity_id"] for row in summary["enriched_seeds"]}
            seed_files = list((root / "output" / "legacy-1" / "seeds").glob("*.json"))
            self.assertEqual(len(identities), 2)
            self.assertEqual(len(seed_files), 2)

    def test_zend_artifacts_exclude_raw_legacy_and_pass2_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            plugin = self.make_plugin_zip(root)
            item = self.raw_seed_item()
            item["pass2_request_id"] = "pass2-secret"
            item["authorization"] = "legacy-auth-secret"
            item["seed"]["body"]["token"] = "legacy-token-secret"
            artifact = self.pass1_artifact_for_raw(item, raw_value="submitted-secret")
            artifact["pass2_request_id"] = "artifact-pass2-secret"
            artifact["request_params"]["body_params"]["authorization"] = "artifact-auth-secret"

            run_enrichment(
                plugin,
                "demo-plugin",
                "legacy-1",
                self.registry(),
                {"suggested_seeds": [item]},
                [artifact],
                root / "output",
                zend_artifacts=[self.zend_artifact_for_raw(item)],
            )

            for path in (root / "output" / "legacy-1").rglob("*.json"):
                persisted = path.read_text(encoding="utf-8")
                for forbidden in (
                    "pass2_request_id",
                    "pass2-secret",
                    "artifact-pass2-secret",
                    "authorization",
                    "legacy-auth-secret",
                    "artifact-auth-secret",
                    "legacy-token-secret",
                    "submitted-secret",
                    "seed_item",
                ):
                    self.assertNotIn(forbidden, persisted, path)

    def test_run_enrichment_rejects_cross_plugin_raw_candidate_and_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            item = self.raw_seed_item()
            item["plugin_slug"] = "other-plugin"

            with self.assertRaisesRegex(ValueError, "RAW_CANDIDATE_PLUGIN_MISMATCH"):
                run_enrichment(
                    self.make_plugin_zip(root),
                    "demo-plugin",
                    "legacy-1",
                    self.registry(),
                    {"suggested_seeds": [item]},
                    [self.pass1_artifact_for_raw(item)],
                    root / "output",
                    zend_artifacts=[self.zend_artifact_for_raw(item)],
                )

            valid = self.raw_seed_item()
            foreign_artifact = self.pass1_artifact_for_raw(valid)
            foreign_artifact["legacy_run_id"] = "legacy-2"
            foreign_artifact["target_plugin"] = "other-plugin"
            result = run_enrichment(
                self.make_plugin_zip(root),
                "demo-plugin",
                "legacy-2",
                self.registry(),
                {"suggested_seeds": [valid]},
                [foreign_artifact],
                root / "output",
                zend_artifacts=[],
            )
            self.assertFalse(result["enriched_seeds"][0]["accepted_pass1_proof"])

    def test_pass1_correlation_rejects_mismatched_compatibility_request_id(self) -> None:
        candidate = self.pass1_candidate()
        artifact = self.pass1_artifact(candidate, compat_request_id_matches=False)

        self.assertIsNone(
            correlate_pass1_artifact(
                candidate,
                artifact,
                legacy_run_id="legacy-1",
                pass1_request_id="pass1-1",
                plugin_slug="demo-plugin",
            )
        )

    def test_uopz_captures_legacy_run_and_request_ids_from_legacy_headers(self) -> None:
        instrumentation = (
            FUZZER_DIR.parent / "web" / "instrumentation" / "hook_coverage" / "uopz_hook_wp.php"
        ).read_text(encoding="utf-8")

        self.assertIn("HTTP_X_HOOKPHUZZ_RUN_ID", instrumentation)
        self.assertIn("HTTP_X_FUZZER_COVID", instrumentation)
        self.assertIn("HTTP_X_HOOKPHUZZ_REQUEST_ID", instrumentation)
        self.assertIn("'legacy_run_id' =>", instrumentation)
        self.assertIn("'run_id' =>", instrumentation)
        self.assertNotIn("HTTP_X_ZEND_DISCOVERY_RUN_ID", instrumentation)

    def test_active_opcode_extension_reads_generated_run_header(self) -> None:
        extension = (
            FUZZER_DIR
            / "zend_discovery"
            / "extension"
            / "hookphuzz_opcode.c"
        ).read_text(encoding="utf-8")

        self.assertIn('#include "php_hookphuzz_opcode.h"', extension)
        self.assertIn("zend_module_entry hookphuzz_opcode_module_entry", extension)
        self.assertIn("HTTP_X_HOOKPHUZZ_RUN_ID", extension)
        self.assertIn('"rest_parameter_events"', extension)
        self.assertNotIn("phase9", extension.lower())

    def test_active_opcode_extension_tracks_wp_rest_request_params_fetch_obj(self) -> None:
        extension = (
            FUZZER_DIR
            / "zend_discovery"
            / "extension"
            / "hookphuzz_opcode.c"
        ).read_text(encoding="utf-8")

        self.assertIn("ZEND_FETCH_OBJ_R", extension)
        self.assertIn("WP_REST_Request", extension)
        self.assertIn('"bucket"', extension)
        self.assertIn('"parameter"', extension)

    def test_phase2_fixture_uses_direct_post_dimension_reads(self) -> None:
        fixture = FUZZER_DIR / "tests" / "fixtures" / "hookphuzz-entrypoint-direct-fixture" / "hookphuzz-entrypoint-direct-fixture.php"
        source = fixture.read_text(encoding="utf-8")
        plugin_zip = FUZZER_DIR.parent / "web" / "applications" / "wordpress" / "_plugins" / "hookphuzz-entrypoint-direct-fixture.zip"

        self.assertIn("$_POST['name'];", source)
        self.assertIn("$_POST['age'];", source)
        self.assertIn("if ($name) {", source)
        self.assertNotIn("??", source)
        self.assertNotIn("isset($_POST", source)
        with zipfile.ZipFile(plugin_zip) as archive:
            archived = archive.read("hookphuzz-entrypoint-direct-fixture/hookphuzz-entrypoint-direct-fixture.php").decode("utf-8")
        self.assertEqual(archived.replace("\r\n", "\n"), source.replace("\r\n", "\n"))

    def test_rest_get_param_fixture_is_packaged_with_search_only_callback(self) -> None:
        fixture = (
            FUZZER_DIR
            / "tests"
            / "fixtures"
            / "hookphuzz-rest-get-param-fixture"
            / "hookphuzz-rest-get-param-fixture.php"
        )
        plugin_zip = FUZZER_DIR.parent / "web" / "applications" / "wordpress" / "_plugins" / "hookphuzz-rest-get-param-fixture.zip"
        source = fixture.read_text(encoding="utf-8")

        self.assertIn("get_param('search')", source)
        self.assertIn("$foo->params['GET']['search']", source)
        self.assertIn("$array['GET']['search']", source)
        self.assertIn("register_rest_route('hookphuzz/v1', '/probe'", source)
        with zipfile.ZipFile(plugin_zip) as archive:
            self.assertTrue(all("\\" not in entry.filename for entry in archive.infolist()))
            self.assertIn("hookphuzz-rest-get-param-fixture/", archive.namelist())
            self.assertTrue(all(entry.create_system == 3 for entry in archive.infolist()))
            archived = archive.read(
                "hookphuzz-rest-get-param-fixture/hookphuzz-rest-get-param-fixture.php"
            ).decode("utf-8")
        self.assertEqual(archived.replace("\r\n", "\n"), source.replace("\r\n", "\n"))

    def test_convergence_identity_and_diff_keep_only_new_runtime_parameters(self) -> None:
        name = {
            "name": "name",
            "path": ["name"],
            "source": "POST",
            "location": "form",
            "helper_depth": 0,
            "observed_count": 1,
            "evidence_kind": "zend_runtime",
            "fuzzable": True,
            "canonical_callback": "Demo::fetch",
        }
        age = {**name, "name": "age", "path": ["age"]}

        self.assertEqual(canonical_runtime_parameter_identity(name), ("POST", ("name",)))
        first = advance_convergence_state([], [name, name])
        second = advance_convergence_state(first["known_parameters"], [name, age])

        self.assertEqual([item["name"] for item in first["new_parameters"]], ["name"])
        self.assertEqual([item["name"] for item in second["new_parameters"]], ["age"])
        self.assertEqual([item["name"] for item in second["known_parameters"]], ["name", "age"])

    def test_convergence_ignores_non_runtime_parameter_provenance(self) -> None:
        static = {
            "name": "age",
            "path": ["age"],
            "source": "POST",
            "location": "form",
            "helper_depth": 0,
            "observed_count": 1,
            "evidence_kind": "static_regex",
            "fuzzable": True,
        }

        result = advance_convergence_state([], [static])

        self.assertEqual(result["new_parameters"], [])
        self.assertEqual(result["known_parameters"], [])

    def test_convergence_materializes_rest_json_parameter_with_json_content_type(self) -> None:
        raw = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "seed": {
                "path": "/wp-json/demo/v1/items",
                "method": "POST",
                "auth_mode": "nopriv",
                "body": {},
                "query_params": {},
                "headers": {},
                "fixed_params": [],
            },
        }
        candidate_key = canonical_identity_id(candidate_from_seed_item(raw, plugin_slug="demo-plugin"))
        parameter = {
            "name": "filters", "path": ["filters"], "source": "REST_JSON", "location": "json",
            "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_rest_runtime",
            "fuzzable": True, "canonical_callback": "Demo::list_items",
        }

        result = materialize_convergence_seeds(
            {"suggested_seeds": [raw]},
            plugin_slug="demo-plugin",
            candidate_key=candidate_key,
            known_parameters=[parameter],
        )

        seed = result["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["body"]["filters"], "FUZZ")
        self.assertEqual(seed["headers"]["Content-Type"], "application/json")
        self.assertEqual(seed["input_params"][0]["source"], "JSON")
        self.assertEqual(seed["input_params"][0]["evidence_kind"], "zend_rest_runtime")

    def test_convergence_materializes_rest_query_and_form_without_json_header(self) -> None:
        raw = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "seed": {
                "path": "/wp-json/demo/v1/items",
                "method": "POST",
                "auth_mode": "nopriv",
                "body": {},
                "query_params": {},
                "headers": {},
                "fixed_params": [],
            },
        }
        candidate_key = canonical_identity_id(candidate_from_seed_item(raw, plugin_slug="demo-plugin"))
        query = {
            "name": "page", "path": ["page"], "source": "REST_QUERY", "location": "query",
            "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_rest_runtime",
            "fuzzable": True, "canonical_callback": "Demo::list_items",
        }
        form = {**query, "name": "term", "path": ["term"], "source": "REST_FORM", "location": "form"}

        result = materialize_convergence_seeds(
            {"suggested_seeds": [raw]},
            plugin_slug="demo-plugin",
            candidate_key=candidate_key,
            known_parameters=[query, form],
        )

        seed = result["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["query_params"]["page"], "FUZZ")
        self.assertEqual(seed["body"]["term"], "FUZZ")
        self.assertNotIn("Content-Type", seed["headers"])
        self.assertEqual([param["source"] for param in seed["input_params"]], ["GET", "POST"])

    def test_convergence_materializes_only_known_runtime_parameters_into_seed(self) -> None:
        raw = self.raw_seed_item()
        candidate_key = canonical_identity_id(candidate_from_seed_item(raw, plugin_slug="demo-plugin"))
        name = {
            "name": "name", "path": ["name"], "source": "POST", "location": "form",
            "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
            "fuzzable": True, "canonical_callback": "Demo::fetch",
        }
        age = {**name, "name": "age", "path": ["age"]}

        result = materialize_convergence_seeds(
            {"suggested_seeds": [raw]},
            plugin_slug="demo-plugin",
            candidate_key=candidate_key,
            known_parameters=[name, age],
        )

        seed = result["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["body"]["action"], raw["seed"]["body"]["action"])
        self.assertEqual(seed["body"]["name"], "FUZZ")
        self.assertEqual(seed["body"]["age"], "FUZZ")
        self.assertEqual(seed["fuzzable_params"], ["name", "age"])
        self.assertTrue(all(item["evidence_kind"] == "zend_runtime" for item in seed["input_params"]))

    def test_convergence_iteration_uses_only_the_matched_current_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            item = self.raw_seed_item()
            item["pass1_request_id"] = "request-0"
            uopz = self.pass1_artifact_for_raw(item)
            zend = self.zend_artifact_for_raw(item, name="name")
            summary = {"legacy_run_id": "legacy-1", "runs": [{
                "hook_name": item["hook_name"], "callback_id": item["callback_id"],
                "seed_variant_id": "", "callback_reached": True, "matched_artifact": "request-0.json",
            }]}
            uopz_dir, zend_dir = root / "uopz", root / "zend"
            uopz_dir.mkdir()
            zend_dir.mkdir()
            (uopz_dir / "request-0.json").write_text(json.dumps(uopz), encoding="utf-8")
            (zend_dir / "request-0.json").write_text(json.dumps(zend), encoding="utf-8")
            extra = json.loads(json.dumps(item))
            extra["hook_name"] = "wp_ajax_other"
            extra["callback_id"] = "other-callback"

            result = converge_iteration(
                raw_report={"suggested_seeds": [item, extra]}, pass_run_summary=summary,
                pass_artifacts_dir=uopz_dir, zend_events_dir=zend_dir,
                registry=prepare_callback_registry(self.registry(), "demo-plugin"),
                plugin_slug="demo-plugin", legacy_run_id="legacy-1", known_state={"known_parameters": []},
            )

            self.assertEqual(result["status"], "CONTINUE")
            self.assertEqual(result["request_id"], "request-0")
            self.assertEqual([row["name"] for row in result["new_parameters"]], ["name"])
            self.assertEqual(result["merged_suggested_seeds"]["suggested_seeds"][0]["seed"]["body"]["name"], "FUZZ")

    def test_convergence_iteration_filters_multi_candidate_input_by_candidate_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            first = self.raw_seed_item(callback_id="ajax-public", action="demo_fetch_items")
            second = self.raw_seed_item(callback_id="ajax-write", action="demo_save_items")
            first["pass1_request_id"] = "request-first"
            second["pass1_request_id"] = "request-second"
            uopz_dir, zend_dir = root / "uopz", root / "zend"
            uopz_dir.mkdir()
            zend_dir.mkdir()
            for item, name in ((first, "name"), (second, "title")):
                artifact_name = f"{item['pass1_request_id']}.json"
                (uopz_dir / artifact_name).write_text(json.dumps(self.pass1_artifact_for_raw(item)), encoding="utf-8")
                (zend_dir / artifact_name).write_text(json.dumps(self.zend_artifact_for_raw(item, name=name)), encoding="utf-8")
            summary = {"legacy_run_id": "legacy-1", "runs": [
                {
                    "hook_name": first["hook_name"], "callback_id": first["callback_id"],
                    "seed_variant_id": "", "callback_reached": True, "matched_artifact": "request-first.json",
                },
                {
                    "hook_name": second["hook_name"], "callback_id": second["callback_id"],
                    "seed_variant_id": "", "callback_reached": True, "matched_artifact": "request-second.json",
                },
            ]}
            second_key = canonical_identity_id(candidate_from_seed_item(second, plugin_slug="demo-plugin", legacy_run_id="legacy-1"))

            result = converge_iteration(
                raw_report={"suggested_seeds": [first, second]}, pass_run_summary=summary,
                pass_artifacts_dir=uopz_dir, zend_events_dir=zend_dir,
                registry=prepare_callback_registry(self.registry(), "demo-plugin"),
                plugin_slug="demo-plugin", legacy_run_id="legacy-1", known_state={"known_parameters": []},
                candidate_key=second_key,
            )

            self.assertEqual(result["candidate_key"], second_key)
            self.assertEqual(result["request_id"], "request-second")
            self.assertEqual([row["name"] for row in result["new_parameters"]], ["title"])
            self.assertEqual(len(result["merged_suggested_seeds"]["suggested_seeds"]), 1)

    def test_convergence_iteration_does_not_converge_when_known_parameter_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            item = self.raw_seed_item()
            item["pass1_request_id"] = "request-0"
            uopz_dir, zend_dir = root / "uopz", root / "zend"
            uopz_dir.mkdir()
            zend_dir.mkdir()
            (uopz_dir / "request-0.json").write_text(json.dumps(self.pass1_artifact_for_raw(item)), encoding="utf-8")
            (zend_dir / "request-0.json").write_text(json.dumps(self.zend_artifact_for_raw(item, name="name")), encoding="utf-8")
            known = [
                {
                    "name": "name", "path": ["name"], "source": "POST", "location": "form",
                    "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "canonical_callback": "Demo::fetch",
                },
                {
                    "name": "age", "path": ["age"], "source": "POST", "location": "form",
                    "helper_depth": 0, "observed_count": 1, "evidence_kind": "zend_runtime",
                    "fuzzable": True, "canonical_callback": "Demo::fetch",
                },
            ]
            summary = {"legacy_run_id": "legacy-1", "runs": [{
                "hook_name": item["hook_name"], "callback_id": item["callback_id"],
                "seed_variant_id": "", "callback_reached": True, "matched_artifact": "request-0.json",
            }]}

            result = converge_iteration(
                raw_report={"suggested_seeds": [item]}, pass_run_summary=summary,
                pass_artifacts_dir=uopz_dir, zend_events_dir=zend_dir,
                registry=prepare_callback_registry(self.registry(), "demo-plugin"),
                plugin_slug="demo-plugin", legacy_run_id="legacy-1", known_state={"known_parameters": known},
            )

            self.assertEqual(result["status"], "REPLAY_FAILED")
            self.assertEqual([row["name"] for row in result["missing_parameters"]], ["age"])

    def test_pass2_verification_accepts_rest_json_runtime_evidence(self) -> None:
        raw = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "seed": {
                "path": "/wp-json/demo/v1/items",
                "method": "POST",
                "auth_mode": "nopriv",
                "headers": {"Content-Type": "application/json"},
                "zend_canonical_callback": "Demo::list_items",
                "input_params": [{
                    "name": "filters", "path": ["filters"], "source": "JSON",
                    "location": "json", "fuzzable": True, "evidence_kind": "zend_rest_runtime",
                }],
            },
        }
        candidate = candidate_from_seed_item(raw, plugin_slug="demo-plugin", legacy_run_id="legacy-1")
        artifact = self.pass1_artifact(candidate, request_params={"json_params": {"filters": "redacted"}})
        artifact.update({
            "request_id": "rest-pass2",
            "canonical_identity_id": canonical_identity_id(candidate),
            "http_method": "POST",
            "content_type": "application/json",
            "hook_coverage": {"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        })
        zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-pass2",
            "request_method": "POST",
            "target_loading": {"load_status": "loaded", "file_target_count": 1},
            "rest_parameter_events": [{
                "callback": "Demo::list_items",
                "namespace": "demo/v1",
                "route_pattern": "/items",
                "endpoint_definition_index": 0,
                "materialized_route": "/wp-json/demo/v1/items",
                "method": "POST",
                "name": "filters",
                "location": "json",
                "observed_count": 1,
            }],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            uopz_dir, zend_dir = root / "uopz", root / "zend"
            uopz_dir.mkdir()
            zend_dir.mkdir()
            (uopz_dir / "rest-pass2.json").write_text(json.dumps(artifact), encoding="utf-8")
            (zend_dir / "rest-pass2.json").write_text(json.dumps(zend), encoding="utf-8")

            summary = verify_pass2_contract(
                {"legacy_run_id": "legacy-1", "runs": [{
                    "hook_name": "rest-items", "callback_id": "rest-items", "seed_variant_id": "",
                    "callback_reached": True, "matched_artifact": "rest-pass2.json", "resolved_method": "POST",
                }]},
                {"suggested_seeds": [raw]},
                zend_dir,
                pass2_artifacts_dir=uopz_dir,
            )

            self.assertEqual(summary, {"accepted": 1, "total": 1})

    def test_pass2_verification_rejects_rest_event_for_wrong_route(self) -> None:
        raw = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest",
            "namespace": "demo/v1",
            "route_pattern": "/items",
            "endpoint_definition_index": 0,
            "materialized_route": "/wp-json/demo/v1/items",
            "callback_id": "rest-items",
            "seed": {
                "path": "/wp-json/demo/v1/items",
                "method": "POST",
                "auth_mode": "nopriv",
                "zend_canonical_callback": "Demo::list_items",
                "input_params": [{
                    "name": "filters", "path": ["filters"], "source": "JSON",
                    "location": "json", "fuzzable": True, "evidence_kind": "zend_rest_runtime",
                }],
            },
        }
        candidate = candidate_from_seed_item(raw, plugin_slug="demo-plugin", legacy_run_id="legacy-1")
        artifact = self.pass1_artifact(candidate, request_params={"json_params": {"filters": "redacted"}})
        artifact.update({
            "request_id": "rest-pass2",
            "canonical_identity_id": canonical_identity_id(candidate),
            "http_method": "POST",
            "hook_coverage": {"executed_callbacks": {"rest-items": {"callback_id": "rest-items"}}},
        })
        zend = {
            "schema_version": 4,
            "run_id": "legacy-1",
            "request_id": "rest-pass2",
            "request_method": "POST",
            "rest_parameter_events": [{
                "callback": "Demo::list_items",
                "namespace": "demo/v1",
                "route_pattern": "/other",
                "endpoint_definition_index": 0,
                "materialized_route": "/wp-json/demo/v1/other",
                "method": "POST",
                "name": "filters",
                "location": "json",
                "observed_count": 1,
            }],
        }
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            uopz_dir, zend_dir = root / "uopz", root / "zend"
            uopz_dir.mkdir()
            zend_dir.mkdir()
            (uopz_dir / "rest-pass2.json").write_text(json.dumps(artifact), encoding="utf-8")
            (zend_dir / "rest-pass2.json").write_text(json.dumps(zend), encoding="utf-8")

            summary = verify_pass2_contract(
                {"legacy_run_id": "legacy-1", "runs": [{
                    "hook_name": "rest-items", "callback_id": "rest-items", "seed_variant_id": "",
                    "callback_reached": True, "matched_artifact": "rest-pass2.json", "resolved_method": "POST",
                }]},
                {"suggested_seeds": [raw]},
                zend_dir,
                pass2_artifacts_dir=uopz_dir,
            )

            self.assertEqual(summary, {"accepted": 0, "total": 1})

    def test_combine_final_seed_reports_requires_every_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            first = root / "first.json"
            second = root / "second.json"
            first.write_text(json.dumps({"suggested_seeds": [self.raw_seed_item()]}), encoding="utf-8")
            second.write_text(json.dumps({"suggested_seeds": [self.raw_seed_item(callback_id="ajax-write", action="demo_save_items")]}), encoding="utf-8")

            combined = combine_final_seed_reports([first, second], expected_count=2)

            self.assertEqual(len(combined["suggested_seeds"]), 2)
            with self.assertRaises(ValueError):
                combine_final_seed_reports([first], expected_count=2)

    def test_engine_has_no_legacy_runner_imports(self) -> None:
        engine_source = (FUZZER_DIR / "zend_discovery" / "engine.py").read_text(encoding="utf-8")

        self.assertNotIn("config_exporter", engine_source)
        self.assertNotIn("generated_config_runner", engine_source)
        self.assertNotIn("run_discovery", engine_source)

    def test_legacy_zend_bridge_is_only_compatibility_reexports(self) -> None:
        bridge_source = (FUZZER_DIR / "hook_energy" / "seed_generation" / "zend_bridge.py").read_text(encoding="utf-8")

        self.assertIn("from zend_discovery.convergence import", bridge_source)
        self.assertNotIn("def materialize_convergence_seeds", bridge_source)
        self.assertNotIn("REST_JSON", bridge_source)

    def test_zend_dockerfile_uses_only_zend_owned_extension_source(self) -> None:
        dockerfile = (FUZZER_DIR.parent / "web" / "Dockerfile.zend").read_text(encoding="utf-8")

        self.assertIn("phuzz-main/code/fuzzer/zend_discovery/extension/", dockerfile)
        self.assertNotIn("research/hookphuzz-opcode", dockerfile)
        self.assertNotIn("phase10", dockerfile.lower())
        self.assertNotIn("phase11", dockerfile.lower())
        self.assertNotIn("phase12", dockerfile.lower())
        self.assertNotIn("phase13", dockerfile.lower())

if __name__ == "__main__":
    unittest.main()
