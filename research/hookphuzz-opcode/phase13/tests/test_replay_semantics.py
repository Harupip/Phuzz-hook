#!/usr/bin/env python3
"""Offline semantic checks for Phase 13 replay configuration evidence."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import classify_authentication as classifier
from classify_authentication import ValidationError, atomic, result_for, validate
from generate_replay_config import generate


def catalog() -> dict:
    base = {"run_id": "catalog-run", "plugin_slug": "plugin", "plugin_version": "1.0", "methods": ["GET"], "method_origin": "runtime_registry", "ownership": "plugin", "callback": "endpoint_callback", "permission_callback": "permission_callback", "ownership_evidence": ["plugin"], "limitations": []}
    return {"records": [
        {**base, "endpoint_identity": "public-endpoint", "route": "/plugin/v1/public", "authentication": "public", "schema_parameters": [{"name": "page", "parameter_origin": "schema"}], "runtime_parameters": []},
        {**base, "endpoint_identity": "auth-endpoint", "route": "/plugin/v1/auth", "authentication": "unresolved", "schema_parameters": [{"name": "page", "parameter_origin": "schema"}], "runtime_parameters": [{"name": "search", "parameter_origin": "runtime", "plugin_slug": "plugin", "plugin_version": "1.0"}]},
    ]}


def overlay() -> dict:
    return {"schema_version": 1, "permission_probe_run_id": "probe-run", "replay_run_id": "replay-run", "catalog_run_id": "catalog-run", "catalog_sha256": "", "plugin_slug": "plugin", "plugin_version": "1.0", "endpoint_id": "auth-endpoint", "route": "/plugin/v1/auth", "method": "GET", "callback": "endpoint_callback", "permission_callback": "permission_callback", "classification": "authenticated", "classification_origin": "current_runtime_permission_probe", "anonymous_control": {"request_id": "anon", "denied": True}, "invalidated_auth_control": {"request_id": "invalid", "denied": True}, "valid_auth_control": {"request_id": "valid", "accepted": True, "current_run": True}, "permission_callback_reached": True, "endpoint_callback_reached": True, "request_ids": {"anonymous": "anon", "invalidated_auth": "invalid", "valid_auth": "valid", "permission_callback": "valid", "endpoint_callback": "valid"}, "source_artifacts": ["redacted-log.json"], "source_artifact_sha256": {"redacted-log.json": "a" * 64}, "redaction_pass": True, "containment_pass": True, "limitations": []}


class ReplaySemantics(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.dir = Path(self.temp.name)
        self.catalog_path = self.dir / "catalog.json"
        self.write_catalog(catalog())
        self.evidence = overlay()
        self.evidence["catalog_sha256"] = self.sha
        self.overlay_path = self.dir / "overlay.json"
        atomic(self.overlay_path, self.evidence)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_catalog(self, data: dict) -> None:
        atomic(self.catalog_path, data)
        self.sha = hashlib.sha256(self.catalog_path.read_bytes()).hexdigest()

    def write_overlay(self, data: dict) -> Path:
        path = self.dir / "candidate-overlay.json"
        atomic(path, data)
        return path

    def runtime_evidence(self) -> Path:
        path = self.dir / "runtime.json"
        atomic(path, {"replay_run_id": "replay-run", "request_id": "request", "plugin_slug": "plugin", "plugin_version": "1.0", "endpoint_id": "auth-endpoint", "route": "/plugin/v1/auth", "method": "GET", "callback": "endpoint_callback", "parameters": [{"name": "search", "runtime_source": "WP_REST_Request::get_param", "redacted_value_metadata": "not_persisted"}]})
        return path

    def generate(self, **changes):
        return generate(self.catalog_path, catalog_run=changes.pop("catalog_run", "catalog-run"), catalog_sha=changes.pop("catalog_sha", self.sha), plugin=changes.pop("plugin", "plugin"), version=changes.pop("version", "1.0"), endpoint=changes.pop("endpoint", "public-endpoint"), replay_type=changes.pop("replay_type", "public"), replay_run=changes.pop("replay_run", "replay-run"), request_id="request", output=changes.pop("output", self.dir / "config.json"), overlay=changes.pop("overlay", None), **changes)

    def rejects(self, code: str, action) -> None:
        with self.assertRaisesRegex(ValueError, code):
            action()

    def test_01_valid_public_config_generation(self):
        self.assertEqual(self.generate()["methods"], ["GET"])

    def test_02_valid_authenticated_overlay_classification(self):
        self.assertEqual(validate(self.evidence)["classification"], "authenticated")

    def test_03_valid_authenticated_config_generation(self):
        config = self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.overlay_path)
        self.assertEqual(config["metadata"]["effective_authentication"], "authenticated")

    def test_04_stale_catalog_run_rejected(self):
        evidence = dict(self.evidence); evidence["catalog_run_id"] = "old"
        self.rejects("stale_catalog_run", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))
    def test_05_wrong_plugin_rejected(self):
        evidence = dict(self.evidence); evidence["plugin_slug"] = "other"
        self.rejects("plugin_mismatch", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))
    def test_06_wrong_plugin_version_rejected(self):
        evidence = dict(self.evidence); evidence["plugin_version"] = "2"
        self.rejects("version_mismatch", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))
    def test_07_catalog_sha_mismatch_rejected(self): self.rejects("catalog_sha_mismatch", lambda: self.generate(catalog_sha="0" * 64))
    def test_08_missing_endpoint_rejected(self): self.rejects("missing_endpoint_identity", lambda: self.generate(endpoint="missing"))

    def test_09_unresolved_method_rejected(self):
        data = catalog(); data["records"][0]["methods"] = ["GET", "POST"]; self.write_catalog(data)
        self.rejects("unresolved_method", self.generate)

    def test_10_empty_method_rejected(self):
        data = catalog(); data["records"][0]["methods"] = [""]; self.write_catalog(data)
        self.rejects("unresolved_method", self.generate)

    def test_11_no_get_fallback_introduced(self):
        data = catalog(); data["records"][0]["methods"] = []; self.write_catalog(data)
        self.rejects("unresolved_method", self.generate)

    def test_12_no_post_fallback_introduced(self):
        data = catalog(); data["records"][0]["methods"] = []; self.write_catalog(data)
        self.rejects("unresolved_method", self.generate)

    def test_13_unsupported_parameter_rejected(self):
        data = catalog(); data["records"][0]["schema_parameters"] = [{"name": "x", "parameter_origin": "runtime"}]; self.write_catalog(data)
        self.rejects("unsupported_parameter", self.generate)

    def test_14_schema_parameter_remains_schema_derived(self):
        self.assertEqual(self.generate()["metadata"]["schema_parameters"][0]["parameter_origin"], "schema")

    def test_15_runtime_parameter_remains_runtime_derived(self):
        config = self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.overlay_path, query_parameters={"search": "probe"}, runtime_parameter_evidence=self.runtime_evidence())
        self.assertEqual(config["metadata"]["runtime_parameters"][0]["parameter_origin"], "runtime")
        self.assertEqual(config["query_params"]["data"], [{"name": "search", "value": "probe"}])

    def test_16_phase12_historical_evidence_rejected_as_current(self):
        prior = dict(self.evidence); prior["replay_run_id"] = "phase12-run"
        self.rejects("stale_replay_evidence", lambda: validate(prior, replay_run="replay-run"))

    def test_17_public_config_contains_no_authentication_reference(self):
        self.assertNotIn("authentication_reference", self.generate()["metadata"])

    def test_18_authenticated_config_requires_an_overlay(self): self.rejects("missing_authentication_overlay", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated"))
    def test_19_overlay_from_another_run_rejected(self):
        evidence = dict(self.evidence); evidence["replay_run_id"] = "other"
        self.rejects("stale_replay_evidence", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))
    def test_20_overlay_from_another_plugin_rejected(self):
        evidence = dict(self.evidence); evidence["plugin_slug"] = "other"
        self.rejects("plugin_mismatch", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))
    def test_21_overlay_from_another_endpoint_rejected(self):
        evidence = dict(self.evidence); evidence["endpoint_id"] = "public-endpoint"
        self.rejects("endpoint_mismatch", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.write_overlay(evidence)))

    def test_22_missing_anonymous_denial_rejected(self):
        evidence = dict(self.evidence); evidence["anonymous_control"] = {"request_id": "anon"}
        self.rejects("missing_anonymous_denied", lambda: validate(evidence))
    def test_23_missing_invalidated_auth_denial_rejected(self):
        evidence = dict(self.evidence); evidence["invalidated_auth_control"] = {"request_id": "invalid"}
        self.rejects("missing_invalidated_auth_denied", lambda: validate(evidence))
    def test_24_missing_valid_auth_success_rejected(self):
        evidence = dict(self.evidence); evidence["valid_auth_control"] = {"request_id": "valid", "current_run": True}
        self.rejects("missing_valid_auth_accepted", lambda: validate(evidence))
    def test_25_missing_permission_callback_reach_rejected(self):
        evidence = dict(self.evidence); evidence["permission_callback_reached"] = False
        self.rejects("permission_callback_not_reached", lambda: validate(evidence))
    def test_26_missing_endpoint_callback_reach_rejected(self):
        evidence = dict(self.evidence); evidence["endpoint_callback_reached"] = False
        self.rejects("endpoint_callback_not_reached", lambda: validate(evidence))
    def test_27_mismatched_request_ids_rejected(self):
        evidence = dict(self.evidence); evidence["request_ids"] = dict(evidence["request_ids"], endpoint_callback="other")
        self.rejects("request_id_mismatch", lambda: validate(evidence))

    def test_28_raw_cookie_rejected(self):
        evidence = dict(self.evidence); evidence["Cookie"] = "raw"
        self.rejects("raw_authentication_material", lambda: validate(evidence))
    def test_29_raw_nonce_rejected(self):
        evidence = dict(self.evidence); evidence["metadata"] = "X-WP-Nonce: raw"
        self.rejects("raw_authentication_material", lambda: validate(evidence))
    def test_30_raw_authorization_value_rejected(self):
        evidence = dict(self.evidence); evidence["Authorization"] = "Bearer raw"
        self.rejects("raw_authentication_material", lambda: validate(evidence))
    def test_31_password_or_session_token_rejected(self):
        evidence = dict(self.evidence); evidence["session_token"] = "raw"
        self.rejects("raw_authentication_material", lambda: validate(evidence))
    def test_32_redaction_failure_rejected(self):
        evidence = dict(self.evidence); evidence["redaction_pass"] = False
        self.rejects("redaction_failed", lambda: validate(evidence))
    def test_33_containment_failure_rejected(self):
        evidence = dict(self.evidence); evidence["containment_pass"] = False
        self.rejects("containment_failed", lambda: validate(evidence))

    def test_34_public_and_authenticated_outputs_cannot_collide(self):
        output = self.dir / "same.json"; self.generate(output=output)
        self.rejects("output_collision", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.overlay_path, output=output))

    def test_35_output_writing_is_atomic(self):
        source = self.dir / "evidence.json"; output = self.dir / "atomic.json"; atomic(source, self.evidence)
        saved_argv = sys.argv
        try:
            sys.argv = ["classify_authentication.py", str(source), str(output), "--replay-run", "replay-run", "--catalog-run", "catalog-run", "--catalog-sha", self.sha, "--plugin", "plugin", "--version", "1.0", "--endpoint", "auth-endpoint", "--route", "/plugin/v1/auth", "--method", "GET"]
            self.assertEqual(classifier.main(), 0)
        finally:
            sys.argv = saved_argv
        self.assertTrue(output.with_name("atomic-result.json").is_file())
        self.assertEqual(json.loads(output.read_text())["classification_origin"], "current_runtime_permission_probe")
        self.assertEqual(list(self.dir.glob(".atomic.json.*.tmp")), [])

    def test_36_deterministic_input_produces_deterministic_semantic_output(self):
        first = self.generate(output=self.dir / "one.json")
        second = self.generate(output=self.dir / "two.json")
        self.assertEqual(first, second)

    def test_37_malformed_overlay_json_rejected(self):
        malformed = self.dir / "bad.json"; malformed.write_text("{")
        self.rejects("malformed_overlay", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=malformed))

    def test_38_wrong_overlay_schema_version_rejected(self):
        evidence = dict(self.evidence); evidence["schema_version"] = 2
        self.rejects("wrong_schema_version", lambda: validate(evidence))

    def test_39_stale_replay_evidence_rejected(self):
        evidence = dict(self.evidence); evidence["valid_auth_control"] = dict(evidence["valid_auth_control"], current_run=False)
        self.rejects("stale_replay_evidence", lambda: validate(evidence))

    def test_40_cross_plugin_runtime_parameter_evidence_rejected(self):
        data = catalog(); data["records"][1]["runtime_parameters"][0]["plugin_slug"] = "other"; self.write_catalog(data)
        self.rejects("cross_plugin_runtime_parameter_evidence", lambda: self.generate(endpoint="auth-endpoint", replay_type="authenticated", overlay=self.overlay_path))

    def test_result_artifact_has_precise_failure_classification(self):
        evidence = dict(self.evidence); evidence["redaction_pass"] = False
        result = result_for(evidence)
        self.assertFalse(result["passed"]); self.assertEqual(result["failure_classification"], "redaction_failed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
