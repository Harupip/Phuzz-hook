import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from hook_energy.seed_generation.generated_config_runner import format_validation_result, run_generated_configs
from online_linked import probe_sender
from online_linked.coordinator import OnlineLinkedCoordinator
from online_linked.export import export_online_linked_batch
from seed_generation.verification import seed_validator
from seed_generation.verification.seed_validator import response_details, validate_candidate


class HttpFailureDiagnosticsTests(unittest.TestCase):
    def send(self, *, status=200, location=None, body="", executed=False,
             request_changes=None, zend_changes=None, missing=None, error=None, callback_id="cb",
             hook_name="wp_ajax_test"):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "config.json"
            config.write_text(json.dumps({"target": "http://web/test", "methods": ["POST"]}))
            request_dir, zend_dir = root / "request", root / "zend"
            request_dir.mkdir()
            zend_dir.mkdir()
            coverage = {"executed_callbacks": {"cb": {"hook_name": hook_name}} if executed else {}}
            request = {"request_id": "req", "run_id": "run", "response": {"status_code": status or 500},
                       "hook_coverage": coverage}
            zend = {"request_id": "req", "run_id": "run"}
            request.update(request_changes or {})
            zend.update(zend_changes or {})
            if missing != "request":
                (request_dir / "req.json").write_text(json.dumps(request))
            if missing != "zend":
                (zend_dir / "req.json").write_text(json.dumps(zend))

            class Clock:
                now = 0.0
                def __call__(self):
                    return self.now
                def sleep(self, delay):
                    self.now += delay

            clock = Clock()

            class Session:
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return False
                def send(self, prepared, timeout, allow_redirects):
                    if allow_redirects:
                        raise AssertionError("redirect followed")
                    if error:
                        raise error
                    return type("Response", (), {
                        "status_code": status, "text": body,
                        "headers": {"Location": location or "", "Content-Type": "application/json",
                                    "Retry-After": "7"},
                    })()

            return probe_sender.send_and_wait(
                config, request_id="req", run_id="run", timeout_seconds=0.2,
                expected={"hook_name": hook_name, "callback_id": callback_id},
                session_factory=Session, request_dir=request_dir, zend_dir=zend_dir,
                clock=clock, sleeper=clock.sleep,
            )

    def test_http_cause_requires_evidence_and_preserves_callback(self):
        cases = [
            (302, "/wp-login.php?redirect_to=%2Fwp-admin", "", False, "authentication_redirect"),
            (302, "/wp-login.php", "", True, "redirect_after_callback"),
            (302, "/other", "", False, "redirect"),
            (301, "/other", "", False, "redirect"),
            (303, "/other", "", False, "redirect"),
            (307, "/other", "", False, "redirect"),
            (308, "/other", "", False, "redirect"),
            (304, "/other", "", False, "not_modified"),
            (400, None, "bad request", False, "unknown_http_failure"),
            (403, None, '{"code":"rest_cookie_invalid_nonce"}', False, "nonce_validation_failure"),
            (403, None, "forbidden", False, "unknown_http_failure"),
            (403, None, '{"code":"rest_forbidden"}', False, "authorization_failure"),
            (401, None, '{"code":"rest_not_logged_in"}', False, "authentication_failure"),
            (404, None, '{"code":"rest_no_route"}', False, "route_not_found"),
            (404, None, "not found", True, "unknown_http_failure"),
            (404, None, '{"code":"rest_no_route"}', True, "unknown_http_failure"),
            (429, None, "retry", False, "unknown_http_failure"),
            (500, None, "unknown", False, "unknown_http_failure"),
            (500, None, "exception", True, "server_error_after_callback"),
            (502, None, "upstream", False, "unknown_http_failure"),
            (503, None, "unavailable", False, "unknown_http_failure"),
            (504, None, "gateway timeout", False, "unknown_http_failure"),
            (200, None, "ok", True, None),
        ]
        for status, location, body, executed, category in cases:
            with self.subTest(status=status, body=body, location=location, executed=executed):
                result = self.send(status=status, location=location, body=body, executed=executed)
                self.assertIn("diagnostics", result)
                diagnostic = result["diagnostics"]
                self.assertEqual(diagnostic["http"]["category"], category)
                self.assertEqual(diagnostic["http"]["status_code"], status)
                self.assertEqual(diagnostic["http"]["body"], body)
                self.assertEqual(diagnostic["http"]["headers"]["Retry-After"], "7")
                self.assertEqual(diagnostic["callback"]["outcome"], "executed" if executed else "not_executed")
                self.assertEqual(diagnostic["correlation"]["outcome"], "matched")
                self.assertEqual(result["callback_reached"], executed)

    def test_missing_and_mismatched_artifacts_keep_timeout_and_independent_http(self):
        cases = [
            ({"missing": "request"}, "missing_request_artifact", None, None),
            ({"missing": "zend"}, "missing_zend_artifact", None, None),
            ({"request_changes": {"request_id": "other"}}, "artifact_mismatch", "request", "request_id"),
            ({"request_changes": {"run_id": "other"}}, "artifact_mismatch", "request", "run_id"),
            ({"zend_changes": {"request_id": "other"}}, "artifact_mismatch", "zend", "request_id"),
            ({"zend_changes": {"run_id": "other"}}, "artifact_mismatch", "zend", "run_id"),
        ]
        for kwargs, outcome, artifact, field in cases:
            with self.subTest(kwargs=kwargs):
                result = self.send(**kwargs)
                self.assertEqual(result["status"], "timeout")
                self.assertEqual(result["error"], "CORRELATED_ARTIFACT_TIMEOUT")
                self.assertIn("diagnostics", result)
                diagnostic = result["diagnostics"]
                self.assertEqual(diagnostic["transport"]["outcome"], "response_received")
                self.assertEqual(diagnostic["http"]["status_code"], 200)
                self.assertEqual(diagnostic["correlation"]["outcome"], outcome)
                if field:
                    self.assertEqual((diagnostic["correlation"]["artifact"], diagnostic["correlation"]["field"]),
                                     (artifact, field))
                expected_callback = "not_executed" if kwargs.get("missing") == "zend" or kwargs.get("zend_changes") else "unknown"
                self.assertEqual(diagnostic["callback"]["outcome"], expected_callback)

    def test_ajax_and_rest_use_the_same_evidence_based_http_classification(self):
        for hook_name in ("wp_ajax_test", "rest_route:fixture/v1/items"):
            with self.subTest(hook_name=hook_name):
                result = self.send(status=403, executed=True, hook_name=hook_name,
                                   body='{"code":"rest_cookie_invalid_nonce"}')
                self.assertTrue(result["callback_reached"])
                self.assertEqual(result["diagnostics"]["http"]["category"], "nonce_validation_failure")

    def test_transport_timeout_does_not_replace_artifact_diagnostic(self):
        result = self.send(error=requests.Timeout("network timeout"), missing="request")
        self.assertEqual(result["status"], "http_error")
        self.assertEqual(result["error"], "network timeout")
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["transport"]["outcome"], "timeout")
        self.assertIsNone(result["diagnostics"]["http"]["status_code"])
        self.assertEqual(result["diagnostics"]["correlation"]["outcome"], "missing_request_artifact")

    def test_empty_transport_exception_keeps_its_type(self):
        result = self.send(error=requests.Timeout(), missing="request")
        self.assertEqual(result["diagnostics"]["transport"]["outcome"], "timeout")
        self.assertEqual(result["diagnostics"]["transport"]["error"], "Timeout")
        self.assertEqual(result["diagnostics"]["correlation"]["outcome"], "missing_request_artifact")
        class Client:
            def request(self, **kwargs):
                raise TimeoutError()
        candidate = {"candidate_id": "x", "hook_name": "wp_ajax_test", "callback_id": "cb",
                     "http_template": {"method": "POST", "path": "/admin-ajax.php"}}
        with tempfile.TemporaryDirectory() as tmp:
            validation = validate_candidate(candidate=candidate, base_url="http://web", hook_coverage_dir=tmp,
                                            timeout=1, http_client=Client())
        self.assertEqual(validation["diagnostics"]["transport"]["error"], "TimeoutError")

    def test_config_preparation_failure_is_separate_from_http_and_callback(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "config.json"
            config.write_text("not json")
            result = probe_sender.send_and_wait(config, request_id="req", run_id="run", timeout_seconds=1,
                                                expected={"hook_name": "wp_ajax_test", "callback_id": "cb"})
        self.assertEqual(result["status"], "prepare_error")
        self.assertIn("preparation", result["diagnostics"]["config_validation"])
        self.assertEqual(result["diagnostics"]["config_validation"]["preparation"], "failed")
        self.assertEqual(result["diagnostics"]["transport"]["outcome"], "not_sent")
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")

    def test_missing_execution_coverage_is_unknown_not_login_before_callback(self):
        result = self.send(status=302, location="/wp-login.php", request_changes={"hook_coverage": {}})
        self.assertFalse(result["callback_reached"])
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        self.assertEqual(result["diagnostics"]["http"]["category"], "redirect")

    def test_unknown_callback_identity_is_not_a_failed_callback(self):
        result = self.send(status=302, location="/wp-login.php", callback_id="")
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        self.assertEqual(result["diagnostics"]["http"]["category"], "redirect")

    def test_invalid_location_is_reported_without_interrupting_sender(self):
        result = self.send(status=302, location="http://[", executed=False)
        self.assertEqual(result["status"], "request_completed")
        self.assertEqual(result["diagnostics"]["http"]["category"], "redirect")
        self.assertEqual(result["response_location"], "http://[")

    def test_response_body_decode_failure_does_not_lose_redirect_header(self):
        class Response:
            status_code = 302
            headers = {"location": "/wp-login.php"}
            @property
            def text(self):
                raise UnicodeError("cannot decode body")

        details = response_details(Response())
        self.assertEqual(details["headers"].get("Location"), "/wp-login.php")
        self.assertIsNone(details["body"])

    def test_conflicting_http_and_artifact_status_does_not_infer_error_order(self):
        result = self.send(status=500, executed=True, request_changes={"response": {"status_code": 200}})
        self.assertTrue(result["callback_reached"])
        self.assertEqual(result["diagnostics"]["http"]["category"], "unknown_http_failure")
        self.assertTrue(result["diagnostics"]["http"]["status_mismatch"])

    def test_conflicting_secondary_run_id_is_reported_without_changing_existing_gate(self):
        for changes, artifact, field in (
            ({"request_changes": {"legacy_run_id": "run", "run_id": "other"}}, "request", "run_id"),
            ({"zend_changes": {"run_id": "run", "legacy_run_id": "other"}}, "zend", "legacy_run_id"),
        ):
            with self.subTest(artifact=artifact):
                result = self.send(executed=True, **changes)
                self.assertEqual(result["status"], "callback_reached")
                self.assertIn("identity_conflicts", result["diagnostics"]["correlation"])
                self.assertIn({"artifact": artifact, "field": field, "expected": "run", "actual": "other"},
                              result["diagnostics"]["correlation"]["identity_conflicts"])
                if artifact == "request":
                    self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        result = self.send(status=500, executed=True, missing="zend",
                           request_changes={"legacy_run_id": "run", "run_id": "other",
                                            "errors": [{"errstr": "foreign error"}]})
        self.assertEqual(result["diagnostics"]["correlation"]["outcome"], "missing_zend_artifact")
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        self.assertEqual(result["diagnostics"]["http"]["category"], "unknown_http_failure")
        self.assertEqual(result["diagnostics"]["application"]["php_errors"], [])

    def test_observer_php_errors_are_preserved_without_inventing_bootstrap_stage(self):
        errors = [{"errno": 2, "errstr": "warning", "errfile": "plugin.php", "errline": 17}]
        result = self.send(status=500, request_changes={"errors": errors})
        self.assertIn("php_errors", result["diagnostics"]["application"])
        self.assertEqual(result["diagnostics"]["application"]["php_errors"], errors)
        self.assertEqual(result["diagnostics"]["http"]["category"], "unknown_http_failure")

    def test_missing_zend_preserves_request_callback_as_diagnostic_only(self):
        errors = [{"errno": 2, "errstr": "warning", "errfile": "plugin.php", "errline": 17}]
        result = self.send(status=500, executed=True, missing="zend", request_changes={"errors": errors})
        self.assertEqual(result["status"], "timeout")
        self.assertNotIn("callback_reached", result)
        diagnostic = result["diagnostics"]
        self.assertEqual(diagnostic["correlation"]["outcome"], "missing_zend_artifact")
        self.assertIn("timed_out", diagnostic["correlation"])
        self.assertTrue(diagnostic["correlation"]["timed_out"])
        self.assertEqual(diagnostic["callback"]["outcome"], "executed")
        self.assertEqual(diagnostic["http"]["category"], "server_error_after_callback")
        self.assertEqual(diagnostic["application"]["php_errors"], errors)

    def test_validator_does_not_attribute_foreign_callback_to_response(self):
        candidate = {"candidate_id": "x", "hook_name": "wp_ajax_test", "callback_id": "cb",
                     "http_template": {"method": "POST", "path": "/admin-ajax.php"}}
        with tempfile.TemporaryDirectory() as tmp:
            request_dir = Path(tmp) / "requests"
            request_dir.mkdir()
            class Client:
                def request(self, **kwargs):
                    (request_dir / "foreign.json").write_text(json.dumps({
                        "request_id": "other", "hook_coverage": {
                            "executed_callbacks": {"cb": {"hook_name": "wp_ajax_test"}}},
                    }))
                    return type("Response", (), {"status_code": 500, "content": b"error", "headers": {}})()
            result = validate_candidate(candidate=candidate, base_url="http://web", hook_coverage_dir=tmp,
                                        timeout=1, validation_id="req", http_client=Client())
        self.assertTrue(result["result"]["expected_callback_reached"])
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        self.assertEqual(result["diagnostics"]["http"]["category"], "unknown_http_failure")

    def test_validator_diagnostics_use_the_same_artifact_snapshot_as_validation(self):
        candidate = {"candidate_id": "x", "hook_name": "wp_ajax_test", "callback_id": "cb",
                     "http_template": {"method": "POST", "path": "/admin-ajax.php"}}
        with tempfile.TemporaryDirectory() as tmp:
            request_dir = Path(tmp) / "requests"
            request_dir.mkdir()
            class Client:
                def request(self, **kwargs):
                    (request_dir / "req.json").write_text(json.dumps({
                        "request_id": "req", "hook_coverage": {
                            "executed_callbacks": {"cb": {"hook_name": "wp_ajax_test"}}},
                    }))
                    return type("Response", (), {"status_code": 500, "content": b"error", "headers": {}})()
            original_read = seed_validator._load_json
            def read_then_replace(path):
                payload = original_read(path)
                path.write_text(json.dumps({"request_id": "req", "blindspot_callback_ids": ["missing"],
                                            "hook_coverage": {"executed_callbacks": {}}}))
                return payload
            with patch.object(seed_validator, "_load_json", side_effect=read_then_replace):
                try:
                    result = validate_candidate(candidate=candidate, base_url="http://web", hook_coverage_dir=tmp,
                                                timeout=1, validation_id="req", http_client=Client())
                except ValueError as exc:
                    self.fail(f"diagnostics re-read a changed artifact: {exc}")
        self.assertTrue(result["result"]["expected_callback_reached"])
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "executed")

    def test_generated_report_and_validation_summary_keep_legacy_fields(self):
        payload = {"request_id": "req", "run_id": "run", "response": {"status_code": 500},
                   "hook_coverage": {"executed_callbacks": {"cb": {"hook_name": "wp_ajax_test"}}}}
        snapshots = iter([set(), {"req.json"}])
        report = run_generated_configs(
            [{"config_slug": "test", "hook_name": "wp_ajax_test", "callback_id": "cb"}],
            timeout_seconds=1, legacy_run_id="run",
            run_command=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
            list_artifacts=lambda: next(snapshots), load_artifact=lambda name: payload,
        )
        row = report["runs"][0]
        self.assertTrue(row["callback_reached"])
        self.assertIsNone(row["failure_category"])
        self.assertIn("diagnostics", row)
        self.assertEqual(row["diagnostics"]["requests"][0]["http"]["category"], "server_error_after_callback")
        formatted = format_validation_result(report)["validations"][0]
        self.assertEqual(formatted["status"], "callback_reached")
        self.assertEqual(formatted["diagnostics"], row["diagnostics"])

    def test_generated_report_does_not_attribute_callback_on_another_hook(self):
        payload = {"request_id": "req", "run_id": "run", "response": {"status_code": 500},
                   "hook_coverage": {"executed_callbacks": {"cb": {"hook_name": "wp_ajax_other"}}}}
        snapshots = iter([set(), {"req.json"}])
        report = run_generated_configs(
            [{"config_slug": "test", "hook_name": "wp_ajax_test", "callback_id": "cb"}],
            timeout_seconds=1, legacy_run_id="run",
            run_command=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
            list_artifacts=lambda: next(snapshots), load_artifact=lambda name: payload,
        )
        row = report["runs"][0]
        self.assertTrue(row["callback_reached"])
        diagnostic = row["diagnostics"]["requests"][0]
        self.assertEqual(diagnostic["callback"]["outcome"], "not_executed")
        self.assertEqual(diagnostic["http"]["category"], "unknown_http_failure")

    def test_generated_report_keeps_conflicting_run_identity_unattributed(self):
        payload = {"request_id": "req", "legacy_run_id": "run", "run_id": "other",
                   "response": {"status_code": 500}, "errors": [{"errstr": "foreign error"}],
                   "hook_coverage": {"executed_callbacks": {"cb": {"hook_name": "wp_ajax_test"}}}}
        snapshots = iter([set(), {"req.json"}])
        report = run_generated_configs(
            [{"config_slug": "test", "hook_name": "wp_ajax_test", "callback_id": "cb"}],
            timeout_seconds=1, legacy_run_id="run",
            run_command=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
            list_artifacts=lambda: next(snapshots), load_artifact=lambda name: payload,
        )
        row = report["runs"][0]
        self.assertTrue(row["callback_reached"])
        diagnostic = row["diagnostics"]["requests"][0]
        self.assertEqual(diagnostic["callback"]["outcome"], "unknown")
        self.assertEqual(diagnostic["http"]["category"], "unknown_http_failure")
        self.assertEqual(diagnostic["application"]["php_errors"], [])
        self.assertEqual(diagnostic["correlation"]["outcome"], "artifact_mismatch")
        self.assertEqual(diagnostic["unattributed_php_errors"], [{"errstr": "foreign error"}])

    def test_generated_no_artifact_reports_absence_without_inventing_mapping_failure(self):
        report = run_generated_configs(
            [{"config_slug": "test", "hook_name": "wp_ajax_test", "callback_id": "cb"}],
            timeout_seconds=1, legacy_run_id="run",
            run_command=lambda *args, **kwargs: subprocess.CompletedProcess(args[0], 0),
            list_artifacts=lambda: set(), load_artifact=lambda name: None,
        )
        row = report["runs"][0]
        self.assertEqual(row["failure_category"], "C. request mapping wrong")
        self.assertEqual(row.get("failure_category_basis"), "legacy_heuristic_unconfirmed")
        self.assertEqual(format_validation_result(report)["validations"][0].get("failure_category_basis"),
                         "legacy_heuristic_unconfirmed")
        self.assertIn("correlation", row["diagnostics"])
        self.assertEqual(row["diagnostics"]["correlation"]["outcome"], "no_matching_request_artifact")
        self.assertEqual(row["diagnostics"]["process"]["outcome"], "exited")

    def test_validator_and_coordinator_keep_response_diagnostics(self):
        class Client:
            def request(self, **kwargs):
                return type("Response", (), {"status_code": 403, "content": b"denied", "text": "denied",
                                               "headers": {"Retry-After": "7"}})()

        candidate = {"candidate_id": "x", "hook_name": "wp_ajax_test", "callback_id": "cb",
                     "http_template": {"method": "POST", "path": "/admin-ajax.php"}}
        with tempfile.TemporaryDirectory() as tmp:
            result = validate_candidate(candidate=candidate, base_url="http://web", hook_coverage_dir=tmp,
                                        timeout=1, http_client=Client())
        self.assertEqual(result["response"]["status_code"], 403)
        self.assertIn("diagnostics", result)
        self.assertEqual(result["diagnostics"]["http"]["category"], "unknown_http_failure")
        self.assertEqual(result["diagnostics"]["http"]["body"], "denied")
        self.assertEqual(result["diagnostics"]["callback"]["outcome"], "unknown")
        sender = self.send(status=500, executed=True, body="fatal details")
        row = OnlineLinkedCoordinator._sender_runner_row({}, sender, "run")
        self.assertEqual(row["diagnostics"], sender["diagnostics"])
        self.assertEqual(row["response_status"], 500)

    def test_final_summary_keeps_failed_replay_diagnostics_without_exporting_config(self):
        diagnostic = self.send(status=500, executed=True, body="fatal details")["diagnostics"]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state_path = root / "state.json"
            state_path.write_text(json.dumps({
                "legacy_run_id": "run", "plugin_slug": "fixture", "terminal_status": "NOT_VERIFIED",
                "terminal_reason": "CHILD_REPLAY_FAILED", "versions": [{
                    "version": "v1", "terminal_reason": "GUARD_SATISFACTION_UNKNOWN",
                    "config_type": "fuzzing_ready",
                    "replay_result": {"passed": False, "pass2_verification": {"accepted": 1, "total": 1},
                                      "runner": {"runs": [{"diagnostics": diagnostic}]}},
                }],
            }))
            batch = root / "batch.json"
            batch.write_text(json.dumps({"plugin_slug": "fixture", "candidates": [{
                "identity": "fixture|cb", "hook_name": "wp_ajax_test", "run_id": "run",
                "state_path": str(state_path),
            }]}))
            self.assertEqual(export_online_linked_batch(batch), 0)
            summary = json.loads((root / "final-config-summary.json").read_text())
        skipped = summary["candidates"][0]["skipped_versions"][0]
        self.assertEqual(skipped["reason"], "GATE_NOT_VERIFIED")
        self.assertIn("diagnostics", skipped)
        self.assertEqual(skipped["diagnostics"]["http"]["category"], "server_error_after_callback")
        self.assertEqual(skipped["diagnostics"]["http"]["body"], "fatal details")
        self.assertIn("readiness_evidence", skipped)
        self.assertEqual(skipped["readiness_evidence"], {
            "config_type": "fuzzing_ready", "gate_passed": False,
            "pass2_verification": {"accepted": 1, "total": 1},
        })


if __name__ == "__main__":
    unittest.main()
