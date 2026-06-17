from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_validator import (
    build_validation_request,
    load_candidate,
    validate_candidate,
)


class FakeResponse:
    def __init__(self, status_code: int, content: bytes = b"OK") -> None:
        self.status_code = status_code
        self.content = content


class FakeHttpClient:
    def __init__(self, response: FakeResponse | Exception, artifact_dir: Path | None = None, artifact: dict | None = None) -> None:
        self.response = response
        self.artifact_dir = artifact_dir
        self.artifact = artifact
        self.calls: list[dict] = []

    def request(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response

        if self.artifact_dir is not None and self.artifact is not None:
            artifact_path = self.artifact_dir / f"req-{len(self.calls)}.json"
            artifact_path.write_text(json.dumps(self.artifact), encoding="utf-8")

        return self.response


def build_candidate(
    *,
    candidate_id: str = "candidate-public",
    callback_id: str | None = "cb-public",
    hook_name: str = "wp_ajax_nopriv_demo_lookup",
    method: str = "POST",
    path: str = "/wp-admin/admin-ajax.php",
    query_params: dict | None = None,
    body_params: dict | None = None,
) -> dict:
    return {
        "candidate_id": candidate_id,
        "hook_name": hook_name,
        "callback_id": callback_id,
        "callback_repr": "demo_lookup_handler",
        "http_template": {
            "method": method,
            "path": path,
            "query_params": query_params or {},
            "body_params": body_params if body_params is not None else {"action": "demo_lookup"},
        },
    }


def build_request_artifact(*, executed: dict | list | None = None, registered: dict | list | None = None) -> dict:
    return {
        "request_id": "req-validation",
        "http_method": "POST",
        "http_target": "/wp-admin/admin-ajax.php?action=demo_lookup",
        "endpoint": "ADMIN_AJAX:demo_lookup",
        "hook_coverage": {
            "registered_callbacks": registered or {},
            "executed_callbacks": executed or {},
            "blindspot_callbacks": {},
        },
    }


class SeedValidatorTests(unittest.TestCase):
    def test_validates_true_when_callback_id_appears_in_new_artifact_executed_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            requests_dir = Path(tmp_dir) / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            artifact = build_request_artifact(
                executed={
                    "cb-public": {
                        "callback_id": "cb-public",
                        "hook_name": "wp_ajax_nopriv_demo_lookup",
                        "fired_hook": "wp_ajax_nopriv_demo_lookup",
                    }
                }
            )
            http_client = FakeHttpClient(FakeResponse(200, b"validated"), requests_dir, artifact)

            result = validate_candidate(
                candidate=build_candidate(),
                base_url="http://web",
                hook_coverage_dir=requests_dir.parent,
                timeout=5,
                validation_id="validation-1",
                http_client=http_client,
            )

        self.assertTrue(result["result"]["expected_hook_fired"])
        self.assertTrue(result["result"]["expected_callback_reached"])
        self.assertEqual(result["result"]["confidence"], "high")
        self.assertEqual(result["observed"]["executed_callback_ids"], ["cb-public"])
        self.assertEqual(result["artifacts"]["new_request_artifacts"], ["requests/req-1.json"])
        self.assertEqual(result["response"]["status_code"], 200)
        self.assertEqual(result["response"]["response_size"], len(b"validated"))

    def test_validates_false_when_only_registered_but_not_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            requests_dir = Path(tmp_dir) / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            artifact = build_request_artifact(
                registered={"cb-public": {"callback_id": "cb-public", "hook_name": "wp_ajax_nopriv_demo_lookup"}}
            )
            http_client = FakeHttpClient(FakeResponse(200), requests_dir, artifact)

            result = validate_candidate(
                candidate=build_candidate(),
                base_url="http://web",
                hook_coverage_dir=requests_dir.parent,
                timeout=5,
                validation_id="validation-2",
                http_client=http_client,
            )

        self.assertFalse(result["result"]["expected_hook_fired"])
        self.assertFalse(result["result"]["expected_callback_reached"])
        self.assertEqual(result["result"]["confidence"], "low")
        self.assertIn("registered but was not executed", result["result"]["reason"])
        self.assertEqual(result["observed"]["registered_callback_ids"], ["cb-public"])

    def test_handles_missing_artifact_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hook_coverage_dir = Path(tmp_dir) / "hook-coverage"
            http_client = FakeHttpClient(FakeResponse(204, b""))

            result = validate_candidate(
                candidate=build_candidate(),
                base_url="http://web",
                hook_coverage_dir=hook_coverage_dir,
                timeout=5,
                validation_id="validation-3",
                http_client=http_client,
            )

        self.assertFalse(result["result"]["expected_hook_fired"])
        self.assertFalse(result["result"]["expected_callback_reached"])
        self.assertEqual(result["artifacts"]["artifact_count"], 0)
        self.assertIn("No new hook coverage request artifacts", result["result"]["reason"])

    def test_handles_http_error_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            hook_coverage_dir = Path(tmp_dir) / "hook-coverage"
            http_client = FakeHttpClient(TimeoutError("validation timed out"))

            result = validate_candidate(
                candidate=build_candidate(),
                base_url="http://web",
                hook_coverage_dir=hook_coverage_dir,
                timeout=1,
                validation_id="validation-4",
                http_client=http_client,
            )

        self.assertIsNone(result["response"]["status_code"])
        self.assertIn("validation timed out", result["response"]["error"])
        self.assertFalse(result["result"]["expected_callback_reached"])

    def test_requires_candidate_id_when_multiple_candidates_exist(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            candidate_file = Path(tmp_dir) / "entrypoint_candidates.json"
            candidate_file.write_text(
                json.dumps({"candidates": [build_candidate(candidate_id="one"), build_candidate(candidate_id="two")]}),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(FUZZER_DIR / "hook_energy" / "seed_validator.py"),
                    "--base-url",
                    "http://web",
                    "--candidate-file",
                    str(candidate_file),
                    "--hook-coverage-dir",
                    str(Path(tmp_dir) / "hook-coverage"),
                    "--output-file",
                    str(Path(tmp_dir) / "validation_result.json"),
                    "--timeout",
                    "1",
                ],
                cwd=FUZZER_DIR,
                text=True,
                capture_output=True,
                timeout=20,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--candidate-id is required", result.stderr)

    def test_builds_post_request_correctly_for_admin_ajax_candidate(self) -> None:
        request = build_validation_request(
            build_candidate(body_params={"action": "demo_lookup", "item_id": "FUZZ"}),
            base_url="http://web/",
            validation_id="validation-post",
        )

        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(request["data"], {"action": "demo_lookup", "item_id": "FUZZ"})
        self.assertEqual(request["params"], {})
        self.assertEqual(request["headers"]["X-HookPhuzz-Validation-ID"], "validation-post")
        self.assertEqual(request["headers"]["X-HookPhuzz-Candidate-ID"], "candidate-public")
        self.assertEqual(request["headers"]["X-Fuzzer-Covid"], "validation-post")

    def test_builds_get_request_correctly_for_admin_action_candidate(self) -> None:
        request = build_validation_request(
            build_candidate(
                candidate_id="candidate-admin-action",
                hook_name="admin_action_demo_export",
                method="GET",
                path="/wp-admin/admin.php?page=tools",
                query_params={"action": "demo_export", "nonce": "FUZZ"},
                body_params={},
            ),
            base_url="http://web",
            validation_id="validation-get",
        )

        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["url"], "http://web/wp-admin/admin.php?page=tools&action=demo_export&nonce=FUZZ")
        self.assertEqual(request["data"], {})
        self.assertEqual(request["params"], {})

    def test_load_candidate_accepts_single_seed_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            candidate_file = Path(tmp_dir) / "seed.json"
            candidate_file.write_text(
                json.dumps(
                    {
                        "hook_name": "wp_ajax_nopriv_demo_lookup",
                        "callback_id": "cb-public",
                        "callback_name": "demo_lookup_handler",
                        "seed": {
                            "method": "POST",
                            "path": "/wp-admin/admin-ajax.php",
                            "body": {"action": "demo_lookup"},
                            "query_params": {},
                        },
                    }
                ),
                encoding="utf-8",
            )

            candidate = load_candidate(candidate_file, None)

        self.assertEqual(candidate["candidate_id"], "cb-public")
        self.assertEqual(candidate["http_template"]["body_params"], {"action": "demo_lookup"})

    def test_seed_validator_reports_new_child_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            requests_dir = Path(tmp_dir) / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            artifact = build_request_artifact(
                executed={
                    "cb-level1": {
                        "callback_id": "cb-level1",
                        "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
                        "fired_hook": "wp_ajax_nopriv_hookphuzz_level1",
                    }
                },
                registered={
                    "cb-level2": {
                        "callback_id": "cb-level2",
                        "hook_name": "wp_ajax_nopriv_hookphuzz_level2",
                        "callback_repr": "hookphuzz_level2",
                        "registered_inside_callback": True,
                        "hook_level": 1,
                        "parent_callback_id": "cb-level1",
                        "parent_callback_repr": "hookphuzz_level1",
                        "parent_callback": {
                            "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
                            "callback_id": "cb-level1",
                            "callback_repr": "hookphuzz_level1",
                            "hook_level": 0,
                        },
                    }
                },
            )
            http_client = FakeHttpClient(FakeResponse(200), requests_dir, artifact)

            result = validate_candidate(
                candidate=build_candidate(
                    candidate_id="cb-level1",
                    callback_id="cb-level1",
                    hook_name="wp_ajax_nopriv_hookphuzz_level1",
                    body_params={"action": "hookphuzz_level1"},
                ),
                base_url="http://web",
                hook_coverage_dir=requests_dir.parent,
                timeout=5,
                validation_id="validation-child",
                http_client=http_client,
            )

        self.assertEqual(
            result["observed"]["newly_registered_child_hooks"],
            [
                {
                    "hook_name": "wp_ajax_nopriv_hookphuzz_level2",
                    "callback_id": "cb-level2",
                    "hook_level": 1,
                    "parent_callback_id": "cb-level1",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
