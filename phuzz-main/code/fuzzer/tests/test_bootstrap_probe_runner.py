from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.bootstrap_probe_runner import (
    BOOTSTRAP_PROBE_REPORT,
    default_probes,
    list_request_artifacts,
    run_bootstrap_probes,
    write_report,
)


class FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class FakeHttpClient:
    def __init__(self, statuses: list[int | Exception], artifact_dir: Path | None = None) -> None:
        self.statuses = list(statuses)
        self.artifact_dir = artifact_dir
        self.calls: list[dict] = []

    def request(self, **kwargs):
        call_index = len(self.calls)
        self.calls.append(kwargs)
        result = self.statuses.pop(0)
        if isinstance(result, Exception):
            raise result

        if self.artifact_dir is not None:
            artifact_path = self.artifact_dir / f"req-{call_index}.json"
            artifact_path.write_text(json.dumps({"request_id": f"req-{call_index}"}), encoding="utf-8")

        return FakeResponse(result)


class BootstrapProbeRunnerTests(unittest.TestCase):
    def test_all_default_probes_are_present_with_stable_ids(self) -> None:
        probes = default_probes()

        self.assertEqual(
            [(probe.name, probe.method, probe.path) for probe in probes],
            [
                ("frontend_home", "GET", "/"),
                ("admin_ajax_probe", "POST", "/wp-admin/admin-ajax.php?action=hookphuzz_probe"),
                ("admin_post_probe", "POST", "/wp-admin/admin-post.php?action=hookphuzz_probe"),
                ("rest_api_index", "GET", "/wp-json/"),
                ("rest_route_index", "GET", "/?rest_route=/"),
                ("login_lostpassword", "GET", "/wp-login.php?action=lostpassword"),
                ("wp_admin_index", "GET", "/wp-admin/index.php"),
                ("wp_admin_admin", "GET", "/wp-admin/admin.php"),
                ("xmlrpc_method_call", "POST", "/xmlrpc.php"),
                ("wp_cron", "GET", "/wp-cron.php"),
            ],
        )
        self.assertEqual(probes[0].probe_id, "bootstrap-01-frontend_home")
        self.assertEqual(probes[-1].probe_id, "bootstrap-10-wp_cron")

    def test_report_json_is_written_with_expected_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            hook_coverage_dir = root / "hook-coverage"
            requests_dir = hook_coverage_dir / "requests"
            requests_dir.mkdir(parents=True)
            http_client = FakeHttpClient([200] * 10, artifact_dir=requests_dir)

            report = run_bootstrap_probes(
                base_url="http://web",
                hook_coverage_dir=hook_coverage_dir,
                timeout=5,
                sleep_between_probes=0,
                http_client=http_client,
            )
            output_path = write_report(report, root / "output")

            self.assertEqual(output_path, root / "output" / BOOTSTRAP_PROBE_REPORT)
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 1)
            self.assertEqual(payload["base_url"], "http://web")
            self.assertEqual(payload["probe_count"], 10)
            self.assertEqual(len(payload["probes"]), 10)
            self.assertIn("started_at", payload)
            self.assertIn("finished_at", payload)
            self.assertEqual(payload["summary"]["successful_probes"], 10)
            self.assertEqual(payload["summary"]["failed_probes"], 0)
            self.assertEqual(payload["summary"]["artifacts_created"], 10)
            first_probe = payload["probes"][0]
            for field in (
                "probe_id",
                "name",
                "method",
                "path",
                "url",
                "status_code",
                "duration_ms",
                "error",
                "new_request_artifacts",
            ):
                self.assertIn(field, first_probe)

    def test_failed_http_request_is_recorded_without_stopping_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            http_client = FakeHttpClient([TimeoutError("probe timed out"), 403] + [200] * 8)

            report = run_bootstrap_probes(
                base_url="http://web",
                hook_coverage_dir=Path(tmp_dir) / "hook-coverage",
                timeout=3,
                sleep_between_probes=0,
                http_client=http_client,
            )

            self.assertEqual(len(report["probes"]), 10)
            self.assertIsNone(report["probes"][0]["status_code"])
            self.assertIn("probe timed out", report["probes"][0]["error"])
            self.assertEqual(report["probes"][1]["status_code"], 403)
            self.assertIsNone(report["probes"][1]["error"])
            self.assertEqual(report["summary"]["successful_probes"], 9)
            self.assertEqual(report["summary"]["failed_probes"], 1)

    def test_new_artifacts_are_detected_by_before_after_directory_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            hook_coverage_dir = root / "hook-coverage"
            requests_dir = hook_coverage_dir / "requests"
            requests_dir.mkdir(parents=True)
            (requests_dir / "existing.json").write_text("{}", encoding="utf-8")
            http_client = FakeHttpClient([200] * 10, artifact_dir=requests_dir)

            report = run_bootstrap_probes(
                base_url="http://web",
                hook_coverage_dir=hook_coverage_dir,
                timeout=5,
                sleep_between_probes=0,
                http_client=http_client,
            )

            self.assertEqual(list_request_artifacts(hook_coverage_dir)[0], "requests/existing.json")
            self.assertEqual(report["probes"][0]["new_request_artifacts"], ["requests/req-0.json"])
            all_new_artifacts = [
                artifact
                for probe in report["probes"]
                for artifact in probe["new_request_artifacts"]
            ]
            self.assertNotIn("requests/existing.json", all_new_artifacts)

    def test_probe_requests_include_hookphuzz_headers_and_xmlrpc_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            http_client = FakeHttpClient([200] * 10)

            run_bootstrap_probes(
                base_url="http://web/",
                hook_coverage_dir=Path(tmp_dir) / "hook-coverage",
                timeout=7,
                sleep_between_probes=0,
                http_client=http_client,
            )

            first_call = http_client.calls[0]
            self.assertEqual(first_call["url"], "http://web/")
            self.assertEqual(first_call["headers"]["X-HookPhuzz-Probe-ID"], "bootstrap-01-frontend_home")
            self.assertEqual(first_call["headers"]["X-HookPhuzz-Probe-Name"], "frontend_home")
            self.assertEqual(first_call["headers"]["X-Fuzzer-Covid"], "bootstrap-01-frontend_home")
            self.assertEqual(first_call["timeout"], 7)

            xmlrpc_call = http_client.calls[8]
            self.assertEqual(xmlrpc_call["method"], "POST")
            self.assertEqual(xmlrpc_call["url"], "http://web/xmlrpc.php")
            self.assertEqual(xmlrpc_call["headers"]["Content-Type"], "text/xml")
            self.assertIn("<methodCall>", xmlrpc_call["data"])


if __name__ == "__main__":
    unittest.main()
