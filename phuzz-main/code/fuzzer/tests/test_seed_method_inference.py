from __future__ import annotations

import json
import importlib.util
import sys
import tempfile
import threading
import types
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import requests

for optional_module in ("bleach", "esprima"):
    if optional_module not in sys.modules:
        sys.modules[optional_module] = types.ModuleType(optional_module)
if "bs4" not in sys.modules:
    bs4 = types.ModuleType("bs4")
    bs4.BeautifulSoup = object
    bs4.element = types.SimpleNamespace(Tag=object)
    sys.modules["bs4"] = bs4

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from candidate import Candidate
from hook_energy.seed_generation.config_exporter import build_config_for_seed_item
from hook_energy.seed_generation.generator import LiveHookSeedGenerator
from hook_energy.seed_generation.importer import HookSeedImporter
from hook_energy.seed_validator import build_validation_request

_fuzzer_spec = importlib.util.spec_from_file_location("_hookphuzz_fuzzer", FUZZER_DIR / "fuzzer.py")
assert _fuzzer_spec and _fuzzer_spec.loader
_fuzzer_module = importlib.util.module_from_spec(_fuzzer_spec)
_fuzzer_spec.loader.exec_module(_fuzzer_module)
Fuzzer = _fuzzer_module.Fuzzer


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "seed_method_fixture.php"


def fixture_payload() -> dict:
    callbacks = {}

    def add(callback_id: str, hook_name: str, start_line: int, end_line: int, **extra) -> None:
        callbacks[callback_id] = {
            "callback_id": callback_id,
            "hook_name": hook_name,
            "callback_repr": callback_id,
            "source_file": str(FIXTURE),
            "start_line": start_line,
            "end_line": end_line,
            "is_active": True,
            **extra,
        }

    add("get-only", "wp_ajax_fixture_get", 3, 5)
    add("post-only", "wp_ajax_nopriv_fixture_post", 7, 9)
    add("request-only", "admin_post_fixture_request", 11, 13)
    add("mixed", "admin_post_nopriv_fixture_mixed", 15, 17)
    add("cookie-only", "wp_ajax_fixture_cookie", 19, 21)
    for method, route in (
        ("GET", "get"),
        ("POST", "post"),
        ("PUT", "put"),
        ("PATCH", "patch"),
        ("DELETE", "delete"),
        ("OPTIONS", "options"),
        ("GET,POST", "multi"),
    ):
        add(
            f"rest-{route}",
            f"rest_route:fixture/v1/{route}",
            23,
            25,
            entrypoint_type="rest_route",
            namespace="fixture/v1",
            route=f"/{route}",
            methods=method.split(","),
            permission_callback="__return_true",
        )
    return {"data": {"registered_callbacks": callbacks, "executed_callbacks": {}}}


class MethodInferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.gap, self.report = LiveHookSeedGenerator().build_reports(fixture_payload())
        self.rows = self.report["suggested_seeds"]

    def seeds(self, callback_id: str) -> list[dict]:
        return [row["seed"] for row in self.rows if row["callback_id"] == callback_id]

    def test_fixture_expands_methods_and_records_provenance(self) -> None:
        methods = Counter(row["seed"]["method"] for row in self.rows)
        sources = Counter(row["seed"]["method_source"] for row in self.rows)

        self.assertEqual(
            methods,
            {"GET": 5, "POST": 6, "PUT": 1, "PATCH": 1, "DELETE": 1, "OPTIONS": 1},
        )
        self.assertEqual(
            sources,
            {
                "rest_declaration": 8,
                "parameter_source": 4,
                "ambiguous_request_expansion": 2,
                "fallback": 1,
            },
        )
        self.assertEqual(self.report["schema_version"], "hook-seed-suggestions-v2")

    def test_direct_parameter_placement_follows_each_variant(self) -> None:
        get_seed = self.seeds("get-only")[0]
        post_seed = self.seeds("post-only")[0]
        request = {seed["method"]: seed for seed in self.seeds("request-only")}
        mixed = {seed["method"]: seed for seed in self.seeds("mixed")}
        cookie = self.seeds("cookie-only")[0]

        self.assertEqual(get_seed["query_params"], {"action": "fixture_get", "id": "FUZZ"})
        self.assertEqual(post_seed["body"], {"action": "fixture_post", "id": "FUZZ"})
        self.assertEqual(request["GET"]["query_params"]["id"], "FUZZ")
        self.assertEqual(request["POST"]["body"]["id"], "FUZZ")
        self.assertEqual(mixed["GET"]["query_params"]["a"], "FUZZ")
        self.assertEqual(mixed["POST"]["body"]["b"], "FUZZ")
        self.assertEqual(cookie["cookies"], {"session": "FUZZ"})
        self.assertEqual(cookie["method_source"], "fallback")
        self.assertIsNone(cookie["method_evidence"])

    def test_rest_multi_method_becomes_distinct_seed_and_config_rows(self) -> None:
        seeds = self.seeds("rest-multi")
        self.assertEqual([seed["method"] for seed in seeds], ["GET", "POST"])
        items = [row for row in self.rows if row["callback_id"] == "rest-multi"]
        configs = [build_config_for_seed_item(item) for item in items]
        self.assertEqual([slug for slug, _ in configs], [
            "rest_route_fixture_v1_multi-rest-multi-get",
            "rest_route_fixture_v1_multi-rest-multi-post",
        ])
        self.assertEqual([config["methods"] for _, config in configs], [["GET"], ["POST"]])
        self.assertTrue(all("headers" not in config for _, config in configs))

    def test_rest_method_strings_expand_like_resolved_wp_constants(self) -> None:
        decisions = LiveHookSeedGenerator()._method_decisions(
            "rest_route:fixture/v1/edit",
            {"entrypoint_type": "rest_route", "methods": "POST, PUT|PATCH"},
            [],
        )
        self.assertEqual([item["method"] for item in decisions], ["POST", "PUT", "PATCH"])

    def test_correlated_runtime_method_outranks_parameter_source(self) -> None:
        metadata = {
            "callback_id": "cb",
            "hook_name": "wp_ajax_runtime",
            "callback_repr": "runtime_callback",
            "_executed_callback": {
                "callback_id": "cb",
                "hook_name": "wp_ajax_runtime",
                "callback_repr": "runtime_callback",
                "request_id": "req-1",
                "http_method": "PUT",
                "target_plugin": "fixture",
            },
        }
        decisions = LiveHookSeedGenerator()._method_decisions(
            "wp_ajax_runtime", metadata, [{"source": "POST", "name": "id"}]
        )
        self.assertEqual(decisions[0]["method"], "PUT")
        self.assertEqual(decisions[0]["method_source"], "runtime_observed")
        self.assertEqual(decisions[0]["method_evidence"]["request_id"], "req-1")

    def test_method_report_counts_expanded_callbacks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            LiveHookSeedGenerator().write_artifacts(fixture_payload(), Path(tmp_dir))
            report = json.loads((Path(tmp_dir) / "method_inference_report.json").read_text())
        self.assertEqual(report["total_seeds"], 15)
        self.assertEqual(report["fallback"], 1)
        self.assertEqual(report["unresolved"], 0)
        self.assertEqual(report["expanded_variants"], 3)

    def test_importer_prefers_v2_suggestions_and_reads_v1_without_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            gap_path = root / "hook_gap_report.json"
            seed_path = root / "suggested_seeds.json"
            gap_path.write_text(json.dumps(self.gap), encoding="utf-8")
            seed_path.write_text(json.dumps(self.report), encoding="utf-8")
            importer = HookSeedImporter(
                handoff_doc=root / "handoff.md",
                hook_gap_report=gap_path,
                suggested_seeds=seed_path,
            )
            imported = importer.import_from_handoff()
            self.assertEqual(
                len(imported.authenticated_queue) + len(imported.unauthenticated_queue),
                15,
            )
            self.assertIn("ambiguous_request_expansion", {
                item.method_source
                for item in imported.authenticated_queue + imported.unauthenticated_queue
            })

            legacy = self.gap["callbacks"][0]
            legacy["seed"].pop("method_source", None)
            legacy["seed"].pop("method_confidence", None)
            legacy["seed"].pop("method_evidence", None)
            seed_path.write_text(json.dumps({"suggested_seeds": []}), encoding="utf-8")
            gap_path.write_text(json.dumps({"callbacks": [legacy], "summary": {}}), encoding="utf-8")
            legacy_result = importer.import_from_handoff()
            old = (legacy_result.authenticated_queue + legacy_result.unauthenticated_queue)[0]
            self.assertEqual(old.method_source, "legacy_artifact")
            self.assertEqual(old.method_confidence, "low")
            self.assertIsNone(old.method_evidence)

    def test_candidate_hash_distinguishes_method_and_placement(self) -> None:
        def candidate(method: str, query: dict, body: dict) -> Candidate:
            return Candidate(
                http_target="http://example.test/wp-admin/admin-ajax.php",
                http_method=method,
                fixed_params={"query_params": query, "body_params": body},
                fuzz_params={"query_params": {}, "body_params": {}},
            )

        self.assertNotEqual(
            candidate("GET", {"id": "1"}, {}).get_params_hash(),
            candidate("POST", {}, {"id": "1"}).get_params_hash(),
        )
        self.assertNotEqual(
            candidate("POST", {"id": "1"}, {}).get_params_hash(),
            candidate("POST", {}, {"id": "1"}).get_params_hash(),
        )

    def test_validator_preserves_patch_and_delete_body_methods(self) -> None:
        for method in ("PUT", "PATCH", "DELETE"):
            request = build_validation_request(
                {
                    "http_template": {
                        "method": method,
                        "path": "/fixture",
                        "body_params": {"id": method.lower()},
                    }
                },
                base_url="http://web",
                validation_id="validation",
            )
            self.assertEqual(request["method"], method)
            self.assertEqual(request["data"], {"id": method.lower()})


class RequestPreparationIntegrationTests(unittest.TestCase):
    def test_real_requests_keep_method_query_and_form_body(self) -> None:
        received = []

        class Handler(BaseHTTPRequestHandler):
            def _capture(self) -> None:
                size = int(self.headers.get("Content-Length", "0"))
                received.append(
                    {
                        "method": self.command,
                        "query": parse_qs(urlsplit(self.path).query),
                        "body": parse_qs(self.rfile.read(size).decode()),
                    }
                )
                self.send_response(204)
                self.end_headers()

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _capture

            def log_message(self, *_args) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for method, query, body in (
                ("GET", {"id": "get"}, {}),
                ("POST", {}, {"id": "post"}),
                ("PUT", {}, {"id": "put"}),
                ("PATCH", {}, {"id": "patch"}),
                ("DELETE", {"id": "delete"}, {}),
            ):
                candidate = Candidate(
                    http_target=f"http://127.0.0.1:{server.server_port}/fixture",
                    http_method=method,
                    fixed_params={
                        "query_params": query,
                        "body_params": body,
                        "cookies": {},
                        "headers": {},
                    },
                    fuzz_params={
                        "query_params": {},
                        "body_params": {},
                        "cookies": {},
                        "headers": {},
                    },
                )
                prepared = Fuzzer.prepare_request(None, candidate)
                response = requests.Session().send(prepared, timeout=5)
                self.assertEqual(response.status_code, 204)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            server.server_close()

        self.assertEqual([item["method"] for item in received], ["GET", "POST", "PUT", "PATCH", "DELETE"])
        self.assertEqual(received[0]["query"], {"id": ["get"]})
        self.assertEqual(received[1]["body"], {"id": ["post"]})
        self.assertEqual(received[2]["body"], {"id": ["put"]})
        self.assertEqual(received[3]["body"], {"id": ["patch"]})
        self.assertEqual(received[4]["query"], {"id": ["delete"]})


if __name__ == "__main__":
    unittest.main()
