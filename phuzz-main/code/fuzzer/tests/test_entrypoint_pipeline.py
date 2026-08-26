from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from seed_generation.pipeline.pipeline import _clone_probe_seed_item, run_entrypoint_pipeline


def coverage_payload(source_root: Path) -> dict:
    ajax = source_root / "ajax.php"
    ajax.write_text(
        "<?php\nfunction demo_lookup() {\n  $term = $_POST['term'];\n}\n",
        encoding="utf-8",
    )
    rest_get = source_root / "rest-get.php"
    rest_get.write_text(
        "<?php\nfunction rest_items() {\n  $term = $_GET['term'];\n}\n",
        encoding="utf-8",
    )
    rest_post = source_root / "rest-post.php"
    rest_post.write_text("<?php\nfunction rest_update() {}\n", encoding="utf-8")
    rest_bad = source_root / "rest-bad.php"
    rest_bad.write_text("<?php\nfunction rest_bad() {}\n", encoding="utf-8")
    return {
        "data": {
            "registered_callbacks": {
                "cb-ajax": {
                    "hook_name": "wp_ajax_nopriv_demo_lookup",
                    "callback_repr": "demo_lookup",
                    "source_file": str(ajax),
                    "start_line": 2,
                    "end_line": 4,
                    "is_active": True,
                },
                "cb-rest-get": {
                    "entrypoint_type": "rest_route",
                    "hook_name": "rest_route:demo/v1/items",
                    "callback_repr": "rest_items",
                    "namespace": "demo/v1",
                    "route": "/items",
                    "methods": ["GET"],
                    "permission_callback": "__return_true",
                    "argument_definitions": {"term": {"type": "string", "required": False}},
                    "source_file": str(rest_get),
                    "start_line": 2,
                    "end_line": 4,
                    "is_active": True,
                },
                "cb-rest-post": {
                    "entrypoint_type": "rest_route",
                    "hook_name": "rest_route:demo/v1/items/(?P<id>\\d+)",
                    "callback_repr": "rest_update",
                    "namespace": "demo/v1",
                    "route": "/items/(?P<id>\\d+)",
                    "methods": ["POST"],
                    "permission_callback": "__return_true",
                    "argument_definitions": {
                        "id": {"type": "integer", "required": True},
                        "payload": {"type": "string", "required": True},
                    },
                    "input_params": [{"name": "payload", "source": "JSON", "confidence": "runtime_observed"}],
                    "source_file": str(rest_post),
                    "start_line": 2,
                    "end_line": 3,
                    "is_active": True,
                },
                "cb-rest-bad": {
                    "entrypoint_type": "rest_route",
                    "hook_name": "rest_route:demo/v1/bad",
                    "callback_repr": "rest_bad",
                    "namespace": "demo/v1",
                    "route": "/bad",
                    "methods": ["POST"],
                    "permission_callback": "__return_true",
                    "argument_definitions": {"opaque": {"type": "object", "required": True}},
                    "source_file": str(rest_bad),
                    "start_line": 2,
                    "end_line": 3,
                    "is_active": True,
                },
            },
            "executed_callbacks": {},
        }
    }


def direct_fixture_payload(source_root: Path) -> dict:
    fixture = source_root / "direct.php"
    fixture.write_text(
        "\n".join(
            [
                "<?php",
                "function direct_post() {",
                "  $value = $_POST['direct_post_value'];",
                "}",
                "function direct_get() {",
                "  $value = $_GET['direct_get_value'];",
                "}",
                "function helper_only() {",
                "  $value = DirectFixtureRequest::get('helper_value');",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "metadata": {"total_registered_callbacks": 3, "total_executed_callbacks": 0},
        "data": {
            "registered_callbacks": {
                "cb-post": {
                    "hook_name": "wp_ajax_hookphuzz_entrypoint_direct_ajax",
                    "callback_repr": "direct_post",
                    "source_file": str(fixture),
                    "start_line": 2,
                    "end_line": 4,
                    "is_active": True,
                },
                "cb-get": {
                    "hook_name": "admin_post_hookphuzz_entrypoint_direct_admin",
                    "callback_repr": "direct_get",
                    "source_file": str(fixture),
                    "start_line": 5,
                    "end_line": 7,
                    "is_active": True,
                },
                "cb-helper": {
                    "hook_name": "wp_ajax_nopriv_hookphuzz_entrypoint_helper",
                    "callback_repr": "helper_only",
                    "source_file": str(fixture),
                    "start_line": 8,
                    "end_line": 10,
                    "is_active": True,
                },
            },
            "executed_callbacks": {},
        },
    }


def prepared_request_preview(config_path: Path) -> dict:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    method = config["methods"][0]
    parts = list(urlparse(config["target"]))
    query = dict(parse_qs(parts[4]))
    query = {key: values[-1] for key, values in query.items()}
    parts[4] = ""
    headers = _section(config, "headers")
    query.update(_section(config, "query_params"))
    body = _section(config, "body_params")
    if method in {"GET", "OPTIONS", "TRACE"}:
        parts[4] = urlencode(query)
        return {"method": method, "url": urlunparse(parts), "headers": headers, "body": None}
    return {
        "method": method,
        "url": urlunparse(parts) + (("?" + urlencode(query)) if query else ""),
        "headers": headers,
        "body": json.dumps(body) if headers.get("Content-Type") == "application/json" else urlencode(body),
    }


def _section(config: dict, name: str) -> dict:
    section = config.get(name, {})
    return {item["name"]: item["value"] for item in section.get("data", [])}


class EntrypointPipelineTests(unittest.TestCase):
    def test_rest_probe_preserves_fixed_fields_and_selected_transport_only(self) -> None:
        seed_item = {
            "plugin_slug": "demo-plugin",
            "entrypoint_type": "rest_route",
            "hook_name": "rest_route:demo/v1/items",
            "callback_id": "cb-rest-items",
            "route": "/items",
            "namespace": "demo/v1",
            "seed": {
                "method": "POST",
                "resolved_method": "POST",
                "path": "/wp-json/demo/v1/items",
                "body": {"action": "finish", "id": "old", "course_id": 7},
                "query_params": {"rest_route": "/demo/v1/items", "id": "old-query", "lang": "en"},
                "headers": {"X-Test-Token": "keep", "Content-Type": "application/x-www-form-urlencoded"},
                "fixed_params": ["action", "course_id"],
                "fuzzable_params": ["id"],
                "input_params": [{"name": "id", "location": "form", "fuzzable": True}],
            },
        }

        form = _clone_probe_seed_item(
            seed_item,
            seed_item["seed"],
            name="id",
            probe={
                "location": "form",
                "content_type": "application/x-www-form-urlencoded",
                "schema_type": "integer",
                "seed_variant_id": "rest_probe_form_id",
            },
        )["seed"]
        json_probe = _clone_probe_seed_item(
            seed_item,
            seed_item["seed"],
            name="id",
            probe={
                "location": "json",
                "content_type": "application/json",
                "schema_type": "integer",
                "seed_variant_id": "rest_probe_json_id",
            },
        )["seed"]

        self.assertEqual(form["body"], {"action": "finish", "course_id": 7, "id": 1})
        self.assertEqual(form["query_params"], {"rest_route": "/demo/v1/items", "lang": "en"})
        self.assertEqual(form["headers"], {"X-Test-Token": "keep", "Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(set(form["fixed_params"]), {"action", "course_id", "id"})

        json_source = json.loads(json.dumps(seed_item))
        json_source["seed"]["headers"]["Content-Type"] = "application/json"
        form_from_json = _clone_probe_seed_item(
            json_source,
            json_source["seed"],
            name="id",
            probe={
                "location": "form",
                "content_type": "application/x-www-form-urlencoded",
                "schema_type": "integer",
                "seed_variant_id": "rest_probe_form_id_from_json",
            },
        )["seed"]
        self.assertEqual(form_from_json["headers"], {
            "X-Test-Token": "keep",
            "Content-Type": "application/x-www-form-urlencoded",
        })

        headerless_source = json.loads(json.dumps(seed_item))
        headerless_source["seed"]["headers"] = {}
        headerless_form = _clone_probe_seed_item(
            headerless_source,
            headerless_source["seed"],
            name="id",
            probe={
                "location": "form",
                "content_type": "application/x-www-form-urlencoded",
                "schema_type": "integer",
                "seed_variant_id": "rest_probe_form_id_headerless",
            },
        )["seed"]
        self.assertEqual(headerless_form["headers"], {})

        self.assertEqual(json_probe["body"], {"action": "finish", "course_id": 7, "id": 1})
        self.assertEqual(json_probe["query_params"], {"rest_route": "/demo/v1/items", "lang": "en"})
        self.assertEqual(json_probe["headers"], {"X-Test-Token": "keep", "Content-Type": "application/json"})
        self.assertEqual(set(json_probe["fixed_params"]), {"action", "course_id", "id"})

    def test_pipeline_generates_ajax_rest_get_rest_post_and_skips_ambiguous_rest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            result = run_entrypoint_pipeline(
                coverage_payload(root),
                plugin_slug="demo-plugin",
                output_dir=root / "pipeline",
                target_base="http://web",
            )
            configs = root / "pipeline" / "configs"

            summary = result["pipeline_summary"]
            self.assertEqual(
                summary["summary"],
                {
                    "entrypoints": 4,
                    "registered": 4,
                    "direct_http_candidates": 4,
                    "generated": 3,
                    "skipped": 1,
                    "ambiguous_http_method": 0,
                },
            )

            ajax = json.loads((configs / "wp_ajax_nopriv_demo_lookup-cb-ajax-post.json").read_text())
            self.assertEqual(ajax["target"], "http://web/wp-admin/admin-ajax.php")
            self.assertEqual(ajax["methods"], ["POST"])
            self.assertEqual(ajax["body_params"]["fixed"], ["action"])
            self.assertEqual(ajax["body_params"]["fuzz"], ["term"])

            rest_get = json.loads((configs / "rest_route_demo_v1_items-cb-rest-get-get.json").read_text())
            self.assertEqual(rest_get["target"], "http://web/wp-json/demo/v1/items")
            self.assertEqual(rest_get["methods"], ["GET"])
            self.assertEqual(rest_get["query_params"]["fuzz"], ["term"])
            self.assertNotIn("body_params", rest_get)

            rest_post_path = configs / "rest_route_demo_v1_items_P_id_d-cb-rest-post-post.json"
            rest_post = json.loads(rest_post_path.read_text())
            self.assertEqual(rest_post["target"], "http://web/wp-json/demo/v1/items/1")
            self.assertEqual(rest_post["methods"], ["POST"])
            self.assertEqual(rest_post["headers"]["data"], [{"name": "Content-Type", "value": "application/json"}])
            self.assertEqual(rest_post["body_params"]["fuzz"], ["payload"])
            self.assertNotIn("id", json.dumps(rest_post.get("body_params", {})))
            self.assertNotIn("id", json.dumps(rest_post.get("query_params", {})))

            skipped = result["config_summary"]["skipped"][0]
            self.assertEqual(skipped["hook_name"], "rest_route:demo/v1/bad")
            self.assertEqual(skipped["reason"], "unsupported_rest_schema")
            bad_entry = next(item for item in summary["entrypoints"] if item["callback_id"] == "cb-rest-bad")
            bad_param = bad_entry["parameters"][0]
            self.assertEqual(bad_param["location"], "unknown")
            self.assertEqual(bad_param["location_candidates"], ["query", "form", "json"])

            ajax_prepared = prepared_request_preview(configs / "wp_ajax_nopriv_demo_lookup-cb-ajax-post.json")
            self.assertEqual(ajax_prepared["method"], "POST")
            self.assertEqual(ajax_prepared["url"], "http://web/wp-admin/admin-ajax.php")
            self.assertEqual(parse_qs(ajax_prepared["body"]), {"action": ["demo_lookup"], "term": ["fuzz"]})

            rest_prepared = prepared_request_preview(rest_post_path)
            self.assertEqual(rest_prepared["method"], "POST")
            self.assertEqual(rest_prepared["url"], "http://web/wp-json/demo/v1/items/1")
            self.assertEqual(rest_prepared["headers"]["Content-Type"], "application/json")
            self.assertEqual(json.loads(rest_prepared["body"]), {"payload": "fuzz"})

    def test_schema_only_non_path_rest_param_is_skipped_not_placed_in_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            payload = coverage_payload(root)
            payload["data"]["registered_callbacks"] = {
                "cb-rest-post": payload["data"]["registered_callbacks"]["cb-rest-post"]
            }
            payload["data"]["registered_callbacks"]["cb-rest-post"].pop("input_params")

            result = run_entrypoint_pipeline(
                payload,
                plugin_slug="demo-plugin",
                output_dir=root / "pipeline",
                target_base="http://web",
            )

            self.assertEqual(result["pipeline_summary"]["summary"]["generated"], 0)
            self.assertEqual(result["config_summary"]["skipped"][0]["reason"], "rest_schema_parameter_location_unknown")
            entry = result["pipeline_summary"]["entrypoints"][0]
            payload_param = next(item for item in entry["parameters"] if item["name"] == "payload")
            self.assertEqual(payload_param["location"], "unknown")
            self.assertEqual(payload_param["location_candidates"], ["query", "form", "json"])
            config_paths = sorted((root / "pipeline" / "configs").glob("*.json"))
            self.assertEqual([path.stem for path in config_paths], [
                "rest_route_demo_v1_items_P_id_d-cb-rest-post-rest_probe_form_payload",
                "rest_route_demo_v1_items_P_id_d-cb-rest-post-rest_probe_json_payload",
            ])
            for path in config_paths:
                config = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(config["config_type"], "replay_only")

    def test_minimal_pipeline_generates_direct_get_post_and_skips_helper_guessing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_dir = root / "pipeline"
            config_dir = root / "fuzzer" / "configs" / "generated-config" / "direct-fixture"
            result = run_entrypoint_pipeline(
                direct_fixture_payload(root),
                plugin_slug="direct-fixture",
                output_dir=output_dir,
                output_config_dir=config_dir,
                minimal_artifacts=True,
                target_base="http://web",
            )

            summary = result["pipeline_summary"]["summary"]
            self.assertEqual(summary["registered"], 3)
            self.assertEqual(summary["direct_http_candidates"], 3)
            self.assertEqual(summary["generated"], 2)
            self.assertEqual(summary["skipped"], 1)
            self.assertEqual(summary["ambiguous_http_method"], 1)

            generated = {item["callback_id"]: item for item in result["config_summary"]["generated"]}
            skipped = result["config_summary"]["skipped"][0]
            self.assertEqual(skipped["callback_id"], "cb-helper")
            self.assertEqual(skipped["reason"], "ambiguous_http_method")

            post_path = config_dir / (Path(generated["cb-post"]["config_slug"]).name + ".json")
            get_path = config_dir / (Path(generated["cb-get"]["config_slug"]).name + ".json")
            post_config = json.loads(post_path.read_text(encoding="utf-8"))
            get_config = json.loads(get_path.read_text(encoding="utf-8"))

            self.assertEqual(post_config["methods"], ["POST"])
            self.assertEqual(post_config["body_params"]["fuzz"], ["direct_post_value"])
            self.assertEqual(get_config["methods"], ["GET"])
            self.assertEqual(get_config["query_params"]["fuzz"], ["direct_get_value"])

            self.assertTrue((output_dir / "runtime_coverage_snapshot.json").exists())
            self.assertTrue((output_dir / "entrypoint_pipeline_summary.json").exists())
            self.assertTrue((output_dir / "generated_config_summary.json").exists())
            self.assertFalse((output_dir / "hook_gap_report.json").exists())
            self.assertFalse((output_dir / "suggested_seeds.json").exists())
            self.assertFalse((output_dir / "generated_param_summary.json").exists())


if __name__ == "__main__":
    unittest.main()
