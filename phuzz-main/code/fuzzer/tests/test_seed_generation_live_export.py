from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from seed_generation.pipeline.pipeline import run_entrypoint_pipeline
from seed_generation.source_assisted.static_generator import StaticSeedGenerator
from seed_generation.skeleton.candidate_generator import ZendRuntimeSeedGenerator


def build_live_coverage_payload() -> dict:
    return {
        "schema_version": "uopz-total-coverage-v3",
        "metadata": {
            "total_registered_callbacks": 4,
            "total_executed_callbacks": 2,
            "coverage_percent": "50%",
        },
        "data": {
            "registered_callbacks": {
                "cb-admin-menu": {
                    "callback_id": "cb-admin-menu",
                    "hook_name": "admin_menu",
                    "callback_repr": "bt_comments_create_menu",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 11,
                    "is_active": True,
                    "status": "registered_only",
                },
                "cb-auth": {
                    "callback_id": "cb-auth",
                    "hook_name": "wp_ajax_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 551,
                    "is_active": True,
                    "status": "covered",
                },
                "cb-unauth": {
                    "callback_id": "cb-unauth",
                    "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 551,
                    "is_active": True,
                    "status": "registered_only",
                },
                "cb-enqueue": {
                    "callback_id": "cb-enqueue",
                    "hook_name": "wp_enqueue_scripts",
                    "callback_repr": "sac_wp_enqueue_styles_and_scripts",
                    "type": "action",
                    "priority": 10,
                    "accepted_args": 1,
                    "source_file": "/var/www/html/wp-content/plugins/show-all-comments-in-one-page/bt-comments.php",
                    "source_line": 603,
                    "is_active": True,
                    "status": "covered",
                },
            },
            "executed_callbacks": {
                "cb-auth": {
                    "callback_id": "cb-auth",
                    "hook_name": "wp_ajax_sac_post_type_call",
                    "callback_repr": "sac_post_type_call_callback",
                    "executed_count": 5,
                },
                "cb-enqueue": {
                    "callback_id": "cb-enqueue",
                    "hook_name": "wp_enqueue_scripts",
                    "callback_repr": "sac_wp_enqueue_styles_and_scripts",
                    "executed_count": 1,
                },
            },
            "blindspot_callbacks": {
                "cb-admin-menu": {
                    "callback_id": "cb-admin-menu",
                    "hook_name": "admin_menu",
                },
                "cb-unauth": {
                    "callback_id": "cb-unauth",
                    "hook_name": "wp_ajax_nopriv_sac_post_type_call",
                },
            },
        },
    }


def build_rest_probe_payload(source_root: Path, *, schema_name: str = "id", schema_type: str = "integer") -> dict:
    rest_probe = source_root / "rest-probe.php"
    rest_probe.write_text(
        "\n".join(
            [
                "<?php",
                "function learnpress_rest_probe($request) {",
                f"    if (isset($request['{schema_name}'])) {{",
                f"        return $request['{schema_name}'];",
                "    }",
                "    return null;",
                "}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "data": {
            "registered_callbacks": {
                "cb-rest-probe": {
                    "callback_id": "cb-rest-probe",
                    "entrypoint_type": "rest_route",
                    "hook_name": "rest_route:learnpress/v1/items",
                    "callback_repr": "learnpress_rest_probe",
                    "namespace": "learnpress/v1",
                    "route": "/items",
                    "methods": ["POST"],
                    "permission_callback": "__return_true",
                    "argument_definitions": {
                        schema_name: {"type": schema_type, "required": False},
                    },
                    "input_params": [
                        {"name": schema_name, "source": "REST_ARRAY_ACCESS", "location": "unknown"}
                    ],
                    "source_file": str(rest_probe),
                    "start_line": 2,
                    "end_line": 7,
                    "is_active": True,
                }
            },
            "executed_callbacks": {},
        }
    }


class SeedGeneratorTests(unittest.TestCase):
    def test_zend_runtime_generator_uses_exact_admin_post_runtime_probe_evidence(self) -> None:
        payload = build_live_coverage_payload()
        payload["data"]["registered_callbacks"].update({
            "cb-admin-post": {
                "callback_id": "cb-admin-post",
                "hook_name": "admin_post_hookphuzz_admin_post_test",
                "callback_repr": "hookphuzz_admin_post_test",
                "source_file": "/var/www/html/wp-content/plugins/hp-ap/hp-ap.php",
                "request_id": "registration-request",
                "is_active": True,
            },
            "cb-ambiguous": {
                "callback_id": "cb-ambiguous",
                "hook_name": "admin_post_unrelated_action",
                "callback_repr": "unrelated_admin_post",
                "source_file": "/var/www/html/wp-content/plugins/hp-ap/hp-ap.php",
                "is_active": True,
            },
        })
        payload["data"]["executed_callbacks"]["cb-admin-post"] = {
            "callback_id": "cb-admin-post",
            "hook_name": "admin_post_hookphuzz_admin_post_test",
            "fired_hook": "admin_post_hookphuzz_admin_post_test",
            "callback_repr": "hookphuzz_admin_post_test",
            "executed_count": 1,
            "request_id": "admin-post-fixture-probe",
            "http_method": "POST",
            "target_plugin": "hp-ap",
            "endpoint": "ADMIN_POST:hookphuzz_admin_post_test",
        }

        _, seed_report = ZendRuntimeSeedGenerator().build_reports(payload)
        by_hook = {row["hook_name"]: row for row in seed_report["suggested_seeds"]}

        fixture = by_hook["admin_post_hookphuzz_admin_post_test"]
        self.assertEqual(fixture["seed"]["method"], "POST")
        self.assertEqual(fixture["seed"]["body"], {"action": "hookphuzz_admin_post_test"})
        self.assertEqual(fixture["seed"]["method_source"], "runtime_observed")
        self.assertEqual(by_hook["admin_post_unrelated_action"]["generation_status"], "ambiguous_http_method")
        self.assertIsNone(by_hook["admin_post_unrelated_action"]["seed"]["method"])

    def test_zend_runtime_generator_rejects_mismatched_admin_post_action_evidence(self) -> None:
        payload = build_live_coverage_payload()
        payload["data"]["registered_callbacks"]["cb-admin-post"] = {
            "callback_id": "cb-admin-post",
            "hook_name": "admin_post_hookphuzz_admin_post_test",
            "callback_repr": "hookphuzz_admin_post_test",
            "source_file": "/var/www/html/wp-content/plugins/hp-ap/hp-ap.php",
            "is_active": True,
        }
        payload["data"]["executed_callbacks"]["cb-admin-post"] = {
            "callback_id": "cb-admin-post",
            "hook_name": "admin_post_hookphuzz_admin_post_test",
            "fired_hook": "admin_post_other_action",
            "callback_repr": "hookphuzz_admin_post_test",
            "executed_count": 1,
            "request_id": "admin-post-fixture-probe",
            "http_method": "POST",
            "target_plugin": "hp-ap",
            "endpoint": "ADMIN_POST:other_action",
        }

        _, seed_report = ZendRuntimeSeedGenerator().build_reports(payload)

        self.assertNotIn(
            "admin_post_hookphuzz_admin_post_test",
            {row["hook_name"] for row in seed_report["suggested_seeds"]},
        )

    def test_zend_runtime_generator_is_source_free(self) -> None:
        runtime_source = (
            Path(__file__).resolve().parents[1]
            / "hook_energy"
            / "seed_generation"
            / "zend_runtime"
            / "candidate_generator.py"
        ).read_text(encoding="utf-8")

        self.assertNotIn("InputSignatureExtractor", runtime_source)
        self.assertNotIn("SourcePathResolver", runtime_source)

    def test_zend_runtime_generator_skips_source_extraction_and_builds_post_action_probe(self) -> None:
        _, seed_report = ZendRuntimeSeedGenerator().build_reports(build_live_coverage_payload())

        item = next(
            row for row in seed_report["suggested_seeds"]
            if row["hook_name"] == "wp_ajax_nopriv_sac_post_type_call"
        )
        self.assertEqual(item["seed"]["method"], "POST")
        self.assertEqual(item["seed"]["body"], {"action": "sac_post_type_call"})
        self.assertEqual(item["seed"]["fuzzable_params"], [])
        self.assertEqual(item["seed"]["input_params"], [])

    def test_zend_runtime_generator_reuses_ajax_post_rule_for_heartbeat_hooks(self) -> None:
        payload = build_live_coverage_payload()
        payload["data"]["registered_callbacks"].update({
            "cb-heartbeat": {
                "callback_id": "cb-heartbeat",
                "hook_name": "heartbeat_received",
                "callback_repr": "private_heartbeat",
                "source_file": "/var/www/html/wp-content/plugins/fixture/fixture.php",
                "is_active": True,
            },
            "cb-heartbeat-nopriv": {
                "callback_id": "cb-heartbeat-nopriv",
                "hook_name": "heartbeat_nopriv_received",
                "callback_repr": "public_heartbeat",
                "source_file": "/var/www/html/wp-content/plugins/fixture/fixture.php",
                "is_active": True,
            },
        })

        _, seed_report = ZendRuntimeSeedGenerator().build_reports(payload)
        by_hook = {row["hook_name"]: row for row in seed_report["suggested_seeds"]}

        for hook_name in ("heartbeat_received", "heartbeat_nopriv_received"):
            item = by_hook[hook_name]
            self.assertEqual(item["generation_status"], "supported_http_seed")
            self.assertEqual(item["seed"]["method"], "POST")
            self.assertEqual(item["seed"]["resolved_method"], "POST")
            self.assertEqual(item["seed"]["method_confidence"], "runtime_probe")

    def test_generator_derives_direct_http_seed_and_manual_only_entries(self) -> None:
        generator = StaticSeedGenerator()

        gap_report, seed_report = generator.build_reports(build_live_coverage_payload())

        self.assertEqual(gap_report["summary"]["registered_callbacks"], 4)
        self.assertEqual(gap_report["summary"]["uncovered_callbacks"], 2)
        self.assertEqual(gap_report["summary"]["direct_http_seed_candidates"], 1)
        self.assertEqual(seed_report["summary"]["suggested_entries"], 2)
        self.assertEqual(seed_report["summary"]["direct_http_seed_candidates"], 1)
        self.assertEqual(seed_report["summary"]["manual_only_entries"], 1)

        direct_seed = next(
            item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call"
        )
        self.assertEqual(direct_seed["generation_status"], "ambiguous_http_method")
        self.assertIsNone(direct_seed["seed"]["method"])
        self.assertEqual(direct_seed["seed"]["candidate_methods"], [])
        self.assertEqual(direct_seed["seed"]["path"], "/wp-admin/admin-ajax.php")
        self.assertEqual(direct_seed["seed"]["unresolved_params"], {"action": "sac_post_type_call"})
        self.assertEqual(direct_seed["seed"]["auth_mode"], "unauth-capable")

        manual_only = next(item for item in seed_report["suggested_seeds"] if item["hook_name"] == "admin_menu")
        self.assertEqual(manual_only["generation_status"], "manual_analysis_required")
        self.assertNotIn("seed", manual_only)

    def test_generator_writes_seed_artifacts_without_import_queues(self) -> None:
        generator = StaticSeedGenerator()

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir)
            generator.write_artifacts(build_live_coverage_payload(), output_dir)

            self.assertTrue((output_dir / "hook_gap_report.json").exists())
            self.assertTrue((output_dir / "suggested_seeds.json").exists())
            self.assertTrue((output_dir / "suggested_seeds.md").exists())
            self.assertFalse((output_dir / "imported_auth_seeds.json").exists())
            self.assertFalse((output_dir / "imported_unauth_seeds.json").exists())
            self.assertFalse((output_dir / "manual_analysis_queue.json").exists())

            suggested = json.loads((output_dir / "suggested_seeds.json").read_text(encoding="utf-8"))
            self.assertEqual(suggested["summary"]["direct_http_seed_candidates"], 1)

    def test_generator_adds_extracted_fuzzable_params_to_direct_seed(self) -> None:
        source = "\n".join(
            [
                "<?php",
                "function sac_post_type_call_callback() {",
                "    $action = $_REQUEST['action'];",
                "    $orderby = sanitize_text_field($_REQUEST['orderby']);",
                "    $page = absint($_GET['page']);",
                "}",
                "",
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "bt-comments.php"
            source_file.write_text(source, encoding="utf-8")

            payload = build_live_coverage_payload()
            callback = payload["data"]["registered_callbacks"]["cb-unauth"]
            callback["source_file"] = str(source_file)
            callback["source_line"] = 2
            callback["start_line"] = 2
            callback["end_line"] = 6

            gap_report, seed_report = StaticSeedGenerator().build_reports(payload)

        callback_row = next(
            item for item in gap_report["callbacks"] if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call"
        )
        direct_seed = next(
            item["seed"]
            for item in seed_report["suggested_seeds"]
            if item["hook_name"] == "wp_ajax_nopriv_sac_post_type_call" and item["seed"]["method"] == "GET"
        )

        self.assertIn({"source": "REQUEST", "name": "orderby"}, [
            {"source": item["source"], "name": item["name"]} for item in callback_row["input_params"]
        ])
        self.assertEqual(direct_seed["query_params"]["action"], "sac_post_type_call")
        self.assertEqual(direct_seed["query_params"]["orderby"], "FUZZ")
        self.assertEqual(direct_seed["query_params"]["page"], "FUZZ")
        self.assertEqual(direct_seed["fixed_params"], ["action"])
        self.assertIn("orderby", direct_seed["fuzzable_params"])
        self.assertIn("page", direct_seed["fuzzable_params"])
        self.assertNotIn("action", direct_seed["fuzzable_params"])

    def test_generator_keeps_nonce_fixed_and_prunes_nested_parent_param(self) -> None:
        source = "\n".join(
            [
                "<?php",
                "function save_api_settings() {",
                "    check_ajax_referer('vx_nonce','vx_nonce');",
                "    if (isset($_POST['cfx_settings'])) {",
                "        if (!empty($_POST['cfx_settings']['alert_emails'])) {",
                "            $info_form['alert_emails'] = $_POST['cfx_settings']['alert_emails'];",
                "        }",
                "    }",
                "}",
                "",
            ]
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "crm.php"
            source_file.write_text(source, encoding="utf-8")

            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-crm": {
                            "callback_id": "cb-crm",
                            "hook_name": "wp_ajax_vx_form_save_api_settings",
                            "callback_repr": "cfx_form_admin_pages->save_api_settings",
                            "source_file": str(source_file),
                            "source_line": 2,
                            "start_line": 2,
                            "end_line": 9,
                            "is_active": True,
                            "status": "registered_only",
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            _, seed_report = StaticSeedGenerator().build_reports(payload)

        seed = next(item["seed"] for item in seed_report["suggested_seeds"] if item["seed"]["method"] == "POST")
        self.assertEqual(seed["body"]["action"], "vx_form_save_api_settings")
        self.assertEqual(seed["body"]["vx_nonce"], "fuzz")
        self.assertEqual(seed["body"]["cfx_settings[alert_emails]"], "FUZZ")
        self.assertNotIn("cfx_settings", seed["body"])
        self.assertIn("vx_nonce", seed["fixed_params"])
        self.assertNotIn("vx_nonce", seed["fuzzable_params"])
        self.assertEqual(seed["fuzzable_params"], ["cfx_settings[alert_emails]"])

    def test_rest_post_schema_only_id_generates_isolated_replay_only_probe_configs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            result = run_entrypoint_pipeline(
                build_rest_probe_payload(root),
                plugin_slug="learnpress-fixture",
                output_dir=root / "pipeline",
                target_base="http://web",
            )

            generated = {
                row["seed_variant_id"]: json.loads(Path(row["config_path"]).read_text(encoding="utf-8"))
                for row in result["config_summary"]["generated"]
            }
            self.assertEqual(set(generated), {"rest_probe_form_id", "rest_probe_json_id"})
            self.assertEqual(result["config_summary"]["skipped"][0]["reason"], "rest_schema_parameter_location_unknown")

            form = generated["rest_probe_form_id"]
            self.assertEqual(form["methods"], ["POST"])
            self.assertEqual(form["config_type"], "replay_only")
            self.assertEqual(form["body_params"]["data"], [{"name": "id", "value": 1}])
            self.assertEqual(form["body_params"]["fuzz"], [])
            self.assertNotIn("headers", form)

            jsn = generated["rest_probe_json_id"]
            self.assertEqual(jsn["methods"], ["POST"])
            self.assertEqual(jsn["config_type"], "replay_only")
            self.assertEqual(jsn["headers"]["data"], [{"name": "Content-Type", "value": "application/json"}])
            self.assertEqual(jsn["body_params"]["data"], [{"name": "id", "value": 1}])
            self.assertEqual(jsn["body_params"]["fuzz"], [])

    def test_rest_probe_metadata_is_redacted_and_final_seed_stays_blocked_without_runtime_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            result = run_entrypoint_pipeline(
                build_rest_probe_payload(root, schema_name="slug", schema_type="string"),
                plugin_slug="learnpress-fixture",
                output_dir=root / "pipeline",
                target_base="http://web",
            )

            final_seed = next(
                item for item in result["seed_report"]["suggested_seeds"]
                if item["callback_id"] == "cb-rest-probe" and not item["seed"].get("probe_variant")
            )
            self.assertFalse(final_seed["seed"]["export_allowed"])
            self.assertFalse(final_seed["seed"]["replay_allowed"])
            self.assertEqual(final_seed["seed"]["fuzzable_params"], [])
            self.assertNotIn("slug", final_seed["seed"].get("body", {}))

            probe_rows = {
                row["seed_variant_id"]: row for row in result["config_summary"]["generated"]
            }
            for variant_id in ("rest_probe_form_slug", "rest_probe_json_slug"):
                metadata = probe_rows[variant_id]["probe_request"]
                self.assertTrue(metadata["candidate_value_redacted"])
                self.assertNotIn("candidate_value", metadata)

            config_summary_text = (root / "pipeline" / "generated_config_summary.json").read_text(encoding="utf-8")
            param_summary_text = (root / "pipeline" / "generated_param_summary.json").read_text(encoding="utf-8")
            suggested_text = (root / "pipeline" / "suggested_seeds.json").read_text(encoding="utf-8")
            self.assertNotIn("\"candidate_value\": \"probe\"", config_summary_text)
            self.assertNotIn("\"candidate_value\": \"probe\"", param_summary_text)
            self.assertNotIn("\"candidate_value\": \"probe\"", suggested_text)
            self.assertNotIn("\"slug\": \"probe\"", suggested_text)

    def test_generator_prioritizes_nopriv_over_authenticated_hooks(self) -> None:
        generator = StaticSeedGenerator()

        auth_priority, auth_rank, _ = generator._classify_seed_priority("wp_ajax_demo", True)
        nopriv_priority, nopriv_rank, _ = generator._classify_seed_priority("wp_ajax_nopriv_demo", True)

        self.assertEqual(nopriv_priority, "highest")
        self.assertEqual(auth_priority, "high")
        self.assertGreater(nopriv_rank, auth_rank)


if __name__ == "__main__":
    unittest.main()
