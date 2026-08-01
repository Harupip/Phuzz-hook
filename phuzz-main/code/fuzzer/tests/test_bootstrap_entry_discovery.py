from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy import bootstrap_entry_discovery as bed


def registered_callback(hook_name: str, callback_id: str) -> dict:
    return {
        "callback_id": callback_id,
        "hook_name": hook_name,
        "callback_repr": f"{hook_name}_handler",
    }


def child_registered_callback() -> dict:
    child = registered_callback("wp_ajax_nopriv_hookphuzz_level2", "cb-level2")
    child.update(
        {
            "registered_inside_callback": True,
            "hook_level": 1,
            "parent_hook_name": "wp_ajax_nopriv_hookphuzz_level1",
            "parent_callback_id": "cb-level1",
            "parent_callback_repr": "hookphuzz_level1",
            "registration_stack_depth": 1,
            "parent_callback": {
                "hook_name": "wp_ajax_nopriv_hookphuzz_level1",
                "callback_id": "cb-level1",
                "stable_id": "stable-level1",
                "runtime_id": "runtime-level1",
                "callback_repr": "hookphuzz_level1",
                "function_name": "hookphuzz_level1",
                "class_name": None,
                "method_name": None,
                "source_file": "/var/www/html/wp-content/plugins/demo/plugin.php",
                "source_line": 10,
                "hook_level": 0,
            },
        }
    )
    return child


class BootstrapEntryDiscoveryTests(unittest.TestCase):
    def test_uopz_instrumentation_hooks_register_rest_route(self) -> None:
        instrumentation = (
            FUZZER_DIR.parent / "web" / "instrumentation" / "hook_coverage" / "uopz_hook_wp.php"
        ).read_text(encoding="utf-8")

        self.assertIn("__uopz_register_rest_route", instrumentation)
        self.assertIn("__uopz_record_rest_callback_invocation", instrumentation)
        self.assertIn("__uopz_try_hook_function('register_rest_route'", instrumentation)
        self.assertIn("['entrypoint_type'] = 'rest_route'", instrumentation)

    def test_pipeline_runs_with_mocked_probe_classifier_and_validator(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            hook_coverage_dir = root / "hook-coverage"
            hook_coverage_dir.mkdir()
            registry = hook_coverage_dir / "total_coverage.json"
            registry.write_text(
                json.dumps(
                    {
                        "data": {
                            "registered_callbacks": {
                                "cb-public": registered_callback("wp_ajax_nopriv_abc", "cb-public")
                            },
                            "executed_callbacks": {},
                            "blindspot_callbacks": {},
                        }
                    }
                ),
                encoding="utf-8",
            )

            def fake_probes(**_kwargs):
                return {
                    "schema_version": 1,
                    "probes": [{"probe_id": "probe-1", "new_request_artifacts": ["requests/req.json"]}],
                    "summary": {"artifacts_created": 1},
                }

            def fake_validator(**kwargs):
                candidate = kwargs["candidate"]
                return {
                    "candidate_id": candidate["candidate_id"],
                    "hook_name": candidate["hook_name"],
                    "result": {"expected_hook_fired": True, "expected_callback_reached": True},
                }

            with mock.patch.object(bed.bootstrap_probe_runner, "run_bootstrap_probes", side_effect=fake_probes):
                with mock.patch.object(bed.seed_validator, "validate_candidate", side_effect=fake_validator):
                    report = bed.run_discovery_pipeline(
                        base_url="http://web",
                        hook_coverage_dir=hook_coverage_dir,
                        output_dir=root / "out",
                        coverage_file=None,
                        max_validate=5,
                        timeout=1,
                        pretty=True,
                    )

            out = root / "out"
            self.assertTrue((out / "bootstrap_probe_report.json").exists())
            self.assertTrue((out / "runtime_hook_registry.json").exists())
            self.assertTrue((out / "entrypoint_candidates.json").exists())
            self.assertTrue((out / "direct_http_candidates.json").exists())
            self.assertFalse((out / "generated_phuzz_configs" / "cb-public.json").exists())
            self.assertFalse((out / "validation_results" / "cb-public.validation_result.json").exists())
            self.assertTrue((out / "bootstrap_entry_discovery_report.json").exists())
            self.assertEqual(report["counts"]["generated_phuzz_configs"], 0)
            self.assertEqual(report["counts"]["validated_candidates"], 0)
            self.assertEqual(report["counts"]["expected_hook_fired"], 0)
            self.assertEqual(report["counts"]["expected_callback_reached"], 0)

    def test_validation_selection_prefers_unauthenticated_candidates_and_respects_limit(self) -> None:
        candidates = [
            {"candidate_id": "auth-ajax", "hook_name": "wp_ajax_abc"},
            {"candidate_id": "public-post", "hook_name": "admin_post_nopriv_save"},
            {"candidate_id": "public-heartbeat", "hook_name": "heartbeat_nopriv_received"},
            {"candidate_id": "auth-action", "hook_name": "admin_action_export"},
        ]

        selected = bed.select_candidates_for_validation(candidates, max_validate=2)

        self.assertEqual([item["candidate_id"] for item in selected], ["public-post", "public-heartbeat"])

    def test_final_report_has_paths_counts_limitations_and_no_live_queue_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            artifacts = bed.PipelineArtifacts(
                bootstrap_probe_report=root / "bootstrap_probe_report.json",
                runtime_hook_registry=root / "runtime_hook_registry.json",
                entrypoint_candidates=root / "entrypoint_candidates.json",
                direct_http_candidates=root / "direct_http_candidates.json",
                setup_required_candidates=root / "setup_required_candidates.json",
                non_entry_hooks=root / "non_entry_hooks.json",
                generated_phuzz_configs_dir=root / "generated_phuzz_configs",
                validation_results_dir=root / "validation_results",
            )
            report = bed.build_final_report(
                base_url="http://web",
                started_at="start",
                finished_at="finish",
                output_dir=root,
                artifacts=artifacts,
                bootstrap_report={"probes": [1], "summary": {"artifacts_created": 2}},
                runtime_registry={"registered_callbacks": [1, 2], "executed_callbacks": [1]},
                classification_report={
                    "counts": {"direct_http": 1, "setup_required": 1, "non_entry": 1},
                    "candidates": [{"candidate_id": "cb-public"}],
                },
                generated_configs=[{"candidate_id": "cb-public", "path": root / "generated_phuzz_configs" / "cb-public.json"}],
                validation_summaries=[
                    {
                        "candidate_id": "cb-public",
                        "hook_name": "wp_ajax_nopriv_abc",
                        "entry_type": "ajax_unauthenticated",
                        "config_file": root / "generated_phuzz_configs" / "cb-public.json",
                        "validation_file": root / "validation_results" / "cb-public.validation_result.json",
                        "expected_hook_fired": True,
                        "expected_callback_reached": False,
                    }
                ],
            )

            self.assertIn("bootstrap_probe_report", report["artifacts"])
            self.assertEqual(report["counts"]["probes"], 1)
            self.assertEqual(report["counts"]["probe_artifacts"], 2)
            self.assertEqual(report["counts"]["generated_phuzz_configs"], 1)
            self.assertEqual(report["counts"]["expected_hook_fired"], 1)
            self.assertEqual(report["counts"]["expected_callback_reached"], 0)
            limitations = " ".join(report["limitations"]).lower()
            self.assertIn("not auto-imported", limitations)
            self.assertNotIn("live queue integration", limitations)

    def test_request_artifact_fallback_creates_runtime_registry_when_total_coverage_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            requests_dir = root / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            (requests_dir / "req-1.json").write_text(
                json.dumps(
                    {
                        "hook_coverage": {
                            "registered_callbacks": {
                                "cb-public": registered_callback("wp_ajax_nopriv_abc", "cb-public")
                            },
                            "executed_callbacks": {},
                            "blindspot_callbacks": {},
                        }
                    }
                ),
                encoding="utf-8",
            )

            registry_path = bed.resolve_runtime_registry(None, root / "hook-coverage", root / "out", pretty=True)
            registry = json.loads(registry_path.read_text(encoding="utf-8"))

            self.assertEqual(registry["source"], "request_artifacts")
            self.assertEqual(len(registry["registered_callbacks"]), 1)
            self.assertEqual(registry["registered_callbacks"][0]["callback_id"], "cb-public")

    def test_bootstrap_entry_discovery_preserves_parent_callback_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            requests_dir = root / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            (requests_dir / "req-1.json").write_text(
                json.dumps(
                    {
                        "hook_coverage": {
                            "registered_callbacks": {"cb-level2": child_registered_callback()},
                            "executed_callbacks": {},
                            "blindspot_callbacks": {},
                        }
                    }
                ),
                encoding="utf-8",
            )

            registry_path = bed.resolve_runtime_registry(None, root / "hook-coverage", root / "out", pretty=True)
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            child = registry["data"]["registered_callbacks"]["cb-level2"]

            self.assertTrue(child["registered_inside_callback"])
            self.assertEqual(child["hook_level"], 1)
            self.assertEqual(child["parent_callback_id"], "cb-level1")
            self.assertEqual(child["parent_callback"]["hook_name"], "wp_ajax_nopriv_hookphuzz_level1")

    def test_request_artifact_fallback_preserves_rest_route_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            requests_dir = root / "hook-coverage" / "requests"
            requests_dir.mkdir(parents=True)
            rest_entry = {
                "callback_id": "cb-rest",
                "hook_name": "rest_route:demo/v1/items",
                "entrypoint_type": "rest_route",
                "namespace": "demo/v1",
                "route": "/items",
                "methods": ["GET", "POST"],
                "callback_repr": "Demo_Rest::items",
                "permission_callback": "__return_true",
                "source_file": "/var/www/html/wp-content/plugins/demo/rest.php",
                "start_line": 12,
            }
            (requests_dir / "req-1.json").write_text(
                json.dumps(
                    {
                        "hook_coverage": {
                            "registered_callbacks": {"cb-rest": rest_entry},
                            "executed_callbacks": {},
                            "blindspot_callbacks": {},
                        }
                    }
                ),
                encoding="utf-8",
            )

            registry_path = bed.resolve_runtime_registry(None, root / "hook-coverage", root / "out", pretty=True)
            registry = json.loads(registry_path.read_text(encoding="utf-8"))
            rest = registry["data"]["registered_callbacks"]["cb-rest"]

            self.assertEqual(rest["entrypoint_type"], "rest_route")
            self.assertEqual(rest["namespace"], "demo/v1")
            self.assertEqual(rest["route"], "/items")
            self.assertEqual(rest["methods"], ["GET", "POST"])
            self.assertEqual(rest["callback_repr"], "Demo_Rest::items")
            self.assertEqual(rest["permission_callback"], "__return_true")
            self.assertEqual(rest["source_file"], "/var/www/html/wp-content/plugins/demo/rest.php")
            self.assertEqual(rest["start_line"], 12)


if __name__ == "__main__":
    unittest.main()
