import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.recursive_child_hook_seeds import (
    build_recursive_seed_report,
    run_recursive_child_hook_seeds,
    validate_recursive_seeds,
    write_recursive_artifacts,
)


def child(
    hook_name="wp_ajax_nopriv_child",
    callback_id="cb-child",
    *,
    hook_level=1,
    stable_id=None,
    **extra,
):
    row = {
        "hook_name": hook_name,
        "callback_id": callback_id,
        "callback_repr": callback_id,
        "stable_id": stable_id,
        "registered_inside_callback": True,
        "hook_level": hook_level,
        "parent_callback": {"callback_id": "cb-parent", "callback_repr": "parent"},
        "source_file": "/plugin/demo.php",
        "source_line": 12,
        **extra,
    }
    row.setdefault(
        "_executed_callback",
        {
            "callback_id": callback_id,
            "hook_name": hook_name,
            "callback_repr": callback_id,
            "request_id": f"req-{callback_id}",
            "http_method": "POST",
            "target_plugin": "fixture",
        },
    )
    return row


def coverage(*callbacks):
    return {
        "data": {
            "registered_callbacks": {
                f"row-{index}": callback for index, callback in enumerate(callbacks, start=1)
            }
        }
    }


class RecursiveChildHookSeedTests(unittest.TestCase):
    def test_level_one_child_generates_seed_with_provenance(self):
        report = build_recursive_seed_report([coverage(child())])

        self.assertEqual(len(report["suggested_seeds"]), 1)
        item = report["suggested_seeds"][0]
        self.assertEqual(item["generated_from"], "child_hook")
        self.assertEqual(item["hook_level"], 1)
        self.assertEqual(item["child_hook_name"], "wp_ajax_nopriv_child")
        self.assertEqual(item["child_callback"], "cb-child")
        self.assertEqual(item["seed"]["path"], "/wp-admin/admin-ajax.php")
        self.assertEqual(item["seed"]["body"]["action"], "child")
        self.assertNotIn("action", item["seed"]["query_params"])

    def test_duplicate_children_use_stable_id_then_hook_and_callback(self):
        duplicate = child(stable_id="stable-child")
        fallback = child("admin_post_nopriv_save", "cb-save", stable_id=None)

        report = build_recursive_seed_report(
            [coverage(duplicate, duplicate), coverage(fallback, fallback)]
        )

        self.assertEqual(len(report["suggested_seeds"]), 2)
        self.assertEqual(report["summary"]["duplicates_skipped"], 2)

    def test_max_depth_excludes_deeper_children(self):
        report = build_recursive_seed_report(
            [coverage(child(callback_id="cb-three", hook_level=3), child(callback_id="cb-four", hook_level=4))],
            max_hook_depth=3,
        )

        self.assertEqual([item["hook_level"] for item in report["suggested_seeds"]], [3])
        self.assertEqual(report["summary"]["depth_skipped"], 1)

    def test_replay_discovers_next_level_once_and_respects_max_depth(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            coverage_dir = Path(tmp_dir)
            next_artifact = coverage_dir / "requests" / "next.json"
            next_artifact.parent.mkdir()
            next_artifact.write_text(
                json.dumps(
                    {
                        "hook_coverage": {
                            "registered_callbacks": {
                                "cb-next": child(
                                "admin_post_nopriv_next",
                                "cb-next",
                                hook_level=1,
                                stable_id="stable-next",
                                )
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            def validator(**kwargs):
                callback_id = kwargs["candidate"]["callback_id"]
                artifacts = ["requests/next.json"] if callback_id == "cb-child" else []
                return {
                    "request": {"method": "POST", "url": "http://web/"},
                    "artifacts": {"new_request_artifacts": artifacts},
                    "result": {"expected_callback_reached": True, "status": "callback_reached", "reason": "hit"},
                }

            report, validation = run_recursive_child_hook_seeds(
                [coverage(child())],
                base_url="http://web",
                hook_coverage_dir=coverage_dir,
                timeout=1,
                max_hook_depth=2,
                validator=validator,
            )
            limited, _ = run_recursive_child_hook_seeds(
                [coverage(child())],
                base_url="http://web",
                hook_coverage_dir=coverage_dir,
                timeout=1,
                max_hook_depth=1,
                validator=validator,
            )

        depths = {item["callback_id"]: item["recursive_depth"] for item in report["suggested_seeds"]}
        self.assertEqual(depths, {"cb-child": 1, "cb-next": 2})
        self.assertEqual(validation["summary"], {"total": 2, "callback_reached": 2})
        self.assertEqual([item["callback_id"] for item in limited["suggested_seeds"]], ["cb-child"])

    def test_unsupported_child_goes_to_manual_analysis(self):
        report = build_recursive_seed_report([coverage(child("init", "cb-init"))])

        self.assertEqual(report["suggested_seeds"], [])
        self.assertEqual(len(report["manual_analysis_queue"]), 1)
        self.assertEqual(report["manual_analysis_queue"][0]["child_hook_name"], "init")

    def test_rest_metadata_generates_replayable_seed(self):
        report = build_recursive_seed_report(
            [coverage(child("rest_api_init", "cb-rest", namespace="demo/v1", route="items", methods=["POST"]))]
        )

        seed = report["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["method"], "POST")
        self.assertEqual(seed["path"], "/wp-json/demo/v1/items")

    def test_file_inputs_are_metadata_not_fuzz_params(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            source = Path(tmp_dir) / "demo.php"
            source.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function child_upload() {",
                        "    $upload = $_FILES['upload'];",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            report = build_recursive_seed_report(
                [coverage(child(source_file=str(source), start_line=2, end_line=4))]
            )

        seed = report["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["discovered_file_params"][0]["name"], "upload")
        self.assertNotIn("upload", seed["body"])
        self.assertNotIn("upload", seed["fuzzable_params"])

    def test_writes_seed_configs_and_required_validation_fields(self):
        report = build_recursive_seed_report([coverage(child())])

        def validator(**kwargs):
            candidate = kwargs["candidate"]
            return {
                "request": {"method": "POST", "url": "http://web/wp-admin/admin-ajax.php"},
                "result": {"expected_callback_reached": True, "status": "callback_reached", "reason": "hit"},
            }

        validation = validate_recursive_seeds(
            report,
            base_url="http://web",
            hook_coverage_dir="unused",
            timeout=1,
            validator=validator,
        )

        row = validation["validations"][0]
        self.assertEqual(row["expected_hook"], "wp_ajax_nopriv_child")
        self.assertEqual(row["expected_callback"], "cb-child")
        self.assertTrue(row["callback_reached"])
        self.assertEqual(row["hook_level"], 1)
        self.assertEqual(row["parent_callback"]["callback_id"], "cb-parent")
        self.assertEqual(row["request"]["method"], "POST")

        with tempfile.TemporaryDirectory() as tmp_dir:
            output_dir = Path(tmp_dir) / "recursive-child-hooks"
            paths = write_recursive_artifacts(report, validation, output_dir)
            self.assertTrue(paths["seeds"].is_file())
            self.assertTrue(paths["validation"].is_file())
            self.assertTrue(paths["config_summary"].is_file())
            self.assertEqual(len(paths["configs"]), 1)
            summary = json.loads(paths["config_summary"].read_text(encoding="utf-8"))
            self.assertEqual(summary["generated"][0]["config_path"], str(paths["configs"][0]))


if __name__ == "__main__":
    unittest.main()
