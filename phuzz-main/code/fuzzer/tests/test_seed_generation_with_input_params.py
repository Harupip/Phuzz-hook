from __future__ import annotations

import sys
import subprocess
import tempfile
import unittest
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_generation.generator import LiveHookSeedGenerator


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "hook_input_callbacks.php"


class SeedGenerationWithInputParamsTests(unittest.TestCase):
    def test_seed_reports_include_source_resolution_metadata_from_mapped_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            host_root = Path(tmp_dir) / "example-plugin"
            source_file = host_root / "includes" / "ajax.php"
            source_file.parent.mkdir(parents=True)
            source_file.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function example_lookup_handler() {",
                        "    $item_id = $_REQUEST['item_id'];",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-public": {
                            "hook_name": "wp_ajax_nopriv_example_lookup",
                            "callback_repr": "example_lookup_handler",
                            "source_file": "/var/www/html/wp-content/plugins/example-plugin/includes/ajax.php",
                            "start_line": 2,
                            "end_line": 4,
                            "is_active": True,
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            generator = LiveHookSeedGenerator(
                container_source_root="/var/www/html/wp-content/plugins/example-plugin",
                host_source_root=host_root,
            )
            gap_report, seed_report = generator.build_reports(payload)

        row = gap_report["callbacks"][0]
        seed_item = seed_report["suggested_seeds"][0]
        self.assertEqual(row["source_resolution"]["status"], "zip_mapped")
        self.assertEqual(seed_item["source_resolution"]["status"], "zip_mapped")
        self.assertEqual(seed_item["seed"]["body"]["item_id"], "FUZZ")

    def test_wp_ajax_seed_keeps_action_fixed_and_adds_extracted_fuzzable_params(self) -> None:
        payload = {
            "data": {
                "registered_callbacks": {
                    "cb-public": {
                        "hook_name": "wp_ajax_nopriv_example_lookup",
                        "callback_repr": "Example_Plugin::handle_lookup",
                        "class_name": "Example_Plugin",
                        "method_name": "handle_lookup",
                        "function_name": None,
                        "is_static": True,
                        "is_closure": False,
                        "is_invokable": False,
                        "formal_parameters": [{"name": "request", "type": "array"}],
                        "source_file": str(FIXTURE),
                        "start_line": 2,
                        "end_line": 9,
                        "is_active": True,
                    },
                    "cb-auth": {
                        "hook_name": "wp_ajax_example_lookup",
                        "callback_repr": "Example_Plugin::handle_lookup",
                        "source_file": str(FIXTURE),
                        "start_line": 2,
                        "end_line": 9,
                        "is_active": True,
                    },
                },
                "executed_callbacks": {},
            }
        }
        gap_report, seed_report = LiveHookSeedGenerator().build_reports(payload)

        public = next(
            item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_nopriv_example_lookup"
        )
        auth = next(item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_example_lookup")

        self.assertEqual(public["seed_priority"], "highest")
        self.assertEqual(auth["seed_priority"], "high")
        self.assertEqual(public["seed"]["body"]["action"], "example_lookup")
        self.assertEqual(public["seed"]["body"]["orderby"], "FUZZ")
        self.assertEqual(public["seed"]["body"]["sid"], "FUZZ")
        self.assertEqual(public["seed"]["query_params"]["cnt"], "FUZZ")
        self.assertEqual(public["seed"]["fixed_params"], ["action"])
        self.assertIn("orderby", public["seed"]["fuzzable_params"])
        self.assertNotIn("action", public["seed"]["fuzzable_params"])

        row = next(item for item in gap_report["callbacks"] if item["callback_id"] == "cb-public")
        self.assertEqual(row["class_name"], "Example_Plugin")
        self.assertEqual(row["method_name"], "handle_lookup")
        self.assertIs(row["is_static"], True)
        self.assertEqual(row["formal_parameters"], [{"name": "request", "type": "array"}])

    def test_files_are_discovered_but_not_fuzzed(self) -> None:
        payload = {
            "data": {
                "registered_callbacks": {
                    "cb-public": {
                        "hook_name": "wp_ajax_nopriv_example_lookup",
                        "callback_repr": "Example_Plugin::handle_lookup",
                        "source_file": str(FIXTURE),
                        "start_line": 2,
                        "end_line": 9,
                        "is_active": True,
                    }
                },
                "executed_callbacks": {},
            }
        }

        _, seed_report = LiveHookSeedGenerator().build_reports(payload)

        seed = seed_report["suggested_seeds"][0]["seed"]
        self.assertIn({"name": "avatar", "source": "FILES"}, [
            {"name": item["name"], "source": item["source"]} for item in seed["discovered_file_params"]
        ])
        self.assertNotIn("avatar", seed["body"])
        self.assertNotIn("avatar", seed["fuzzable_params"])

    def test_request_params_follow_request_method_default(self) -> None:
        generator = LiveHookSeedGenerator()

        post_seed = generator._attach_fuzzable_params(
            {
                "method": "POST",
                "path": "/wp-admin/admin-ajax.php",
                "body": {"action": "demo"},
                "auth_mode": "authenticated",
            },
            [{"name": "token", "source": "REQUEST"}],
        )
        get_seed = generator._attach_fuzzable_params(
            {
                "method": "GET",
                "path": "/wp-admin/admin.php",
                "body": {"action": "demo"},
                "auth_mode": "authenticated",
            },
            [{"name": "token", "source": "REQUEST"}],
        )

        self.assertEqual(post_seed["body"]["token"], "FUZZ")
        self.assertNotIn("token", post_seed["query_params"])
        self.assertEqual(get_seed["query_params"]["token"], "FUZZ")
        self.assertNotIn("token", get_seed["body"])

    def test_get_rest_route_seed_uses_wp_json_target_and_query_params(self) -> None:
        source = "<?php\nfunction rest_lookup() {\n    $term = $_GET['term'];\n}\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "rest.php"
            source_file.write_text(source, encoding="utf-8")
            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-rest": {
                            "entrypoint_type": "rest_route",
                            "hook_name": "rest_route:demo/v1/items",
                            "callback_repr": "rest_lookup",
                            "namespace": "demo/v1",
                            "route": "/items",
                            "methods": ["GET"],
                            "source_file": str(source_file),
                            "start_line": 2,
                            "end_line": 4,
                            "is_active": True,
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            _, seed_report = LiveHookSeedGenerator().build_reports(payload)

        item = seed_report["suggested_seeds"][0]
        seed = item["seed"]
        self.assertEqual(item["entrypoint_type"], "rest_route")
        self.assertEqual(seed["path"], "/wp-json/demo/v1/items")
        self.assertEqual(seed["methods"], ["GET"])
        self.assertEqual(seed["query_params"]["term"], "FUZZ")
        self.assertNotIn("term", seed["body"])
        self.assertNotIn("action", seed["body"])
        self.assertEqual(seed["fixed_params"], [])

    def test_post_rest_route_seed_uses_body_params_without_action(self) -> None:
        source = "<?php\nfunction rest_save() {\n    $title = $_POST['title'];\n}\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            source_file = Path(tmp_dir) / "rest.php"
            source_file.write_text(source, encoding="utf-8")
            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-rest": {
                            "entrypoint_type": "rest_route",
                            "hook_name": "rest_route:demo/v1/items",
                            "callback_repr": "rest_save",
                            "namespace": "demo/v1",
                            "route": "items",
                            "methods": ["POST"],
                            "source_file": str(source_file),
                            "start_line": 2,
                            "end_line": 4,
                            "is_active": True,
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            _, seed_report = LiveHookSeedGenerator().build_reports(payload)

        seed = seed_report["suggested_seeds"][0]["seed"]
        self.assertEqual(seed["path"], "/wp-json/demo/v1/items")
        self.assertEqual(seed["body"]["title"], "FUZZ")
        self.assertNotIn("title", seed["query_params"])
        self.assertNotIn("action", seed["body"])
        self.assertEqual(seed["fixed_params"], [])

    def test_unresolved_source_reason_is_reported(self) -> None:
        payload = {
            "data": {
                "registered_callbacks": {
                    "cb-public": {
                        "hook_name": "wp_ajax_nopriv_example_lookup",
                        "callback_repr": "example_lookup_handler",
                        "source_file": "/var/www/html/wp-content/plugins/example-plugin/includes/ajax.php",
                        "start_line": 2,
                        "end_line": 4,
                        "is_active": True,
                    }
                },
                "executed_callbacks": {},
            }
        }

        gap_report, seed_report = LiveHookSeedGenerator(unresolved_source_reason="source_copy_failed").build_reports(payload)

        self.assertEqual(gap_report["callbacks"][0]["source_resolution"]["status"], "unresolved")
        self.assertEqual(gap_report["callbacks"][0]["source_resolution"]["reason"], "source_copy_failed")
        self.assertEqual(seed_report["suggested_seeds"][0]["source_resolution"]["reason"], "source_copy_failed")

    def test_export_cli_imports_as_package_module(self) -> None:
        from hook_energy.seed_generation.export_cli import build_argument_parser

        parser = build_argument_parser()
        args = parser.parse_args(
            [
                "--coverage-file",
                "total_coverage.json",
                "--output-dir",
                "seed-export",
                "--container-source-root",
                "/var/www/html/wp-content/plugins/example-plugin",
                "--host-source-root",
                "src/example-plugin",
                "--source-root",
                "src/example-plugin",
            ]
        )
        self.assertEqual(args.coverage_file, "total_coverage.json")
        self.assertEqual(args.output_dir, "seed-export")
        self.assertEqual(args.container_source_root, "/var/www/html/wp-content/plugins/example-plugin")
        self.assertEqual(args.host_source_root, "src/example-plugin")
        self.assertEqual(args.source_root, "src/example-plugin")

    def test_export_cli_can_run_as_direct_script(self) -> None:
        script = FUZZER_DIR / "hook_energy" / "seed_generation" / "export_cli.py"
        result = subprocess.run(
            [sys.executable, str(script), "--help"],
            cwd=FUZZER_DIR,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--coverage-file", result.stdout)


if __name__ == "__main__":
    unittest.main()
