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
            host_root = Path(tmp_dir) / "gamipress"
            source_file = host_root / "includes" / "ajax-functions.php"
            source_file.parent.mkdir(parents=True)
            source_file.write_text(
                "\n".join(
                    [
                        "<?php",
                        "function gamipress_ajax_get_logs() {",
                        "    $orderby = $_REQUEST['orderby'];",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            payload = {
                "data": {
                    "registered_callbacks": {
                        "cb-public": {
                            "hook_name": "wp_ajax_nopriv_gamipress_get_logs",
                            "callback_repr": "gamipress_ajax_get_logs",
                            "source_file": "/var/www/html/wp-content/plugins/gamipress/includes/ajax-functions.php",
                            "start_line": 2,
                            "end_line": 4,
                            "is_active": True,
                        }
                    },
                    "executed_callbacks": {},
                }
            }

            generator = LiveHookSeedGenerator(
                container_source_root="/var/www/html/wp-content/plugins/gamipress",
                host_source_root=host_root,
            )
            gap_report, seed_report = generator.build_reports(payload)

        row = gap_report["callbacks"][0]
        seed_item = seed_report["suggested_seeds"][0]
        self.assertEqual(row["source_resolution"]["status"], "zip_mapped")
        self.assertEqual(seed_item["source_resolution"]["status"], "zip_mapped")
        self.assertEqual(seed_item["seed"]["body"]["orderby"], "FUZZ")

    def test_wp_ajax_seed_keeps_action_fixed_and_adds_extracted_fuzzable_params(self) -> None:
        payload = {
            "data": {
                "registered_callbacks": {
                    "cb-public": {
                        "hook_name": "wp_ajax_nopriv_gamipress_get_logs",
                        "callback_repr": "GamiPress_Ajax::get_logs",
                        "class_name": "GamiPress_Ajax",
                        "method_name": "get_logs",
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
                        "hook_name": "wp_ajax_gamipress_get_logs",
                        "callback_repr": "GamiPress_Ajax::get_logs",
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
            item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_nopriv_gamipress_get_logs"
        )
        auth = next(item for item in seed_report["suggested_seeds"] if item["hook_name"] == "wp_ajax_gamipress_get_logs")

        self.assertEqual(public["seed_priority"], "highest")
        self.assertEqual(auth["seed_priority"], "high")
        self.assertEqual(public["seed"]["body"]["action"], "gamipress_get_logs")
        self.assertEqual(public["seed"]["body"]["orderby"], "FUZZ")
        self.assertEqual(public["seed"]["body"]["sid"], "FUZZ")
        self.assertEqual(public["seed"]["query_params"]["cnt"], "FUZZ")
        self.assertEqual(public["seed"]["fixed_params"], ["action"])
        self.assertIn("orderby", public["seed"]["fuzzable_params"])
        self.assertNotIn("action", public["seed"]["fuzzable_params"])

        row = next(item for item in gap_report["callbacks"] if item["callback_id"] == "cb-public")
        self.assertEqual(row["class_name"], "GamiPress_Ajax")
        self.assertEqual(row["method_name"], "get_logs")
        self.assertIs(row["is_static"], True)
        self.assertEqual(row["formal_parameters"], [{"name": "request", "type": "array"}])

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
                "/var/www/html/wp-content/plugins/gamipress",
                "--host-source-root",
                "src/gamipress",
                "--source-root",
                "src/gamipress",
            ]
        )
        self.assertEqual(args.coverage_file, "total_coverage.json")
        self.assertEqual(args.output_dir, "seed-export")
        self.assertEqual(args.container_source_root, "/var/www/html/wp-content/plugins/gamipress")
        self.assertEqual(args.host_source_root, "src/gamipress")
        self.assertEqual(args.source_root, "src/gamipress")

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
