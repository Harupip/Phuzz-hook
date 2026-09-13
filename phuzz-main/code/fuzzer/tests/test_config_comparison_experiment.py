from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import unittest
import zipfile
from pathlib import Path


FUZZER_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = FUZZER_DIR.parents[2]
FIXTURE_DIR = Path(__file__).parent / "fixtures" / "config_comparison"
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from config_comparison.comparator import compare_configs
from config_comparison.models import DifferenceKind, Status
from config_comparison.normalizer import normalize_config
from config_comparison.policy import ComparisonPolicy
from seed_generation.config.config_exporter import build_config_for_seed_item


def load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


class ConfigComparisonExperimentTests(unittest.TestCase):
    def test_cf7_reference_matches_a_declaration_permutation(self) -> None:
        expected = load_fixture("cf7_welcome_panel.expected.json")
        actual = copy.deepcopy(expected)
        actual = dict(reversed(list(actual.items())))
        actual["body_params"] = dict(reversed(list(actual["body_params"].items())))
        actual["query_params"] = dict(reversed(list(actual["query_params"].items())))

        result = compare_configs(expected, actual, ComparisonPolicy(mode="strict"))

        self.assertEqual(result.status, Status.MATCH)
        self.assertEqual(result.differences, [])

    def test_stored_cf7_generated_snapshot_is_actual_and_reports_source_move(self) -> None:
        expected = load_fixture("cf7_welcome_panel.expected.json")
        actual = load_fixture("cf7_welcome_panel.generated.json")

        result = compare_configs(expected, actual, ComparisonPolicy(mode="semantic"))

        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.kind == DifferenceKind.SOURCE_MISMATCH for d in result.differences))

    def test_essential_addons_legacy_duplicate_is_invalid(self) -> None:
        result = normalize_config(load_fixture("essential_addons_duplicate.invalid.json"), ComparisonPolicy())

        self.assertIsNone(result.config)
        self.assertTrue(any(error.kind == DifferenceKind.DUPLICATE_PARAMETER for error in result.errors))

    def test_gamipress_fixture_is_explicitly_synthetic(self) -> None:
        manifest = load_fixture("manifest.json")
        entry = next(item for item in manifest["fixtures"] if item["fixture_path"] == "gamipress_get_logs.expected.json")

        self.assertEqual(entry["provenance_kind"], "synthetic_user_example")
        self.assertIsNone(entry["original_repo_relative_path"])

    def test_cf7_plugin_source_smoke_is_opt_in_and_source_backed(self) -> None:
        if os.environ.get("HOOKPHUZZ_COMPARISON_PLUGIN_SMOKE") != "1":
            self.skipTest("SKIP: set HOOKPHUZZ_COMPARISON_PLUGIN_SMOKE=1 for offline CF7 ZIP/source smoke")

        plugin_path = REPO_ROOT / "experiment/02-0day-vulns/plugins/5000000-contact-form-7.5.7.6.zip"
        self.assertTrue(plugin_path.exists())
        self.assertEqual(
            hashlib.sha256(plugin_path.read_bytes()).hexdigest(),
            "b68515fda648a4c880471295e318c29148d08a2791a06712e629c348791e1588",
        )
        with zipfile.ZipFile(plugin_path) as archive:
            source = archive.read("contact-form-7/admin/includes/welcome-panel.php").decode("utf-8")
        lines = source.splitlines()
        line_numbers = {line.strip(): index + 1 for index, line in enumerate(lines)}
        self.assertEqual(line_numbers["'wp_ajax_wpcf7-update-welcome-panel',"], 235)
        self.assertEqual(line_numbers["'wpcf7_admin_ajax_welcome_panel',"], 236)
        self.assertEqual(line_numbers["function wpcf7_admin_ajax_welcome_panel() {"], 240)
        self.assertEqual(line_numbers["check_ajax_referer( 'wpcf7-welcome-panel-nonce', 'welcomepanelnonce' );"], 241)
        self.assertEqual(line_numbers["if ( empty( $_POST['visible'] ) ) {"], 251)

    def test_exporter_output_comparison_is_labeled_integration_not_discovery(self) -> None:
        seed_item = {
            "hook_name": "wp_ajax_wpcf7-update-welcome-panel",
            "callback_id": "cf7-welcome-panel",
            "callback_repr": "wpcf7_admin_ajax_welcome_panel",
            "seed": {
                "method": "POST",
                "method_status": "resolved",
                "path": "/wp-admin/admin-ajax.php",
                "body": {
                    "action": "wpcf7-update-welcome-panel",
                    "visible": "FUZZ",
                },
                "query_params": {},
                "headers": {},
                "cookies": {},
                "auth_mode": "authenticated",
                "fixed_params": ["action"],
                "fuzzable_params": ["visible"],
            },
        }

        _, actual = build_config_for_seed_item(seed_item, target_base="http://web")
        result = compare_configs(
            load_fixture("cf7_welcome_panel.expected.json"),
            actual,
            ComparisonPolicy(mode="semantic"),
        )

        self.assertEqual(actual["body_params"]["data"][0], {"name": "action", "value": "wpcf7-update-welcome-panel"})
        self.assertEqual(actual["body_params"]["data"][1], {"name": "visible", "value": "fuzz"})
        self.assertEqual(actual["body_params"]["fixed"], ["action"])
        self.assertEqual(actual["body_params"]["fuzz"], ["visible"])
        self.assertEqual(result.status, Status.MISMATCH)
        self.assertTrue(any(d.kind == DifferenceKind.SOURCE_MISMATCH for d in result.differences))


if __name__ == "__main__":
    unittest.main()
