from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIG_ROOT = ROOT / "fuzzer" / "configs" / "wordpress"
MATRIX_CONFIG_PATH = ROOT / "scripts" / "wordpress" / "run-wordpress-plugin-matrix.config.ps1"
MATRIX_RUNNER_PATH = ROOT / "scripts" / "wordpress" / "run-wordpress-plugin-matrix.ps1"
BENCHMARK_CONFIG_PATH = ROOT / "scripts" / "benchmarks" / "benchmark-wordpress-phuzz.config.ps1"
BENCHMARK_RUNNER_PATH = ROOT / "scripts" / "benchmarks" / "benchmark-wordpress-phuzz.ps1"


TARGETS = {
    "country-state-city-auto-dropdown": {
        "config": "country-state-city-auto-dropdown-2.7.2-cve-2024-3495-states",
        "zip": "country-state-city-auto-dropdown.2.7.2.zip",
        "url": "https://downloads.wordpress.org/plugin/country-state-city-auto-dropdown.2.7.2.zip",
        "cve": "CVE-2024-3495",
    },
    "wp-google-map-plugin": {
        "config": "wp-google-map-plugin-4.9.1-cve-2026-3222",
        "zip": "wp-google-map-plugin.zip",
        "url": "https://downloads.wordpress.org/plugin/wp-google-map-plugin.4.9.1.zip",
        "cve": "CVE-2026-3222",
    },
    "email-subscribers": {
        "config": "email-subscribers-5.7.14-cve-2024-2876",
        "zip": "email-subscribers.zip",
        "url": "https://downloads.wordpress.org/plugin/email-subscribers.5.7.14.zip",
        "cve": "CVE-2024-2876",
    },
    "booking": {
        "config": "booking-9.9-cve-2024-1207-create-booking",
        "zip": "booking.zip",
        "url": "https://downloads.wordpress.org/plugin/booking.9.9.zip",
        "cve": "CVE-2024-1207",
    },
}


class NewWordPressTargetTests(unittest.TestCase):
    def test_country_state_city_split_configs_have_one_ajax_fuzz_param_each(self) -> None:
        expected = {
            "country-state-city-auto-dropdown-2.7.2-cve-2024-3495-states": (
                "tc_csca_get_states",
                "^cnt$",
            ),
            "country-state-city-auto-dropdown-2.7.2-cve-2024-3495-cities": (
                "tc_csca_get_cities",
                "^sid$",
            ),
        }

        for config_name, (action, fuzz_param) in expected.items():
            with self.subTest(config_name=config_name):
                config = json.loads((CONFIG_ROOT / f"{config_name}.json").read_text(encoding="utf-8"))
                body = {item["name"]: item for item in config["body_params"]["data"]}
                self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
                self.assertEqual(config["methods"], ["POST"])
                self.assertEqual(body["action"]["value"], action)
                self.assertEqual(body["nonce_ajax"]["value"], "fuzz")
                self.assertEqual(config["body_params"]["fixed"], ["^action$", "^nonce_ajax$"])
                self.assertEqual(config["body_params"]["fuzz"], [fuzz_param])

    def test_versioned_configs_parse_and_anchor_fuzz_fields(self) -> None:
        expected_fuzz_fields = {
            "country-state-city-auto-dropdown-2.7.2-cve-2024-3495-states": {"cnt"},
            "country-state-city-auto-dropdown-2.7.2-cve-2024-3495-cities": {"sid"},
            "wp-google-map-plugin-4.9.1-cve-2026-3222": {"location_id"},
            "email-subscribers-5.7.14-cve-2024-2876": {"advanced_filter[conditions][0][0][value]"},
            "booking-9.9-cve-2024-1207-create-booking": {"calendar_request_params[dates_ddmmyy_csv]"},
        }

        for config_name, fields in expected_fuzz_fields.items():
            with self.subTest(config_name=config_name):
                config = json.loads((CONFIG_ROOT / f"{config_name}.json").read_text(encoding="utf-8"))
                self.assertIn("target", config)
                body_fuzz = set(config.get("body_params", {}).get("fuzz", []))
                query_fuzz = set(config.get("query_params", {}).get("fuzz", []))
                seed_fuzz = set()
                for seed in config.get("seed_requests", []):
                    for group in ("query_params", "body_params"):
                        seed_fuzz.update(seed.get("fuzz_params", {}).get(group, {}).keys())
                normalized = {
                    item.strip("^$").replace("\\[", "[").replace("\\]", "]")
                    for item in body_fuzz | query_fuzz | seed_fuzz
                }
                self.assertTrue(fields.issubset(normalized))

                for pattern in body_fuzz | query_fuzz:
                    self.assertTrue(pattern.startswith("^"), pattern)
                    self.assertTrue(pattern.endswith("$"), pattern)

    def test_matrix_metadata_has_zip_and_versioned_config_names(self) -> None:
        text = MATRIX_CONFIG_PATH.read_text(encoding="utf-8")
        runner = MATRIX_RUNNER_PATH.read_text(encoding="utf-8")

        self.assertIn("ConfigName", runner)
        self.assertIn("ZipFile", runner)
        for slug, data in TARGETS.items():
            with self.subTest(slug=slug):
                self.assertRegex(text, rf'Slug = "{re.escape(slug)}"')
                self.assertIn(f'Url = "{data["url"]}"', text)
                self.assertIn(f'ZipFile = "{data["zip"]}"', text)
                self.assertIn(f'ConfigName = "{data["config"]}"', text)
                self.assertIn(f'CVE = "{data["cve"]}"', text)

    def test_benchmark_metadata_has_new_targets_and_config_names(self) -> None:
        text = BENCHMARK_CONFIG_PATH.read_text(encoding="utf-8")
        runner = BENCHMARK_RUNNER_PATH.read_text(encoding="utf-8")

        self.assertIn("ConfigName", runner)
        for slug, data in TARGETS.items():
            with self.subTest(slug=slug):
                self.assertRegex(text, rf'"{re.escape(slug)}"\s*=')
                self.assertIn(data["zip"], text)
                self.assertIn(f'ConfigName = "{data["config"]}"', text)


if __name__ == "__main__":
    unittest.main()
