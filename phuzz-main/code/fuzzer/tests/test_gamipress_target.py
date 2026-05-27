from __future__ import annotations

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "fuzzer" / "configs" / "wordpress" / "gamipress.json"
MATRIX_CONFIG_PATH = (
    ROOT / "scripts" / "wordpress" / "run-wordpress-plugin-matrix.config.ps1"
)
RUNNER_PATH = ROOT / "scripts" / "wordpress" / "run-wordpress-gamipress.ps1"


class GamiPressTargetTests(unittest.TestCase):
    def test_config_targets_gamipress_ajax_orderby(self) -> None:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))

        self.assertEqual(config["target"], "http://web/wp-admin/admin-ajax.php")
        self.assertEqual(config["methods"], ["POST"])
        self.assertEqual(config["body_params"]["fixed"], ["^action$", "^order$", "^limit$", "^page$", "^nonce$"])
        self.assertEqual(config["body_params"]["fuzz"], ["^orderby$"])

        body = {item["name"]: item for item in config["body_params"]["data"]}
        self.assertEqual(body["action"]["value"], "gamipress_get_logs")
        self.assertEqual(body["orderby"]["seeds"], ["fuzz"])
        self.assertEqual(body["order"]["value"], "ASC")
        self.assertEqual(body["limit"]["value"], "10")
        self.assertEqual(body["page"]["value"], "1")
        self.assertEqual(body["nonce"]["value"], "fuzz")

    def test_matrix_contains_vulnerable_gamipress_metadata(self) -> None:
        text = MATRIX_CONFIG_PATH.read_text(encoding="utf-8")

        self.assertRegex(
            text,
            r'Slug = "gamipress"; Category = "SQLi"; Url = "https://downloads\.wordpress\.org/plugin/gamipress\.7\.3\.1\.zip"; Version = "7\.3\.1"; ZipFile = "gamipress\.zip"',
        )

    def test_single_plugin_runner_selects_only_gamipress(self) -> None:
        text = RUNNER_PATH.read_text(encoding="utf-8")

        self.assertIn("run-wordpress-plugin-matrix.ps1", text)
        self.assertRegex(text, re.escape("-Plugins") + r"\s+gamipress")


if __name__ == "__main__":
    unittest.main()
