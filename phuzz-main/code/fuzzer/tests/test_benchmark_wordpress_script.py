from __future__ import annotations

import re
import unittest
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "benchmarks"
    / "benchmark-wordpress-phuzz.ps1"
)


def parse_supported_plugins(script_text: str) -> dict[str, dict[str, object]]:
    pattern = re.compile(
        r'"(?P<slug>[^"]+)"\s*=\s*@\{\s*'
        r'Category = "(?P<category>[^"]+)";\s*'
        r'Service = \$fuzzerService;\s*'
        r'ZipFiles = @\((?P<zip_files>[^)]*)\)\s*'
        r"\}",
        re.MULTILINE,
    )

    plugins: dict[str, dict[str, object]] = {}
    for match in pattern.finditer(script_text):
        zip_files = re.findall(r'"([^"]+)"', match.group("zip_files"))
        plugins[match.group("slug")] = {
            "category": match.group("category"),
            "zip_files": zip_files,
        }
    return plugins


class BenchmarkWordPressScriptTests(unittest.TestCase):
    def test_supported_plugins_include_representative_batch_slugs(self) -> None:
        plugins = parse_supported_plugins(SCRIPT_PATH.read_text(encoding="utf-8"))

        self.assertTrue(
            {
                "ubigeo-peru",
                "show-all-comments-in-one-page",
                "udraw",
                "joomsport-sports-league-results-management",
                "phastpress",
            }.issubset(plugins.keys())
        )

    def test_udraw_requires_woocommerce_zip(self) -> None:
        plugins = parse_supported_plugins(SCRIPT_PATH.read_text(encoding="utf-8"))

        self.assertEqual(
            plugins["udraw"]["zip_files"],
            ["udraw.zip", "woocommerce.zip"],
        )

    def test_runner_defines_long_run_mode_matrix_without_mutating_scoring_env(self) -> None:
        script_text = SCRIPT_PATH.read_text(encoding="utf-8")

        for mode_name in ("PHUZZ_RAW", "PHUZZ_TRACE", "HOOK_TRACE", "HOOK_FAST"):
            self.assertIn(mode_name, script_text)

        self.assertNotIn("function Set-ScoringMode", script_text)
        self.assertNotIn("$originalScoringEnv", script_text)
        self.assertIn("FUZZER_ENABLE_UOPZ", script_text)
        self.assertIn("PHUZZ_SCORING_MODE", script_text)

    def test_runner_exposes_long_run_and_hook_fast_parameters(self) -> None:
        script_text = SCRIPT_PATH.read_text(encoding="utf-8")

        for parameter_name in ("RunHours", "BucketMinutes", "TraceMinutes", "FastSeedLimit"):
            self.assertRegex(script_text, rf"\${parameter_name}\b")

        self.assertIn("run_manifest.json", script_text)
        self.assertIn("hook_gap_report.json", script_text)
        self.assertIn("FUZZER_CONFIG_FILE", script_text)

    def test_runner_accepts_comma_separated_selection_values(self) -> None:
        script_text = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn('([string]$value).Split(",")', script_text)


if __name__ == "__main__":
    unittest.main()
