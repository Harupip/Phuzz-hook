from __future__ import annotations

import csv
import json
import shutil
import sys
import unittest
from contextlib import contextmanager
from pathlib import Path

FUZZER_DIR = Path(__file__).resolve().parents[1]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from benchmarking.report import generate_report


@contextmanager
def temporary_workspace(name: str):
    base = FUZZER_DIR / "output" / "test-temp"
    base.mkdir(parents=True, exist_ok=True)
    path = base / name
    if path.exists():
        shutil.rmtree(path)
    path.mkdir()
    try:
        yield path
    finally:
        if path.exists():
            shutil.rmtree(path)


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_timeline(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "bucket_index",
        "elapsed_start_seconds",
        "elapsed_end_seconds",
        "requests",
        "requests_per_second",
        "requests_per_minute",
        "cumulative_unique_callbacks",
        "blindspots_reduced",
        "unique_vulns",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def build_run(root: Path, mode: str, requests_per_second: float, unique_vulns: int) -> Path:
    run_dir = root / f"{mode}-run-01"
    write_json(
        run_dir / "benchmark_summary.json",
        {
            "plugin": "photo-gallery",
            "mode": mode,
            "run": 1,
            "requests_per_second": requests_per_second,
            "unique_vulns_found_within_budget": unique_vulns,
        },
    )
    write_json(
        run_dir / "run_manifest.json",
        {
            "plugin": "photo-gallery",
            "mode": mode,
            "run_minutes": 90,
            "trace_minutes": 20 if mode == "HOOK_FAST" else None,
            "fast_minutes": 70 if mode == "HOOK_FAST" else None,
            "fuzzer_enable_uopz": 0 if mode in {"PHUZZ_RAW", "HOOK_FAST"} else 1,
        },
    )
    write_timeline(
        run_dir / "coverage_timeline.csv",
        [
            {
                "bucket_index": 1,
                "elapsed_start_seconds": 0,
                "elapsed_end_seconds": 300,
                "requests": 150,
                "requests_per_second": requests_per_second,
                "requests_per_minute": requests_per_second * 60,
                "cumulative_unique_callbacks": 0 if mode in {"PHUZZ_RAW", "HOOK_FAST"} else 8,
                "blindspots_reduced": 0 if mode in {"PHUZZ_RAW", "HOOK_FAST"} else 8,
                "unique_vulns": 0,
            },
            {
                "bucket_index": 2,
                "elapsed_start_seconds": 300,
                "elapsed_end_seconds": 600,
                "requests": 180,
                "requests_per_second": requests_per_second,
                "requests_per_minute": requests_per_second * 60,
                "cumulative_unique_callbacks": 0 if mode in {"PHUZZ_RAW", "HOOK_FAST"} else 14,
                "blindspots_reduced": 0 if mode in {"PHUZZ_RAW", "HOOK_FAST"} else 14,
                "unique_vulns": unique_vulns,
            },
        ],
    )
    return run_dir


class BenchmarkReportTests(unittest.TestCase):
    def test_generate_report_writes_markdown_and_svg_from_benchmark_artifacts(self) -> None:
        with temporary_workspace("benchmark-report-complete") as tmp_dir:
            root = tmp_dir / "20260520-095953-photo-gallery"
            root.mkdir()
            runs = [
                build_run(root, "PHUZZ_RAW", 0.60, 1),
                build_run(root, "PHUZZ_TRACE", 0.48, 1),
                build_run(root, "HOOK_TRACE", 0.50, 2),
                build_run(root, "HOOK_FAST", 0.55, 0),
            ]
            hook_fast_dir = runs[-1]
            (hook_fast_dir / "trace-phase").mkdir()
            write_json(
                hook_fast_dir / "seed-export" / "hook_gap_report.json",
                {
                    "summary": {
                        "registered_callbacks": 68,
                        "uncovered_callbacks": 54,
                        "direct_http_seed_candidates": 17,
                    }
                },
            )
            write_json(hook_fast_dir / "seed-export" / "suggested_seeds.json", {"suggested_seeds": []})
            write_json(hook_fast_dir / "hook-fast-config.json", {"seed_requests": []})
            write_json(
                root / "benchmark_results.json",
                {
                    "plugin": "photo-gallery",
                    "total_runs": 4,
                    "modes": [
                        {"mode": "PHUZZ_RAW", "median_requests_per_second": 0.60, "median_uopz_overhead_ratio": 1.0},
                        {"mode": "PHUZZ_TRACE", "median_requests_per_second": 0.48, "median_uopz_overhead_ratio": 0.8},
                        {"mode": "HOOK_TRACE", "median_requests_per_second": 0.50, "median_uopz_overhead_ratio": 0.83},
                        {"mode": "HOOK_FAST", "median_requests_per_second": 0.55, "median_uopz_overhead_ratio": 0.92},
                    ],
                    "runs": [
                        {
                            "plugin": "photo-gallery",
                            "mode": "HOOK_TRACE",
                            "run": 1,
                            "time_to_first_unique_vuln_seconds": 420,
                            "requests_to_first_unique_vuln": 210,
                            "unique_vulns_found_within_budget": 2,
                        }
                    ],
                },
            )
            (root / "benchmark_results.csv").write_text("plugin,mode\nphoto-gallery,PHUZZ_RAW\n", encoding="utf-8")

            artifacts = generate_report(root)

            markdown = artifacts.markdown_path.read_text(encoding="utf-8")
            svg = artifacts.svg_path.read_text(encoding="utf-8")
            self.assertIn("bounded 7-hour pilot evidence", markdown)
            self.assertIn("| HOOK_TRACE | 0.5000 | 0.83 |", markdown)
            self.assertIn("registered=68", markdown)
            self.assertIn("Shallow/deep interpretation", markdown)
            self.assertIn("HOOK_FAST fast phase runs with UOPZ off", markdown)
            self.assertIn("<svg", svg)
            self.assertIn("HOOK_TRACE callbacks", svg)
            self.assertIn("Requests per second", svg)
            self.assertIn("polyline", svg)

    def test_generate_report_flags_missing_hook_fast_artifacts(self) -> None:
        with temporary_workspace("benchmark-report-missing") as tmp_dir:
            root = tmp_dir / "20260520-095953-photo-gallery"
            root.mkdir()
            build_run(root, "HOOK_FAST", 0.55, 0)
            write_json(
                root / "benchmark_results.json",
                {
                    "plugin": "photo-gallery",
                    "total_runs": 1,
                    "modes": [{"mode": "HOOK_FAST", "median_requests_per_second": 0.55}],
                    "runs": [],
                },
            )
            (root / "benchmark_results.csv").write_text("plugin,mode\nphoto-gallery,HOOK_FAST\n", encoding="utf-8")

            artifacts = generate_report(root)

            markdown = artifacts.markdown_path.read_text(encoding="utf-8")
            self.assertIn("Missing artifacts", markdown)
            self.assertIn("HOOK_FAST-run-01/seed-export/hook_gap_report.json", markdown)


if __name__ == "__main__":
    unittest.main()
