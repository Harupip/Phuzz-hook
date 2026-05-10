from __future__ import annotations

import argparse
import json
from pathlib import Path

from generator import LiveHookSeedGenerator


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export seed suggestions from a live hook coverage snapshot.")
    parser.add_argument("--coverage-file", required=True, help="Path to total_coverage.json snapshot on the host.")
    parser.add_argument("--output-dir", required=True, help="Directory to write hook_gap_report and suggested seeds.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    coverage_file = Path(args.coverage_file)
    output_dir = Path(args.output_dir)

    payload = json.loads(coverage_file.read_text(encoding="utf-8-sig"))
    generator = LiveHookSeedGenerator()
    gap_report, seed_report = generator.write_artifacts(payload, output_dir)

    print(
        "Seed export summary: "
        f"registered={gap_report['summary']['registered_callbacks']} "
        f"| uncovered={gap_report['summary']['uncovered_callbacks']} "
        f"| direct_http_candidates={seed_report['summary']['direct_http_seed_candidates']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
