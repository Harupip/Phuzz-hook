from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
    from hook_energy.seed_generation.zend_runtime.candidate_generator import ZendRuntimeSeedGenerator
else:
    from .candidate_generator import ZendRuntimeSeedGenerator


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export runtime-only Zend/UOPZ bootstrap candidates from hook coverage."
    )
    parser.add_argument("--coverage-file", required=True, help="Path to total_coverage.json snapshot on the host.")
    parser.add_argument("--output-dir", required=True, help="Directory to write runtime candidate artifacts.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    payload = json.loads(Path(args.coverage_file).read_text(encoding="utf-8-sig"))
    generator = ZendRuntimeSeedGenerator()
    gap_report, seed_report = generator.write_artifacts(payload, Path(args.output_dir))
    print(
        "Zend runtime seed export summary: "
        f"registered={gap_report['summary']['registered_callbacks']} "
        f"| uncovered={gap_report['summary']['uncovered_callbacks']} "
        f"| bootstrap_candidates={seed_report['summary']['direct_http_seed_candidates']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
