from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from hook_energy.seed_generation.generator import LiveHookSeedGenerator
else:
    from .generator import LiveHookSeedGenerator


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export seed suggestions from a live hook coverage snapshot.")
    parser.add_argument("--coverage-file", required=True, help="Path to total_coverage.json snapshot on the host.")
    parser.add_argument("--output-dir", required=True, help="Directory to write hook_gap_report and suggested seeds.")
    parser.add_argument("--container-source-root", help="Runtime/container source root to map from.")
    parser.add_argument("--host-source-root", help="Host source root mapped from --container-source-root.")
    parser.add_argument("--source-root", help="Host plugin source root or extracted ZIP root for suffix-based mapping.")
    parser.add_argument("--unresolved-source-reason", help="Reason to record when callback source cannot be resolved.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    coverage_file = Path(args.coverage_file)
    output_dir = Path(args.output_dir)

    payload = json.loads(coverage_file.read_text(encoding="utf-8-sig"))
    generator = LiveHookSeedGenerator(
        container_source_root=args.container_source_root,
        host_source_root=args.host_source_root,
        source_root=args.source_root,
        unresolved_source_reason=args.unresolved_source_reason,
    )
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
