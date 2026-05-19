from __future__ import annotations

import argparse
import json
from pathlib import Path

try:
    from .config_export import build_fast_seed_config
    from .generator import LiveHookSeedGenerator
    from .importer import HookSeedImporter
except ImportError:
    from config_export import build_fast_seed_config
    from generator import LiveHookSeedGenerator
    from importer import HookSeedImporter


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export seed suggestions from a live hook coverage snapshot.")
    parser.add_argument("--coverage-file", required=True, help="Path to total_coverage.json snapshot on the host.")
    parser.add_argument("--output-dir", required=True, help="Directory to write hook_gap_report and suggested seeds.")
    parser.add_argument("--source-config", help="Optional PHUZZ source config used to build a HOOK_FAST config.")
    parser.add_argument("--fast-config-output", help="Optional path to write a generated seed_requests config.")
    parser.add_argument("--target-base", default="http://web", help="Base URL used when expanding hook seed paths.")
    parser.add_argument("--seed-limit", type=int, default=5, help="Maximum unauthenticated hook seeds in fast config.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    coverage_file = Path(args.coverage_file)
    output_dir = Path(args.output_dir)

    payload = json.loads(coverage_file.read_text(encoding="utf-8-sig"))
    generator = LiveHookSeedGenerator()
    gap_report, seed_report = generator.write_artifacts(payload, output_dir)

    if args.fast_config_output:
        if not args.source_config:
            raise SystemExit("--source-config is required with --fast-config-output")
        importer = HookSeedImporter(
            handoff_doc=output_dir / "SEED_HANDOFF_FOR_AGENTS.md",
            hook_gap_report=output_dir / "hook_gap_report.json",
            suggested_seeds=output_dir / "suggested_seeds.json",
        )
        imported = importer.write_artifacts(output_dir)
        source_config = json.loads(Path(args.source_config).read_text(encoding="utf-8"))
        fast_config, warnings = build_fast_seed_config(
            imported,
            source_config=source_config,
            target_base=args.target_base,
            seed_limit=args.seed_limit,
        )
        fast_config["hook_fast_warnings"] = warnings
        Path(args.fast_config_output).write_text(
            json.dumps(fast_config, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    print(
        "Seed export summary: "
        f"registered={gap_report['summary']['registered_callbacks']} "
        f"| uncovered={gap_report['summary']['uncovered_callbacks']} "
        f"| direct_http_candidates={seed_report['summary']['direct_http_seed_candidates']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
