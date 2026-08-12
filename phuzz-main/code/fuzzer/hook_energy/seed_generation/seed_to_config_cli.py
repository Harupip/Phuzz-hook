from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from hook_energy.seed_generation.config_exporter import export_seed_configs
else:
    from .config_exporter import export_seed_configs


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Convert hook seed suggestions into PHUZZ config JSON files.")
    parser.add_argument("--suggested-seeds", required=True, help="Path to suggested_seeds.json.")
    parser.add_argument("--output-config-dir", required=True, help="Directory for generated PHUZZ config JSON files.")
    parser.add_argument("--summary", required=True, help="Path to write generated/skipped summary JSON.")
    parser.add_argument("--target-base", default="http://web", help="Base URL used for generated PHUZZ targets.")
    parser.add_argument("--replay-only", action="store_true", help="Write replay-only configs with no fuzz fields.")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(suggested_path.read_text(encoding="utf-8-sig"))

    summary = export_seed_configs(
        payload,
        output_config_dir=Path(args.output_config_dir),
        summary_path=Path(args.summary),
        target_base=args.target_base,
        replay_only=args.replay_only,
    )
    print(f"Seed config export summary: generated={len(summary['generated'])} skipped={len(summary['skipped'])}")
    for item in summary["generated"]:
        print(f"FUZZER_CONFIG={item['config_slug']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
