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
    parser.add_argument(
        "--runtime-discovery-artifact",
        action="append",
        default=[],
        help="Request artifact containing runtime_param_discoveries; may be repeated.",
    )
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(suggested_path.read_text(encoding="utf-8-sig"))

    discoveries = []
    for artifact_path in args.runtime_discovery_artifact:
        try:
            artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            discoveries.append({"artifact_path": str(artifact_path)})
            continue
        if isinstance(artifact, dict) and isinstance(artifact.get("runtime_param_discoveries"), list):
            discoveries.extend(item for item in artifact["runtime_param_discoveries"] if isinstance(item, dict))
        else:
            discoveries.append({"artifact_path": str(artifact_path)})

    summary = export_seed_configs(
        payload,
        output_config_dir=Path(args.output_config_dir),
        summary_path=Path(args.summary),
        target_base=args.target_base,
        runtime_param_discoveries=discoveries,
    )
    print(f"Seed config export summary: generated={len(summary['generated'])} skipped={len(summary['skipped'])}")
    for item in summary["generated"]:
        print(f"FUZZER_CONFIG={item['config_slug']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
