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
    parser.add_argument(
        "--runtime-discovery-manifest",
        help="JSON manifest listing the bounded runtime discovery artifacts for this run.",
    )
    return parser


def load_runtime_discovery_artifacts(paths: list[str]) -> list[dict]:
    discoveries = []
    for artifact_path in paths:
        try:
            artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError):
            discoveries.append({"artifact_path": str(artifact_path)})
            continue
        if isinstance(artifact, dict) and isinstance(artifact.get("runtime_param_discoveries"), list):
            discoveries.extend(item for item in artifact["runtime_param_discoveries"] if isinstance(item, dict))
        else:
            discoveries.append({"artifact_path": str(artifact_path)})
    return discoveries


def load_runtime_discovery_manifest(path: str) -> list[str]:
    try:
        manifest = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"runtime discovery manifest is unreadable: {path}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1 or not isinstance(manifest.get("run_id"), str):
        raise ValueError("runtime discovery manifest has unsupported schema")
    paths: list[str] = []
    seen: set[str] = set()
    for entry in manifest.get("artifacts", []):
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or not entry["path"].strip():
            raise ValueError("runtime discovery manifest has malformed artifact entry")
        normalized = str(Path(entry["path"]).resolve())
        if normalized in seen:
            continue
        if not Path(normalized).is_file():
            if entry.get("required", True):
                raise ValueError(f"runtime discovery manifest required artifact is missing: {entry['path']}")
            continue
        seen.add(normalized)
        paths.append(normalized)
    return paths


def main() -> int:
    args = build_argument_parser().parse_args()
    suggested_path = Path(args.suggested_seeds)
    payload = json.loads(suggested_path.read_text(encoding="utf-8-sig"))

    paths = list(args.runtime_discovery_artifact)
    if args.runtime_discovery_manifest:
        paths.extend(load_runtime_discovery_manifest(args.runtime_discovery_manifest))
    discoveries = load_runtime_discovery_artifacts(list(dict.fromkeys(paths)))

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
