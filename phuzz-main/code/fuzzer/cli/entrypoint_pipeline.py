from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from hook_energy.seed_generation.generated_config_runner import (
        format_validation_result,
        load_generated_configs,
        run_generated_configs,
        write_report,
    )
    from seed_generation.pipeline.pipeline import run_entrypoint_pipeline
else:
    from hook_energy.seed_generation.generated_config_runner import format_validation_result, load_generated_configs, run_generated_configs, write_report
    from seed_generation.pipeline.pipeline import run_entrypoint_pipeline


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build a unified AJAX/REST HookPhuzz entrypoint pipeline.")
    parser.add_argument("--coverage-file", required=True)
    parser.add_argument("--plugin-slug", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--output-config-dir")
    parser.add_argument("--minimal-artifacts", action="store_true")
    parser.add_argument("--target-base", default="http://web")
    parser.add_argument("--container-source-root")
    parser.add_argument("--host-source-root")
    parser.add_argument("--source-root")
    parser.add_argument("--unresolved-source-reason")
    parser.add_argument("--runtime-parameters-only", action="store_true")
    parser.add_argument("--run-generated-configs", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=30)
    parser.add_argument("--service", default="fuzzer-wordpress-plugin")
    return parser


def main() -> int:
    args = build_argument_parser().parse_args()
    coverage_path = Path(args.coverage_file)
    output_dir = Path(args.output_dir)
    result = run_entrypoint_pipeline(
        json.loads(coverage_path.read_text(encoding="utf-8-sig")),
        plugin_slug=args.plugin_slug,
        output_dir=output_dir,
        output_config_dir=args.output_config_dir,
        minimal_artifacts=args.minimal_artifacts,
        target_base=args.target_base,
        container_source_root=args.container_source_root,
        host_source_root=args.host_source_root,
        source_root=args.source_root,
        unresolved_source_reason=args.unresolved_source_reason,
        runtime_parameters_only=args.runtime_parameters_only,
    )
    if args.run_generated_configs:
        summary_path = output_dir / "generated_config_summary.json"
        run_report = run_generated_configs(
            load_generated_configs(summary_path),
            timeout_seconds=args.timeout_seconds,
            service=args.service,
        )
        run_report["generated_config_summary"] = str(summary_path)
        write_report(run_report, output_dir / "generated_config_run_summary.json")
        write_report(format_validation_result(run_report), output_dir / "validation_result.json")
    summary = result["pipeline_summary"]["summary"]
    print(
        "Entrypoint pipeline summary: "
        f"generated={summary['generated']} skipped={summary['skipped']} output={output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
