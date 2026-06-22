from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


def load_config_slugs(path: Path) -> list[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(payload, Mapping) or not isinstance(payload.get("generated"), list):
        raise ValueError("generated_config_summary.json must contain a generated array")

    slugs: list[str] = []
    for index, item in enumerate(payload["generated"]):
        slug = item.get("config_slug") if isinstance(item, Mapping) else None
        if not isinstance(slug, str) or not slug.strip():
            raise ValueError(f"generated[{index}].config_slug must be a non-empty string")
        slugs.append(slug.strip())
    return slugs


def run_generated_configs(
    config_slugs: Sequence[str],
    *,
    timeout_seconds: int,
    service: str = "fuzzer-wordpress-plugin",
    run_command: CommandRunner = subprocess.run,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    runs: list[dict[str, Any]] = []
    for index, slug in enumerate(config_slugs, start=1):
        container_name = _container_name(index, slug)
        command = [
            "docker",
            "compose",
            "run",
            "--rm",
            "-T",
            "--name",
            container_name,
            "-e",
            f"FUZZER_CONFIG={slug}",
            service,
        ]
        started_at = time.monotonic()
        try:
            result = run_command(
                command,
                timeout=timeout_seconds,
                check=False,
            )
            status = "passed" if result.returncode == 0 else "failed"
            exit_code: int | None = result.returncode
        except subprocess.TimeoutExpired:
            run_command(
                ["docker", "rm", "-f", container_name],
                timeout=30,
                check=False,
                capture_output=True,
                text=True,
            )
            status = "timed_out"
            exit_code = None

        runs.append(
            {
                "config_slug": slug,
                "status": status,
                "exit_code": exit_code,
                "duration_seconds": round(time.monotonic() - started_at, 3),
                "container_name": container_name,
            }
        )

    return {
        "timeout_seconds": timeout_seconds,
        "runs": runs,
        "counts": {
            "total": len(runs),
            "passed": sum(row["status"] == "passed" for row in runs),
            "failed": sum(row["status"] == "failed" for row in runs),
            "timed_out": sum(row["status"] == "timed_out" for row in runs),
        },
    }


def write_report(report: Mapping[str, Any], output_file: Path) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = output_path.with_name(f"{output_path.name}.tmp")
    temporary_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    temporary_path.replace(output_path)


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run generated HookPhuzz configs sequentially.")
    parser.add_argument("--generated-config-summary", required=True)
    parser.add_argument("--output-file", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--service", default="fuzzer-wordpress-plugin")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        source_path = Path(args.generated_config_summary)
        slugs = load_config_slugs(source_path)
        report = run_generated_configs(
            slugs,
            timeout_seconds=args.timeout_seconds,
            service=args.service,
        )
        report["generated_config_summary"] = str(source_path)
        write_report(report, Path(args.output_file))
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    counts = report["counts"]
    print(
        "Generated config run summary: "
        f"passed={counts['passed']} failed={counts['failed']} "
        f"timed_out={counts['timed_out']} output={args.output_file}"
    )
    return 0 if counts["failed"] == 0 and counts["timed_out"] == 0 else 1


def _container_name(index: int, slug: str) -> str:
    safe_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", slug).strip(".-") or "config"
    return f"hookphuzz-generated-{index}-{safe_slug}"[:120]


if __name__ == "__main__":
    raise SystemExit(main())
