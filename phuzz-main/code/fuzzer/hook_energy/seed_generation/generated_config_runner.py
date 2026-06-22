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

FUZZER_DIR = Path(__file__).resolve().parents[2]
if str(FUZZER_DIR) not in sys.path:
    sys.path.insert(0, str(FUZZER_DIR))

from hook_energy.seed_validator import evaluate_artifact_payloads


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
REQUESTS_DIR = "/shared-tmpfs/hook-coverage/requests"


def load_generated_configs(path: Path) -> list[dict[str, str]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(payload, Mapping) or not isinstance(payload.get("generated"), list):
        raise ValueError("generated_config_summary.json must contain a generated array")

    configs: list[dict[str, str]] = []
    for index, item in enumerate(payload["generated"]):
        for field in ("config_slug", "hook_name", "callback_id"):
            value = item.get(field) if isinstance(item, Mapping) else None
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"generated[{index}].{field} must be a non-empty string")
        configs.append({field: str(item[field]).strip() for field in ("config_slug", "hook_name", "callback_id")})
    return configs


def list_request_artifacts() -> set[str]:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "sh", "-lc", f"find {REQUESTS_DIR} -maxdepth 1 -type f -printf '%f\\n'"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not list hook coverage request artifacts")
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def load_request_artifact(name: str) -> Any:
    if Path(name).name != name:
        raise ValueError(f"Invalid request artifact name: {name}")
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "cat", f"{REQUESTS_DIR}/{name}"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Could not read request artifact: {name}")
    return json.loads(result.stdout)


def run_generated_configs(
    generated_configs: Sequence[Mapping[str, str]],
    *,
    timeout_seconds: int,
    service: str = "fuzzer-wordpress-plugin",
    run_command: CommandRunner = subprocess.run,
    list_artifacts: ArtifactLister = list_request_artifacts,
    load_artifact: ArtifactLoader = load_request_artifact,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    runs: list[dict[str, Any]] = []
    for index, config in enumerate(generated_configs, start=1):
        slug = str(config["config_slug"])
        container_name = _container_name(index, slug)
        artifacts_before = list_artifacts()
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
            process_status = "exited" if result.returncode == 0 else "failed"
            exit_code: int | None = result.returncode
        except subprocess.TimeoutExpired:
            run_command(
                ["docker", "rm", "-f", container_name],
                timeout=30,
                check=False,
                capture_output=True,
                text=True,
            )
            process_status = "window_elapsed"
            exit_code = None

        new_artifacts = sorted(list_artifacts() - artifacts_before)
        validation = evaluate_artifact_payloads(
            {"hook_name": config["hook_name"], "callback_id": config["callback_id"]},
            [load_artifact(name) for name in new_artifacts],
        )

        runs.append(
            {
                "config_slug": slug,
                "hook_name": config["hook_name"],
                "callback_id": config["callback_id"],
                "process_status": process_status,
                "validation_status": validation["status"],
                "validation_reason": validation["reason"],
                "callback_reached": validation["expected_callback_reached"],
                "requests_created": len(new_artifacts),
                "request_artifacts": new_artifacts,
                "exit_code": exit_code,
                "duration_seconds": round(time.monotonic() - started_at, 3),
                "container_name": container_name,
            }
        )

    statuses = (
        "callback_reached",
        "registered_not_executed",
        "hook_fired_target_not_registered",
        "no_artifact",
        "not_observed",
    )
    return {
        "timeout_seconds": timeout_seconds,
        "runs": runs,
        "counts": {
            "total": len(runs),
            "process_failed": sum(row["process_status"] == "failed" for row in runs),
            **{status: sum(row["validation_status"] == status for row in runs) for status in statuses},
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
        generated_configs = load_generated_configs(source_path)
        report = run_generated_configs(
            generated_configs,
            timeout_seconds=args.timeout_seconds,
            service=args.service,
        )
        report["generated_config_summary"] = str(source_path)
        write_report(report, Path(args.output_file))
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    counts = report["counts"]
    print(
        "Generated config run summary: "
        f"callback_reached={counts['callback_reached']} "
        f"process_failed={counts['process_failed']} output={args.output_file}"
    )
    return 0 if counts["process_failed"] == 0 and counts["callback_reached"] == counts["total"] else 1


def _container_name(index: int, slug: str) -> str:
    safe_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", slug).strip(".-") or "config"
    return f"hookphuzz-generated-{index}-{safe_slug}"[:120]


if __name__ == "__main__":
    raise SystemExit(main())
