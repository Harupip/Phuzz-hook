from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit, urlunsplit
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
ArtifactRecovery = Callable[[], list[tuple[str, Any]]]
REQUESTS_DIR = "/shared-tmpfs/hook-coverage/requests"
STOP_ON_VULN_EXIT_CODE = 1337 % 256


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
        row = {field: str(item[field]).strip() for field in ("config_slug", "hook_name", "callback_id")}
        config_path = item.get("config_path")
        if config_path is not None:
            if not isinstance(config_path, str) or not config_path.strip():
                raise ValueError(f"generated[{index}].config_path must be a non-empty string")
            row["config_path"] = config_path.strip()
        entrypoint_type = item.get("entrypoint_type")
        if entrypoint_type is not None:
            if not isinstance(entrypoint_type, str) or not entrypoint_type.strip():
                raise ValueError(f"generated[{index}].entrypoint_type must be a non-empty string")
            row["entrypoint_type"] = entrypoint_type.strip()
        configs.append(row)
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


def recover_request_artifacts_direct_copy() -> list[tuple[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="hookphuzz-artifacts-") as temp_dir:
        destination = Path(temp_dir)
        result = subprocess.run(
            ["docker", "compose", "cp", f"web:{REQUESTS_DIR}/.", str(destination)],
            timeout=30,
            check=False,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "Could not directly copy request artifacts")
        return [
            (path.name, json.loads(path.read_text(encoding="utf-8-sig")))
            for path in sorted(destination.glob("*.json"))
        ]


def run_generated_configs(
    generated_configs: Sequence[Mapping[str, str]],
    *,
    timeout_seconds: int,
    service: str = "fuzzer-wordpress-plugin",
    run_command: CommandRunner = subprocess.run,
    list_artifacts: ArtifactLister = list_request_artifacts,
    load_artifact: ArtifactLoader = load_request_artifact,
    recover_artifacts: ArtifactRecovery = recover_request_artifacts_direct_copy,
    force_primary_artifact_read_failure: bool = False,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")

    rest_transport = _rest_transport_mode()
    runs: list[dict[str, Any]] = []
    for index, config in enumerate(generated_configs, start=1):
        slug = str(config["config_slug"])
        container_name = _container_name(index, slug)
        started_at = time.monotonic()
        try:
            artifacts_before = list_artifacts()
        except Exception as exc:
            runs.append(_runner_error_row(config, container_name, started_at, str(exc)))
            continue
        runtime_slug, requested_url, effective_url, fallback_used = _runtime_config_for_rest(config, rest_transport)
        command = [
            "docker",
            "compose",
            "run",
            "--rm",
            "-T",
            "--name",
            container_name,
            "-e",
            f"FUZZER_CONFIG={runtime_slug}",
            service,
        ]
        try:
            result = run_command(
                command,
                timeout=timeout_seconds,
                check=False,
            )
            exit_code: int | None = result.returncode
            if result.returncode == 0:
                process_status = "exited"
            elif result.returncode == STOP_ON_VULN_EXIT_CODE:
                process_status = "vuln_found"
            else:
                process_status = "failed"
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
        except Exception as exc:
            runs.append(_runner_error_row(config, container_name, started_at, str(exc)))
            continue

        artifact_status = "loaded"
        artifact_retrieval_method = "compose_exec"
        reporting_status = "ok"
        reporting_error = None
        try:
            new_artifacts = sorted(list_artifacts() - artifacts_before)
            if force_primary_artifact_read_failure:
                raise subprocess.TimeoutExpired("docker compose exec artifact read", 30)
            artifact_payloads = [(name, load_artifact(name)) for name in new_artifacts]
        except Exception as exc:
            reporting_error = _reporting_error_code(exc)
            artifact_status = "failed"
            reporting_status = "degraded"
            try:
                artifact_payloads = recover_artifacts()
                new_artifacts = [name for name, _ in artifact_payloads]
                artifact_status = "recovered"
                artifact_retrieval_method = "direct_copy"
            except Exception:
                new_artifacts = []
                artifact_payloads = []
        validation = evaluate_artifact_payloads(
            {"hook_name": config["hook_name"], "callback_id": config["callback_id"]},
            [payload for _, payload in artifact_payloads],
        )
        matched_artifact = _matched_artifact(config, artifact_payloads)
        failure_category = _failure_category(process_status, validation["status"])

        runs.append(
            {
                "config_slug": slug,
                "config_path": config.get("config_path"),
                "hook_name": config["hook_name"],
                "callback_id": config["callback_id"],
                "entrypoint_type": config.get("entrypoint_type"),
                "requested_url": requested_url,
                "effective_url": effective_url,
                "rest_fallback_used": fallback_used,
                "process_status": process_status,
                "execution_status": _execution_status(process_status, validation["expected_callback_reached"]),
                "validation_status": validation["status"],
                "validation_reason": validation["reason"],
                "callback_reached": validation["expected_callback_reached"],
                "artifact_status": artifact_status,
                "artifact_retrieval_method": artifact_retrieval_method,
                "reporting_status": reporting_status,
                "reporting_error": reporting_error,
                "failure_category": failure_category,
                "requests_created": len(new_artifacts),
                "request_artifacts": new_artifacts,
                "matched_artifact": matched_artifact,
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
            "vuln_found": sum(row["process_status"] == "vuln_found" for row in runs),
            "runner_error": sum(row["process_status"] == "runner_error" for row in runs),
            **{status: sum(row["validation_status"] == status for row in runs) for status in statuses},
        },
    }


def format_validation_result(report: Mapping[str, Any]) -> dict[str, Any]:
    validations = []
    for row in report.get('runs', []):
        validations.append(
            {
                'config_slug': row.get('config_slug'),
                'hook_name': row.get('hook_name'),
                'callback_id': row.get('callback_id'),
                'entrypoint_type': row.get('entrypoint_type'),
                'status': row.get('validation_status'),
                'callback_reached': bool(row.get('callback_reached')),
                'failure_category': row.get('failure_category'),
                'reason': row.get('validation_reason'),
                'matched_artifact': row.get('matched_artifact'),
            }
        )
    return {
        'summary': {
            'total': len(validations),
            'callback_reached': sum(row['callback_reached'] for row in validations),
        },
        'validations': validations,
    }

def format_recursive_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    results = [_format_recursive_result(row) for row in report.get("runs", [])]
    return {
        "total_configs": len(results),
        "passed": sum(row["status"] == "callback_reached" for row in results),
        "failed": sum(row["status"] in {"failed", "runner_error"} for row in results),
        "timed_out": sum(row["status"] == "timed_out" for row in results),
        "results": results,
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
    parser.add_argument("--output-format", choices=("default", "recursive"), default="default")
    parser.add_argument("--force-primary-artifact-read-failure", action="store_true", help="Validation-only: force primary artifact read failure and exercise direct-copy recovery.")
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
            force_primary_artifact_read_failure=args.force_primary_artifact_read_failure,
        )
        report["generated_config_summary"] = str(source_path)
        output_report = format_recursive_summary(report) if args.output_format == "recursive" else report
        output_path = Path(args.output_file)
        write_report(output_report, output_path)
        if args.output_format == 'default':
            write_report(format_validation_result(report), output_path.with_name('validation_result.json'))
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.output_format == "recursive":
        print(f"Recursive config run summary: output={args.output_file}")
        summary = format_recursive_summary(report)
        return 0 if summary["passed"] == summary["total_configs"] and summary["failed"] == 0 else 1

    counts = report["counts"]
    print(
        "Generated config run summary: "
        f"callback_reached={counts['callback_reached']} "
        f"vuln_found={counts['vuln_found']} "
        f"process_failed={counts['process_failed']} output={args.output_file}"
    )
    return 0 if counts["process_failed"] == 0 and counts["runner_error"] == 0 and counts["callback_reached"] == counts["total"] else 1


def _container_name(index: int, slug: str) -> str:
    safe_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", slug).strip(".-") or "config"
    return f"hookphuzz-generated-{index}-{safe_slug}"[:120]


def _runtime_config_slug(config: Mapping[str, str]) -> str:
    config_path = config.get("config_path")
    if not config_path:
        return str(config["config_slug"])

    normalized = str(config_path).replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    lowered = [part.lower() for part in parts]
    if "fuzzer" in lowered:
        index = len(lowered) - 1 - lowered[::-1].index("fuzzer")
        slug = "/".join([".."] + parts[index + 1 :])
    else:
        slug = normalized
    return slug[:-5] if slug.lower().endswith(".json") else slug


def _rest_transport_mode() -> str:
    try:
        result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "sh", "-lc", "curl -fsS -o /dev/null -w '%{http_code}' http://localhost/wp-json/"],
        timeout=30, check=False, capture_output=True, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "rest_route"
    return "canonical" if result.returncode == 0 and result.stdout.strip() == "200" else "rest_route"


def _runtime_config_for_rest(config: Mapping[str, str], transport: str) -> tuple[str, str | None, str | None, bool]:
    config_path = config.get("config_path")
    if config.get("entrypoint_type") != "rest_route" or not config_path:
        return _runtime_config_slug(config), None, None, False
    path = Path(config_path)
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    requested = str(payload.get("target", ""))
    if transport != "rest_route" or not requested:
        return _runtime_config_slug(config), requested, requested, False
    target = urlsplit(requested)
    prefix = "/wp-json/"
    if not target.path.startswith(prefix):
        return _runtime_config_slug(config), requested, requested, False
    route = target.path[len(prefix) - 1 :]
    effective = urlunsplit((target.scheme, target.netloc, "/", f"rest_route={route}", ""))
    replay_path = path.with_name(f"{path.stem}__rest_route_replay.json")
    payload["target"] = effective
    replay_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    replay_config = {**config, "config_path": str(replay_path)}
    return _runtime_config_slug(replay_config), requested, effective, True


def _execution_status(process_status: str, callback_reached: bool) -> str:
    if callback_reached:
        return "callback_reached"
    return process_status


def _reporting_error_code(exc: Exception) -> str:
    name = type(exc).__name__.lower()
    text = str(exc).lower()
    if "timeoutexpired" in name or "timed out" in text or "timeout" in text:
        return "compose_exec_timeout"
    return name or "artifact_transport_error"

def _failure_category(process_status: str, validation_status: str) -> str | None:
    if validation_status == 'callback_reached':
        return None
    if process_status == 'runner_error' or validation_status == 'runner_error':
        return 'F. instrumentation/generation bug'
    if validation_status in {'no_artifact', 'hook_fired_target_not_registered'}:
        return 'C. request mapping wrong'
    if validation_status == 'registered_not_executed':
        return 'E. callback registered but not HTTP reachable'
    if validation_status == 'not_observed':
        return 'B. auth/login branch mismatch'
    if process_status == 'failed':
        return 'A. plugin dependency/context missing'
    return 'F. instrumentation/generation bug'

def _matched_artifact(config: Mapping[str, str], artifacts: Sequence[tuple[str, Any]]) -> str | None:
    candidate = {"hook_name": config["hook_name"], "callback_id": config["callback_id"]}
    for name, payload in artifacts:
        validation = evaluate_artifact_payloads(candidate, [payload])
        if validation["expected_callback_reached"]:
            return name
    return None


def _runner_error_row(
    config: Mapping[str, str],
    container_name: str,
    started_at: float,
    reason: str,
) -> dict[str, Any]:
    return {
        "config_slug": str(config["config_slug"]),
        "config_path": config.get("config_path"),
        "hook_name": str(config["hook_name"]),
        "callback_id": str(config["callback_id"]),
        "entrypoint_type": config.get("entrypoint_type"),
        "process_status": "runner_error",
        "execution_status": "runner_error",
        "validation_status": "runner_error",
        "validation_reason": reason,
        "callback_reached": False,
        "artifact_status": "not_attempted",
        "artifact_retrieval_method": None,
        "reporting_status": "failed",
        "reporting_error": reason,
        "failure_category": "F. instrumentation/generation bug",
        "requests_created": 0,
        "request_artifacts": [],
        "matched_artifact": None,
        "exit_code": None,
        "duration_seconds": round(time.monotonic() - started_at, 3),
        "container_name": container_name,
    }


def _format_recursive_result(row: Mapping[str, Any]) -> dict[str, Any]:
    status = _recursive_status(row)
    return {
        "config": str(row.get("config_path") or row.get("config_slug", "")),
        "expected_hook": str(row.get("hook_name", "")),
        "expected_callback": str(row.get("callback_id", "")),
        "status": status,
        "matched_artifact": row.get("matched_artifact"),
        "reason": str(row.get("validation_reason", "")),
        "duration_seconds": row.get("duration_seconds", 0),
    }


def _recursive_status(row: Mapping[str, Any]) -> str:
    if row.get("callback_reached"):
        return "callback_reached"
    if row.get("process_status") == "runner_error":
        return "runner_error"
    if row.get("process_status") == "window_elapsed":
        return "timed_out"
    return "failed"


if __name__ == "__main__":
    raise SystemExit(main())





