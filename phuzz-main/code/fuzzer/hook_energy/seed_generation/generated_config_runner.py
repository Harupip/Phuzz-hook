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

from seed_generation.verification.seed_validator import evaluate_artifact_payloads


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]
ArtifactLister = Callable[[], set[str]]
ArtifactLoader = Callable[[str], Any]
ProcessFactory = Callable[..., Any]
REQUESTS_DIR = "/shared-tmpfs/hook-coverage/requests"
FINDING_ARTIFACT_DIR = "/shared-tmpfs/fuzzer-findings"
ZEND_ARTIFACTS_DIR = "/shared/opcode-events"
STOP_ON_VULN_EXIT_CODE = 1337 % 256
ARTIFACT_READ_ATTEMPTS = 3
ARTIFACT_RETRY_DELAY_SECONDS = 0.05
METHOD_PROVENANCE_FIELDS = (
    "resolved_method",
    "candidate_methods",
    "method_status",
    "method_source",
    "method_confidence",
    "method_evidence",
    "observed_request_method",
    "route_declared_methods",
    "seed_variant_id",
)
AUTHENTICATED_ENTRYPOINT_TYPES = {"ajax_authenticated", "admin_post_authenticated"}
UNAUTHENTICATED_ENTRYPOINT_TYPES = {"ajax_unauthenticated", "admin_post_unauthenticated"}


def load_generated_configs(path: Path) -> list[dict[str, Any]]:
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
        for field in METHOD_PROVENANCE_FIELDS:
            if field in item:
                row[field] = item[field]
        configs.append(row)
    return configs


def list_request_artifacts() -> set[str]:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "sh", "-lc", f"find {REQUESTS_DIR} -maxdepth 1 -type f -name '*.json' -printf '%f\\n'"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not list hook coverage request artifacts")
    return _stable_artifact_names(result.stdout)


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


def load_finding_artifact(name: str) -> Any:
    if Path(name).name != name:
        raise ValueError(f"Invalid finding artifact name: {name}")
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "cat", f"{FINDING_ARTIFACT_DIR}/{name}"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or f"Could not read finding artifact: {name}")
    return json.loads(result.stdout)


def list_zend_artifacts() -> set[str]:
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "web", "sh", "-lc", f"find {ZEND_ARTIFACTS_DIR} -maxdepth 1 -type f -name '*.json' -printf '%f\\n'"],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not list Zend opcode artifacts")
    return _stable_artifact_names(result.stdout)


def _stable_artifact_names(output: str) -> set[str]:
    """Keep only finalized JSON artifacts; writers expose temporary files during rename."""
    return {
        name
        for name in (line.strip() for line in output.splitlines())
        if name and name.endswith(".json") and ".tmp" not in name
    }


def _load_artifact_with_retry(load_artifact: ArtifactLoader, name: str) -> Any:
    """Tolerate a short read/list race while an artifact is being finalized."""
    last_error: Exception | None = None
    for attempt in range(ARTIFACT_READ_ATTEMPTS):
        try:
            return load_artifact(name)
        except (OSError, RuntimeError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
            last_error = exc
            if attempt + 1 == ARTIFACT_READ_ATTEMPTS:
                raise
            time.sleep(ARTIFACT_RETRY_DELAY_SECONDS)
    raise RuntimeError(f"Could not read artifact: {name}") from last_error


def read_correlated_artifact_pair(
    request_dir: Path,
    zend_dir: Path,
    *,
    request_id: str,
    run_id: str,
    expected: Mapping[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Read one complete request/Zend pair from already-mounted directories."""
    expected = expected if isinstance(expected, Mapping) else {}
    request_id = str(request_id).strip()
    run_id = str(run_id).strip()
    if (
        not request_id
        or not run_id
        or request_id in {".", ".."}
        or re.fullmatch(r"[A-Za-z0-9_.-]+", request_id) is None
        or Path(request_id).name != request_id
        or ".tmp" in request_id
    ):
        return None

    request_path = Path(request_dir) / f"{request_id}.json"
    zend_path = Path(zend_dir) / f"{request_id}.json"
    try:
        request_payload = json.loads(request_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(request_payload, Mapping):
        return None
    if str(request_payload.get("request_id") or "").strip() != request_id:
        return None
    if str(request_payload.get("legacy_run_id") or request_payload.get("run_id") or "").strip() != run_id:
        return None
    response = request_payload.get("response")
    if not isinstance(response, Mapping):
        return None
    try:
        if int(response.get("status_code")) != 200:
            return None
    except (TypeError, ValueError):
        return None
    if expected.get("plugin_slug") and str(request_payload.get("target_plugin") or "") != str(expected["plugin_slug"]):
        return None
    if expected.get("hook_name") or expected.get("callback_id"):
        coverage = request_payload.get("hook_coverage")
        if not _artifact_matches_callback(
            request_payload,
            coverage if isinstance(coverage, Mapping) else {},
            hook_name=str(expected.get("hook_name") or ""),
            callback_id=str(expected.get("callback_id") or ""),
        ):
            return None
    if expected.get("method") and str(request_payload.get("http_method") or "").upper() != str(expected["method"]).upper():
        return None
    auth_context = request_payload.get("auth_context")
    if auth_context is None:
        request_params = request_payload.get("request_params")
        headers = request_params.get("headers") if isinstance(request_params, Mapping) else {}
        if isinstance(headers, Mapping):
            auth_context = next(
                (value for name, value in headers.items()
                 if str(name).lower() == "x-hookphuzz-auth-context"),
                None,
            )
    if expected.get("auth_context") and str(auth_context or "") != str(expected["auth_context"]):
        return None

    try:
        zend_payload = json.loads(zend_path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(zend_payload, Mapping):
        return None
    if str(zend_payload.get("request_id") or "").strip() != request_id:
        return None
    if str(zend_payload.get("run_id") or zend_payload.get("legacy_run_id") or "").strip() != run_id:
        return None
    return {
        "request_name": request_path.name,
        "request": dict(request_payload),
        "zend_name": zend_path.name,
        "zend": dict(zend_payload),
    }


def _artifact_matches_callback(
    request_payload: Mapping[str, Any],
    coverage: Mapping[str, Any],
    *,
    hook_name: str,
    callback_id: str,
) -> bool:
    """Match callback identity from either legacy top-level or hook coverage fields."""
    if request_payload.get("hook_name") or request_payload.get("callback_id"):
        return (
            (not hook_name or str(request_payload.get("hook_name") or "") == hook_name)
            and (not callback_id or str(request_payload.get("callback_id") or "") == callback_id)
        )
    entries: list[tuple[str, Mapping[str, Any]]] = []
    for bucket in ("registered_callbacks", "executed_callbacks"):
        mapping = coverage.get(bucket)
        if not isinstance(mapping, Mapping):
            continue
        entries.extend(
            (str(key), entry) for key, entry in mapping.items() if isinstance(entry, Mapping)
        )
    for key, entry in entries:
        entry_ids = {key}
        if entry.get("callback_id"):
            entry_ids.add(str(entry["callback_id"]))
        entry_hooks = {
            str(entry.get(field) or "")
            for field in ("hook_name", "fired_hook")
            if entry.get(field)
        }
        if callback_id and callback_id not in entry_ids:
            continue
        if hook_name and hook_name not in entry_hooks:
            continue
        return True
    return not hook_name and not callback_id


def run_generated_configs(
    generated_configs: Sequence[Mapping[str, str]],
    *,
    timeout_seconds: int,
    service: str = "fuzzer-wordpress-plugin",
    legacy_run_id: str = "",
    fuzzer_node_id: int | str | None = None,
    run_command: CommandRunner = subprocess.run,
    list_artifacts: ArtifactLister = list_request_artifacts,
    load_artifact: ArtifactLoader = load_request_artifact,
    finding_artifact_loader: ArtifactLoader = load_finding_artifact,
    stop_on_callback: bool = False,
    process_factory: ProcessFactory = subprocess.Popen,
    list_zend_artifacts: ArtifactLister = list_zend_artifacts,
    poll_interval_seconds: float = 0.1,
) -> dict[str, Any]:
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if poll_interval_seconds < 0:
        raise ValueError("poll_interval_seconds must not be negative")

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
        command = [
            "docker",
            "compose",
            "run",
            "--rm",
            "-T",
            "--name",
            container_name,
            "-e",
            f"FUZZER_CONFIG={_runtime_config_slug(config)}",
        ]
        finding_artifact_name = _finding_artifact_name(legacy_run_id, container_name)
        command += [
            "-e",
            f"HOOKPHUZZ_FINDING_ARTIFACT={FINDING_ARTIFACT_DIR}/{finding_artifact_name}",
        ]
        if legacy_run_id:
            command += ["-e", f"HOOKPHUZZ_LEGACY_RUN_ID={legacy_run_id}"]
        if fuzzer_node_id is not None:
            command += ["-e", f"FUZZER_NODE_ID={fuzzer_node_id}"]
        command.append(service)
        stop_reason = None
        try:
            if stop_on_callback:
                process_status, exit_code, stop_reason = _run_until_callback(
                    command,
                    container_name=container_name,
                    config=config,
                    artifacts_before=artifacts_before,
                    timeout_seconds=timeout_seconds,
                    process_factory=process_factory,
                    run_command=run_command,
                    list_artifacts=list_artifacts,
                    load_artifact=load_artifact,
                    list_zend_artifacts=list_zend_artifacts,
                    poll_interval_seconds=poll_interval_seconds,
                )
            else:
                result = run_command(
                    command,
                    timeout=timeout_seconds,
                    check=False,
                )
                exit_code = result.returncode
                process_status = _process_status(result.returncode)
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

        finding_artifact = None
        finding_artifact_error = None
        if process_status == "vuln_found":
            try:
                finding_artifact = finding_artifact_loader(finding_artifact_name)
            except Exception as exc:
                finding_artifact_error = str(exc)

        try:
            new_artifacts = sorted(list_artifacts() - artifacts_before)
            artifact_payloads = [(name, _load_artifact_with_retry(load_artifact, name)) for name in new_artifacts]
        except Exception as exc:
            runs.append(_runner_error_row(config, container_name, started_at, str(exc)))
            continue
        validation = evaluate_artifact_payloads(
            {"hook_name": config["hook_name"], "callback_id": config["callback_id"]},
            [payload for _, payload in artifact_payloads],
        )
        matched_artifact = _matched_artifact(config, artifact_payloads)
        failure_category = _failure_category(process_status, validation["status"])

        run_row = {
            "config_slug": slug,
            "config_path": config.get("config_path"),
            "hook_name": config["hook_name"],
            "callback_id": config["callback_id"],
            "entrypoint_type": config.get("entrypoint_type"),
            **_method_metadata(config),
            "process_status": process_status,
            "stop_reason": stop_reason,
            "validation_status": validation["status"],
            "validation_reason": validation["reason"],
            "callback_reached": validation["expected_callback_reached"],
            "failure_category": failure_category,
            "requests_created": len(new_artifacts),
            "request_artifacts": new_artifacts,
            "matched_artifact": matched_artifact,
            "exit_code": exit_code,
            "duration_seconds": round(time.monotonic() - started_at, 3),
            "container_name": container_name,
        }
        if process_status == "vuln_found":
            run_row["finding_artifact"] = finding_artifact
            run_row["finding_artifact_path"] = f"{FINDING_ARTIFACT_DIR}/{finding_artifact_name}"
            if finding_artifact_error:
                run_row["finding_artifact_error"] = finding_artifact_error
        runs.append(run_row)

    expected_auth_skip = classify_expected_auth_skips(runs)
    statuses = (
        "callback_reached",
        "registered_not_executed",
        "hook_fired_target_not_registered",
        "no_artifact",
        "not_observed",
    )
    report = {
        "timeout_seconds": timeout_seconds,
        "stop_on_callback": stop_on_callback,
        "runs": runs,
        "counts": {
            "total": len(runs),
            "process_failed": sum(row["process_status"] == "failed" for row in runs),
            "vuln_found": sum(row["process_status"] == "vuln_found" for row in runs),
            "runner_error": sum(row["process_status"] == "runner_error" for row in runs),
            "expected_auth_skip": expected_auth_skip,
            **{status: sum(row["validation_status"] == status for row in runs) for status in statuses},
        },
    }
    if legacy_run_id:
        report["legacy_run_id"] = legacy_run_id
    return report


def format_validation_result(report: Mapping[str, Any]) -> dict[str, Any]:
    validations = []
    for row in report.get('runs', []):
        validations.append(
            {
                'config_slug': row.get('config_slug'),
                'hook_name': row.get('hook_name'),
                'callback_id': row.get('callback_id'),
                'entrypoint_type': row.get('entrypoint_type'),
                **_method_metadata(row),
                'status': row.get('validation_status'),
                'callback_reached': bool(row.get('callback_reached')),
                'expected_auth_skip': bool(row.get('expected_auth_skip')),
                'expected_auth_reason': row.get('expected_auth_reason'),
                'failure_category': row.get('failure_category'),
                'reason': row.get('validation_reason'),
                'matched_artifact': row.get('matched_artifact'),
            }
        )
    return {
        'summary': {
            'total': len(validations),
            'callback_reached': sum(row['callback_reached'] for row in validations),
            'expected_auth_skip': sum(row['expected_auth_skip'] for row in validations),
        },
        'validations': validations,
    }

def format_recursive_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    results = [_format_recursive_result(row) for row in report.get("runs", [])]
    return {
        "total_configs": len(results),
        "passed": sum(row["status"] == "callback_reached" for row in results),
        "expected_auth_skip": sum(row["status"] == "expected_auth_skip" for row in results),
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
    parser.add_argument("--legacy-run-id", default="")
    parser.add_argument("--stop-on-callback", action="store_true")
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
            legacy_run_id=args.legacy_run_id,
            stop_on_callback=args.stop_on_callback,
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
        accepted = summary["passed"] + summary["expected_auth_skip"]
        return 0 if accepted == summary["total_configs"] and summary["failed"] == 0 else 1

    counts = report["counts"]
    print(
        "Generated config run summary: "
        f"callback_reached={counts['callback_reached']} "
        f"expected_auth_skip={counts['expected_auth_skip']} "
        f"vuln_found={counts['vuln_found']} "
        f"process_failed={counts['process_failed']} output={args.output_file}"
    )
    accepted = counts["callback_reached"] + counts["expected_auth_skip"]
    if counts["expected_auth_skip"]:
        print(
            "Generated config terminal status: "
            f"PASS_PARTIAL_AUTH_EXPECTED ({counts['callback_reached']} callback_reached, "
            f"{counts['expected_auth_skip']} expected auth skip)"
        )
    return 0 if counts["process_failed"] == 0 and counts["runner_error"] == 0 and accepted == counts["total"] else 1


def _container_name(index: int, slug: str) -> str:
    safe_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "-", slug).strip(".-") or "config"
    return f"hookphuzz-generated-{index}-{safe_slug}"[:120]


def _finding_artifact_name(legacy_run_id: str, container_name: str) -> str:
    safe_run_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(legacy_run_id or "run")).strip(".-") or "run"
    safe_container = re.sub(r"[^a-zA-Z0-9_.-]+", "-", container_name).strip(".-") or "worker"
    return f"{safe_run_id}-{safe_container}.json"


def _process_status(returncode: int) -> str:
    if returncode == 0:
        return "exited"
    if returncode == STOP_ON_VULN_EXIT_CODE:
        return "vuln_found"
    return "failed"


def _run_until_callback(
    command: Sequence[str],
    *,
    container_name: str,
    config: Mapping[str, str],
    artifacts_before: set[str],
    timeout_seconds: int,
    process_factory: ProcessFactory,
    run_command: CommandRunner,
    list_artifacts: ArtifactLister,
    load_artifact: ArtifactLoader,
    list_zend_artifacts: ArtifactLister,
    poll_interval_seconds: float,
) -> tuple[str, int | None, str | None]:
    process = process_factory(command)
    deadline = time.monotonic() + timeout_seconds
    candidate = {"hook_name": config["hook_name"], "callback_id": config["callback_id"]}

    try:
        while True:
            new_artifacts = sorted(list_artifacts() - artifacts_before)
            for name in new_artifacts:
                payload = _load_artifact_with_retry(load_artifact, name)
                stop_reason = _stop_reason_for_request_artifact(
                    candidate,
                    name,
                    payload,
                    list_zend_artifacts,
                )
                if stop_reason is None:
                    continue
                _terminate_process(process, container_name, run_command)
                if stop_reason == "callback_reached":
                    return "stopped_on_callback", None, stop_reason
                return "stopped_on_request", None, stop_reason

            returncode = process.poll()
            if returncode is not None:
                return _process_status(returncode), returncode, None

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_process(process, container_name, run_command)
                return "window_elapsed", None, "timeout"
            if poll_interval_seconds:
                time.sleep(min(poll_interval_seconds, remaining))
    except Exception:
        _terminate_process(process, container_name, run_command)
        raise


def _stop_reason_for_request_artifact(
    candidate: Mapping[str, str],
    name: str,
    payload: Any,
    list_zend_artifacts: ArtifactLister,
) -> str | None:
    if not _request_artifact_is_ready(payload):
        return None
    if not _callback_artifact_is_ready(candidate, payload):
        return "request_completed"
    return "callback_reached" if _zend_artifact_matches_request(name, list_zend_artifacts) else None


def _zend_artifact_matches_request(name: str, list_zend_artifacts: ArtifactLister) -> bool:
    try:
        zend_names = list_zend_artifacts()
    except Exception:
        return False
    return Path(name).stem in {Path(item).stem for item in zend_names}


def _terminate_process(process: Any, container_name: str, run_command: CommandRunner) -> None:
    run_command(
        ["docker", "rm", "-f", container_name],
        timeout=30,
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=30)


def _callback_artifact_is_ready(candidate: Mapping[str, str], payload: Any) -> bool:
    if not _request_artifact_is_ready(payload):
        return False
    validation = evaluate_artifact_payloads(candidate, [payload])
    return bool(validation["expected_callback_reached"])


def _request_artifact_is_ready(payload: Any) -> bool:
    if not isinstance(payload, Mapping):
        return False
    response = payload.get("response")
    if not isinstance(response, Mapping):
        return False
    try:
        return int(response.get("status_code")) == 200
    except (TypeError, ValueError):
        return False


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


def classify_expected_auth_skips(runs: list[dict[str, Any]]) -> int:
    """Mark only forced-auth nopriv misses paired with a reached auth variant."""
    reached_authenticated_hooks = {
        str(row.get("hook_name") or "")
        for row in runs
        if row.get("entrypoint_type") in AUTHENTICATED_ENTRYPOINT_TYPES
        and row.get("callback_reached") is True
        and row.get("process_status") not in {"failed", "runner_error"}
    }
    expected_count = 0
    for row in runs:
        hook_name = str(row.get("hook_name") or "")
        counterpart = _authenticated_counterpart_hook(hook_name)
        if (
            row.get("entrypoint_type") in UNAUTHENTICATED_ENTRYPOINT_TYPES
            and row.get("validation_status") == "registered_not_executed"
            and row.get("process_status") not in {"failed", "runner_error"}
            and counterpart in reached_authenticated_hooks
        ):
            row["expected_auth_skip"] = True
            row["expected_auth_reason"] = "authenticated_counterpart_reached"
            row["failure_category"] = None
            expected_count += 1
    return expected_count


def _authenticated_counterpart_hook(hook_name: str) -> str | None:
    for unauthenticated_prefix, authenticated_prefix in (
        ("wp_ajax_nopriv_", "wp_ajax_"),
        ("admin_post_nopriv_", "admin_post_"),
    ):
        if hook_name.startswith(unauthenticated_prefix):
            return authenticated_prefix + hook_name[len(unauthenticated_prefix):]
    return None

def _method_metadata(value: Mapping[str, Any]) -> dict[str, Any]:
    return {field: value.get(field) for field in METHOD_PROVENANCE_FIELDS if field in value}


def _matched_artifact(config: Mapping[str, Any], artifacts: Sequence[tuple[str, Any]]) -> str | None:
    candidate = {"hook_name": config["hook_name"], "callback_id": config["callback_id"]}
    for name, payload in artifacts:
        validation = evaluate_artifact_payloads(candidate, [payload])
        if validation["expected_callback_reached"]:
            return name
    return None


def _runner_error_row(
    config: Mapping[str, Any],
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
        **_method_metadata(config),
        "process_status": "runner_error",
        "validation_status": "runner_error",
        "validation_reason": reason,
        "callback_reached": False,
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
    if row.get("expected_auth_skip"):
        return "expected_auth_skip"
    if row.get("callback_reached"):
        return "callback_reached"
    if row.get("process_status") == "runner_error":
        return "runner_error"
    if row.get("process_status") == "window_elapsed":
        return "timed_out"
    return "failed"


if __name__ == "__main__":
    raise SystemExit(main())
